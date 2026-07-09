package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/term"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"syscall"
)

// --- shared constants & state paths ---

const (
	defaultWGName = "wg0"

	stateDir     = "/var/lib/wg-go" // JSON state
	clientsDir   = "/clients"       // exported client .conf
	stateParams  = stateDir + "/params.json"
	stateClients = stateDir + "/clients.json"
)

// --- data models ---

type Params struct {
	ServerPubIP   string `json:"SERVER_PUB_IP"`
	ServerPubNIC  string `json:"SERVER_PUB_NIC"`
	ServerWGNic   string `json:"SERVER_WG_NIC"`
	ServerWGIPv4  string `json:"SERVER_WG_IPV4"`
	ServerWGIPv6  string `json:"SERVER_WG_IPV6"`
	ServerPort    int    `json:"SERVER_PORT"`
	ServerPrivKey string `json:"SERVER_PRIV_KEY"`
	ServerPubKey  string `json:"SERVER_PUB_KEY"`
	ClientDNS1    string `json:"CLIENT_DNS_1"`
	ClientDNS2    string `json:"CLIENT_DNS_2"`
	AllowedIPs    string `json:"ALLOWED_IPS"`
}

type ClientEntry struct {
	Name         string `json:"name"`
	IPv4         string `json:"ipv4"`
	IPv6         string `json:"ipv6"`
	PublicKey    string `json:"public_key"`
	PreSharedKey string `json:"preshared_key"`
	TotalRxBytes uint64 `json:"total_rx_bytes,omitempty"`
	TotalTxBytes uint64 `json:"total_tx_bytes,omitempty"`
	LastRxBytes  uint64 `json:"last_rx_bytes,omitempty"`
	LastTxBytes  uint64 `json:"last_tx_bytes,omitempty"`
}

type ClientsState struct {
	List []ClientEntry `json:"list"`
}

func usage() {
	fmt.Print(`wg-go-installer - WireGuard server installer/manager (Docker-friendly)

Usage:
  wg-go-installer            # interactive menu
  wg-go-installer menu       # interactive menu
  wg-go-installer install    # interactive install, then add a client
  wg-go-installer up         # reapply saved params (bring wg up)
  wg-go-installer add --name <client>
  wg-go-installer list
  wg-go-installer show-qr --name <client>
  wg-go-installer show-config --name <client>
  wg-go-installer export --name <client> --dest </path/to/dir>
  wg-go-installer regenerate-configs [--endpoint-host <host>] [--client-dns 10.66.66.1]
  wg-go-installer generate-profiles [--endpoint-host <host>] [--client-dns 10.66.66.1]
  wg-go-installer edit --name <client> [--new-name <new>] [--rotate-keys]
  wg-go-installer revoke --name <client>
  wg-go-installer monitor [--interval 5s]
  wg-go-installer status
  wg-go-installer uninstall
`)
}

func mustRoot() {
	if os.Geteuid() != 0 {
		log.Fatalf("Run as root (NET_ADMIN is required when Dockerized).")
	}
}

func ensureDirs() {
	_ = os.MkdirAll("/etc/wireguard", 0o700)
	_ = os.MkdirAll(stateDir, 0o700)
	_ = os.MkdirAll(clientsDir, 0o755)
}

var errInputInterrupted = errors.New("input interrupted")

func backendMode() string {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("WG_BACKEND")))
	if v == "userspace" {
		return "userspace"
	}
	return "kernel"
}

func usingUserspace() bool {
	return backendMode() == "userspace"
}

func userspaceCommandArgs(iface string) []string {
	bin := strings.TrimSpace(os.Getenv("WG_USERSPACE_BIN"))
	if bin == "" {
		bin = "wireguard-go"
	}
	flags := strings.TrimSpace(os.Getenv("WG_USERSPACE_FLAGS"))
	args := []string{}
	if flags != "" {
		args = append(args, strings.Fields(flags)...)
	}
	args = append(args, iface)
	return append([]string{bin}, args...)
}

func spawnUserspaceBackend(iface string) error {
	cmdArgs := userspaceCommandArgs(iface)
	log.Printf("Starting userspace backend (%s): %s", backendMode(), strings.Join(cmdArgs, " "))
	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	go cmd.Wait()
	return nil
}

func waitForLink(name string, timeout time.Duration) (netlink.Link, error) {
	deadline := time.Now().Add(timeout)
	for {
		link, err := netlink.LinkByName(name)
		if err == nil {
			return link, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("link %s not found", name)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func ensureKernelLink(p Params) (netlink.Link, error) {
	link, err := netlink.LinkByName(p.ServerWGNic)
	if err == nil {
		return link, nil
	}
	gl := &netlink.GenericLink{
		LinkAttrs: netlink.LinkAttrs{Name: p.ServerWGNic, MTU: 1420},
		LinkType:  "wireguard",
	}
	if err := netlink.LinkAdd(gl); err != nil {
		return nil, fmt.Errorf("link add: %w", err)
	}
	return gl, nil
}

func ensureUserspaceLink(p Params) (netlink.Link, error) {
	link, err := netlink.LinkByName(p.ServerWGNic)
	if err == nil {
		return link, nil
	}
	if err := spawnUserspaceBackend(p.ServerWGNic); err != nil {
		return nil, err
	}
	return waitForLink(p.ServerWGNic, 5*time.Second)
}

func configureLink(link netlink.Link, p Params) error {
	_ = netlink.LinkSetMTU(link, 1420)
	for _, cidr := range serverInterfaceCIDRs(p) {
		ipn, err := parseHostCIDR(cidr)
		if err != nil {
			return fmt.Errorf("invalid server interface CIDR %q: %w", cidr, err)
		}
		if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: ipn}); err != nil && !errors.Is(err, syscall.EEXIST) {
			// ignore duplicates
		}
	}
	return netlink.LinkSetUp(link)
}

func serverInterfaceCIDRs(p Params) []string {
	return []string{p.ServerWGIPv4 + "/24", p.ServerWGIPv6 + "/64"}
}

func parseHostCIDR(cidr string) (*net.IPNet, error) {
	ip, ipn, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	ipn.IP = ip
	return ipn, nil
}

func readLineInteractive(prompt string) (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print(prompt)
		text, err := reader.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", err
		}
		return strings.TrimSpace(text), err
	}

	fmt.Print(prompt)
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		reader := bufio.NewReader(os.Stdin)
		text, err2 := reader.ReadString('\n')
		if err2 != nil && !errors.Is(err2, io.EOF) {
			return "", err2
		}
		return strings.TrimSpace(text), err2
	}
	defer term.Restore(fd, oldState)

	reader := bufio.NewReader(os.Stdin)
	var buf []rune
	cursor := 0

	redraw := func() {
		fmt.Print("\r\033[2K")
		fmt.Print(prompt)
		fmt.Print(string(buf))
		if cursor < len(buf) {
			fmt.Printf("\033[%dD", len(buf)-cursor)
		}
	}

	for {
		r, _, err := reader.ReadRune()
		if err != nil {
			if errors.Is(err, io.EOF) {
				fmt.Print("\r\n")
				return strings.TrimSpace(string(buf)), io.EOF
			}
			return "", err
		}
		switch r {
		case '\r', '\n':
			fmt.Print("\r\n")
			return strings.TrimSpace(string(buf)), nil
		case 4: // Ctrl+D
			fmt.Print("\r\n")
			return "", io.EOF
		case 3: // Ctrl+C
			fmt.Print("\r\n")
			return "", errInputInterrupted
		case 127, 8: // Backspace
			if cursor > 0 {
				buf = append(buf[:cursor-1], buf[cursor:]...)
				cursor--
				redraw()
			}
		case 27: // Escape sequences (arrows)
			next, _, err := reader.ReadRune()
			if err != nil {
				continue
			}
			if next != '[' {
				continue
			}
			dir, _, err := reader.ReadRune()
			if err != nil {
				continue
			}
			switch dir {
			case 'C': // right
				if cursor < len(buf) {
					cursor++
					fmt.Print("\033[1C")
				}
			case 'D': // left
				if cursor > 0 {
					cursor--
					fmt.Print("\033[1D")
				}
			default:
			}
		default:
			buf = append(buf[:cursor], append([]rune{r}, buf[cursor:]...)...)
			cursor++
			redraw()
		}
	}
}

func readLine(prompt string) (string, error) {
	text, err := readLineInteractive(prompt)
	if err != nil && errors.Is(err, errInputInterrupted) {
		return "", err
	}
	return strings.TrimSpace(text), err
}

func readLineOrExit(prompt string) string {
	text, err := readLine(prompt)
	if err != nil {
		if errors.Is(err, errInputInterrupted) {
			os.Exit(1)
		}
		if errors.Is(err, io.EOF) {
			os.Exit(0)
		}
		log.Fatal(err)
	}
	return text
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func fdSet(fd int, set *syscall.FdSet) {
	index := fd / 64
	offset := uint(fd % 64)
	set.Bits[index] |= 1 << offset
}

func fdIsSet(fd int, set *syscall.FdSet) bool {
	index := fd / 64
	offset := uint(fd % 64)
	return set.Bits[index]&(1<<offset) != 0
}

func runCmd(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func iptablesRuleExists(v6 bool, table, chain string, rule []string) bool {
	bin := "iptables"
	if v6 {
		bin = "ip6tables"
	}
	args := []string{}
	if table != "" {
		args = append(args, "-t", table)
	}
	args = append(args, "-C", chain)
	args = append(args, rule...)
	_, err := runCmd(bin, args...)
	return err == nil
}

func iptablesAddRule(v6 bool, table, chain string, rule []string) {
	if iptablesRuleExists(v6, table, chain, rule) {
		return
	}
	bin := "iptables"
	if v6 {
		bin = "ip6tables"
	}
	args := []string{}
	if table != "" {
		args = append(args, "-t", table)
	}
	args = append(args, "-A", chain)
	args = append(args, rule...)
	if _, err := runCmd(bin, args...); err != nil {
		log.Printf("%s add rule failed: %v", bin, err)
	}
}

func iptablesDeleteRule(v6 bool, table, chain string, rule []string) {
	bin := "iptables"
	if v6 {
		bin = "ip6tables"
	}
	for iptablesRuleExists(v6, table, chain, rule) {
		args := []string{}
		if table != "" {
			args = append(args, "-t", table)
		}
		args = append(args, "-D", chain)
		args = append(args, rule...)
		if _, err := runCmd(bin, args...); err != nil {
			log.Printf("%s delete rule failed: %v", bin, err)
			return
		}
	}
}

func defaultPubNIC() string {
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{}, netlink.RT_FILTER_DST)
	if err == nil {
		for _, route := range routes {
			if route.Dst != nil || route.LinkIndex == 0 {
				continue
			}
			link, err := netlink.LinkByIndex(route.LinkIndex)
			if err == nil && strings.TrimSpace(link.Attrs().Name) != "" {
				return link.Attrs().Name
			}
		}
	}
	return "eth0"
}

func firstGlobalAddrV4() string {
	return firstGlobalAddr(func(ip net.IP) bool { return ip.To4() != nil })
}

func firstGlobalAddrV6() string {
	return firstGlobalAddr(func(ip net.IP) bool { return ip.To4() == nil && ip.To16() != nil })
}

func firstGlobalAddr(match func(net.IP) bool) string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || !ip.IsGlobalUnicast() || !match(ip) {
				continue
			}
			return ip.String()
		}
	}
	return ""
}

func bracketIPv6(host string) string {
	if strings.Contains(host, ":") && !(strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]")) {
		return "[" + host + "]"
	}
	return host
}

func randomPort() int {
	rand.Seed(time.Now().UnixNano())
	return 49152 + rand.Intn(65535-49152+1)
}

func validateIP(ip string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP: %s", ip)
	}
	return nil
}

func validateCIDR(c string) error {
	if _, _, err := net.ParseCIDR(c); err != nil {
		return fmt.Errorf("invalid CIDR: %s", c)
	}
	return nil
}

func prompt(defaultVal, question string, validate func(string) error) string {
	for {
		var p string
		if defaultVal != "" {
			p = fmt.Sprintf("%s [%s]: ", question, defaultVal)
		} else {
			p = fmt.Sprintf("%s: ", question)
		}
		text := readLineOrExit(p)
		if text == "" {
			text = defaultVal
		}
		if validate != nil {
			if err := validate(text); err != nil {
				fmt.Printf("  -> %v\n", err)
				continue
			}
		}
		return text
	}
}

func ensureTun() error {
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		return fmt.Errorf("/dev/net/tun not found (Docker must pass --device /dev/net/tun and cap NET_ADMIN)")
	}
	return nil
}

func mustJSON(v any) []byte {
	b, _ := json.MarshalIndent(v, "", "  ")
	return b
}

func saveParams(p Params) error {
	return os.WriteFile(stateParams, mustJSON(p), 0o600)
}

func loadParams() (Params, error) {
	var p Params
	raw, err := os.ReadFile(stateParams)
	if err != nil {
		return p, err
	}
	err = json.Unmarshal(raw, &p)
	return p, err
}

func createOrUpWG(p Params) error {
	if err := ensureTun(); err != nil {
		return err
	}
	var (
		link netlink.Link
		err  error
	)
	if usingUserspace() {
		link, err = ensureUserspaceLink(p)
	} else {
		link, err = ensureKernelLink(p)
	}
	if err != nil {
		return err
	}
	if err := configureLink(link, p); err != nil {
		return err
	}
	return configureDevice(p)
}

func configureDevice(p Params) error {
	priv, err := wgtypes.ParseKey(p.ServerPrivKey)
	if err != nil {
		return fmt.Errorf("server private key: %w", err)
	}
	client, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer client.Close()

	cfg := wgtypes.Config{
		PrivateKey: &priv,
		ListenPort: &p.ServerPort,
	}
	return client.ConfigureDevice(p.ServerWGNic, cfg)
}

func iptablesApply(p Params, add bool) {
	rules := []struct {
		v6    bool
		table string
		chain string
		rule  []string
	}{
		{false, "nat", "POSTROUTING", []string{"-o", p.ServerPubNIC, "-j", "MASQUERADE"}},
		{false, "", "FORWARD", []string{"-i", p.ServerPubNIC, "-o", p.ServerWGNic, "-j", "ACCEPT"}},
		{false, "", "FORWARD", []string{"-i", p.ServerWGNic, "-j", "ACCEPT"}},
		{true, "nat", "POSTROUTING", []string{"-o", p.ServerPubNIC, "-j", "MASQUERADE"}},
		{true, "", "FORWARD", []string{"-i", p.ServerWGNic, "-j", "ACCEPT"}},
	}
	for _, r := range rules {
		if add {
			iptablesAddRule(r.v6, r.table, r.chain, r.rule)
		} else {
			iptablesDeleteRule(r.v6, r.table, r.chain, r.rule)
		}
	}
}

func generateServerParamsInteractive() (Params, error) {
	p := Params{}

	pub4 := firstGlobalAddrV4()
	pub6 := firstGlobalAddrV6()
	pub := pub4
	if pub == "" {
		pub = pub6
	}

	p.ServerPubIP = prompt(pub, "IPv4 or IPv6 public address", func(s string) error {
		host := strings.Trim(s, "[]")
		if net.ParseIP(host) == nil {
			return fmt.Errorf("invalid IP")
		}
		return nil
	})
	p.ServerPubNIC = prompt(defaultPubNIC(), "Public interface", func(s string) error {
		if s == "" {
			return errors.New("required")
		}
		m, _ := regexp.MatchString(`^[a-zA-Z0-9_.-]+$`, s)
		if !m {
			return fmt.Errorf("invalid interface name")
		}
		return nil
	})
	p.ServerWGNic = prompt(defaultWGName, "WireGuard interface name", func(s string) error {
		if len(s) == 0 || len(s) > 15 {
			return fmt.Errorf("1..15 chars")
		}
		m, _ := regexp.MatchString(`^[a-zA-Z0-9_.-]+$`, s)
		if !m {
			return fmt.Errorf("invalid interface name")
		}
		return nil
	})
	p.ServerWGIPv4 = prompt("10.66.66.1", "Server WireGuard IPv4 (no CIDR)", validateIP)
	p.ServerWGIPv6 = prompt("fd42:42:42::1", "Server WireGuard IPv6 (no CIDR)", validateIP)
	port := prompt(strconv.Itoa(randomPort()), "Server WireGuard port [1-65535]", func(s string) error {
		n, err := strconv.Atoi(s)
		if err != nil {
			return err
		}
		if n < 1 || n > 65535 {
			return fmt.Errorf("out of range")
		}
		return nil
	})
	p.ServerPort, _ = strconv.Atoi(port)
	p.ClientDNS1 = prompt("10.66.66.1", "First DNS for clients", validateIP)
	p.ClientDNS2 = prompt("10.66.66.1", "Second DNS for clients (blank = same as #1)", func(s string) error {
		if s == "" {
			return nil
		}
		return validateIP(s)
	})
	if p.ClientDNS2 == "" {
		p.ClientDNS2 = p.ClientDNS1
	}
	p.AllowedIPs = prompt("0.0.0.0/0,::/0", "Allowed IPs for clients (full tunnel)", func(s string) error {
		for _, seg := range strings.Split(s, ",") {
			if err := validateCIDR(strings.TrimSpace(seg)); err != nil {
				return err
			}
		}
		return nil
	})

	// Keys
	priv, _ := wgtypes.GeneratePrivateKey()
	p.ServerPrivKey = priv.String()
	p.ServerPubKey = priv.PublicKey().String()
	return p, nil
}

func parseIPv4Base(ip string) (string, error) {
	ip4 := net.ParseIP(ip).To4()
	if ip4 == nil {
		return "", fmt.Errorf("not IPv4: %s", ip)
	}
	parts := strings.Split(ip4.String(), ".")
	return strings.Join(parts[:3], "."), nil
}

func loadClients() (ClientsState, error) {
	var cs ClientsState
	raw, err := os.ReadFile(stateClients)
	if err != nil {
		if os.IsNotExist(err) {
			return ClientsState{List: []ClientEntry{}}, nil
		}
		return cs, err
	}
	err = json.Unmarshal(raw, &cs)
	return cs, err
}

func saveClients(cs ClientsState) error {
	return os.WriteFile(stateClients, mustJSON(cs), 0o600)
}

func nextClientIPs(p Params, cs ClientsState) (string, string, error) {
	base4, err := parseIPv4Base(p.ServerWGIPv4)
	if err != nil {
		return "", "", err
	}
	used := map[string]bool{}
	for _, c := range cs.List {
		used[c.IPv4] = true
	}
	for i := 2; i <= 254; i++ {
		ip4 := fmt.Sprintf("%s.%d", base4, i)
		if !used[ip4] {
			base6 := strings.Split(p.ServerWGIPv6, "::")[0]
			ip6 := fmt.Sprintf("%s::%d", base6, i)
			return ip4, ip6, nil
		}
	}
	return "", "", fmt.Errorf("subnet full (253 clients)")
}

func addPeerToDevice(p Params, peerPub, psk, ipv4, ipv6 string) error {
	client, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer client.Close()

	pub, err := wgtypes.ParseKey(peerPub)
	if err != nil {
		return err
	}
	var pre *wgtypes.Key
	if psk != "" {
		k, err := wgtypes.ParseKey(psk)
		if err != nil {
			return err
		}
		pre = &k
	}
	allowed := []net.IPNet{}
	for _, ipcidr := range []string{ipv4 + "/32", ipv6 + "/128"} {
		_, ipn, _ := net.ParseCIDR(ipcidr)
		allowed = append(allowed, *ipn)
	}
	cfg := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey:         pub,
				PresharedKey:      pre,
				ReplaceAllowedIPs: true,
				AllowedIPs:        allowed,
			},
		},
	}
	return client.ConfigureDevice(p.ServerWGNic, cfg)
}

func syncSavedPeersToDevice(p Params, cs ClientsState) error {
	client, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer client.Close()

	peers := make([]wgtypes.PeerConfig, 0, len(cs.List))
	for _, entry := range cs.List {
		pub, err := wgtypes.ParseKey(entry.PublicKey)
		if err != nil {
			return fmt.Errorf("client %s public key: %w", entry.Name, err)
		}

		var pre *wgtypes.Key
		if entry.PreSharedKey != "" {
			k, err := wgtypes.ParseKey(entry.PreSharedKey)
			if err != nil {
				return fmt.Errorf("client %s preshared key: %w", entry.Name, err)
			}
			pre = &k
		}

		allowed := []net.IPNet{}
		for _, ipcidr := range []string{entry.IPv4 + "/32", entry.IPv6 + "/128"} {
			_, ipn, err := net.ParseCIDR(ipcidr)
			if err != nil {
				return fmt.Errorf("client %s allowed IP %s: %w", entry.Name, ipcidr, err)
			}
			allowed = append(allowed, *ipn)
		}

		peers = append(peers, wgtypes.PeerConfig{
			PublicKey:         pub,
			PresharedKey:      pre,
			ReplaceAllowedIPs: true,
			AllowedIPs:        allowed,
		})
	}

	cfg := wgtypes.Config{
		ReplacePeers: true,
		Peers:        peers,
	}
	return client.ConfigureDevice(p.ServerWGNic, cfg)
}

func writeClientConf(p Params, name, clientPriv, ipv4, ipv6, clientPSK string) (string, error) {
	endpoint := fmt.Sprintf("%s:%d", bracketIPv6(p.ServerPubIP), p.ServerPort)
	content := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/32,%s/128
DNS = %s,%s

# Uncomment to set a custom MTU
# MTU = 1420

[Peer]
PublicKey = %s
PresharedKey = %s
Endpoint = %s
AllowedIPs = %s
`, clientPriv, ipv4, ipv6, p.ClientDNS1, p.ClientDNS2, p.ServerPubKey, clientPSK, endpoint, p.AllowedIPs)

	fn := filepath.Join(clientsDir, fmt.Sprintf("%s-client-%s.conf", p.ServerWGNic, name))
	if err := os.WriteFile(fn, []byte(content), 0o600); err != nil {
		return "", err
	}
	return fn, nil
}

func printQR(path string) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}
	payload := strings.TrimSpace(string(raw))
	if payload == "" {
		fmt.Println("(empty config)")
		return
	}
	if renderExternalQR(payload) {
		return
	}
	fmt.Println("\nUnable to render QR code automatically — install `qrencode` to enable in-terminal QR output.")
	fmt.Printf("Client config path: %s\n\n", path)
}

func renderExternalQR(data string) bool {
	if _, err := exec.LookPath("qrencode"); err == nil {
		cmd := exec.Command("qrencode", "-t", "ANSIUTF8", "-m", "2")
		cmd.Stdin = strings.NewReader(data)
		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &out
		if err := cmd.Run(); err == nil {
			fmt.Println("\n──── Client QR (qrencode) ────")
			fmt.Print(out.String())
			fmt.Print("──────────────────────────────\n")
			return true
		}
	}
	return false
}

func addClient(name string) (string, error) {
	if err := validateClientName(name); err != nil {
		return "", err
	}

	p, err := loadParams()
	if err != nil {
		return "", err
	}
	cs, err := loadClients()
	if err != nil {
		return "", err
	}
	for _, c := range cs.List {
		if c.Name == name {
			return "", fmt.Errorf("client %q already exists", name)
		}
	}

	ip4, ip6, err := nextClientIPs(p, cs)
	if err != nil {
		return "", err
	}

	// Keys
	priv, _ := wgtypes.GeneratePrivateKey()
	pub := priv.PublicKey()
	psk, _ := wgtypes.GenerateKey()

	// Apply to device
	if err := addPeerToDevice(p, pub.String(), psk.String(), ip4, ip6); err != nil {
		return "", err
	}

	// Save state
	cs.List = append(cs.List, ClientEntry{
		Name:         name,
		IPv4:         ip4,
		IPv6:         ip6,
		PublicKey:    pub.String(),
		PreSharedKey: psk.String(),
	})
	if err := saveClients(cs); err != nil {
		return "", err
	}

	// Write config file
	fn, err := writeClientConf(p, name, priv.String(), ip4, ip6, psk.String())
	if err != nil {
		return "", err
	}
	return fn, nil
}

func addClientFlow() {
	name := readLineOrExit("Client name [alnum/_- up to 15]: ")
	fn, err := addClient(name)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("\nClient config written to %s\n", fn)
	fmt.Println("QR code:")
	printQR(fn)
}

func addClientNonInteractive(name string) {
	fn, err := addClient(name)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Client config: %s\n", fn)
	printQR(fn)
}

func listClientsFlow() {
	cs, err := loadClients()
	if err != nil {
		log.Fatal(err)
	}
	if len(cs.List) == 0 {
		fmt.Println("No existing clients.")
		return
	}
	printClientTable(cs)
}

func printClientTable(cs ClientsState) {
	for i, c := range cs.List {
		pubShort := c.PublicKey
		if len(pubShort) > 16 {
			pubShort = pubShort[:16] + "..."
		}
		fmt.Printf("%d) %-15s  %-15s  %-22s  pub=%s\n", i+1, c.Name, c.IPv4, c.IPv6, pubShort)
	}
}

func selectClientIndex(cs ClientsState) (int, bool) {
	for {
		inp := readLineOrExit("Select client # (or 'b' to go back): ")
		trimmed := strings.TrimSpace(inp)
		switch strings.ToLower(trimmed) {
		case "b", "back":
			return -1, false
		}
		n, err := strconv.Atoi(trimmed)
		if err != nil || n < 1 || n > len(cs.List) {
			fmt.Println("Invalid selection.")
			continue
		}
		return n - 1, true
	}
}

func clientConfigPath(wgName, clientName string) string {
	return filepath.Join(clientsDir, fmt.Sprintf("%s-client-%s.conf", wgName, clientName))
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func firstExistingDir(paths ...string) string {
	for _, path := range paths {
		if path == "" {
			continue
		}
		info, err := os.Stat(path)
		if err == nil && info.IsDir() {
			return path
		}
	}
	for _, path := range paths {
		if path != "" {
			return path
		}
	}
	return ""
}

func runtimeClientsDir() string {
	return firstExistingDir(strings.TrimSpace(os.Getenv("WG_CLIENTS_DIR")), clientsDir, "clients")
}

func readParamsFromCandidates() (Params, string, error) {
	for _, path := range []string{stateParams, "wg-state/params.json"} {
		if !pathExists(path) {
			continue
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return Params{}, path, err
		}
		var p Params
		if err := json.Unmarshal(raw, &p); err != nil {
			return Params{}, path, err
		}
		return p, path, nil
	}
	return Params{}, "", os.ErrNotExist
}

func endpointHostFromFlagsOrState(value string) (string, error) {
	host := strings.TrimSpace(value)
	if host != "" {
		return host, nil
	}
	p, _, err := readParamsFromCandidates()
	if err != nil {
		return "", fmt.Errorf("endpoint host is required when saved params are missing; pass --endpoint-host vpn.example.com")
	}
	if strings.TrimSpace(p.ServerPubIP) == "" {
		return "", fmt.Errorf("saved params do not contain SERVER_PUB_IP; pass --endpoint-host vpn.example.com")
	}
	return p.ServerPubIP, nil
}

func validateAllowedIPs(value string) error {
	for _, seg := range strings.Split(value, ",") {
		if err := validateCIDR(strings.TrimSpace(seg)); err != nil {
			return err
		}
	}
	return nil
}

func rewriteConfigField(data, key, value string) string {
	lines := strings.Split(data, "\n")
	found := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, key) || !strings.Contains(line, "=") {
			continue
		}
		left := strings.TrimSpace(strings.SplitN(line, "=", 2)[0])
		if left == key {
			lines[i] = fmt.Sprintf("%s = %s", key, value)
			found = true
		}
	}
	if !found {
		lines = append(lines, fmt.Sprintf("%s = %s", key, value))
	}
	return strings.Join(lines, "\n")
}

func rewriteClientConfigFile(path, endpoint, dns, allowedIPs string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	data := string(raw)
	data = rewriteConfigField(data, "DNS", dns)
	data = rewriteConfigField(data, "Endpoint", endpoint)
	data = rewriteConfigField(data, "AllowedIPs", allowedIPs)
	return os.WriteFile(path, []byte(data), 0o600)
}

func copyClientConfigVariant(src, dest, endpoint, dns, allowedIPs string) error {
	raw, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	data := string(raw)
	data = rewriteConfigField(data, "DNS", dns)
	data = rewriteConfigField(data, "Endpoint", endpoint)
	data = rewriteConfigField(data, "AllowedIPs", allowedIPs)
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return err
	}
	return os.WriteFile(dest, []byte(data), 0o600)
}

func listClientConfigFiles(dir string) ([]string, error) {
	files, err := filepath.Glob(filepath.Join(dir, "wg0-client-*.conf"))
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		files, err = filepath.Glob(filepath.Join(dir, "*-client-*.conf"))
		if err != nil {
			return nil, err
		}
	}
	return files, nil
}

func copyDir(src, dest string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", src)
	}
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dest, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		mode := os.FileMode(0o600)
		if fileInfo, err := d.Info(); err == nil {
			mode = fileInfo.Mode()
		}
		return os.WriteFile(target, data, mode)
	})
}

func updateParamsJSONFile(path, endpointHost, dns, allowedIPs string, port int) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var p Params
	if err := json.Unmarshal(raw, &p); err != nil {
		return err
	}
	p.ServerPubIP = endpointHost
	p.ServerPort = port
	p.ClientDNS1 = dns
	p.ClientDNS2 = dns
	p.AllowedIPs = allowedIPs
	return os.WriteFile(path, mustJSON(p), 0o600)
}

func updateParamsFile(path, endpointHost, dns, allowedIPs string, port int) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	updates := map[string]string{
		"SERVER_PUB_IP": endpointHost,
		"SERVER_PORT":   strconv.Itoa(port),
		"CLIENT_DNS_1":  dns,
		"CLIENT_DNS_2":  dns,
		"ALLOWED_IPS":   allowedIPs,
	}
	seen := map[string]bool{}
	lines := strings.Split(string(raw), "\n")
	for i, line := range lines {
		if !strings.Contains(line, "=") || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		key := strings.TrimSpace(strings.SplitN(line, "=", 2)[0])
		if val, ok := updates[key]; ok {
			lines[i] = key + "=" + val
			seen[key] = true
		}
	}
	for key, val := range updates {
		if !seen[key] {
			lines = append(lines, key+"="+val)
		}
	}
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o600)
}

func regenerateConfigs(endpointHost string, endpointPort int, clientDNS, allowedIPs string, backup bool) error {
	if endpointPort < 1 || endpointPort > 65535 {
		return fmt.Errorf("endpoint port out of range")
	}
	if err := validateIP(clientDNS); err != nil {
		return err
	}
	if err := validateAllowedIPs(allowedIPs); err != nil {
		return err
	}
	endpointHost, err := endpointHostFromFlagsOrState(endpointHost)
	if err != nil {
		return err
	}
	clientsPath := runtimeClientsDir()
	if clientsPath == "" || !pathExists(clientsPath) {
		return fmt.Errorf("clients directory not found; set WG_CLIENTS_DIR or run inside Docker with ./clients:/clients")
	}
	if backup {
		backupName := "clients.backup." + time.Now().Format("2006-01-02-1504")
		backupParent := strings.TrimSpace(os.Getenv("WG_CLIENT_BACKUP_DIR"))
		var backupPath string
		if backupParent != "" {
			backupPath = filepath.Join(backupParent, backupName)
		} else {
			backupPath = fmt.Sprintf("%s.backup.%s", strings.TrimRight(clientsPath, string(os.PathSeparator)), time.Now().Format("2006-01-02-1504"))
		}
		if err := copyDir(clientsPath, backupPath); err != nil {
			return fmt.Errorf("backup clients: %w", err)
		}
		fmt.Printf("Backup saved to %s\n", backupPath)
	}
	endpoint := fmt.Sprintf("%s:%d", bracketIPv6(endpointHost), endpointPort)
	files, err := listClientConfigFiles(clientsPath)
	if err != nil {
		return err
	}
	for _, file := range files {
		if err := rewriteClientConfigFile(file, endpoint, clientDNS, allowedIPs); err != nil {
			return err
		}
		fmt.Printf("Updated %s\n", file)
	}
	for _, path := range []string{stateParams, "wg-state/params.json"} {
		if pathExists(path) {
			if err := updateParamsJSONFile(path, endpointHost, clientDNS, allowedIPs, endpointPort); err != nil {
				return err
			}
			fmt.Printf("Updated %s\n", path)
		}
	}
	for _, path := range []string{"/etc/wireguard/params", "wg-data/params"} {
		if pathExists(path) {
			if err := updateParamsFile(path, endpointHost, clientDNS, allowedIPs, endpointPort); err != nil {
				return err
			}
			fmt.Printf("Updated %s\n", path)
		}
	}
	fmt.Printf("Done. Client configs are in %s\n", clientsPath)
	return nil
}

func generateProfiles(endpointHost string, endpointPort int, clientDNS, fullAllowedIPs, privateAllowedIPs string) error {
	if endpointPort < 1 || endpointPort > 65535 {
		return fmt.Errorf("endpoint port out of range")
	}
	if err := validateIP(clientDNS); err != nil {
		return err
	}
	if err := validateAllowedIPs(fullAllowedIPs); err != nil {
		return err
	}
	if err := validateAllowedIPs(privateAllowedIPs); err != nil {
		return err
	}
	endpointHost, err := endpointHostFromFlagsOrState(endpointHost)
	if err != nil {
		return err
	}
	clientsPath := runtimeClientsDir()
	if clientsPath == "" || !pathExists(clientsPath) {
		return fmt.Errorf("clients directory not found; set WG_CLIENTS_DIR or run inside Docker with ./clients:/clients")
	}
	files, err := listClientConfigFiles(clientsPath)
	if err != nil {
		return err
	}
	fullDir := firstExistingDir(strings.TrimSpace(os.Getenv("WG_CLIENTS_FULL_DIR")), filepath.Clean(clientsPath)+"-full", "clients-full")
	privateDir := firstExistingDir(strings.TrimSpace(os.Getenv("WG_CLIENTS_PRIVATE_DIR")), filepath.Clean(clientsPath)+"-private", "clients-private")
	endpoint := fmt.Sprintf("%s:%d", bracketIPv6(endpointHost), endpointPort)
	count := 0
	for _, file := range files {
		base := strings.TrimSuffix(filepath.Base(file), ".conf")
		fullPath := filepath.Join(fullDir, base+"-FULL.conf")
		privatePath := filepath.Join(privateDir, base+"-PRIVATE.conf")
		if err := copyClientConfigVariant(file, fullPath, endpoint, clientDNS, fullAllowedIPs); err != nil {
			return err
		}
		if err := copyClientConfigVariant(file, privatePath, endpoint, clientDNS, privateAllowedIPs); err != nil {
			return err
		}
		fmt.Printf("[FULL] %s\n", fullPath)
		fmt.Printf("[PRIV] %s\n", privatePath)
		count++
	}
	fmt.Printf("Generated %d profile pairs.\n", count)
	fmt.Printf("Full tunnel: DNS=%s AllowedIPs=%s\n", clientDNS, fullAllowedIPs)
	fmt.Printf("Private tunnel: DNS=%s AllowedIPs=%s\n", clientDNS, privateAllowedIPs)
	return nil
}

func regenerateConfigsFlow() {
	p, _, _ := readParamsFromCandidates()
	endpointHost := prompt(p.ServerPubIP, "Endpoint host clients should connect to", func(s string) error {
		if strings.TrimSpace(s) == "" {
			return errors.New("required")
		}
		return nil
	})
	defaultPort := p.ServerPort
	if defaultPort == 0 {
		defaultPort = 51820
	}
	portRaw := prompt(strconv.Itoa(defaultPort), "Endpoint port", func(s string) error {
		n, err := strconv.Atoi(s)
		if err != nil {
			return err
		}
		if n < 1 || n > 65535 {
			return fmt.Errorf("out of range")
		}
		return nil
	})
	port, _ := strconv.Atoi(portRaw)
	dns := prompt(firstNonEmpty(p.ClientDNS1, "10.66.66.1"), "Client DNS", validateIP)
	allowed := prompt(firstNonEmpty(p.AllowedIPs, "0.0.0.0/0,::/0"), "AllowedIPs for default client configs", validateAllowedIPs)
	backup := promptYesNo("Backup clients directory before rewriting?", true)
	if err := regenerateConfigs(endpointHost, port, dns, allowed, backup); err != nil {
		fmt.Println("Error:", err)
	}
}

func generateProfilesFlow() {
	p, _, _ := readParamsFromCandidates()
	endpointHost := prompt(p.ServerPubIP, "Endpoint host clients should connect to", func(s string) error {
		if strings.TrimSpace(s) == "" {
			return errors.New("required")
		}
		return nil
	})
	defaultPort := p.ServerPort
	if defaultPort == 0 {
		defaultPort = 51820
	}
	portRaw := prompt(strconv.Itoa(defaultPort), "Endpoint port", func(s string) error {
		n, err := strconv.Atoi(s)
		if err != nil {
			return err
		}
		if n < 1 || n > 65535 {
			return fmt.Errorf("out of range")
		}
		return nil
	})
	port, _ := strconv.Atoi(portRaw)
	dns := prompt(firstNonEmpty(p.ClientDNS1, "10.66.66.1"), "Client DNS", validateIP)
	fullAllowed := prompt(firstNonEmpty(p.AllowedIPs, "0.0.0.0/0,::/0"), "FULL profile AllowedIPs", validateAllowedIPs)
	privateAllowed := prompt("10.66.66.0/24, fd42:42:42::/64", "PRIVATE profile AllowedIPs", validateAllowedIPs)
	if err := generateProfiles(endpointHost, port, dns, fullAllowed, privateAllowed); err != nil {
		fmt.Println("Error:", err)
	}
}

func findClientIndexByName(cs ClientsState, name string) int {
	for i, c := range cs.List {
		if c.Name == name {
			return i
		}
	}
	return -1
}

func showClientQRByName(name string) {
	cs, err := loadClients()
	if err != nil {
		log.Fatal(err)
	}
	idx := -1
	for i, c := range cs.List {
		if c.Name == name {
			idx = i
			break
		}
	}
	if idx < 0 {
		log.Fatalf("client %s not found", name)
	}
	p, err := loadParams()
	if err != nil {
		log.Fatal(err)
	}
	showClientQRAtIndex(cs, idx, p)
}

func showClientQRAtIndex(cs ClientsState, idx int, p Params) {
	path := clientConfigPath(p.ServerWGNic, cs.List[idx].Name)
	if _, err := os.Stat(path); err != nil {
		log.Fatalf("client config missing: %s", path)
	}
	fmt.Printf("\nClient config: %s\n", path)
	printQR(path)
}

func showClientQRFlow() {
	cs, err := loadClients()
	if err != nil {
		log.Fatal(err)
	}
	if len(cs.List) == 0 {
		fmt.Println("No clients to display.")
		return
	}
	printClientTable(cs)
	idx, ok := selectClientIndex(cs)
	if !ok {
		fmt.Println("Cancelled.")
		return
	}
	p, err := loadParams()
	if err != nil {
		log.Fatal(err)
	}
	showClientQRAtIndex(cs, idx, p)
}

func showClientConfigByName(name string) {
	cs, err := loadClients()
	if err != nil {
		log.Fatal(err)
	}
	idx := findClientIndexByName(cs, name)
	if idx < 0 {
		log.Fatalf("client %s not found", name)
	}
	p, err := loadParams()
	if err != nil {
		log.Fatal(err)
	}
	showClientConfigAtIndex(cs, idx, p)
}

func showClientConfigAtIndex(cs ClientsState, idx int, p Params) {
	path := clientConfigPath(p.ServerWGNic, cs.List[idx].Name)
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("client config missing: %s", path)
	}
	fmt.Printf("\nClient config: %s\n\n%s\n", path, string(data))
}

func showClientConfigFlow() {
	cs, err := loadClients()
	if err != nil {
		log.Fatal(err)
	}
	if len(cs.List) == 0 {
		fmt.Println("No clients to display.")
		return
	}
	printClientTable(cs)
	idx, ok := selectClientIndex(cs)
	if !ok {
		fmt.Println("Cancelled.")
		return
	}
	p, err := loadParams()
	if err != nil {
		log.Fatal(err)
	}
	showClientConfigAtIndex(cs, idx, p)
}

func exportClientConfigFlow() {
	cs, err := loadClients()
	if err != nil {
		log.Fatal(err)
	}
	if len(cs.List) == 0 {
		fmt.Println("No clients to export.")
		return
	}
	printClientTable(cs)
	idx, ok := selectClientIndex(cs)
	if !ok {
		fmt.Println("Cancelled.")
		return
	}
	name := cs.List[idx].Name
	destDir := strings.TrimSpace(readLineOrExit("Destination folder (blank cancels): "))
	if destDir == "" || strings.EqualFold(destDir, "b") || strings.EqualFold(destDir, "back") {
		fmt.Println("Export cancelled.")
		return
	}
	path, err := exportClientConfig(name, destDir)
	if err != nil {
		fmt.Printf("Export failed: %v\n", err)
		return
	}
	fmt.Printf("Client %s config copied to %s\n", name, path)
}

func exportClientConfig(name, dest string) (string, error) {
	cs, err := loadClients()
	if err != nil {
		return "", err
	}
	idx := findClientIndexByName(cs, name)
	if idx < 0 {
		return "", fmt.Errorf("client %s not found", name)
	}
	p, err := loadParams()
	if err != nil {
		return "", err
	}
	src := clientConfigPath(p.ServerWGNic, cs.List[idx].Name)
	if _, err := os.Stat(src); err != nil {
		return "", fmt.Errorf("client config missing: %w", err)
	}
	base := filepath.Base(src)
	finalPath := resolveExportPath(dest, base)
	if err := os.MkdirAll(filepath.Dir(finalPath), 0o700); err != nil {
		return "", err
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(finalPath, data, 0o600); err != nil {
		return "", err
	}
	return finalPath, nil
}

func resolveExportPath(input, filename string) string {
	if input == "" {
		return filepath.Join("/clients", filename)
	}
	clean := filepath.Clean(input)
	if strings.HasSuffix(input, string(os.PathSeparator)) {
		return filepath.Join(clean, filename)
	}
	if info, err := os.Stat(clean); err == nil && info.IsDir() {
		return filepath.Join(clean, filename)
	}
	if filepath.Ext(clean) == "" {
		return filepath.Join(clean, filename)
	}
	return clean
}

func promptYesNo(question string, defaultYes bool) bool {
	var hint string
	if defaultYes {
		hint = " [Y/n]: "
	} else {
		hint = " [y/N]: "
	}
	for {
		answer := strings.ToLower(strings.TrimSpace(readLineOrExit(question + hint)))
		if answer == "" {
			return defaultYes
		}
		if answer == "y" || answer == "yes" {
			return true
		}
		if answer == "n" || answer == "no" {
			return false
		}
		fmt.Println("Please answer y or n.")
	}
}

func readClientPrivateKey(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "PrivateKey") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1]), nil
			}
		}
	}
	return "", fmt.Errorf("private key not found in %s", path)
}

func rotateClientKeys(p Params, entry ClientEntry) (string, ClientEntry, error) {
	oldPub, err := wgtypes.ParseKey(entry.PublicKey)
	if err != nil {
		return "", entry, err
	}
	client, err := wgctrl.New()
	if err != nil {
		return "", entry, err
	}
	defer client.Close()

	removeCfg := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{{PublicKey: oldPub, Remove: true}},
	}
	if err := client.ConfigureDevice(p.ServerWGNic, removeCfg); err != nil {
		return "", entry, err
	}

	priv, _ := wgtypes.GeneratePrivateKey()
	pub := priv.PublicKey()
	psk, _ := wgtypes.GenerateKey()

	if err := addPeerToDevice(p, pub.String(), psk.String(), entry.IPv4, entry.IPv6); err != nil {
		return "", entry, err
	}

	entry.PublicKey = pub.String()
	entry.PreSharedKey = psk.String()
	return priv.String(), entry, nil
}

func applyClientEdit(p Params, cs ClientsState, idx int, newName string, rotate bool) (ClientsState, string, error) {
	entry := cs.List[idx]
	if newName == "" {
		newName = entry.Name
	}
	oldConfPath := clientConfigPath(p.ServerWGNic, entry.Name)

	var (
		clientPriv string
		err        error
	)
	if rotate {
		clientPriv, entry, err = rotateClientKeys(p, entry)
		if err != nil {
			return cs, "", err
		}
	} else {
		clientPriv, err = readClientPrivateKey(oldConfPath)
		if err != nil {
			fmt.Println("Existing client config missing private key; regenerating fresh keys.")
			clientPriv, entry, err = rotateClientKeys(p, entry)
			if err != nil {
				return cs, "", err
			}
		}
	}

	entry.Name = newName
	cs.List[idx] = entry
	if err := saveClients(cs); err != nil {
		return cs, "", err
	}

	newConfPath, err := writeClientConf(p, entry.Name, clientPriv, entry.IPv4, entry.IPv6, entry.PreSharedKey)
	if err != nil {
		return cs, "", err
	}
	if oldConfPath != newConfPath {
		_ = os.Remove(oldConfPath)
	}
	return cs, newConfPath, nil
}

func editClientFlow() {
	cs, err := loadClients()
	if err != nil {
		log.Fatal(err)
	}
	if len(cs.List) == 0 {
		fmt.Println("No clients to edit.")
		return
	}
	printClientTable(cs)
	idx, ok := selectClientIndex(cs)
	if !ok {
		fmt.Println("Cancelled.")
		return
	}
	entry := cs.List[idx]
	p, err := loadParams()
	if err != nil {
		log.Fatal(err)
	}

	newName := strings.TrimSpace(readLineOrExit(fmt.Sprintf("New client name (leave blank to keep %s): ", entry.Name)))
	if newName == "" {
		newName = entry.Name
	} else {
		if err := validateClientName(newName); err != nil {
			fmt.Println(err)
			return
		}
		for _, c := range cs.List {
			if c.Name == newName {
				fmt.Println("Client name already exists.")
				return
			}
		}
	}

	rotate := promptYesNo("Regenerate keys for this client?", false)
	cs, newConfPath, err := applyClientEdit(p, cs, idx, newName, rotate)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("\nUpdated client config written to %s\n", newConfPath)
	printQR(newConfPath)
}

func editClientByName(name, newName string, rotate bool) {
	cs, err := loadClients()
	if err != nil {
		log.Fatal(err)
	}
	idx := findClientIndexByName(cs, name)
	if idx < 0 {
		log.Fatalf("client %s not found", name)
	}
	if strings.TrimSpace(newName) == "" {
		newName = name
	} else {
		if err := validateClientName(newName); err != nil {
			log.Fatal(err)
		}
		if findClientIndexByName(cs, newName) >= 0 && newName != name {
			log.Fatalf("client name %s already exists", newName)
		}
	}
	p, err := loadParams()
	if err != nil {
		log.Fatal(err)
	}
	_, newConfPath, err := applyClientEdit(p, cs, idx, newName, rotate)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Updated config written to %s\n", newConfPath)
	printQR(newConfPath)
}

func validateClientName(name string) error {
	matched, _ := regexp.MatchString(`^[a-zA-Z0-9_-]{1,15}$`, name)
	if !matched {
		return fmt.Errorf("invalid client name (1-15 chars, alnum/_-)")
	}
	return nil
}

func accumulateCounter(last, total *uint64, current int64) bool {
	if current < 0 {
		return false
	}
	curr := uint64(current)
	changed := false
	if *last == 0 && *total == 0 {
		if *last != curr {
			*last = curr
			changed = true
		}
		return changed
	}
	if curr >= *last {
		delta := curr - *last
		if delta > 0 {
			*total += delta
			changed = true
		}
		if *last != curr {
			*last = curr
			changed = true
		}
		return changed
	}
	if *last != curr {
		*last = curr
		changed = true
	}
	return changed
}

func updateUsageEntry(entry *ClientEntry, rx, tx int64) bool {
	changed := false
	if accumulateCounter(&entry.LastRxBytes, &entry.TotalRxBytes, rx) {
		changed = true
	}
	if accumulateCounter(&entry.LastTxBytes, &entry.TotalTxBytes, tx) {
		changed = true
	}
	return changed
}

func formatBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	val := float64(n)
	suffix := "KMGT"
	exp := 0
	for val >= unit && exp < len(suffix) {
		val /= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", val, suffix[exp-1])
}

func formatAgo(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t)
	if d < time.Second {
		return "just now"
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
}

type peerMonitor struct {
	Name           string
	PublicKey      string
	LastHandshake  time.Time
	SessionRxBytes int64
	SessionTxBytes int64
	TotalRxBytes   uint64
	TotalTxBytes   uint64
	Endpoint       string
}

func gatherPeerStats(p Params, persist bool) ([]peerMonitor, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	defer client.Close()
	dev, err := client.Device(p.ServerWGNic)
	if err != nil {
		return nil, err
	}
	return gatherPeerStatsFromDevice(dev, persist)
}

func gatherPeerStatsFromDevice(dev *wgtypes.Device, persist bool) ([]peerMonitor, error) {
	cs, err := loadClients()
	if err != nil {
		return nil, err
	}
	index := map[string]*ClientEntry{}
	for i := range cs.List {
		index[cs.List[i].PublicKey] = &cs.List[i]
	}
	type snap struct {
		hs       time.Time
		rx       int64
		tx       int64
		endpoint string
	}
	snaps := map[string]snap{}
	changed := false
	for _, peer := range dev.Peers {
		pub := peer.PublicKey.String()
		entry := index[pub]
		if entry == nil {
			continue
		}
		if updateUsageEntry(entry, peer.ReceiveBytes, peer.TransmitBytes) {
			changed = true
		}
		snaps[pub] = snap{
			hs:       peer.LastHandshakeTime,
			rx:       peer.ReceiveBytes,
			tx:       peer.TransmitBytes,
			endpoint: peer.Endpoint.String(),
		}
	}
	if persist && changed {
		if err := saveClients(cs); err != nil {
			return nil, err
		}
	}
	stats := make([]peerMonitor, 0, len(cs.List))
	for _, entry := range cs.List {
		s := snaps[entry.PublicKey]
		stats = append(stats, peerMonitor{
			Name:           entry.Name,
			PublicKey:      entry.PublicKey,
			LastHandshake:  s.hs,
			SessionRxBytes: s.rx,
			SessionTxBytes: s.tx,
			TotalRxBytes:   entry.TotalRxBytes,
			TotalTxBytes:   entry.TotalTxBytes,
			Endpoint:       s.endpoint,
		})
	}
	return stats, nil
}

func printPeerStatsTable(stats []peerMonitor) int {
	lines := 0
	fmt.Printf("\rClient monitor snapshot @ %s\n", time.Now().Format(time.RFC3339))
	lines++
	fmt.Printf("%-16s %-7s %-10s %-12s %-12s %-12s %-12s\n", "Name", "Active", "Last HS", "Sess RX", "Sess TX", "Total RX", "Total TX")
	lines++
	for _, st := range stats {
		name := st.Name
		if strings.TrimSpace(name) == "" {
			if len(st.PublicKey) >= 12 {
				name = st.PublicKey[:12]
			} else {
				name = st.PublicKey
			}
		}
		active := "no"
		if !st.LastHandshake.IsZero() && time.Since(st.LastHandshake) < 2*time.Minute {
			active = "yes"
		}
		fmt.Printf("%-16s %-7s %-10s %-12s %-12s %-12s %-12s\n",
			name,
			active,
			formatAgo(st.LastHandshake),
			formatBytes(uint64(max64(st.SessionRxBytes, 0))),
			formatBytes(uint64(max64(st.SessionTxBytes, 0))),
			formatBytes(st.TotalRxBytes),
			formatBytes(st.TotalTxBytes),
		)
		lines++
	}
	if len(stats) == 0 {
		fmt.Println("(no peers configured)")
		lines++
	}
	fmt.Println()
	lines++
	return lines
}

func monitorClients(interval time.Duration) {
	p, err := loadParams()
	if err != nil {
		fmt.Println("No saved params found. Run install first.")
		return
	}
	if interval <= 0 {
		stats, err := gatherPeerStats(p, true)
		if err != nil {
			fmt.Printf("Monitor error: %v\n", err)
			return
		}
		printPeerStatsTable(stats)
		return
	}

	fmt.Println("Monitoring clients (type 'q' then Enter to stop).")
	linesPrinted := 0
	fd := int(os.Stdin.Fd())
	for {
		stats, err := gatherPeerStats(p, true)
		if err != nil {
			fmt.Printf("Monitor error: %v\n", err)
			return
		}
		linesPrinted = printPeerStatsTable(stats)
		quit, err := waitForMonitorQuit(fd, interval)
		if err != nil {
			fmt.Printf("Monitor input error: %v\n", err)
			return
		}
		if quit {
			if linesPrinted > 0 {
				fmt.Printf("\033[%dA\033[J", linesPrinted)
			}
			fmt.Println("Monitor stopped.")
			return
		}
		if linesPrinted > 0 {
			fmt.Printf("\033[%dA\033[J", linesPrinted)
		}
	}
}

func waitForMonitorQuit(fd int, interval time.Duration) (bool, error) {
	if interval <= 0 {
		return false, nil
	}
	tv := syscall.NsecToTimeval(interval.Nanoseconds())
	var readfds syscall.FdSet
	fdSet(fd, &readfds)
	n, err := syscall.Select(fd+1, &readfds, nil, nil, &tv)
	if err != nil {
		if err == syscall.EINTR {
			return false, nil
		}
		return false, err
	}
	if n == 0 || !fdIsSet(fd, &readfds) {
		return false, nil
	}
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return false, err
	}
	return strings.EqualFold(strings.TrimSpace(line), "q"), nil
}

func revokeByName(name string) {
	p, err := loadParams()
	if err != nil {
		log.Fatal(err)
	}
	cs, err := loadClients()
	if err != nil {
		log.Fatal(err)
	}
	idx := -1
	var pubKey string
	for i, c := range cs.List {
		if c.Name == name {
			idx = i
			pubKey = c.PublicKey
			break
		}
	}
	if idx < 0 {
		log.Fatalf("client %s not found", name)
	}
	pub, err := wgtypes.ParseKey(pubKey)
	if err != nil {
		log.Fatal(err)
	}
	client, err := wgctrl.New()
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
	cfg := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{{PublicKey: pub, Remove: true}},
	}
	if err := client.ConfigureDevice(p.ServerWGNic, cfg); err != nil {
		log.Fatal(err)
	}
	cs.List = append(cs.List[:idx], cs.List[idx+1:]...)
	if err := saveClients(cs); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Client revoked:", name)
}

func installFlow() {
	mustRoot()
	ensureDirs()
	fmt.Println("\nWireGuard install (Go)")
	p, err := generateServerParamsInteractive()
	if err != nil {
		log.Fatal(err)
	}
	if err := saveParams(p); err != nil {
		log.Fatal(err)
	}

	if err := createOrUpWG(p); err != nil {
		log.Fatalf("wg setup failed: %v", err)
	}

	if !skipIPTables() {
		iptablesApply(p, true)
	} else {
		fmt.Println("Skipping iptables; host is expected to handle NAT & forwarding.")
	}
	fmt.Println("✓ WireGuard is up. Let's add a first client.")
	addClientFlow()
}

func uninstallFlow() {
	mustRoot()
	p, err := loadParams()
	if err == nil {
		if !skipIPTables() {
			iptablesApply(p, false)
		}
		if link, _ := netlink.LinkByName(p.ServerWGNic); link != nil {
			_ = netlink.LinkSetDown(link)
			_ = netlink.LinkDel(link)
		}
	}
	_ = os.Remove(stateParams)
	_ = os.Remove(stateClients)
	fmt.Println("WireGuard removed (interface & rules cleaned, state deleted).")
}

func upFlow() {
	mustRoot()
	ensureDirs()
	p, err := loadParams()
	if err != nil {
		log.Fatalf("no saved params: %v", err)
	}
	if err := createOrUpWG(p); err != nil {
		log.Fatalf("wg setup failed: %v", err)
	}
	cs, err := loadClients()
	if err != nil {
		log.Fatalf("load clients: %v", err)
	}
	if err := syncSavedPeersToDevice(p, cs); err != nil {
		log.Fatalf("sync saved peers: %v", err)
	}
	if !skipIPTables() {
		iptablesApply(p, true)
	}
	fmt.Printf("WireGuard interface %s is up using saved params and %d saved clients.\n", p.ServerWGNic, len(cs.List))
}

func statusFlow() {
	p, err := loadParams()
	if err != nil {
		fmt.Println("No saved params found. Run install first.")
		return
	}
	fmt.Printf("Backend: %s\n", backendMode())
	link, err := netlink.LinkByName(p.ServerWGNic)
	if err != nil {
		fmt.Printf("Interface %s: down (not found)\n", p.ServerWGNic)
	} else {
		state := "down"
		if link.Attrs().Flags&net.FlagUp != 0 {
			state = "up"
		}
		fmt.Printf("Interface %s: %s (index %d)\n", p.ServerWGNic, state, link.Attrs().Index)
		fmt.Printf("  IPv4: %s/24\n", p.ServerWGIPv4)
		fmt.Printf("  IPv6: %s/64\n", p.ServerWGIPv6)
	}

	client, err := wgctrl.New()
	if err != nil {
		fmt.Printf("wgctrl error: %v\n", err)
		return
	}
	defer client.Close()
	dev, err := client.Device(p.ServerWGNic)
	if err != nil {
		fmt.Printf("Device read error: %v\n", err)
		return
	}
	stats, err := gatherPeerStatsFromDevice(dev, true)
	if err != nil {
		fmt.Printf("Failed to collect peer stats: %v\n", err)
		return
	}
	fmt.Printf("Listen port: %d\n", dev.ListenPort)
	fmt.Printf("Peers: %d\n", len(stats))
	for _, st := range stats {
		name := st.Name
		if strings.TrimSpace(name) == "" && len(st.PublicKey) >= 8 {
			name = st.PublicKey[:8]
		}
		ago := formatAgo(st.LastHandshake)
		fmt.Printf("  %-12s last:%-8s sessRX:%-10s sessTX:%-10s totalRX:%-10s totalTX:%-10s\n",
			name,
			ago,
			formatBytes(uint64(max64(st.SessionRxBytes, 0))),
			formatBytes(uint64(max64(st.SessionTxBytes, 0))),
			formatBytes(st.TotalRxBytes),
			formatBytes(st.TotalTxBytes),
		)
	}
}

func printMenu() {
	fmt.Println()
	fmt.Println("┌────────────────────────────────────────────────────┐")
	fmt.Println("│ wg-go-installer - SERVER MODE                      │")
	fmt.Println("├────────────────────────────────────────────────────┤")
	fmt.Println("│ Run this on the VPN server/VPS, not client devices │")
	fmt.Println("│ Typical flow: 1 install -> 3 add -> 5 scan QR      │")
	fmt.Println("├────────────────────────────────────────────────────┤")
	fmt.Println("│ 1) Install & bring up server                       │")
	fmt.Println("│ 2) Bring server up (saved)                         │")
	fmt.Println("│ 3) Add a new client                                │")
	fmt.Println("│ 4) List clients                                    │")
	fmt.Println("│ 5) Show client QR                                  │")
	fmt.Println("│ 6) Show client config                              │")
	fmt.Println("│ 7) Export client config                            │")
	fmt.Println("│ 8) View server status                              │")
	fmt.Println("│ 9) Monitor clients (live)                          │")
	fmt.Println("│10) Edit client                                     │")
	fmt.Println("│11) Revoke client                                   │")
	fmt.Println("│12) Regenerate endpoint/DNS in configs              │")
	fmt.Println("│13) Generate FULL and PRIVATE profile variants      │")
	fmt.Println("│14) Uninstall/cleanup                               │")
	fmt.Println("│15) Exit                                            │")
	fmt.Println("└────────────────────────────────────────────────────┘")
	fmt.Println("Type the number, or 'h' for help, 'b' to redisplay, 'q' to quit.")
}

func menu() {
	showMenu := true
	for {
		if showMenu {
			printMenu()
			showMenu = false
		}
		input := strings.TrimSpace(readLineOrExit("Action [1-15 | h=help | b=back | q=quit]: "))
		switch strings.ToLower(input) {
		case "h", "help", "?":
			showMenu = true
			continue
		case "b", "back":
			showMenu = true
			continue
		case "q", "quit", "exit", "15":
			fmt.Println("Goodbye!")
			return
		case "1":
			installFlow()
		case "2":
			upFlow()
		case "3":
			addClientFlow()
		case "4":
			listClientsFlow()
		case "5":
			showClientQRFlow()
		case "6":
			showClientConfigFlow()
		case "7":
			exportClientConfigFlow()
		case "8":
			statusFlow()
		case "9":
			monitorClients(5 * time.Second)
		case "10":
			editClientFlow()
		case "11":
			name := readLineOrExit("Client name to revoke: ")
			revokeByName(strings.TrimSpace(name))
		case "12":
			regenerateConfigsFlow()
		case "13":
			generateProfilesFlow()
		case "14":
			uninstallFlow()
		default:
			fmt.Println("Invalid choice (type 'h' for help).")
		}
	}
}

func skipIPTables() bool {
	v := os.Getenv("WG_SKIP_IPTABLES")
	v = strings.ToLower(strings.TrimSpace(v))
	return v == "1" || v == "true" || v == "yes"
}

func main() {
	if len(os.Args) == 1 {
		menu()
		return
	}
	switch os.Args[1] {
	case "menu":
		menu()
	case "help", "-h", "--help":
		usage()
	case "install":
		installFlow()
	case "up":
		upFlow()
	case "add":
		fs := flag.NewFlagSet("add", flag.ExitOnError)
		name := fs.String("name", "", "client name")
		short := fs.String("n", "", "client name (shorthand)")
		_ = fs.Parse(os.Args[2:])
		val := firstNonEmpty(*name, *short)
		if val == "" {
			fmt.Println("add requires --name")
			os.Exit(1)
		}
		addClientNonInteractive(val)
	case "list":
		listClientsFlow()
	case "show-qr":
		fs := flag.NewFlagSet("show-qr", flag.ExitOnError)
		name := fs.String("name", "", "client name")
		short := fs.String("n", "", "client name (shorthand)")
		_ = fs.Parse(os.Args[2:])
		val := firstNonEmpty(*name, *short)
		if val == "" {
			fmt.Println("show-qr requires --name")
			os.Exit(1)
		}
		showClientQRByName(val)
	case "show-config":
		fs := flag.NewFlagSet("show-config", flag.ExitOnError)
		name := fs.String("name", "", "client name")
		short := fs.String("n", "", "client name (shorthand)")
		_ = fs.Parse(os.Args[2:])
		val := firstNonEmpty(*name, *short)
		if val == "" {
			fmt.Println("show-config requires --name")
			os.Exit(1)
		}
		showClientConfigByName(val)
	case "export":
		fs := flag.NewFlagSet("export", flag.ExitOnError)
		name := fs.String("name", "", "client name")
		short := fs.String("n", "", "client name (shorthand)")
		dest := fs.String("dest", "", "destination directory")
		_ = fs.Parse(os.Args[2:])
		val := firstNonEmpty(*name, *short)
		target := strings.TrimSpace(*dest)
		if val == "" || target == "" {
			fmt.Println("export requires --name and --dest")
			os.Exit(1)
		}
		path, err := exportClientConfig(val, target)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Client %s copied to %s\n", val, path)
	case "regenerate-configs":
		fs := flag.NewFlagSet("regenerate-configs", flag.ExitOnError)
		endpointHost := fs.String("endpoint-host", "", "public DNS name or IP clients should connect to")
		endpointPort := fs.Int("endpoint-port", 51820, "WireGuard endpoint port")
		clientDNS := fs.String("client-dns", "10.66.66.1", "DNS server written to client configs")
		allowedIPs := fs.String("allowed-ips", "0.0.0.0/0,::/0", "AllowedIPs written to client configs")
		backup := fs.Bool("backup", true, "backup clients directory before rewriting")
		_ = fs.Parse(os.Args[2:])
		if err := regenerateConfigs(*endpointHost, *endpointPort, *clientDNS, *allowedIPs, *backup); err != nil {
			log.Fatal(err)
		}
	case "generate-profiles":
		fs := flag.NewFlagSet("generate-profiles", flag.ExitOnError)
		endpointHost := fs.String("endpoint-host", "", "public DNS name or IP clients should connect to")
		endpointPort := fs.Int("endpoint-port", 51820, "WireGuard endpoint port")
		clientDNS := fs.String("client-dns", "10.66.66.1", "DNS server written to profile variants")
		fullAllowed := fs.String("full-allowed-ips", "0.0.0.0/0,::/0", "AllowedIPs for full-tunnel profiles")
		privateAllowed := fs.String("private-allowed-ips", "10.66.66.0/24, fd42:42:42::/64", "AllowedIPs for private/split profiles")
		_ = fs.Parse(os.Args[2:])
		if err := generateProfiles(*endpointHost, *endpointPort, *clientDNS, *fullAllowed, *privateAllowed); err != nil {
			log.Fatal(err)
		}
	case "edit":
		fs := flag.NewFlagSet("edit", flag.ExitOnError)
		name := fs.String("name", "", "client name")
		short := fs.String("n", "", "client name (shorthand)")
		newName := fs.String("new-name", "", "new client name")
		rotate := fs.Bool("rotate-keys", false, "regenerate keys")
		_ = fs.Parse(os.Args[2:])
		val := firstNonEmpty(*name, *short)
		if val == "" {
			fmt.Println("edit requires --name")
			os.Exit(1)
		}
		editClientByName(val, *newName, *rotate)
	case "revoke":
		fs := flag.NewFlagSet("revoke", flag.ExitOnError)
		name := fs.String("name", "", "client name")
		short := fs.String("n", "", "client name (shorthand)")
		_ = fs.Parse(os.Args[2:])
		val := firstNonEmpty(*name, *short)
		if val == "" {
			fmt.Println("revoke requires --name")
			os.Exit(1)
		}
		revokeByName(val)
	case "monitor":
		fs := flag.NewFlagSet("monitor", flag.ExitOnError)
		interval := fs.Duration("interval", 5*time.Second, "refresh interval, 0 for single snapshot")
		_ = fs.Parse(os.Args[2:])
		fmt.Println("Press Ctrl+C to stop monitoring.")
		monitorClients(*interval)
	case "status":
		statusFlow()
	case "uninstall":
		uninstallFlow()
	default:
		usage()
	}
}
