package main

import (
	"bufio"
	"flag"
	"fmt"
	"hash/fnv"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type clientApp struct {
	ConfigPath        string
	RuntimeConfigPath string
	IfName            string
	LogPath           string
	useResolved       bool
	useNFT            bool
	resolvBackup      string
}

func main() {
	var cfgPath string
	var action string
	flag.StringVar(&cfgPath, "config", "", "WireGuard client config path")
	flag.StringVar(&action, "action", "menu", "Action: up, down, status, test-ks, import, menu")
	flag.Parse()

	app := newClientApp(cfgPath)

	switch strings.ToLower(action) {
	case "up":
		app.bringUp()
	case "down":
		app.bringDown()
	case "status":
		app.status()
	case "test-ks":
		app.testKillSwitch()
	case "import":
		app.importConfigInteractive()
	case "menu":
		app.menu()
	default:
		fmt.Println("Unknown action:", action)
		os.Exit(1)
	}
}

func newClientApp(cfg string) *clientApp {
	cfg = strings.TrimSpace(cfg)
	if cfg == "" {
		cfg = strings.TrimSpace(os.Getenv("WG_CLIENT_CONFIG"))
	}
	if cfg == "" {
		cfg = "/etc/wireguard/peer-laptop.conf"
	}
	ifName := clientInterfaceName(cfg)
	runtimeConfig := filepath.Join(clientRuntimeDir(), ifName+".conf")
	logPath := strings.TrimSpace(os.Getenv("WG_CLIENT_LOG"))
	if logPath == "" {
		logPath = filepath.Join(os.Getenv("HOME"), "wg-client.log")
	}
	app := &clientApp{
		ConfigPath:        cfg,
		RuntimeConfigPath: runtimeConfig,
		IfName:            ifName,
		LogPath:           logPath,
	}
	if commandExists("resolvectl") {
		app.useResolved = true
	}
	if commandExists("nft") {
		app.useNFT = true
	}
	return app
}

func (c *clientApp) menu() {
	reader := bufio.NewReader(os.Stdin)
	showMenu := true
	for {
		if showMenu {
			c.printMenu()
			showMenu = false
		}
		fmt.Print("Action [1-6 | h=help | q=quit]: ")
		choiceRaw, _ := reader.ReadString('\n')
		choice := strings.TrimSpace(strings.ToLower(choiceRaw))
		switch choice {
		case "h", "help", "?":
			showMenu = true
			continue
		case "1":
			c.importConfigInteractive()
		case "2":
			c.bringUp()
		case "3":
			c.bringDown()
		case "4":
			c.status()
		case "5":
			c.testKillSwitch()
		case "6", "q", "quit", "exit":
			fmt.Println("Bye!")
			return
		default:
			fmt.Println("Invalid choice.")
		}
	}
}

func (c *clientApp) printMenu() {
	fmt.Println()
	fmt.Println("┌────────────────────────────────────────────────────┐")
	fmt.Println("│ wg-client - CLIENT MODE                            │")
	fmt.Println("├────────────────────────────────────────────────────┤")
	fmt.Println("│ Run this on your laptop/desktop Linux client       │")
	fmt.Println("│ Typical flow: 1 import config -> 2 connect         │")
	fmt.Println("├────────────────────────────────────────────────────┤")
	fmt.Printf("│ Interface: %-39s │\n", abbreviatePath(c.IfName, 39))
	fmt.Printf("│ Config:    %-39s │\n", abbreviatePath(c.ConfigPath, 39))
	fmt.Println("├────────────────────────────────────────────────────┤")
	fmt.Println("│ 1) Import configuration                            │")
	fmt.Println("│ 2) Connect VPN (up + DNS/leak checks)              │")
	fmt.Println("│ 3) Disconnect VPN (down + cleanup)                 │")
	fmt.Println("│ 4) Status                                          │")
	fmt.Println("│ 5) Kill-switch self-test                           │")
	fmt.Println("│ 6) Exit                                            │")
	fmt.Println("└────────────────────────────────────────────────────┘")
}

func (c *clientApp) bringUp() {
	c.logf("Bringing up %s using %s", c.IfName, c.ConfigPath)
	if err := checkReadable(c.ConfigPath); err != nil {
		fmt.Println(err)
		return
	}
	if err := c.upCore(); err != nil {
		fmt.Println("Error:", err)
		c.printConnectHint(err)
		return
	}
	if err := c.ksOn(); err != nil {
		fmt.Println("Kill-switch error:", err)
	}
	c.handshakeAndChecks()
}

func (c *clientApp) bringDown() {
	c.logf("Bringing down %s", c.IfName)
	c.dnsClear()
	if err := c.ksOff(); err != nil {
		fmt.Println("Kill-switch error:", err)
	}
	_, _ = runCmd("sudo", "wg-quick", "down", c.RuntimeConfigPath)
}

func (c *clientApp) status() {
	fmt.Printf("Interface %s: ", c.IfName)
	if c.ifIsUp() {
		fmt.Println("up")
		out, _ := runCmd("sudo", "wg", "show", c.IfName)
		fmt.Println(out)
	} else {
		fmt.Println("down")
	}
}

func (c *clientApp) testKillSwitch() {
	fmt.Println("Kill-switch self-test (will restore state afterwards).")
	wasUp := c.ifIsUp()
	ksWasOn := c.ksIsOn()
	if !wasUp {
		fmt.Println("Interface was down — bringing it up temporarily (without kill-switch).")
		if err := c.upCore(); err != nil {
			fmt.Println("Unable to bring interface up:", err)
			return
		}
	}
	if err := c.ksOn(); err != nil {
		fmt.Println("Kill-switch error:", err)
		return
	}
	fmt.Println("Bringing tunnel down to verify kill-switch blocks traffic...")
	_, _ = runCmd("sudo", "wg-quick", "down", c.RuntimeConfigPath)
	if c.checkPublicAccess() {
		fmt.Println("❌ Kill-switch did not block connections.")
	} else {
		fmt.Println("✅ Kill-switch blocked IPv4/IPv6 egress as expected.")
	}
	if wasUp {
		c.upCore()
	} else {
		fmt.Println("Leaving tunnel down (it was down before the test).")
	}
	if ksWasOn {
		c.ksOn()
	} else {
		c.ksOff()
	}
	fmt.Println("Kill-switch self-test complete.")
}

func (c *clientApp) importConfigInteractive() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("Source WireGuard config path: ")
	src, _ := reader.ReadString('\n')
	src = strings.TrimSpace(src)
	if src == "" {
		fmt.Println("Import cancelled.")
		return
	}
	if err := checkReadable(src); err != nil {
		fmt.Println("Import failed:", err)
		return
	}
	defaultDest := c.ConfigPath
	fmt.Printf("Destination path [%s]: ", defaultDest)
	dest, _ := reader.ReadString('\n')
	dest = strings.TrimSpace(dest)
	if dest == "" {
		dest = defaultDest
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		fmt.Println("Unable to prepare destination:", err)
		return
	}
	if err := copyFile(src, dest); err != nil {
		fmt.Println("Import failed:", err)
		return
	}
	c.ConfigPath = dest
	c.IfName = clientInterfaceName(dest)
	c.RuntimeConfigPath = filepath.Join(clientRuntimeDir(), c.IfName+".conf")
	fmt.Printf("Configuration imported to %s (interface %s)\n", dest, c.IfName)
}

func (c *clientApp) upCore() error {
	if err := need("wg-quick"); err != nil {
		return err
	}
	if err := c.prepareRuntimeConfig(); err != nil {
		return err
	}
	_, _ = runCmd("sudo", "wg-quick", "down", c.RuntimeConfigPath)
	if out, err := runCmd("sudo", "wg-quick", "up", c.RuntimeConfigPath); err != nil {
		if strings.TrimSpace(out) != "" {
			return fmt.Errorf("wg-quick up failed: %w\n%s", err, out)
		}
		return fmt.Errorf("wg-quick up failed: %w", err)
	}
	time.Sleep(300 * time.Millisecond)
	if c.dnsManaged() {
		c.applyManagedDNS()
	}
	c.resolveEndpointPreferV6()
	return nil
}

func (c *clientApp) prepareRuntimeConfig() error {
	if err := os.MkdirAll(filepath.Dir(c.RuntimeConfigPath), 0o700); err != nil {
		return err
	}
	data, err := os.ReadFile(c.ConfigPath)
	if err != nil {
		return err
	}
	data = prepareWGQuickConfig(data, c.dnsManaged())
	return os.WriteFile(c.RuntimeConfigPath, data, 0o600)
}

func (c *clientApp) dnsManaged() bool {
	if v := strings.TrimSpace(os.Getenv("WG_CLIENT_KEEP_DNS")); v == "1" || strings.EqualFold(v, "true") {
		return false
	}
	if v := strings.TrimSpace(os.Getenv("WG_CLIENT_MANAGE_DNS")); v != "" {
		return v == "1" || strings.EqualFold(v, "true")
	}
	return true
}

func prepareWGQuickConfig(data []byte, stripDNS bool) []byte {
	if !stripDNS {
		return data
	}
	lines := strings.Split(string(data), "\n")
	out := make([]string, 0, len(lines)+1)
	removedDNS := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "DNS") && strings.Contains(trimmed, "=") {
			removedDNS = true
			continue
		}
		out = append(out, line)
	}
	if removedDNS {
		out = append(out, "# DNS is managed by wg-client via resolvectl or /etc/resolv.conf.")
	}
	return []byte(strings.Join(out, "\n"))
}

func (c *clientApp) printConnectHint(err error) {
	msg := err.Error()
	if strings.Contains(msg, "src_valid_mark") || strings.Contains(msg, "Read-only file system") {
		fmt.Println()
		fmt.Println("Hint: full-tunnel WireGuard needs permission to update host routing/sysctl state.")
		fmt.Println("If you run the client helper through Docker, rebuild after the latest compose change and use the repo root:")
		fmt.Println("  docker compose --profile client build wg-client")
		fmt.Println("  docker compose --profile client run --rm -it -e WG_CLIENT_INTERFACE=wgpc wg-client")
		fmt.Println("If Docker still makes /proc/sys read-only, run the Go client directly on the host instead:")
		fmt.Println("  go build -o wg-client ./cmd/wg-client")
		fmt.Println("  sudo ./wg-client -config clients/wg0-client-PC_Kagha.conf")
	}
	if strings.Contains(msg, "resolvconf") || strings.Contains(msg, "could not detect a useable init system") {
		fmt.Println()
		fmt.Println("Hint: the helper strips DNS from the temporary wg-quick config by default.")
		fmt.Println("Rebuild the client image before retrying so wg-quick does not call container resolvconf.")
	}
}

func (c *clientApp) handshakeAndChecks() {
	fmt.Println("Handshake:")
	out, _ := runCmd("sudo", "wg", "show", c.IfName)
	fmt.Println(out)
	fmt.Println()
	fmt.Println("Leak checks:")
	v4, _ := runCmd("curl", "-4", "-s", "--max-time", "5", "https://api.ipify.org")
	v6, _ := runCmd("curl", "-6", "-s", "--max-time", "5", "https://api64.ipify.org")
	fmt.Println("  IPv4:", blankToNA(v4))
	fmt.Println("  IPv6:", blankToNA(v6))
	fmt.Println("  DNS:", blankToNA(c.dnsWhoAmI()))
	fmt.Println()
	fmt.Println("Ping tests via tunnel:")
	runCmdStream("ping", "-c", "2", "-4", "1.1.1.1")
	runCmdStream("ping", "-c", "2", "-6", "2606:4700:4700::1111")
	if _, err := runCmd("ping", "-c", "1", "-6", "2606:4700:4700::1111"); err != nil {
		fmt.Println()
		fmt.Println("Note: IPv6 internet was unreachable through the tunnel.")
		fmt.Println("That is usually a server-side issue: the VPN server needs a global IPv6")
		fmt.Println("address, a default IPv6 route, and IPv6 masquerade for wg0 egress.")
		fmt.Println("Check on the server: `ip -6 addr show`, `ip -6 route show default`, and AdGuard/DNS reachability.")
	}
}

func (c *clientApp) applyManagedDNS() {
	dnsList := c.cfgDNSList()
	if len(dnsList) == 0 {
		return
	}
	if c.useResolved {
		args := append([]string{"resolvectl", "dns", c.IfName}, dnsList...)
		_, _ = runCmd("sudo", args...)
		_, _ = runCmd("sudo", "resolvectl", "domain", c.IfName, "~.")
		return
	}
	backup := "/etc/resolv.conf.wg-client-backup"
	if existing, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		_ = os.WriteFile(backup, existing, 0o644)
		c.resolvBackup = backup
	}
	var sb strings.Builder
	for _, d := range dnsList {
		sb.WriteString("nameserver " + d + "\n")
	}
	sb.WriteString("options trust-ad\n")
	if err := os.WriteFile("/etc/resolv.conf", []byte(sb.String()), 0o644); err != nil {
		fmt.Println("Warning: unable to write /etc/resolv.conf for AdGuard DNS:", err)
	}
}

func (c *clientApp) dnsClear() {
	if c.useResolved {
		_, _ = runCmd("sudo", "resolvectl", "revert", c.IfName)
	}
	if c.resolvBackup != "" {
		if data, err := os.ReadFile(c.resolvBackup); err == nil {
			_ = os.WriteFile("/etc/resolv.conf", data, 0o644)
		}
		_ = os.Remove(c.resolvBackup)
		c.resolvBackup = ""
	}
}

func (c *clientApp) resolveEndpointPreferV6() {
	host := c.cfgEndpointHost()
	port := c.cfgEndpointPort()
	if host == "" || port == "" {
		return
	}
	endpoint := ""
	if ip := resolveHost(host, true); ip != "" {
		endpoint = fmt.Sprintf("[%s]:%s", ip, port)
	} else if ip := resolveHost(host, false); ip != "" {
		endpoint = fmt.Sprintf("%s:%s", ip, port)
	}
	if endpoint == "" {
		fmt.Println("⚠️  Could not resolve endpoint host; leaving config as-is.")
		return
	}
	peer := c.peerPublicKey()
	if peer == "" {
		return
	}
	_, _ = runCmd("sudo", "wg", "set", c.IfName, "peer", peer, "endpoint", endpoint)
}

func (c *clientApp) cfgDNSList() []string {
	content, _ := os.ReadFile(c.ConfigPath)
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "DNS") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				val := strings.ReplaceAll(parts[1], ",", " ")
				fields := strings.Fields(val)
				return fields
			}
		}
	}
	return nil
}

func (c *clientApp) cfgEndpointHost() string {
	raw := c.cfgEndpointRaw()
	if strings.HasPrefix(raw, "[") {
		if idx := strings.LastIndex(raw, "]"); idx != -1 {
			return raw[1:idx]
		}
	}
	if idx := strings.LastIndex(raw, ":"); idx != -1 {
		return raw[:idx]
	}
	return raw
}

func (c *clientApp) cfgEndpointPort() string {
	raw := c.cfgEndpointRaw()
	if idx := strings.LastIndex(raw, ":"); idx != -1 {
		return raw[idx+1:]
	}
	return ""
}

func (c *clientApp) cfgEndpointRaw() string {
	content, _ := os.ReadFile(c.ConfigPath)
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "Endpoint") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

func (c *clientApp) peerPublicKey() string {
	out, err := runCmd("sudo", "wg", "show", c.IfName)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "peer: ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "peer: "))
		}
	}
	return ""
}

func (c *clientApp) ifIsUp() bool {
	_, err := runCmd("ip", "link", "show", c.IfName)
	return err == nil
}

func (c *clientApp) dnsWhoAmI() string {
	dnsList := c.cfgDNSList()
	if len(dnsList) == 0 {
		return ""
	}
	for _, host := range []string{"whoami.cloudflare", "o-o.myaddr.l.google.com", "myip.opendns.com"} {
		for _, dns := range dnsList {
			if host == "myip.opendns.com" {
				ifout, err := runCmd("dig", "+short", "A", host, "@"+dns)
				if err == nil && strings.TrimSpace(ifout) != "" {
					return strings.TrimSpace(ifout)
				}
			} else {
				ifout, err := runCmd("dig", "+short", "TXT", host, "@"+dns)
				if err == nil && strings.TrimSpace(ifout) != "" {
					return strings.Trim(strings.TrimSpace(ifout), "\"")
				}
			}
		}
	}
	if out, err := runCmd("curl", "-fsS", "--max-time", "3", "https://api64.ipify.org"); err == nil {
		return strings.TrimSpace(out) + " (http)"
	}
	return ""
}

func (c *clientApp) checkPublicAccess() bool {
	_, err4 := runCmd("curl", "-4", "-s", "--max-time", "5", "https://api.ipify.org")
	_, err6 := runCmd("curl", "-6", "-s", "--max-time", "5", "https://api64.ipify.org")
	return err4 == nil || err6 == nil
}

func (c *clientApp) ksOn() error {
	c.logf("Enabling kill-switch")
	if c.useNFT {
		mark := c.fwmark()
		_, _ = runCmd("sudo", "nft", "list", "table", "inet", "wgks")
		_, _ = runCmd("sudo", "nft", "list", "chain", "inet", "wgks", "out")
		_, _ = runCmd("sudo", "nft", "flush", "chain", "inet", "wgks", "out")
		configs := [][]string{
			{"sudo", "nft", "add", "table", "inet", "wgks"},
			{"sudo", "nft", "add", "chain", "inet", "wgks", "out", "{", "type", "filter", "hook", "output", "priority", "0;", "policy", "accept;", "}"},
		}
		for _, cmd := range configs {
			_, _ = runCmd(cmd[0], cmd[1:]...)
		}
		_, _ = runCmd("sudo", "nft", "flush", "chain", "inet", "wgks", "out")
		_, _ = runCmd("sudo", "nft", "add", "rule", "inet", "wgks", "out", "oifname", c.IfName, "return")
		_, _ = runCmd("sudo", "nft", "add", "rule", "inet", "wgks", "out", "meta", "mark", mark, "return")
		_, _ = runCmd("sudo", "nft", "add", "rule", "inet", "wgks", "out", "ct", "state", "established,related", "return")
		_, _ = runCmd("sudo", "nft", "add", "rule", "inet", "wgks", "out", "ct", "state", "new", "drop")
		return nil
	}
	mark := c.fwmark()
	for _, args := range [][]string{
		{"sudo", "iptables", "-C", "OUTPUT", "!", "-o", c.IfName, "-m", "mark", "!", "--mark", mark, "-m", "conntrack", "--ctstate", "NEW", "-j", "DROP"},
		{"sudo", "ip6tables", "-C", "OUTPUT", "!", "-o", c.IfName, "-m", "mark", "!", "--mark", mark, "-m", "conntrack", "--ctstate", "NEW", "-j", "DROP"},
	} {
		if _, err := runCmd(args[0], args[1:]...); err == nil {
			continue
		}
		addArgs := append([]string{args[0], "-I"}, args[2:]...)
		_, _ = runCmd(addArgs[0], addArgs[1:]...)
	}
	return nil
}

func (c *clientApp) ksOff() error {
	c.logf("Disabling kill-switch")
	if c.useNFT {
		_, _ = runCmd("sudo", "nft", "flush", "chain", "inet", "wgks", "out")
		return nil
	}
	mark := c.fwmark()
	for i := 0; i < 3; i++ {
		_, _ = runCmd("sudo", "iptables", "-D", "OUTPUT", "!", "-o", c.IfName, "-m", "mark", "!", "--mark", mark, "-m", "conntrack", "--ctstate", "NEW", "-j", "DROP")
		_, _ = runCmd("sudo", "ip6tables", "-D", "OUTPUT", "!", "-o", c.IfName, "-m", "mark", "!", "--mark", mark, "-m", "conntrack", "--ctstate", "NEW", "-j", "DROP")
	}
	return nil
}

func (c *clientApp) ksIsOn() bool {
	if c.useNFT {
		_, err := runCmd("sudo", "nft", "list", "chain", "inet", "wgks", "out")
		return err == nil
	}
	mark := c.fwmark()
	_, err := runCmd("sudo", "iptables", "-C", "OUTPUT", "!", "-o", c.IfName, "-m", "mark", "!", "--mark", mark, "-m", "conntrack", "--ctstate", "NEW", "-j", "DROP")
	return err == nil
}

func (c *clientApp) fwmark() string {
	out, err := runCmd("sudo", "wg", "show", c.IfName)
	if err != nil {
		return "51820"
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "fwmark:") {
			fields := strings.Fields(line)
			return fields[len(fields)-1]
		}
	}
	return "51820"
}

func resolveHost(host string, preferV6 bool) string {
	var cmd *exec.Cmd
	if preferV6 {
		cmd = exec.Command("getent", "ahosts", host)
	} else {
		cmd = exec.Command("getent", "ahosts", host)
	}
	out, err := cmd.Output()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "STREAM") {
				fields := strings.Fields(line)
				if len(fields) > 0 {
					ip := fields[0]
					isV6 := strings.Contains(ip, ":")
					if preferV6 && isV6 {
						return ip
					}
					if !preferV6 && !isV6 {
						return ip
					}
				}
			}
		}
	}
	return ""
}

func copyFile(src, dest string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dest, data, 0o600)
}

func clientInterfaceName(configPath string) string {
	if override := strings.TrimSpace(os.Getenv("WG_CLIENT_INTERFACE")); override != "" {
		return truncateInterfaceName(sanitizeInterfaceName(override))
	}
	base := strings.TrimSuffix(filepath.Base(configPath), filepath.Ext(configPath))
	base = sanitizeInterfaceName(base)
	if len(base) <= 15 {
		return base
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(configPath))
	return fmt.Sprintf("wg%x", h.Sum32())
}

func sanitizeInterfaceName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "wgclient"
	}
	var b strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "wgclient"
	}
	return b.String()
}

func truncateInterfaceName(name string) string {
	if len(name) <= 15 {
		return name
	}
	return name[:15]
}

func clientRuntimeDir() string {
	if dir := strings.TrimSpace(os.Getenv("WG_CLIENT_RUNTIME_DIR")); dir != "" {
		return dir
	}
	if _, err := os.Stat("/data"); err == nil {
		return "/data"
	}
	return os.TempDir()
}

func abbreviatePath(path string, max int) string {
	if len(path) <= max {
		return path
	}
	if max <= 3 {
		return path[:max]
	}
	return path[:max-3] + "..."
}

func runCmd(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(output)), err
}

func runCmdStream(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
}

func commandExists(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

func need(cmd string) error {
	if !commandExists(cmd) {
		return fmt.Errorf("missing command: %s", cmd)
	}
	return nil
}

func checkReadable(path string) error {
	if _, err := os.Stat(path); err != nil {
		return err
	}
	return nil
}

func blankToNA(val string) string {
	val = strings.TrimSpace(val)
	if val == "" {
		return "(no reply)"
	}
	return val
}

func (c *clientApp) logf(format string, args ...interface{}) {
	f, err := os.OpenFile(c.LogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Printf(format+"\n", args...)
		return
	}
	defer f.Close()
	msg := fmt.Sprintf("[%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), fmt.Sprintf(format, args...))
	io.WriteString(f, msg)
	fmt.Print(fmt.Sprintf(format+"\n", args...))
}
