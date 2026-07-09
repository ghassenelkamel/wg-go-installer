package main

import (
	"strings"
	"testing"
)

func TestPrepareWGQuickConfigStripsDNS(t *testing.T) {
	input := []byte(`[Interface]
PrivateKey = placeholder
Address = 10.66.66.3/32,fd42:42:42::3/128
DNS = 10.66.66.1

[Peer]
PublicKey = placeholder
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0,::/0
`)

	got := string(prepareWGQuickConfig(input, true))
	if strings.Contains(got, "DNS =") {
		t.Fatalf("runtime wg-quick config still contains DNS line:\n%s", got)
	}
	if !strings.Contains(got, "AllowedIPs = 0.0.0.0/0,::/0") {
		t.Fatalf("runtime wg-quick config lost peer settings:\n%s", got)
	}
}

func TestClientInterfaceNameIsLinuxSafe(t *testing.T) {
	got := clientInterfaceName("/configs/wg0-client-PC_Kagha.conf")
	if len(got) > 15 {
		t.Fatalf("interface name too long: %q", got)
	}
	if got == "" {
		t.Fatal("interface name is empty")
	}
}
