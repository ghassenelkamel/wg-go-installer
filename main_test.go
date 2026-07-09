package main

import (
	"strings"
	"testing"
)

func TestServerInterfaceCIDRsUseHostAddresses(t *testing.T) {
	p := Params{
		ServerWGIPv4: "10.66.66.1",
		ServerWGIPv6: "fd42:42:42::1",
	}

	got := serverInterfaceCIDRs(p)
	want := []string{"10.66.66.1/24", "fd42:42:42::1/64"}
	if len(got) != len(want) {
		t.Fatalf("unexpected CIDR count: got %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("CIDR[%d]: got %q, want %q", i, got[i], want[i])
		}
	}
}

func TestParseHostCIDRPreservesHostAddress(t *testing.T) {
	cases := []string{
		"10.66.66.1/24",
		"fd42:42:42::1/64",
	}

	for _, cidr := range cases {
		ipn, err := parseHostCIDR(cidr)
		if err != nil {
			t.Fatalf("parseHostCIDR(%q) error = %v", cidr, err)
		}
		if got := ipn.String(); got != cidr {
			t.Fatalf("parseHostCIDR(%q) = %q, want %q", cidr, got, cidr)
		}
	}
}

func TestRewriteConfigField(t *testing.T) {
	input := `[Interface]
PrivateKey = placeholder
DNS = 1.1.1.1

[Peer]
Endpoint = old.example.com:51820
AllowedIPs = 10.0.0.0/8
`

	got := rewriteConfigField(input, "DNS", "10.66.66.1")
	got = rewriteConfigField(got, "Endpoint", "vpn.example.com:51820")
	got = rewriteConfigField(got, "AllowedIPs", "0.0.0.0/0,::/0")

	for _, want := range []string{
		"DNS = 10.66.66.1",
		"Endpoint = vpn.example.com:51820",
		"AllowedIPs = 0.0.0.0/0,::/0",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("rewritten config missing %q:\n%s", want, got)
		}
	}
}
