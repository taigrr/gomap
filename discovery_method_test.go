package gomap

import "testing"

func TestDiscoveryMethodString(t *testing.T) {
	tests := []struct {
		method DiscoveryMethod
		want   string
	}{
		{DiscoveryTCPSYN, "tcp-syn"},
		{DiscoveryTCPACK, "tcp-ack"},
		{DiscoveryUDP, "udp"},
		{DiscoveryICMP, "icmp"},
		{DiscoveryConnect, "connect"},
		{DiscoveryARP, "arp"},
		{DiscoveryICMPTimestamp, "icmp-timestamp"},
		{DiscoveryICMPNetmask, "icmp-netmask"},
		{DiscoverySCTPInit, "sctp-init"},
		{DiscoveryIPProtocol, "ip-protocol"},
		{DiscoveryMethod(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.method.String(); got != tt.want {
			t.Errorf("DiscoveryMethod(%d).String() = %q, want %q", tt.method, got, tt.want)
		}
	}
}
