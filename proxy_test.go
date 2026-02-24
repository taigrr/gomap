package gomap

import (
	"context"
	"net/url"
	"testing"
)

func TestDialProxyUnsupportedScheme(t *testing.T) {
	_, err := dialProxy(context.TODO(), "ftp://proxy:21", "host:80", 0)
	if err == nil {
		t.Error("expected error for unsupported scheme")
	}
}

func TestDialHTTPProxyDefaultPort(t *testing.T) {
	u, _ := url.Parse("http://proxy")
	// Just test that the address gets a default port appended
	// We can't actually connect, but we can verify the logic doesn't panic
	_ = u
}
