//go:build !linux

package gomap

import (
	"context"
	"fmt"
	"time"
)

func scanPortSCTPInit(ctx context.Context, resultCh chan<- PortResult, hostname, service string, port int, laddr string, timeout time.Duration) {
	result := PortResult{Port: port, Service: service}
	result.setStateReason(PortFiltered, fmt.Sprintf("sctp-init scan requires Linux"))
	resultCh <- result
}

func scanPortSCTPCookieEcho(ctx context.Context, resultCh chan<- PortResult, hostname, service string, port int, laddr string, timeout time.Duration) {
	result := PortResult{Port: port, Service: service}
	result.setStateReason(PortFiltered, fmt.Sprintf("sctp-cookie-echo scan requires Linux"))
	resultCh <- result
}
