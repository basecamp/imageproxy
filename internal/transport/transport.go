package transport

import (
	"context"
	"errors"
	"net"
	"net/http"

	"github.com/fcjr/aia-transport-go"
)

type DialContextFn func(ctx context.Context, network string, addr string) (net.Conn, error)
type DialFn func(network string, addr string) (net.Conn, error)

var zeroDialer net.Dialer

// NewTransport returns a http.Transport that supports a deny list of hosts
// that won't be dialed.
func NewTransport(denyHosts []string) (*http.Transport, error) {
	t, err := aia.NewTransport()
	if err != nil {
		return nil, err
	}

	if t.DialContext != nil {
		t.DialContext = wrapDialContextWithDenyHosts(t.DialContext, denyHosts)
	} else if t.Dial != nil {
		t.Dial = wrapDialWithDenyHosts(t.Dial, denyHosts)
	} else {
		t.DialContext = wrapDialContextWithDenyHosts(zeroDialer.DialContext, denyHosts)
	}

	// When there's no custom TLS dialer, dial and any custom non-TLS dialer is used
	// so we'd be covered by the above wrapping
	if t.DialTLS != nil {
		t.DialTLS = wrapDialWithDenyHosts(t.DialTLS, denyHosts)
	}

	return t, nil
}

func wrapDialContextWithDenyHosts(fn DialContextFn, denyHosts []string) (wrappedFn DialContextFn) {
	wrappedFn = func(ctx context.Context, network string, addr string) (net.Conn, error) {
		conn, err := fn(ctx, network, addr)
		if err != nil {
			return conn, err
		}

		if denied := checkAddr(denyHosts, conn.RemoteAddr().String()); denied == nil {
			return conn, err
		} else {
			return nil, denied
		}
	}

	return
}

func wrapDialWithDenyHosts(fn DialFn, denyHosts []string) (wrappedFn DialFn) {
	wrappedFn = func(network string, addr string) (net.Conn, error) {
		conn, err := fn(network, addr)
		if err != nil {
			return conn, err
		}

		if denied := checkAddr(denyHosts, conn.RemoteAddr().String()); denied == nil {
			return conn, err
		} else {
			return nil, denied
		}
	}

	return
}

// checkAddr returns resolved addr an error if addr matches any of the hosts or CIDR given
func checkAddr(hosts []string, addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}

	if ip := net.ParseIP(host); ip != nil {
		errDeniedHost := errors.New("address matches a denied host")

		for _, host := range hosts {
			if _, ipnet, err := net.ParseCIDR(host); err == nil {
				if ipnet.Contains(ip) {
					return errDeniedHost
				}
			} else if ip.String() == host {
				return errDeniedHost
			}
		}
	}

	return nil
}
