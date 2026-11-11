package appsec

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"golang.org/x/net/http/httpguts"
)

// Validate checks enabled configuration without disclosing secret values.
func (h *Handler) Validate() error {
	if !h.WAF && !h.Bot {
		return nil
	}
	if h.FailureAction != "" && h.FailureAction != "deny" && h.FailureAction != "passthrough" {
		return errors.New("appsec: failure_action must be deny or passthrough")
	}
	u, err := url.Parse(h.Endpoint)
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return errors.New("appsec: endpoint must be an HTTP(S) URL without userinfo or fragment")
	}
	if strings.TrimSpace(h.APIKey) == "" || !httpguts.ValidHeaderFieldValue(h.APIKey) {
		return errors.New("appsec: api_key must be a nonempty valid header value")
	}
	// Both limits are read with one extra byte for overflow detection.
	maxInt := int64(int(^uint(0) >> 1))
	if h.MaxBodyBytes <= 0 || h.MaxBodyBytes >= maxInt || h.MaxResponseBytes <= 0 || h.MaxResponseBytes >= maxInt {
		return errors.New("appsec: byte budgets must be positive and leave room for overflow detection")
	}
	if h.Timeout <= 0 || h.MaxInFlight <= 0 {
		return errors.New("appsec: timeout and max_in_flight must be positive")
	}
	if h.CAFile != "" && u.Scheme != "https" {
		return errors.New("appsec: ca_file requires an HTTPS endpoint")
	}
	return nil
}

func (h *Handler) newClient(systemRoots func() (*x509.CertPool, error)) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// The configured endpoint is the trust boundary; do not route its credential
	// through an implicitly selected environment proxy or follow redirects.
	transport.Proxy = nil
	transport.DisableCompression = true
	transport.MaxIdleConns = h.MaxInFlight
	transport.MaxIdleConnsPerHost = h.MaxInFlight
	transport.MaxConnsPerHost = h.MaxInFlight
	transport.DialContext = (&net.Dialer{Timeout: time.Duration(h.Timeout), KeepAlive: 30 * time.Second}).DialContext
	transport.TLSHandshakeTimeout = time.Duration(h.Timeout)
	transport.ResponseHeaderTimeout = time.Duration(h.Timeout)
	if h.CAFile != "" {
		pem, err := os.ReadFile(h.CAFile)
		if err != nil {
			return nil, errors.New("appsec: cannot read ca_file")
		}
		roots, err := systemRoots()
		if err != nil {
			return nil, errors.New("appsec: cannot load system certificate roots")
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, errors.New("appsec: ca_file contains no certificates")
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: roots}
	}
	return &http.Client{
		Transport:     transport,
		Timeout:       time.Duration(h.Timeout),
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

// UnmarshalCaddyfile accepts one value per named subdirective, inside route.
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	seen := make(map[string]bool)
	for d.Next() {
		if d.NextArg() {
			return d.Err("trueops_appsec takes named subdirectives only")
		}
		for d.NextBlock(0) {
			key := d.Val()
			var value string
			if d.Nesting() != 1 || seen[key] || !d.AllArgs(&value) {
				return d.Err("appsec: each subdirective requires exactly one value and may appear once")
			}
			seen[key] = true
			var err error
			switch key {
			case "waf", "bot":
				if value != "on" && value != "off" {
					return d.Err("appsec: policy values must be on or off")
				}
				if key == "waf" {
					h.WAF = value == "on"
				} else {
					h.Bot = value == "on"
				}
			case "endpoint":
				h.Endpoint = value
			case "api_key":
				h.APIKey = value
			case "ca_file":
				h.CAFile = value
			case "failure_action":
				h.FailureAction = value
			case "timeout":
				var duration time.Duration
				duration, err = caddy.ParseDuration(value)
				h.Timeout = caddy.Duration(duration)
			case "max_body_bytes":
				h.MaxBodyBytes, err = strconv.ParseInt(value, 10, 64)
			case "max_response_bytes":
				h.MaxResponseBytes, err = strconv.ParseInt(value, 10, 64)
			case "max_in_flight":
				h.MaxInFlight, err = strconv.Atoi(value)
			default:
				return d.Err("appsec: unknown subdirective")
			}
			if err != nil {
				return d.Err("appsec: invalid duration or integer budget")
			}
		}
	}
	return h.Validate()
}
