package appsec

import (
	"context"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func (h *Handler) inspect(r *http.Request, body []byte) (envelope, int) {
	var empty envelope
	ip, ok := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string)
	if _, err := netip.ParseAddr(ip); !ok || err != nil {
		return empty, http.StatusServiceUnavailable
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(h.Timeout))
	defer cancel()
	// WroteRequest rejects allow after failed/incomplete transmission. The pinned
	// engine profile must also prohibit partial-body inspection on its side.
	written := make(chan error, 1)
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{WroteRequest: func(info httptrace.WroteRequestInfo) {
		select {
		case written <- info.Err:
		default:
		}
	}})
	method := http.MethodGet
	var upload *uploadBody
	if len(body) > 0 {
		method = http.MethodPost
		upload = newUploadBody(body)
	}
	req := (&http.Request{
		Method: method, URL: h.runtime.endpoint, Host: h.runtime.endpoint.Host,
		Header: r.Header.Clone(), Body: http.NoBody, ContentLength: int64(len(body)),
	}).WithContext(ctx)
	if upload != nil {
		req.Body = upload
	}
	// GetBody remains nil: uncertain submissions and POSTs cannot be replayed.
	stripHopHeaders(req.Header)
	for key := range req.Header {
		if strings.HasPrefix(strings.ToLower(key), "x-crowdsec-appsec-") {
			delete(req.Header, key)
		}
	}
	req.Header.Del("Content-Length")
	req.Header.Set("X-Crowdsec-Appsec-Ip", ip)
	req.Header.Set("X-Crowdsec-Appsec-Uri", r.URL.RequestURI())
	req.Header.Set("X-Crowdsec-Appsec-Host", r.Host)
	req.Header.Set("X-Crowdsec-Appsec-Verb", r.Method)
	req.Header.Set("X-Crowdsec-Appsec-Api-Key", h.APIKey)
	req.Header.Set("X-Crowdsec-Appsec-User-Agent", r.UserAgent())
	req.Header.Set("X-Crowdsec-Appsec-Http-Version", strconv.Itoa(r.ProtoMajor)+strconv.Itoa(r.ProtoMinor))
	req.Header.Set("User-Agent", "trueops-appsec")
	// Request/transport own upload until Close, which may happen after Do returns.
	// Stop I/O first, then await Close before releasing the capture reservation.
	defer func() {
		cancel()
		if upload != nil {
			<-upload.closed
		}
	}()
	resp, err := h.runtime.client.Do(req)
	if err != nil {
		return empty, http.StatusServiceUnavailable
	}
	defer resp.Body.Close()
	failure := http.StatusServiceUnavailable
	if resp.StatusCode == http.StatusForbidden {
		failure = http.StatusForbidden
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusForbidden {
		return empty, failure
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, h.MaxResponseBytes+1))
	if err != nil || int64(len(data)) > h.MaxResponseBytes {
		return empty, failure
	}
	decision, err := decodeEnvelope(data)
	if err != nil {
		return empty, failure
	}
	if resp.StatusCode == http.StatusOK {
		if decision.Action != "allow" {
			return empty, failure
		}
		select {
		case err := <-written:
			if err != nil {
				return empty, failure
			}
		case <-ctx.Done():
			return empty, failure
		}
		if ctx.Err() != nil {
			return empty, failure
		}
	} else if decision.Action == "allow" {
		// A blocked transport response cannot authorize the application.
		return empty, failure
	}
	return decision, 0
}

var hopHeaders = [...]string{
	"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
	"Proxy-Connection", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

func stripHopHeaders(header http.Header) {
	for _, connection := range header.Values("Connection") {
		for name := range strings.SplitSeq(connection, ",") {
			header.Del(strings.TrimSpace(name))
		}
	}
	for _, name := range hopHeaders {
		header.Del(name)
	}
}
