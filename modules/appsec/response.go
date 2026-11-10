package appsec

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/http/httpguts"
)

const challengePrefix = "/crowdsec-internal/challenge/"

type envelope struct {
	Action     string
	HTTPStatus int
	Body       string
	Headers    http.Header
	Cookies    []string
}

// Decode native fields once, rejecting ambiguous duplicate security fields.
// Unknown fields remain forward-compatible and bounded by max_response_bytes.
func decodeEnvelope(data []byte) (envelope, error) {
	var e envelope
	bad := errors.New("invalid native AppSec envelope")
	if !utf8.Valid(data) {
		return e, bad
	}
	d := json.NewDecoder(bytes.NewReader(data))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return e, bad
	}
	var seen uint8
	for d.More() {
		token, err = d.Token()
		if err != nil {
			return e, bad
		}
		// Token rejects non-string object keys before returning successfully.
		name := token.(string)
		var bit uint8
		var target any
		switch name {
		case "action":
			bit, target = 1, &e.Action
		case "http_status":
			bit, target = 2, &e.HTTPStatus
		case "user_body_content":
			bit, target = 4, &e.Body
		case "user_headers":
			bit, target = 8, &e.Headers
		case "user_cookies":
			bit, target = 16, &e.Cookies
		default:
			var ignored json.RawMessage
			target = &ignored
		}
		if bit != 0 && seen&bit != 0 {
			return e, bad
		}
		seen |= bit
		if bit == 8 {
			e.Headers, err = decodeHeaders(d)
		} else {
			err = d.Decode(target)
		}
		if err != nil {
			return e, bad
		}
	}
	if token, err = d.Token(); err != nil || token != json.Delim('}') {
		return e, bad
	}
	if _, err = d.Token(); err != io.EOF || e.Action == "" {
		return e, bad
	}
	return e, nil
}

// HTTP header names are case insensitive even though JSON object keys are not.
// Merge aliases before replacing the browser's existing header once, preserving
// every native value (particularly CSP and Set-Cookie) in wire order.
func decodeHeaders(d *json.Decoder) (http.Header, error) {
	token, err := d.Token()
	if err != nil {
		return nil, err
	}
	if token == nil {
		return nil, nil
	}
	if token != json.Delim('{') {
		return nil, errors.New("invalid native headers")
	}
	headers := make(http.Header)
	for d.More() {
		token, err = d.Token()
		if err != nil {
			return nil, err
		}
		name := token.(string) // Token has validated the object key.
		var values []string
		if err = d.Decode(&values); err != nil {
			return nil, err
		}
		name = http.CanonicalHeaderKey(name)
		if prior, exists := headers[name]; exists {
			headers[name] = append(prior, values...)
		} else {
			headers[name] = values
		}
	}
	_, err = d.Token()
	return headers, err
}

func isChallengePath(path string) bool { return strings.HasPrefix(path, challengePrefix) }

func (h *Handler) remediate(w http.ResponseWriter, r *http.Request, e envelope) error {
	if e.Action != "challenge" {
		status := http.StatusForbidden
		if e.Action == "ban" && e.HTTPStatus >= 400 && e.HTTPStatus <= 599 {
			status = e.HTTPStatus
		}
		return h.reject(w, r, status, "deny")
	}
	if e.HTTPStatus == 0 {
		e.HTTPStatus = http.StatusOK
	}
	if !h.Bot || e.Body == "" || e.HTTPStatus < 200 || e.HTTPStatus > 599 {
		return h.reject(w, r, http.StatusForbidden, "invalid_challenge")
	}
	// Validate all metadata before writing anything. A malformed envelope must
	// never leave success cookies or partly applied headers on a denial.
	for name, values := range e.Headers {
		if !httpguts.ValidHeaderFieldName(name) {
			return h.reject(w, r, http.StatusForbidden, "invalid_challenge")
		}
		for _, hop := range hopHeaders {
			if strings.EqualFold(name, hop) {
				return h.reject(w, r, http.StatusForbidden, "invalid_challenge")
			}
		}
		if strings.EqualFold(name, "Content-Length") {
			// Framing is generated from the relayed body, not engine-supplied metadata.
			continue
		}
		for _, value := range values {
			if !httpguts.ValidHeaderFieldValue(value) {
				return h.reject(w, r, http.StatusForbidden, "invalid_challenge")
			}
		}
	}
	for _, cookie := range e.Cookies {
		if !httpguts.ValidHeaderFieldValue(cookie) {
			return h.reject(w, r, http.StatusForbidden, "invalid_challenge")
		}
	}
	w.Header().Del("Content-Length")
	for name, values := range e.Headers {
		if strings.EqualFold(name, "Content-Length") {
			continue
		}
		w.Header().Del(name)
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	for _, cookie := range e.Cookies {
		w.Header().Add("Set-Cookie", cookie)
	}
	h.trace("challenge", e.HTTPStatus)
	w.WriteHeader(e.HTTPStatus)
	if r.Method == http.MethodHead {
		return nil
	}
	_, err := io.WriteString(w, e.Body)
	return err
}
