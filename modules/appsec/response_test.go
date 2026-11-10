package appsec

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEnvelopeMalformedFieldsAndExtensions(t *testing.T) {
	for _, data := range [][]byte{
		{0xff}, []byte(`{"action":42}`), []byte(`{false}`),
		[]byte(`{"action":"allow"`), []byte(`{"user_headers":`),
		[]byte(`{"action":"allow"]`),
		[]byte(`{"action":"allow","user_headers":[]}`),
		[]byte(`{"action":"allow","user_headers":{false}}`),
		[]byte(`{"action":"allow","user_headers":{"X-Test":42}}`),
		[]byte(`{"action":"allow","user_cookies":"wrong"}`),
		[]byte(`{"action":"allow","http_status":"wrong"}`),
		[]byte(`{"action":"allow","future":`),
	} {
		if _, err := decodeEnvelope(data); err == nil {
			t.Errorf("accepted malformed fixture %q", data)
		}
	}
	for _, data := range []string{
		`{"action":"allow","future":{"version":1}}`,
		`{"action":"allow","user_headers":null}`,
	} {
		if _, err := decodeEnvelope([]byte(data)); err != nil {
			t.Fatalf("forward-compatible response rejected: %v", err)
		}
	}
}

func TestEnvelopeRejectsNonStringObjectKeys(t *testing.T) {
	for _, key := range []string{"false", "true", "null", "42", "[]", "{}"} {
		for _, data := range []string{
			`{` + key + `:"allow"}`,
			`{"action":"allow","user_headers":{` + key + `:[]}}`,
		} {
			if _, err := decodeEnvelope([]byte(data)); err == nil {
				t.Errorf("accepted non-string key in %q", data)
			}
		}
	}
}

type failedWriter struct{ header http.Header }

func (w failedWriter) Header() http.Header     { return w.header }
func (failedWriter) WriteHeader(int)           {}
func (failedWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestChallengeFramingRepeatedHeadersAndWriteFailure(t *testing.T) {
	engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reply(w, 403, `{"action":"challenge","user_body_content":"challenge","user_headers":{"Content-Length":["99999"],"X-Repeated":["one","two"],"Set-Cookie":["header=a"]},"user_cookies":["cookie=b"]}`)
	}))
	defer engine.Close()
	h := configured(t, engine.URL, true, true)
	w, called := execute(t, h, incoming("GET", "http://site.test/", ""))
	if called || w.Code != 200 || w.Header().Get("Content-Length") == "99999" || len(w.Header().Values("Set-Cookie")) != 2 || len(w.Header().Values("X-Repeated")) != 2 {
		t.Fatal("challenge framing/metadata changed")
	}
	err := h.ServeHTTP(failedWriter{make(http.Header)}, incoming("GET", "http://site.test/", ""), nil)
	if !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("write error not propagated: %v", err)
	}
	if len(h.runtime.slots) != 0 {
		t.Fatal("write failure leaked capacity")
	}
}

func FuzzNativeEnvelope(f *testing.F) {
	for _, seed := range []string{`{"action":"allow"}`, `{"action":"ban","http_status":429}`, `{"action":"challenge","http_status":307,"user_body_content":"page","user_headers":{"Content-Security-Policy":["one"],"content-security-policy":["two"]},"user_cookies":["a=b"]}`, `{"action":"ban","action":"allow"}`, `null`, `{"user_headers":{`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip("bounds already enforced by the transport")
		}
		e, err := decodeEnvelope(data)
		if err != nil {
			return
		}
		if !json.Valid(data) || e.Action == "" {
			t.Fatal("invalid envelope accepted")
		}
		for name := range e.Headers {
			if strings.ContainsAny(name, "\r\n") {
				continue
			}
			if name != http.CanonicalHeaderKey(name) {
				t.Fatal("header alias not normalized")
			}
		}
	})
}
