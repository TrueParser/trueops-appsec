package pool_test

import (
	"bytes"
	"net/http"
	"strings"
	"testing"

	"github.com/TrueParser/trueops-appsec/modules/upstreampool"
)

func TestCandidatePoolRestartAndReload(t *testing.T) {
	f := setup(t)
	initial := f.status(t, "site")
	held := make(chan error, 1)
	go func() {
		e, _, err := request(f.client, f.site, "/hold", "POST", []byte("durable-held-v1"))
		if err == nil && e.Version != "v1" {
			err = http.ErrAbortHandler
		}
		held <- err
	}()
	f.waitHeld()
	f.put(t, upstreampool.Update{ExpectedInstance: initial.Instance, ExpectedRevision: 1, Spec: upstreampool.Spec{Revision: 2, Targets: f.v2}}, 200)
	f.reload()
	after := f.status(t, "site")
	if after.Instance != initial.Instance || after.Revision != 2 || len(after.Draining) != 1 || after.Draining[0].Active != 1 {
		t.Fatalf("reload lost applied state or active generation: %+v", after)
	}
	f.release()
	if err := <-held; err != nil {
		t.Fatal(err)
	}
	if len(f.status(t, "site").Draining) != 0 {
		t.Fatal("reload retained completed old generation")
	}
	f.restart()
	after = f.status(t, "site")
	if after.Instance == initial.Instance || after.Revision != 2 {
		t.Fatalf("restart did not restore committed V2 under a new instance: %+v", after)
	}
	f.put(t, upstreampool.Update{ExpectedInstance: initial.Instance, ExpectedRevision: 2, Spec: upstreampool.Spec{Revision: 3, Targets: f.v1}}, 409)
	for range 30 {
		e, _, err := request(f.client, f.site, "/echo?after=restart", "POST", []byte("restored-body"))
		if err != nil || e.Version != "v2" {
			t.Fatal("restart served bootstrap V1", e, err)
		}
	}
	t.Log("forced reload preserved applied V2 and held V1 drain; abrupt process restart restored V2 and rejected stale instance; 30 post-restart requests reached V2")
}

func TestCandidatePoolAdminBoundary(t *testing.T) {
	f := setup(t)
	before := f.status(t, "site")
	for _, check := range []struct {
		method, path, body string
		want               int
	}{
		{"POST", "/upstream-pools/site", "{}", 405},
		{"PUT", "/upstream-pools/site", `{"expected_instance":"forged","expected_revision":1,"revision":2,"targets":["127.0.0.1:1"]}`, 409},
		{"PUT", "/upstream-pools/site", `{"unknown":true}`, 400},
		{"PUT", "/upstream-pools/site", strings.Repeat(" ", 1<<20) + "{}", 413},
		{"PUT", "/upstream-pools/site", "{}" + strings.Repeat(" ", 1<<20), 413},
		{"GET", "/upstream-pools/missing", "", 404},
	} {
		req, err := http.NewRequest(check.method, f.admin+check.path, bytes.NewBufferString(check.body))
		if err != nil {
			t.Fatal(err)
		}
		resp, err := f.control.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != check.want {
			t.Fatalf("%s %s status=%d want=%d", check.method, check.path, resp.StatusCode, check.want)
		}
	}
	after := f.status(t, "site")
	if after.Instance != before.Instance || after.Revision != before.Revision {
		t.Fatal("rejected control changed serving pool")
	}
	resp, err := f.control.Get(f.admin + "/upstream-pools/site")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("runtime evidence may be cached")
	}
	t.Log("native Admin method, instance, schema, body-size and missing-pool boundaries preserved serving state; reads use no-store")
}
