package pool_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// External origins are opt-in disposable fixtures; never point at applications.
func (f *fixture) externalOrigins(t *testing.T, v1, v2 string) {
	t.Helper()
	f.v1, f.v2 = strings.Split(v1, ","), strings.Split(v2, ",")
	if len(f.v1) < 2 || len(f.v1) != len(f.v2) {
		t.Fatal("external V1/V2 lists require matching sets of at least two fixture targets")
	}
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 3 * time.Second}
	t.Cleanup(client.CloseIdleConnections)
	control := func(action string) error {
		for _, target := range f.v1 {
			resp, err := client.Post("http://"+target+"/__pool_"+action, "text/plain", nil)
			if err != nil {
				return err
			}
			_ = resp.Body.Close()
			if resp.StatusCode != 204 {
				return fmt.Errorf("fixture control %s status=%d", action, resp.StatusCode)
			}
		}
		return nil
	}
	if err := control("reset"); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	f.release = func() {
		once.Do(func() {
			if err := control("release"); err != nil {
				t.Error(err)
			}
		})
	}
	f.retire = func(retire bool) error {
		action := "restore"
		if retire {
			action = "retire"
		}
		return control(action)
	}
	f.waitHeld = func() {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			for _, target := range f.v1 {
				resp, err := client.Get("http://" + target + "/__pool_state")
				if err != nil {
					t.Fatal(err)
				}
				var state struct{ Held int }
				err = json.NewDecoder(resp.Body).Decode(&state)
				_ = resp.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				if state.Held > 0 {
					return
				}
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal("remote held request was not observed")
	}
	t.Cleanup(func() {
		f.release()
		if err := control("restore"); err != nil {
			t.Error(err)
		}
		for _, target := range append(append([]string{}, f.v1...), f.v2...) {
			resp, err := client.Get("http://" + target + "/__pool_state")
			if err == nil {
				var state any
				_ = json.NewDecoder(resp.Body).Decode(&state)
				_ = resp.Body.Close()
				t.Logf("external origin=%s state=%v", target, state)
			}
		}
	})
	t.Logf("external fixtures: V1=%v V2=%v; traffic crosses the specified target network", f.v1, f.v2)
}
