package main

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestArtifactServerDoesNotExposeOtherFiles(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"bundle.tar.gz", "SHA256SUMS", "private.env"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	h, err := artifactHandler(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		method, path string
		code         int
	}{
		{"GET", "/bundle.tar.gz", 200}, {"HEAD", "/SHA256SUMS", 200},
		{"GET", "/", 404}, {"GET", "/private.env", 404},
		{"GET", "/../private.env", 404}, {"POST", "/bundle.tar.gz", 405},
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
		t.Logf("%s %s => %d", tc.method, tc.path, w.Code)
		if w.Code != tc.code {
			t.Fatalf("want %d", tc.code)
		}
	}
}
