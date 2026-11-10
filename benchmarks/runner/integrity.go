package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func verifyBundle(root string) error {
	f, err := os.Open(filepath.Join(root, "SHA256SUMS"))
	if err != nil {
		return err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	count := 0
	for s.Scan() {
		parts := strings.SplitN(s.Text(), "  ", 2)
		if len(parts) != 2 || len(parts[0]) != 64 {
			return fmt.Errorf("invalid bundle checksum manifest")
		}
		rel := filepath.FromSlash(parts[1])
		path := filepath.Join(root, rel)
		if filepath.IsAbs(rel) || !strings.HasPrefix(filepath.Clean(path), filepath.Clean(root)+string(os.PathSeparator)) {
			return fmt.Errorf("checksum path escapes bundle")
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		h := sha256.New()
		_, err = io.Copy(h, file)
		file.Close()
		if err != nil {
			return err
		}
		if hex.EncodeToString(h.Sum(nil)) != parts[0] {
			return fmt.Errorf("bundle checksum mismatch: %s", parts[1])
		}
		count++
	}
	if err = s.Err(); err != nil {
		return err
	}
	if count == 0 {
		return fmt.Errorf("empty bundle checksum manifest")
	}
	return nil
}
