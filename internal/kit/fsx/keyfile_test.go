package fsx

import (
	"errors"
	"os"
	"strings"
	"testing"
)

var (
	errTestMissing = errors.New("missing")
	errTestTooOpen = errors.New("too open")
	errTestInvalid = errors.New("invalid")
	testRefusals   = KeyFileRefusals{Missing: errTestMissing, TooOpen: errTestTooOpen, Invalid: errTestInvalid, Reading: "read test key"}
)

// Chaque refus de ReadPrivate devient celui de l'appelant.
func TestReadKeyFile_TranslatesEachRefusal(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := ReadKeyFile(root, "key", 16, testRefusals); !errors.Is(err, errTestMissing) {
		t.Fatalf("missing: %v", err)
	}
	if err := root.WriteFile("key", []byte("0123456789abcdefX"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadKeyFile(root, "key", 16, testRefusals); !errors.Is(err, errTestInvalid) {
		t.Fatalf("too long: %v", err)
	}
	content, err := ReadKeyFile(root, "key", 17, testRefusals)
	if err != nil || string(content) != "0123456789abcdefX" {
		t.Fatalf("read %q %v", content, err)
	}
	if err := root.Chmod("key", 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadKeyFile(root, "key", 17, testRefusals); !errors.Is(err, errTestTooOpen) {
		t.Fatalf("readable by the group: %v", err)
	}
	if err := root.Mkdir("dir", 0o700); err != nil {
		t.Fatal(err)
	}
	_, err = ReadKeyFile(root, "dir", 17, testRefusals)
	if err == nil || !strings.HasPrefix(err.Error(), "read test key: ") || errors.Is(err, errTestInvalid) {
		t.Fatalf("unreadable: %v", err)
	}
}
