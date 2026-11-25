package fsx

import (
	"errors"
	"strings"
	"testing"
	"testing/iotest"
)

func TestReadLimited_ReadsExactlyTheLimit(t *testing.T) {
	content, err := ReadLimited(strings.NewReader("0123456789abcdef"), 16)
	if err != nil || string(content) != "0123456789abcdef" {
		t.Fatalf("read %q %v", content, err)
	}
	if content, err := ReadLimited(strings.NewReader(""), 16); err != nil || len(content) != 0 {
		t.Fatalf("empty: %q %v", content, err)
	}
}

// Un contenu trop long ne se rend pas, même en partie.
func TestReadLimited_RefusesOneByteOverTheLimit(t *testing.T) {
	content, err := ReadLimited(strings.NewReader("0123456789abcdefX"), 16)
	if !errors.Is(err, ErrTooLarge) || content != nil {
		t.Fatalf("one byte over: %q %v", content, err)
	}
}

// Une lecture qui échoue rend son erreur, pas ErrTooLarge.
func TestReadLimited_ReturnsTheReadError(t *testing.T) {
	broken := errors.New("broken")
	content, err := ReadLimited(iotest.ErrReader(broken), 16)
	if !errors.Is(err, broken) || errors.Is(err, ErrTooLarge) || content != nil {
		t.Fatalf("read error: %q %v", content, err)
	}
}
