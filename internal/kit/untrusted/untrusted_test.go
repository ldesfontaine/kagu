package untrusted

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestR_A1_13_UntrustedRefusesControlBidiAndBrokenUTF8(t *testing.T) {
	refused := map[string]string{
		"échappement":         "a\x1bb",
		"saut de ligne":       "a\nb",
		"nul":                 "a\x00b",
		"C1":                  "a\u0085b",
		"RLO":                 "a\u202eb",
		"LRI":                 "a\u2066b",
		"PDI":                 "a\u2069b",
		"RLM":                 "a\u200fb",
		"UTF-8 coupé":         "caf\xc3",
		"octet isolé":         "a\xffb",
		"UTF-8 coupé au bout": "é"[:1],
	}
	for name, text := range refused {
		if !HasControl(text) {
			t.Errorf("%s: %q accepted", name, text)
		}
		clean, changed := Strip(text)
		if !changed || !strings.ContainsRune(clean, replacement) || HasControl(clean) {
			t.Errorf("%s: Strip(%q) = %q, %v", name, text, clean, changed)
		}
	}
	accepted := []string{"", "plain", "café 日本語", "tab\u00a0insécable", "emoji 🙂", "déjà U+FFFD \ufffd"}
	for _, text := range accepted {
		if HasControl(text) {
			t.Errorf("%q refused", text)
		}
		if clean, changed := Strip(text); changed || clean != text {
			t.Errorf("Strip(%q) = %q, %v", text, clean, changed)
		}
	}
}

func TestStrip_ReplacesEachRefusedCharacter(t *testing.T) {
	clean, changed := Strip("a\x1b\u202eb\xff")
	if !changed || clean != "a\ufffd\ufffdb\ufffd" {
		t.Errorf("got %q, %v", clean, changed)
	}
}

func TestBound_NeverCutsACharacter(t *testing.T) {
	text := strings.Repeat("é", 10) // deux octets par caractère
	for limit := range len(text) + 3 {
		cut := Bound(text, limit)
		if len(cut) > limit || !utf8.ValidString(cut) || !strings.HasPrefix(text, cut) {
			t.Errorf("limit %d: %q", limit, cut)
		}
	}
	if got := Bound("short", 10); got != "short" {
		t.Errorf("short text changed: %q", got)
	}
	if got := Bound("é", 1); got != "" {
		t.Errorf("a character wider than the limit must give nothing: %q", got)
	}
	if got := Bound("abc", -1); got != "" {
		t.Errorf("negative limit: %q", got)
	}
}
