package shape

import (
	"errors"
	"strings"
	"testing"
)

func TestR_A1_12_ALabelIsJudgedTheSameEverywhere(t *testing.T) {
	const max = 80
	cases := []struct {
		name string
		text string
		want error
	}{
		{"plain", "web", nil},
		{"trimmed", "  web  ", nil},
		{"only spaces", "   \t ", ErrLabelEmpty},
		{"empty", "", ErrLabelEmpty},
		{"escape", "web\x1b[31m", ErrLabelHasControl},
		{"newline", "web\nbis", ErrLabelHasControl},
		{"bidi override", "web\u202e", ErrLabelHasControl},
		{"invalid utf8", "web\xff", ErrLabelHasControl},
		{"80 accented", strings.Repeat("é", 80), nil},
		{"81 accented", strings.Repeat("é", 81), ErrLabelTooLong},
		{"80 plus spaces", " " + strings.Repeat("é", 80) + " ", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Label(c.text, max); !errors.Is(got, c.want) {
				t.Fatalf("Label(%q) = %v, want %v", c.text, got, c.want)
			}
		})
	}
}
