package fsx

import (
	"regexp"
	"strings"
	"testing"
)

// Le suffixe d'un temporaire reste de seize hexadécimaux, ce que
// removeLeftoverTemps sait reconnaître.
func TestUniqueTempName_KeepsItsShape(t *testing.T) {
	name, err := uniqueTempName("dir/file")
	if err != nil {
		t.Fatal(err)
	}
	suffix, found := strings.CutPrefix(name, "dir/file"+tempInfix)
	if !found || !regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(suffix) || !isTempSuffix(suffix) {
		t.Fatalf("name %q", name)
	}
}
