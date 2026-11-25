package brand

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Une élision collée au nom (« d'Kagu ») est fausse dès que le nom commence
// par une consonne : le nom vient d'une variable, l'article ne s'y adapte pas.
// On écrit « de Kagu », « le Kagu » ou une tournure sans article.
var elidedBeforeProductName = regexp.MustCompile(
	`[A-Za-zÀ-ÿ]['’]\s*(?:"\s*\+\s*)?(?:` +
		`\{product\}|\{\{product\}\}|brand\.ProductName|productName\(\)|\$\{[^}]*[pP]roduct[^}]*\}|` +
		`Kagu|kagu)`)

// Les catalogues, le Go de production et le front, tests exclus : un test
// peut citer l'erreur à titre d'exemple.
func carriesProductText(relative string) bool {
	switch {
	case strings.HasSuffix(relative, "_test.go"), strings.HasSuffix(relative, ".test.ts"), strings.HasSuffix(relative, ".test.tsx"):
		return false
	case strings.HasSuffix(relative, ".go"):
		return true
	case strings.HasSuffix(relative, ".toml"):
		return strings.HasPrefix(relative, "internal/kit/lang/")
	case strings.HasPrefix(relative, "web/src/"):
		return strings.HasSuffix(relative, ".ts") || strings.HasSuffix(relative, ".tsx")
	}
	return false
}

func TestProductNameHasNoElision(t *testing.T) {
	root := moduleRoot(t)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if entry.IsDir() {
			switch relative {
			case ".git", "web/node_modules", "web/dist":
				return filepath.SkipDir
			}
			return nil
		}
		if !carriesProductText(relative) {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for index, line := range strings.Split(string(content), "\n") {
			if found := elidedBeforeProductName.FindString(line); found != "" {
				t.Errorf("%s:%d: élision devant le nom du produit (%q) : écrire « de », « le » ou sans article", relative, index+1, found)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestElisionPattern_FlagsEveryWayToWriteTheName(t *testing.T) {
	flagged := []string{
		`"adresse d'"+brand.ProductName+", x"`,
		`"adresse d' " + brand.ProductName`,
		`adresse d'{product}`,
		`l’{{product}}`,
		"`l'${productName()}`",
		`qu'{product}`,
		`adresse d'Kagu`,
	}
	for _, line := range flagged {
		if !elidedBeforeProductName.MatchString(line) {
			t.Errorf("non repéré : %s", line)
		}
	}
	allowed := []string{
		`"adresse de "+brand.ProductName`,
		`adresse de {product}`,
		`« {product} » ne répond pas`,
		`le jeton de '{product}'`,
		`printf '%s' 'oc_…'`,
	}
	for _, line := range allowed {
		if elidedBeforeProductName.MatchString(line) {
			t.Errorf("repéré à tort : %s", line)
		}
	}
}
