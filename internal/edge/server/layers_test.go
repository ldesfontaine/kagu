package server

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Les règles d'import entre les familles d'internal/ (17-conventions-code.md,
// « Les règles d'import »). Le rang se lit dans le chemin : la seule table est
// ranks. Une exception se déclare dans layerExceptions, avec sa raison.

const modulePath = "github.com/ldesfontaine/kagu/"

// ranks : famille → rang d'import ; un dossier ne s'importe que s'il est du
// même rang ou plus bas.
var ranks = map[string]int{"kit": 0, "fact": 1, "wire": 2, "gesture": 3, "domain": 4, "view": 5, "edge": 6}

// layerExceptions : les imports qui contredisent une règle, avec la raison.
// Clé : « fichier importé-par-lui » → « chemin importé », relatif au module.
var layerExceptions = map[string]string{}

const (
	// Règles 1 et 2 : kit est au rang 0, la règle du rang le tient déjà.
	ruleImportRank   = 1 // un paquet n'importe que son dossier ou plus bas
	ruleAgentOffEdge = 3 // edge/agent et edge/gate n'importent ni server ni store
	ruleSubOfServer  = 4 // un sous-paquet de edge/server n'importe pas edge/server
	ruleTestKit      = 5 // un banc n'est importé que par des _test.go
	ruleHasFamily    = 6 // un paquet vit dans l'un des sept dossiers
)

type layerFault struct {
	rule int
	text string
}

// familyOf rend la famille d'un chemin relatif au module (« internal/fact/probe/x.go »).
func familyOf(relative string) (string, bool) {
	parts := strings.Split(relative, "/")
	if len(parts) < 3 || parts[0] != "internal" {
		return "", false
	}
	_, known := ranks[parts[1]]
	return parts[1], known
}

// isTestKit : un banc se nomme `*test` (waittest, servertest…) ou `testkit`.
func isTestKit(packageDir string) bool {
	name := path.Base(packageDir)
	return strings.HasSuffix(name, "test") || name == "testkit"
}

func isStandardLibrary(importPath string) bool {
	return !strings.Contains(strings.SplitN(importPath, "/", 2)[0], ".")
}

// layerFaults relève les règles 1 à 5 sur les imports d'un fichier.
// relative : chemin du fichier relatif au module, avec des « / ».
func layerFaults(relative string, file *ast.File) []layerFault {
	packageDir := path.Dir(relative)
	family, inFamily := familyOf(relative)
	isTestFile := strings.HasSuffix(relative, "_test.go")
	var faults []layerFault
	add := func(rule int, importPath, why string) {
		// Les règles 1 à 4 portent sur le graphe de production : un test
		// emprunte le store ou un autre rang pour son décor.
		if isTestFile && rule != ruleTestKit {
			return
		}
		if _, excepted := layerExceptions[relative+" → "+importPath]; excepted {
			return
		}
		faults = append(faults, layerFault{rule, relative + " importe " + importPath + " : " + why})
	}

	for _, spec := range file.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			continue
		}
		if isStandardLibrary(importPath) {
			continue
		}
		if !strings.HasPrefix(importPath, modulePath) {
			continue
		}
		target := strings.TrimPrefix(importPath, modulePath)
		targetFamily, targetKnown := familyOf(target + "/")
		if strings.HasPrefix(target, "internal/") {
			if !targetKnown {
				add(ruleImportRank, importPath, "dossier hors des sept familles")
			} else if inFamily {
				if ranks[targetFamily] > ranks[family] {
					add(ruleImportRank, importPath, "importe un rang plus haut ("+family+" → "+targetFamily+")")
				}
			}
			if isTestKit(target) && !isTestFile && !isTestKit(packageDir) {
				add(ruleTestKit, importPath, "un banc n'est importé que par des _test.go")
			}
		}
		if inFamily && family == "edge" {
			if (strings.HasPrefix(packageDir, "internal/edge/agent") || strings.HasPrefix(packageDir, "internal/edge/gate")) &&
				(isPackageOrBelow(target, "internal/edge/server") || isPackageOrBelow(target, "internal/edge/store")) {
				add(ruleAgentOffEdge, importPath, "l'agent et la porte n'importent ni edge/server ni edge/store")
			}
			if strings.HasPrefix(packageDir, "internal/edge/server/") && target == "internal/edge/server" {
				add(ruleSubOfServer, importPath, "un sous-paquet de edge/server n'importe pas edge/server")
			}
		}
	}
	return faults
}

func isPackageOrBelow(target, root string) bool {
	return target == root || strings.HasPrefix(target, root+"/")
}

// packageFamilyFault : la règle 6 sur le dossier d'un paquet (relatif au
// module). Rend vide si le dossier est rangé.
func packageFamilyFault(packageDir string) string {
	if !strings.HasPrefix(packageDir, "internal/") {
		return ""
	}
	if _, known := familyOf(packageDir + "/"); !known || strings.Count(packageDir, "/") < 2 {
		return packageDir + " : un paquet vit dans l'un des sept dossiers d'internal/, pas ailleurs"
	}
	return ""
}

func checkLayerRules(t *testing.T, rules ...int) {
	t.Helper()
	wanted := map[int]bool{}
	for _, rule := range rules {
		wanted[rule] = true
	}
	checked := 0
	forEachGoFile(t, moduleRoot(), true, func(file string, fileSet *token.FileSet, parsed *ast.File) {
		relative, err := filepath.Rel(moduleRoot(), file)
		if err != nil {
			t.Fatal(err)
		}
		checked++
		for _, fault := range layerFaults(filepath.ToSlash(relative), parsed) {
			if wanted[fault.rule] {
				t.Errorf("règle %d : %s", fault.rule, fault.text)
			}
		}
	})
	if checked == 0 {
		t.Fatal("no source file seen: the guard no longer sees the code")
	}
}

// Un paquet n'importe que son dossier ou un rang plus bas (règles 1 et 2 :
// kit, au rang 0, n'importe aucun autre paquet d'openCloud). Les bibliothèques
// tierces de kit (go-toml dans lang, x/crypto dans release) ne sont pas
// relevées : la règle 2 dit « bibliothèque standard », question posée à Lucas.
func TestLayers_NoImportGoesUp(t *testing.T) {
	checkLayerRules(t, ruleImportRank)
}

// Le bord se tient à l'écart : l'agent et la porte ne montent pas au serveur
// ni à la base, un sous-paquet du serveur ne remonte pas à sa racine.
func TestLayers_AgentStaysOffTheServer(t *testing.T) {
	checkLayerRules(t, ruleAgentOffEdge, ruleSubOfServer)
}

func TestLayers_TestKitsOnlyInTests(t *testing.T) {
	checkLayerRules(t, ruleTestKit)
}

func TestLayers_EveryPackageHasAFamily(t *testing.T) {
	seen := map[string]bool{}
	forEachGoFile(t, moduleRoot(), true, func(file string, fileSet *token.FileSet, parsed *ast.File) {
		relative, err := filepath.Rel(moduleRoot(), file)
		if err != nil {
			t.Fatal(err)
		}
		packageDir := path.Dir(filepath.ToSlash(relative))
		if seen[packageDir] {
			return
		}
		seen[packageDir] = true
		if fault := packageFamilyFault(packageDir); fault != "" {
			t.Errorf("règle %d : %s", ruleHasFamily, fault)
		}
	})
	if len(seen) == 0 {
		t.Fatal("no source file seen: the guard no longer sees the code")
	}
}

// Les gardes ne valent que si elles échouent sur la faute : on leur donne
// des sources fautifs, jamais un fichier laissé dans le dépôt.
func TestLayers_GuardCatchesItsFault(t *testing.T) {
	cases := []struct {
		name   string
		file   string
		source string
		rule   int
	}{
		{"import going up", "internal/kit/faulty/faulty.go", `package faulty
import _ "github.com/ldesfontaine/kagu/internal/fact/machine"
`, ruleImportRank},
		{"kit importing another family", "internal/kit/faulty/faulty.go", `package faulty
import _ "github.com/ldesfontaine/kagu/internal/kit/refusal"
import _ "github.com/ldesfontaine/kagu/internal/edge/config"
`, ruleImportRank},
		{"agent importing the server", "internal/edge/agent/faulty.go", `package agent
import _ "github.com/ldesfontaine/kagu/internal/edge/server"
`, ruleAgentOffEdge},
		{"server sub-package importing the server", "internal/edge/server/faulty/faulty.go", `package faulty
import _ "github.com/ldesfontaine/kagu/internal/edge/server"
`, ruleSubOfServer},
		{"test kit imported outside a test", "internal/domain/faulty/faulty.go", `package faulty
import _ "github.com/ldesfontaine/kagu/internal/kit/wait/waittest"
`, ruleTestKit},
	}
	for _, c := range cases {
		file, err := parser.ParseFile(token.NewFileSet(), c.file, c.source, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		caught := false
		for _, fault := range layerFaults(c.file, file) {
			caught = caught || fault.rule == c.rule
		}
		if !caught {
			t.Errorf("%s: rule %d not caught", c.name, c.rule)
		}
	}

	if packageFamilyFault("internal/stray") == "" || packageFamilyFault("internal/stray/pkg") == "" {
		t.Error("package outside the families not caught")
	}
	if packageFamilyFault("internal/kit/refusal") != "" || packageFamilyFault("cmd/kagu") != "" {
		t.Error("a well-placed package was refused")
	}

	for key, reason := range layerExceptions {
		if strings.TrimSpace(reason) == "" {
			t.Errorf("exception %q sans raison écrite", key)
		}
	}
}
