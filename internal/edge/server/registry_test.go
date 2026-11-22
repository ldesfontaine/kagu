package server

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ldesfontaine/kagu/internal/fact/machine"
	"github.com/ldesfontaine/kagu/internal/gesture/verb"
	"github.com/ldesfontaine/kagu/internal/kit/audit"
	"github.com/ldesfontaine/kagu/internal/wire/agentwire"
)

// Un seul registre des gestes (brique B-5, R-A1-14) : les genres d'ordres
// (agentwire), les droits qu'ils exigent (machine jusqu'à agentpolicy, T03-01)
// et les verbes avec leur action d'audit (verb, audit) se croisent ici.

// gestureLists sont les listes que le test croise.
type gestureLists struct {
	// Spec.Right de chaque genre du registre.
	rights map[agentwire.Kind]string
	// Les noms de droits connus : machine.CapabilityNames, puis agentpolicy.
	knownRights []string
	// Verb.Order et Verb.Audit de chaque verbe, par identifiant (T02-02).
	verbOrders map[string]agentwire.Kind
	verbAudits map[string]audit.Action
	// audit.Actions.
	knownActions []audit.Action
}

// disagreements rend chaque nom d'une liste que l'autre ne connaît pas.
func (l gestureLists) disagreements() []string {
	var found []string
	for kind, right := range l.rights {
		if !slices.Contains(l.knownRights, right) {
			found = append(found, "genre "+string(kind)+" : droit "+right+" inconnu")
		}
	}
	for id, kind := range l.verbOrders {
		if _, known := l.rights[kind]; !known {
			found = append(found, "verbe "+id+" : genre "+string(kind)+" hors du registre")
		}
	}
	for id, action := range l.verbAudits {
		if !slices.Contains(l.knownActions, action) {
			found = append(found, "verbe "+id+" : action d'audit "+string(action)+" inconnue")
		}
	}
	return found
}

func currentGestureLists() gestureLists {
	lists := gestureLists{
		rights:       map[agentwire.Kind]string{},
		knownRights:  machine.CapabilityNames(),
		verbOrders:   map[string]agentwire.Kind{},
		verbAudits:   map[string]audit.Action{},
		knownActions: audit.Actions(),
	}
	for _, kind := range agentwire.OrderKinds() {
		spec, _ := agentwire.SpecOf(kind)
		lists.rights[kind] = spec.Right
	}
	return lists
}

func TestRegistry_ThreeListsAgree(t *testing.T) {
	lists := currentGestureLists()
	if len(lists.rights) == 0 || len(lists.knownActions) == 0 {
		t.Fatal("an empty list: the test no longer sees the registry")
	}
	for _, disagreement := range lists.disagreements() {
		t.Error(disagreement)
	}
	// verb.Verb n'a pas encore Order ni Audit : T02-02 les pose et remplit
	// verbOrders et verbAudits ici. D'ici là, les verbes ne sont pas croisés.
	t.Logf("%d verbes non croisés : verb.Verb n'a pas encore Order ni Audit (T02-02)", len(verb.Default.All()))
}

// Le témoin : chaque liste a sa faute, et chacune est vue.
func TestRegistry_ThreeListsAgree_SeesEachFault(t *testing.T) {
	faults := map[string]func(*gestureLists){
		"unknown kind": func(l *gestureLists) { l.verbOrders["docker.purge"] = "docker.purge" },
		"unknown right": func(l *gestureLists) {
			l.rights[agentwire.KindDockerDeploy] = "docker.deploi"
		},
		"unknown audit action": func(l *gestureLists) { l.verbAudits["docker.deploy"] = "docker.deploi" },
	}
	for name, fault := range faults {
		lists := currentGestureLists()
		fault(&lists)
		if found := lists.disagreements(); len(found) != 1 {
			t.Errorf("%s: %v", name, found)
		}
	}
}

// literalRights rend les déclarations de genre dont le droit est une chaîne
// tapée : une faute de frappe y donnerait un genre que personne ne peut
// exécuter, découvert en production.
func literalRights(fileSet *token.FileSet, file *ast.File) []string {
	var found []string
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || len(call.Args) < 2 || !declaresAKind(call.Fun) {
			return true
		}
		if _, literal := call.Args[1].(*ast.BasicLit); literal {
			found = append(found, fileSet.Position(call.Pos()).String())
		}
		return true
	})
	return found
}

// declaresAKind reconnaît Define[P], agentwire.Define[P] et DefineWithoutParams.
func declaresAKind(function ast.Expr) bool {
	if index, generic := function.(*ast.IndexExpr); generic {
		function = index.X
	}
	name := ""
	switch typed := function.(type) {
	case *ast.Ident:
		name = typed.Name
	case *ast.SelectorExpr:
		name = typed.Sel.Name
	}
	return name == "Define" || name == "DefineWithoutParams"
}

func TestRegistry_RightsAreNamedConstants(t *testing.T) {
	declared := 0
	forEachGoFile(t, moduleRoot(), false, func(path string, fileSet *token.FileSet, file *ast.File) {
		if filepath.Base(path) == "registry.go" && strings.Contains(filepath.ToSlash(path), "internal/wire/agentwire/") {
			declared++
		}
		for _, at := range literalRights(fileSet, file) {
			t.Errorf("%s : le droit d'un genre se nomme par sa constante, jamais en chaîne", at)
		}
	})
	if declared != 1 {
		t.Fatal("internal/wire/agentwire/registry.go not seen: the guard no longer sees the registry")
	}
	const faulty = `package faulty

var registry = []Spec{
	Define[DockerParams](KindDockerDeploy, "docker.deploy"),
	agentwire.Define[DockerParams](KindDockerUpdate, machine.CapabilityDockerUpdate),
	DefineWithoutParams(KindAgentPing, "observe"),
}
`
	fileSet := token.NewFileSet()
	file, err := parser.ParseFile(fileSet, "faulty.go", faulty, 0)
	if err != nil {
		t.Fatal(err)
	}
	if found := literalRights(fileSet, file); len(found) != 2 {
		t.Fatalf("the guard sees %v in a source with two typed rights", found)
	}
}
