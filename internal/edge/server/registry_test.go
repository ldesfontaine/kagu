package server

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/gesture/verb"
	"github.com/ldesfontaine/kagu/internal/kit/audit"
	"github.com/ldesfontaine/kagu/internal/wire/agentwire"
)

// Un seul registre des gestes (brique B-5, R-A1-14) : les genres d'ordres
// (agentwire), les droits qu'ils exigent (agentpolicy) et les verbes avec leur action d'audit (verb, audit) se croisent ici.

// gestureLists sont les listes que le test croise.
type gestureLists struct {
	// Spec.Right de chaque genre du registre.
	rights map[agentwire.Kind]string
	// Les noms de droits connus d'agentpolicy.
	knownRights []string
	// Verb.Order, Verb.Right et Verb.Audit de chaque verbe, par identifiant.
	verbOrders map[string]agentwire.Kind
	verbRights map[string]string
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
		if kind == "" {
			if l.verbRights[id] != "" {
				found = append(found, "verbe "+id+" : droit "+l.verbRights[id]+" sans ordre")
			}
			continue
		}
		right, known := l.rights[kind]
		switch {
		case !known:
			found = append(found, "verbe "+id+" : genre "+string(kind)+" hors du registre")
		case l.verbRights[id] != right:
			found = append(found, "verbe "+id+" : droit "+l.verbRights[id]+", le genre exige "+right)
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
		knownRights:  agentpolicy.Names(),
		verbOrders:   map[string]agentwire.Kind{},
		verbRights:   map[string]string{},
		verbAudits:   map[string]audit.Action{},
		knownActions: audit.Actions(),
	}
	for _, kind := range agentwire.OrderKinds() {
		spec, _ := agentwire.SpecOf(kind)
		lists.rights[kind] = spec.Right
	}
	for _, offered := range verb.Default.All() {
		lists.verbOrders[offered.ID] = offered.Order
		lists.verbRights[offered.ID] = offered.Right
		lists.verbAudits[offered.ID] = offered.Audit
	}
	return lists
}

func TestRegistry_ThreeListsAgree(t *testing.T) {
	lists := currentGestureLists()
	if len(lists.rights) == 0 || len(lists.knownActions) == 0 || len(lists.verbAudits) == 0 {
		t.Fatal("an empty list: the test no longer sees the registry")
	}
	for _, disagreement := range lists.disagreements() {
		t.Error(disagreement)
	}
}

// Le témoin : chaque liste a sa faute, et chacune est vue.
func TestRegistry_ThreeListsAgree_SeesEachFault(t *testing.T) {
	faults := map[string]func(*gestureLists){
		"unknown kind": func(l *gestureLists) { l.verbOrders["agent.ping"] = "docker.purge" },
		"right not the right of the kind": func(l *gestureLists) {
			l.verbRights["agent.update"] = agentpolicy.CapabilityObserve
		},
		"right without an order": func(l *gestureLists) { l.verbRights["probe.pause"] = agentpolicy.CapabilityObserve },
		"unknown right": func(l *gestureLists) {
			l.rights[agentwire.KindDockerDeploy] = "docker.deploi"
		},
		"unknown audit action": func(l *gestureLists) { l.verbAudits["agent.ping"] = "docker.deploi" },
		"no audit action":      func(l *gestureLists) { l.verbAudits["probe.pause"] = "" },
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
	agentwire.Define[DockerParams](KindDockerUpdate, agentpolicy.CapabilityDockerUpdate),
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

// notAgentpolicyRights relève les déclarations de genre dont le droit n'est
// pas une constante d'agentpolicy : une chaîne, une variable, la constante
// d'un autre paquet.
func notAgentpolicyRights(fileSet *token.FileSet, file *ast.File) (declared int, found []string) {
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || len(call.Args) < 2 || !declaresAKind(call.Fun) {
			return true
		}
		declared++
		right, isSelector := call.Args[1].(*ast.SelectorExpr)
		if !isSelector || !isIdent(right.X, "agentpolicy") || !strings.HasPrefix(right.Sel.Name, "Capability") {
			found = append(found, fileSet.Position(call.Pos()).String())
		}
		return true
	})
	return declared, found
}

// R-A1-14 : le droit d'un genre est un nom défini par agentpolicy, jamais une
// chaîne ni une constante d'ailleurs.
func TestR_A1_14_ARightOfTheRegistryIsAnAgentpolicyConstant(t *testing.T) {
	fileSet := token.NewFileSet()
	file, err := parser.ParseFile(fileSet, filepath.Join(moduleRoot(), "internal", "wire", "agentwire", "registry.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	declared, found := notAgentpolicyRights(fileSet, file)
	if declared != len(agentwire.OrderKinds()) {
		t.Fatalf("%d declarations seen for %d kinds: the guard no longer sees the registry", declared, len(agentwire.OrderKinds()))
	}
	for _, at := range found {
		t.Errorf("%s : le droit d'un genre est une constante d'agentpolicy", at)
	}
	const faulty = `package faulty

var registry = []Spec{
	Define[DockerParams](KindDockerDeploy, "docker.deploy"),
	Define[DockerParams](KindDockerUpdate, machine.CapabilityDockerUpdate),
	DefineWithoutParams(KindAgentRollback, updateRight),
	DefineWithoutParams(KindAgentPing, agentpolicy.CapabilityObserve),
}
`
	faultyFile, err := parser.ParseFile(fileSet, "faulty.go", faulty, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, found := notAgentpolicyRights(fileSet, faultyFile); len(found) != 3 {
		t.Fatalf("the guard sees %v in a source with three rights from elsewhere", found)
	}
}

// rightNameDefinition reconnaît la définition d'un nom de droit : le motif du
// critère B-5 (fiche A3, §8), élargi à toute constante Capability….
var rightNameDefinition = regexp.MustCompile(`\bCapability[A-Z]\w*\s*=`)

const agentpolicyDir = "internal/fact/agentpolicy/"

// B-5 : les noms de droits ne se définissent qu'une fois, dans agentpolicy ;
// aucun alias ailleurs, tests compris.
func TestB5_RightNamesAreDefinedOnlyInAgentpolicy(t *testing.T) {
	inAgentpolicy := 0
	err := filepath.WalkDir(filepath.Join(moduleRoot(), "internal"), func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		content, err := os.ReadFile(path) // #nosec G304 -- le dépôt lui-même, parcouru par le test.
		if err != nil {
			return err
		}
		found := len(rightNameDefinition.FindAll(content, -1))
		if strings.Contains(filepath.ToSlash(path), agentpolicyDir) {
			inAgentpolicy += found
		} else if found > 0 {
			t.Errorf("%s : %d nom(s) de droit défini(s) hors d'agentpolicy", path, found)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if inAgentpolicy != len(agentpolicy.Names()) {
		t.Fatalf("%d definitions in agentpolicy for %d known rights: the guard no longer sees them", inAgentpolicy, len(agentpolicy.Names()))
	}
	alias := "const Capability" + "Observe = agentpolicy.Capability" + "Observe"
	if !rightNameDefinition.MatchString(alias) {
		t.Fatal("the guard does not see an alias")
	}
}

// isAgentwireKind reconnaît le type agentwire.Kind.
func isAgentwireKind(expr ast.Expr) bool {
	selector, ok := expr.(*ast.SelectorExpr)
	return ok && selector.Sel.Name == "Kind" && isIdent(selector.X, "agentwire")
}

// namesARight dit si un nœud nomme ou juge un droit d'agent : le champ Right
// d'une déclaration, une constante agentpolicy.Capability…, agentpolicy.HasCapability.
func namesARight(node ast.Node) bool {
	selector, ok := node.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	if selector.Sel.Name == "Right" {
		return true
	}
	return isIdent(selector.X, "agentpolicy") &&
		(strings.HasPrefix(selector.Sel.Name, "Capability") || selector.Sel.Name == "HasCapability")
}

func mentionsARight(root ast.Node) bool {
	found := false
	ast.Inspect(root, func(node ast.Node) bool {
		found = found || namesARight(node)
		return !found
	})
	return found
}

// kindRightTables relève ce qui dit le droit d'un genre hors du registre
// (R-A1-1) : une fonction qui prend un agentwire.Kind et nomme ou juge un
// droit (un relais de Spec.Right, une table en switch, un second juge), une
// table map[agentwire.Kind]… qui nomme un droit. La forme est jugée, pas le
// nom : restic.RightOf, qui juge un droit et non un genre, n'y tombe pas.
func kindRightTables(fileSet *token.FileSet, file *ast.File) []string {
	var found []string
	ast.Inspect(file, func(node ast.Node) bool {
		switch typed := node.(type) {
		case *ast.FuncDecl:
			if typed.Body != nil && takesAKind(typed) && mentionsARight(typed.Body) {
				found = append(found, fileSet.Position(typed.Pos()).String()+": "+typed.Name.Name)
			}
		case *ast.CompositeLit:
			table, isMap := typed.Type.(*ast.MapType)
			if isMap && isAgentwireKind(table.Key) && mentionsARight(typed) {
				found = append(found, fileSet.Position(typed.Pos()).String()+": map[agentwire.Kind]")
			}
		}
		return true
	})
	return found
}

func takesAKind(function *ast.FuncDecl) bool {
	for _, field := range function.Type.Params.List {
		if isAgentwireKind(field.Type) {
			return true
		}
	}
	return false
}

func TestR_A1_1_NoOtherTableSaysTheRightOfAKind(t *testing.T) {
	checked := 0
	forEachGoFile(t, moduleRoot(), false, func(path string, fileSet *token.FileSet, file *ast.File) {
		checked++
		if isUnder(path, "internal/wire/agentwire/") {
			return
		}
		for _, at := range kindRightTables(fileSet, file) {
			t.Errorf("%s : le droit d'un genre se lit dans agentwire.Spec, aucune autre table ne le dit", at)
		}
	})
	if checked == 0 {
		t.Fatal("no source file seen: the guard no longer sees the code")
	}
	const faulty = `package faulty

func RightOf(kind agentwire.Kind) (string, bool) {
	spec, known := agentwire.SpecOf(kind)
	return spec.Right, known
}

func coversOrder(capabilities []agentpolicy.Capability, kind agentwire.Kind) bool {
	right, known := RightOf(kind)
	return known && agentpolicy.HasCapability(capabilities, right)
}

func rightOfKind(kind agentwire.Kind) string {
	switch kind {
	case agentwire.KindDockerDeploy:
		return agentpolicy.CapabilityDockerDeploy
	}
	return ""
}

var rights = map[agentwire.Kind]string{agentwire.KindDockerUpdate: agentpolicy.CapabilityDockerUpdate}

func RightOfMachine(target machine.Status, right string) bool {
	return agentpolicy.HasCapability(target.Agent.Capabilities, right)
}

func labelOf(kind agentwire.Kind) string { return string(kind) }
`
	fileSet := token.NewFileSet()
	file, err := parser.ParseFile(fileSet, "faulty.go", faulty, 0)
	if err != nil {
		t.Fatal(err)
	}
	if found := kindRightTables(fileSet, file); len(found) != 4 {
		t.Fatalf("the guard sees %v in a source with four tables and two innocent functions", found)
	}
}
