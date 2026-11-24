package server

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Les gardes « une logique, une définition » (17-conventions-code.md) :
// elles lisent le source et refusent la deuxième écriture d'un geste qui a
// déjà sa maison. Une exception se déclare ici, avec sa raison.

// forEachGoFile parcourt le source Go du module (le front et .git exclus) ;
// withTests dit s'il faut aussi les _test.go.
func forEachGoFile(t *testing.T, root string, withTests bool, visit func(path string, fileSet *token.FileSet, file *ast.File)) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == "web" || entry.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		if !withTests && strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fileSet := token.NewFileSet()
		file, err := parser.ParseFile(fileSet, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		visit(path, fileSet, file)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func moduleRoot() string { return filepath.Join("..", "..", "..") }

// Où vit chaque outil de test : seuls ses fichiers peuvent porter le geste.
const (
	waittestDir   = "internal/kit/wait/waittest/"
	goldentestDir = "internal/kit/goldentest/"
	testkitDir    = "internal/kit/testkit/"
)

// oneDefinitionExceptions : les endroits où le geste s'écrit encore à la
// main, avec la raison. Chemin du fichier (relatif au module) → raison.
var oneDefinitionExceptions = map[string]string{}

func isException(path string) bool {
	relative := filepath.ToSlash(strings.TrimPrefix(path, moduleRoot()+string(filepath.Separator)))
	_, excepted := oneDefinitionExceptions[relative]
	return excepted
}

// handWrittenDeadlines relève les `deadline := time.Now().Add(…)` : la
// boucle d'attente écrite à la main dans un test.
func handWrittenDeadlines(fileSet *token.FileSet, file *ast.File) []string {
	var found []string
	ast.Inspect(file, func(node ast.Node) bool {
		assign, ok := node.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			return true
		}
		name, ok := assign.Lhs[0].(*ast.Ident)
		if !ok || name.Name != "deadline" || !isNowPlus(assign.Rhs[0]) {
			return true
		}
		found = append(found, fileSet.Position(assign.Pos()).String())
		return true
	})
	return found
}

// isNowPlus dit si l'expression est `time.Now().Add(…)`.
func isNowPlus(expr ast.Expr) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	add, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || add.Sel.Name != "Add" {
		return false
	}
	now, ok := add.X.(*ast.CallExpr)
	if !ok {
		return false
	}
	nowFunc, ok := now.Fun.(*ast.SelectorExpr)
	if !ok || nowFunc.Sel.Name != "Now" {
		return false
	}
	pkg, ok := nowFunc.X.(*ast.Ident)
	return ok && pkg.Name == "time"
}

// relayedWaits relève les fonctions `wait…` qui ne font que passer
// l'attente à waittest.Until : l'appelant nomme lui-même ce qu'il attend.
func relayedWaits(fileSet *token.FileSet, file *ast.File) []string {
	var found []string
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Body == nil || !strings.HasPrefix(strings.ToLower(function.Name.Name), "wait") {
			continue
		}
		if onlyCallsUntil(function) {
			found = append(found, fileSet.Position(function.Pos()).String()+": "+function.Name.Name+" relaie waittest.Until, l'appeler directement")
		}
	}
	return found
}

// onlyCallsUntil dit si le corps se réduit à `waittest.Until(…)`, avec ou
// sans `t.Helper()`, et si la condition est celle que la fonction a reçue :
// un helper qui bâtit sa propre condition (un compteur, un fichier) nomme
// une attente, il ne relaie rien.
func onlyCallsUntil(function *ast.FuncDecl) bool {
	calls := 0
	for _, statement := range function.Body.List {
		expression, ok := statement.(*ast.ExprStmt)
		if !ok {
			return false
		}
		call, ok := expression.X.(*ast.CallExpr)
		if !ok {
			return false
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		switch {
		case selector.Sel.Name == "Helper":
		case selector.Sel.Name == "Until" && isIdent(selector.X, "waittest") && len(call.Args) > 0 && isParameter(function, call.Args[len(call.Args)-1]):
			calls++
		default:
			return false
		}
	}
	return calls == 1
}

func isParameter(function *ast.FuncDecl, expr ast.Expr) bool {
	ident, ok := expr.(*ast.Ident)
	if !ok {
		return false
	}
	for _, field := range function.Type.Params.List {
		for _, name := range field.Names {
			if name.Name == ident.Name {
				return true
			}
		}
	}
	return false
}

func isIdent(expr ast.Expr, name string) bool {
	ident, ok := expr.(*ast.Ident)
	return ok && ident.Name == name
}

// copiedTestHelpers : les petits gestes de test qui ont une maison. Nom →
// où il vit.
var copiedTestHelpers = map[string]string{
	"ptr":                "new(valeur) (Go 1.26)",
	"compareGolden":      "goldentest.Compare",
	"closedPort":         "testkit.ClosedPort",
	"closedLoopbackPort": "testkit.ClosedPort",
	"mustJSON":           "testkit.MustJSON",
	"sumOf":              "testkit.SHA256Hex",
	"sha256Hex":          "testkit.SHA256Hex",
	"sumHex":             "testkit.SHA256Hex",
	"newRoot":            "testkit.EmptyRoot",
	"openRoot":           "testkit.EmptyRoot",
	"openEmptyRoot":      "testkit.EmptyRoot",
	"emptyStateDir":      "testkit.EmptyRoot",
	"listenLoopback":     "testkit.AcceptingLoopback",
	"listenOnLoopback":   "testkit.AcceptingLoopback",
}

// copiedHelpers relève les fonctions libres (sans receveur) qui recopient
// un geste de testkit ou de goldentest.
func copiedHelpers(fileSet *token.FileSet, file *ast.File) []string {
	var found []string
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Recv != nil {
			continue
		}
		if home, copied := copiedTestHelpers[function.Name.Name]; copied {
			found = append(found, fileSet.Position(function.Pos()).String()+": "+function.Name.Name+" (utiliser "+home+")")
		}
	}
	return found
}

// redefinedUpdateFlags relève les `flag.Bool("update", …)` : le drapeau
// -update appartient à goldentest.
func redefinedUpdateFlags(fileSet *token.FileSet, file *ast.File) []string {
	var found []string
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "Bool" {
			return true
		}
		if pkg, ok := selector.X.(*ast.Ident); !ok || pkg.Name != "flag" {
			return true
		}
		if literal, ok := call.Args[0].(*ast.BasicLit); ok && literal.Value == `"update"` {
			found = append(found, fileSet.Position(call.Pos()).String())
		}
		return true
	})
	return found
}

// Une attente de test se dit `waittest.Until`, jamais une boucle à délai
// écrite à la main : les bornes courtes cassent sous une CI chargée.
func TestOneDefinition_TestWaitsGoThroughWaittest(t *testing.T) {
	checked := 0
	forEachGoFile(t, moduleRoot(), true, func(path string, fileSet *token.FileSet, file *ast.File) {
		if !strings.HasSuffix(path, "_test.go") || strings.Contains(filepath.ToSlash(path), waittestDir) || isException(path) {
			return
		}
		checked++
		for _, at := range handWrittenDeadlines(fileSet, file) {
			t.Errorf("%s: boucle d'attente écrite à la main, utiliser waittest.Until", at)
		}
		for _, at := range relayedWaits(fileSet, file) {
			t.Errorf("%s", at)
		}
	})
	if checked == 0 {
		t.Fatal("no test file seen: the guard no longer sees the code")
	}
}

// Un petit geste de test (pointeur, golden, port fermé, JSON, empreinte,
// racine vide) a une seule définition.
func TestOneDefinition_TestHelpersLiveInTheirKit(t *testing.T) {
	checked := 0
	forEachGoFile(t, moduleRoot(), true, func(path string, fileSet *token.FileSet, file *ast.File) {
		slashed := filepath.ToSlash(path)
		if !strings.HasSuffix(path, "_test.go") || strings.Contains(slashed, testkitDir) || strings.Contains(slashed, goldentestDir) || isException(path) {
			return
		}
		checked++
		for _, at := range copiedHelpers(fileSet, file) {
			t.Errorf("%s", at)
		}
		for _, at := range redefinedUpdateFlags(fileSet, file) {
			t.Errorf("%s: le drapeau -update est déclaré par goldentest", at)
		}
	})
	if checked == 0 {
		t.Fatal("no test file seen: the guard no longer sees the code")
	}
}

// machineFactKey reconnaît la clé d'un fait de machine (hors ligne, inconnue,
// sans agent) déclarée sous le nom d'un autre domaine : « backup.machine_offline ».
var machineFactKey = regexp.MustCompile(`^"([a-z_]+)\.(machine_offline|machine_unknown|machine_invalid|no_agent)"$`)

// machineFactKeyExceptions : les clés de même suffixe qui disent autre chose
// que le fait de machine, avec la raison.
var machineFactKeyExceptions = map[string]string{
	"manifest.machine_unknown": "une ligne du manifeste nomme une machine absente : la clé porte la ligne et la valeur, ce n'est pas le refus d'une machine visée",
}

// machineFactKeys relève les littéraux qui déclarent le refus d'un fait de
// machine hors de `machine`.
func machineFactKeys(fileSet *token.FileSet, file *ast.File) []string {
	var found []string
	ast.Inspect(file, func(node ast.Node) bool {
		literal, ok := node.(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			return true
		}
		match := machineFactKey.FindStringSubmatch(literal.Value)
		if match == nil || match[1] == "machine" {
			return true
		}
		if _, excepted := machineFactKeyExceptions[strings.Trim(literal.Value, `"`)]; excepted {
			return true
		}
		found = append(found, fileSet.Position(literal.Pos()).String()+": "+literal.Value)
		return true
	})
	return found
}

// Un fait de machine (hors ligne, inconnue, sans agent) se refuse avec la
// sentinelle de `machine`, jamais avec une copie sous la clé d'un domaine.
func TestOneDefinition_MachineFacts(t *testing.T) {
	checked := 0
	forEachGoFile(t, moduleRoot(), false, func(path string, fileSet *token.FileSet, file *ast.File) {
		if isException(path) {
			return
		}
		checked++
		for _, at := range machineFactKeys(fileSet, file) {
			t.Errorf("%s : utiliser machine.ErrOffline, machine.ErrUnknown ou machine.ErrNoAgent", at)
		}
	})
	if checked == 0 {
		t.Fatal("no source file seen: the guard no longer sees the code")
	}
}

// identDir : la seule maison du tirage d'un identifiant.
const identDir = "internal/kit/ident/"

// secretDrawExceptions : les fonctions qui tirent un aléa et l'écrivent en
// hexadécimaux sans passer par ident, avec la raison. Clé : « fichier
// fonction », fichier relatif au module.
var secretDrawExceptions = map[string]string{
	"internal/domain/restic/proxy.go Start": "le jeton du mandataire local ouvre le dépôt à qui le connaît : un secret, pas un identifiant (128 bits, dans l'URL donnée à restic)",
}

// handWrittenIdentifierDraws relève les fonctions qui appellent rand.Read puis
// hex.EncodeToString : l'identifiant tiré à la main, sans ident.New.
func handWrittenIdentifierDraws(fileSet *token.FileSet, file *ast.File) []string {
	var found []string
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Body == nil {
			continue
		}
		draws, encodes := false, false
		ast.Inspect(function.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			receiver, ok := selector.X.(*ast.Ident)
			if !ok {
				return true
			}
			draws = draws || (receiver.Name == "rand" && selector.Sel.Name == "Read")
			encodes = encodes || (receiver.Name == "hex" && selector.Sel.Name == "EncodeToString")
			return true
		})
		if draws && encodes {
			found = append(found, fileSet.Position(function.Pos()).String()+": "+function.Name.Name)
		}
	}
	return found
}

// Un identifiant se tire par ident.New (ou ident.NewSized), jamais par un
// rand.Read suivi de hex.EncodeToString. Un secret garde son tirage et sa
// raison dans secretDrawExceptions.
func TestOneDefinition_IdentifiersAreDrawnByIdent(t *testing.T) {
	checked := 0
	seenExceptions := map[string]bool{}
	forEachGoFile(t, moduleRoot(), true, func(path string, fileSet *token.FileSet, file *ast.File) {
		relative := filepath.ToSlash(strings.TrimPrefix(path, moduleRoot()+string(filepath.Separator)))
		if strings.HasPrefix(relative, identDir) {
			return
		}
		checked++
		for _, at := range handWrittenIdentifierDraws(fileSet, file) {
			name := at[strings.LastIndex(at, ": ")+2:]
			key := relative + " " + name
			if _, excepted := secretDrawExceptions[key]; excepted {
				seenExceptions[key] = true
				continue
			}
			t.Errorf("%s : un identifiant se tire par ident.New ou ident.NewSized ; un secret se déclare dans secretDrawExceptions", at)
		}
	})
	if checked == 0 {
		t.Fatal("no source file seen: the guard no longer sees the code")
	}
	for key := range secretDrawExceptions {
		if !seenExceptions[key] {
			t.Errorf("exception %q : plus aucun tirage à la main, la retirer", key)
		}
	}
}

// untrustedDir : la seule maison du jugement d'un texte venu d'ailleurs.
const untrustedDir = "internal/kit/untrusted/"

// controlCheckExceptions : les fonctions qui appellent encore
// unicode.IsControl, avec la raison : elles jugent autrement que
// untrusted.HasControl. Clé : « fichier fonction », fichier relatif au module.
var controlCheckExceptions = map[string]string{
	"internal/domain/alert/payload.go flatten":       "remplace par une espace, sans refuser, et traite aussi U+2028 et U+2029 : le nom reste lisible dans le message",
	"internal/kit/audit/actor.go cleanLabel":         "nettoie et coupe un libellé : retire aussi U+FFFD, il ne refuse pas",
	"internal/edge/server/api_manifest.go printable": "nettoie et coupe un nom indicatif : retire aussi U+FFFD, il ne refuse pas",
	"internal/kit/hostinfo/detect.go readText":       "rogne les espaces et les contrôles aux deux bouts d'un fichier du noyau : il coupe, il ne juge pas",
}

// controlChecks relève les fonctions qui nomment unicode.IsControl, appelé
// ou passé en valeur (strings.ContainsFunc(texte, unicode.IsControl)) :
// « position: fonction ».
func controlChecks(fileSet *token.FileSet, file *ast.File) []string {
	var found []string
	for _, declaration := range file.Decls {
		name := "(niveau du paquet)"
		if function, ok := declaration.(*ast.FuncDecl); ok {
			name = function.Name.Name
		}
		ast.Inspect(declaration, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if ok && selector.Sel.Name == "IsControl" && isIdent(selector.X, "unicode") {
				found = append(found, fileSet.Position(selector.Pos()).String()+": "+name)
			}
			return true
		})
	}
	return found
}

// Un texte venu d'ailleurs se juge par untrusted.HasControl, jamais par un
// unicode.IsControl écrit à la main : l'UTF-8 cassé et les caractères bidi
// ne passeraient pas. Une fonction qui juge autrement se déclare dans
// controlCheckExceptions, avec sa raison.
func TestOneDefinition_UntrustedText(t *testing.T) {
	checked := 0
	seenExceptions := map[string]bool{}
	forEachGoFile(t, moduleRoot(), true, func(path string, fileSet *token.FileSet, file *ast.File) {
		relative := relativeToModule(path)
		if strings.HasPrefix(relative, untrustedDir) {
			return
		}
		checked++
		for _, at := range controlChecks(fileSet, file) {
			name := at[strings.LastIndex(at, ": ")+2:]
			key := relative + " " + name
			if _, excepted := controlCheckExceptions[key]; excepted {
				seenExceptions[key] = true
				continue
			}
			t.Errorf("%s : utiliser untrusted.HasControl ; un autre sens se déclare dans controlCheckExceptions", at)
		}
	})
	if checked == 0 {
		t.Fatal("no source file seen: the guard no longer sees the code")
	}
	for key := range controlCheckExceptions {
		if !seenExceptions[key] {
			t.Errorf("exception %q : plus d'appel à unicode.IsControl, la retirer", key)
		}
	}
}

// tokenHashHandWritten relève les fonctions d'un seul paramètre chaîne qui
// rendent hex.EncodeToString(sha256.Sum256([]byte(paramètre))[:]) : une
// deuxième empreinte de jeton. Un site qui hache autre chose qu'un jeton
// (contenu, clé, plan) a plus d'un paramètre ou n'est pas cette forme.
func tokenHashHandWritten(fileSet *token.FileSet, file *ast.File) []string {
	var found []string
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Body == nil {
			continue
		}
		param, ok := singleStringParam(function)
		if !ok || !hashesParamAsHex(function, param) {
			continue
		}
		found = append(found, fileSet.Position(function.Pos()).String()+": "+function.Name.Name)
	}
	return found
}

// singleStringParam rend le nom du seul paramètre, s'il est de type string.
func singleStringParam(function *ast.FuncDecl) (string, bool) {
	params := function.Type.Params.List
	if len(params) != 1 || len(params[0].Names) != 1 || !isIdent(params[0].Type, "string") {
		return "", false
	}
	return params[0].Names[0].Name, true
}

// hashesParamAsHex dit si le corps appelle sha256.Sum256([]byte(param)) et
// rend tel quel hex.EncodeToString du résultat : une empreinte coupée ou
// suivie d'un autre texte n'est pas celle d'un jeton.
func hashesParamAsHex(function *ast.FuncDecl, param string) bool {
	hashes, returnsHex := false, false
	ast.Inspect(function.Body, func(node ast.Node) bool {
		if returned, ok := node.(*ast.ReturnStmt); ok && len(returned.Results) == 1 {
			_, isHex := isSelectorCall(returned.Results[0], "hex", "EncodeToString")
			returnsHex = returnsHex || isHex
		}
		if call, ok := isSelectorCall(node, "sha256", "Sum256"); ok && len(call.Args) == 1 {
			convert, ok := call.Args[0].(*ast.CallExpr)
			hashes = hashes || (ok && len(convert.Args) == 1 && isIdent(convert.Args[0], param))
		}
		return true
	})
	return hashes && returnsHex
}

// Une empreinte de jeton s'écrit par ident.HashToken, nulle part ailleurs :
// la changer rendrait faux tous les jetons en base. Les tests ont
// testkit.SHA256Hex, qui prend un contenu, pas un jeton.
func TestOneDefinition_TokenHash(t *testing.T) {
	checked := 0
	forEachGoFile(t, moduleRoot(), true, func(path string, fileSet *token.FileSet, file *ast.File) {
		if isUnder(path, identDir, testkitDir) {
			return
		}
		checked++
		if isException(path) {
			return
		}
		for _, at := range tokenHashHandWritten(fileSet, file) {
			t.Errorf("%s : l'empreinte d'un jeton est ident.HashToken ; une autre forme se déclare dans oneDefinitionExceptions", at)
		}
	})
	if checked == 0 {
		t.Fatal("no source file seen: the guard no longer sees the code")
	}
}

// Les gardes ne valent que si elles échouent sur la faute : on leur donne
// un source fautif.
func TestOneDefinition_GuardsCatchTheirFault(t *testing.T) {
	const faulty = `package faulty

import (
	"flag"
	"time"
	"unicode"
)

var update = flag.Bool("update", false, "")

func ptr(days int) *int { return &days }

func wait() {
	deadline := time.Now().Add(2 * time.Second)
	_ = deadline
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	waittest.Until(t, "condition", condition)
}

var ErrOffline = refusal.Conflict("backup.machine_offline", "offline")

func hasControl(text string) bool {
	return strings.ContainsFunc(text, unicode.IsControl)
}

func newID() string {
	raw := make([]byte, 8)
	_, _ = rand.Read(raw)
	return hex.EncodeToString(raw)
}

func hashToken(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
`
	fileSet := token.NewFileSet()
	file, err := parser.ParseFile(fileSet, "faulty_test.go", faulty, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	if got := handWrittenDeadlines(fileSet, file); len(got) != 1 {
		t.Errorf("hand-written deadline not caught: %v", got)
	}
	if got := relayedWaits(fileSet, file); len(got) != 1 {
		t.Errorf("relayed wait not caught: %v", got)
	}
	if got := copiedHelpers(fileSet, file); len(got) != 1 {
		t.Errorf("copied helper not caught: %v", got)
	}
	if got := redefinedUpdateFlags(fileSet, file); len(got) != 1 {
		t.Errorf("redefined -update flag not caught: %v", got)
	}
	if got := machineFactKeys(fileSet, file); len(got) != 1 {
		t.Errorf("machine fact key outside machine not caught: %v", got)
	}
	if got := handWrittenIdentifierDraws(fileSet, file); len(got) != 1 {
		t.Errorf("hand-drawn identifier not caught: %v", got)
	}
	if got := controlChecks(fileSet, file); len(got) != 1 {
		t.Errorf("hand-written control check not caught: %v", got)
	}
	if got := tokenHashHandWritten(fileSet, file); len(got) != 1 {
		t.Errorf("copied token hash not caught: %v", got)
	}
}

var orderCount = regexp.MustCompile(`(?i)\b(un|deux|trois|quatre|cinq|six|sept|huit|neuf|dix|onze|douze|treize|\d+) ordres existent\b`)

// La liste des ordres vit dans agentwire.OrderKinds : la documentation y
// renvoie, elle ne la compte pas (le compte périme à chaque ordre ajouté).
func TestOneDefinition_DocDoesNotCountTheOrders(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join(moduleRoot(), "docs", "projet", "22-fonctionnement.md"))
	if err != nil {
		t.Fatal(err)
	}
	if found := orderCount.FindString(string(doc)); found != "" {
		t.Errorf("22-fonctionnement.md compte les ordres (%q) : renvoyer à agentwire.OrderKinds", found)
	}
	if !orderCount.MatchString("Huit ordres existent") {
		t.Error("the order-count pattern no longer matches what it must refuse")
	}
}

// Les gardes de copies (T00-04) : quatre gestes qui ont chacun une maison,
// et que le code d'aujourd'hui écrit encore plusieurs fois. Chaque inventaire
// dit, par fichier (par littéral pour les regexp), combien d'écritures
// restent : il ne fait que descendre. Un fichier qui monte ou qui apparaît est
// refusé ; un fichier qui baisse oblige à baisser son entrée, jusqu'à la
// retirer. Un échange (une faute ajoutée, une autre retirée ailleurs) ne passe pas.
var (
	repeatedRegexpInventory = map[string]int{
		"`^(?:([0-9]{1,5}):)?([0-9]{1,5})(?:/(?:tcp|udp))?$`": 1,
		"`^/[A-Za-z0-9._/-]{1,254}$`":                         2,
		"`^[0-9a-f]{64}$`":                                    4,
		"`^[A-Za-z0-9:_.@-]{1,250}\\.service$`":               1,
		"`^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$`":                 2,
		"`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`":               1,
		"`^[\\x21-\\x7e]+$`":                                  1,
		"`^[a-z0-9][a-z0-9-]{0,62}$`":                         1,
		"`^[a-z0-9][a-z0-9_-]{0,62}$`":                        1,
		"`^sha256:[0-9a-f]{64}$`":                             2,
	}
	handBuiltTransportInventory = map[string]int{
		"internal/domain/alert/notifier.go":         1,
		"internal/domain/proxmox/client.go":         1,
		"internal/edge/agent/proxmox_api.go":        1,
		"internal/edge/agent/restic_target.go":      1,
		"internal/fact/firewall/opnsense/client.go": 1,
		"internal/fact/lifecycle/source.go":         1,
		"internal/fact/probe/check.go":              1,
		"internal/kit/mcpcheck/mcpcheck.go":         1,
		"internal/kit/registry/client.go":           1,
	}
	handBoundedReadInventory = map[string]int{
		"cmd/kagu/backup.go":                        1,
		"internal/domain/proxmox/client.go":         1,
		"internal/edge/agent/proxmox_api.go":        1,
		"internal/edge/agent/proxmox_token.go":      1,
		"internal/fact/firewall/opnsense/client.go": 1,
		"internal/fact/lifecycle/source.go":         1,
		"internal/fact/sshkeys/read.go":             1,
		"internal/kit/proxysecret/proxysecret.go":   1,
		"internal/kit/release/library.go":           1,
		"internal/kit/release/release.go":           1,
	}
	handDrawnIdentifierInventory = map[string]int{
		"internal/domain/restic/proxy.go": 1,
	}
)

// Les maisons des gestes : seuls ces chemins (relatifs au module) les écrivent.
var (
	transportHomes  = []string{"internal/kit/egress/", "internal/kit/dockerapi/", "cmd/kagu/control.go"}
	boundedReadHome = "internal/kit/fsx/"
	identifierHome  = "internal/kit/ident/"
)

func relativeToModule(path string) string {
	return filepath.ToSlash(strings.TrimPrefix(path, moduleRoot()+string(filepath.Separator)))
}

func isUnder(path string, homes ...string) bool {
	relative := relativeToModule(path)
	for _, home := range homes {
		if strings.HasPrefix(relative, home) {
			return true
		}
	}
	return false
}

func isSelectorCall(node ast.Node, pkg, name string) (*ast.CallExpr, bool) {
	call, ok := node.(*ast.CallExpr)
	if !ok {
		return nil, false
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != name {
		return nil, false
	}
	return call, isIdent(selector.X, pkg)
}

// regexpLiterals relève chaque `regexp.MustCompile("…")` : le littéral et sa place.
func regexpLiterals(fileSet *token.FileSet, file *ast.File) map[string][]string {
	found := map[string][]string{}
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := isSelectorCall(node, "regexp", "MustCompile")
		if !ok || len(call.Args) != 1 {
			return true
		}
		literal, ok := call.Args[0].(*ast.BasicLit)
		if ok && literal.Kind == token.STRING {
			found[literal.Value] = append(found[literal.Value], fileSet.Position(literal.Pos()).String())
		}
		return true
	})
	return found
}

// handBuiltTransports relève les `&http.Transport{` : un client HTTP gardé
// se construit par egress.
func handBuiltTransports(fileSet *token.FileSet, file *ast.File) []string {
	var found []string
	ast.Inspect(file, func(node ast.Node) bool {
		literal, ok := node.(*ast.CompositeLit)
		if !ok {
			return true
		}
		selector, ok := literal.Type.(*ast.SelectorExpr)
		if ok && selector.Sel.Name == "Transport" && isIdent(selector.X, "http") {
			found = append(found, fileSet.Position(literal.Pos()).String())
		}
		return true
	})
	return found
}

// handBoundedReads relève les `io.LimitReader(x, limite+1)` : une lecture
// plafonnée passe par fsx.
func handBoundedReads(fileSet *token.FileSet, file *ast.File) []string {
	var found []string
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := isSelectorCall(node, "io", "LimitReader")
		if !ok || len(call.Args) != 2 {
			return true
		}
		sum, ok := call.Args[1].(*ast.BinaryExpr)
		if !ok || sum.Op != token.ADD {
			return true
		}
		if one, ok := sum.Y.(*ast.BasicLit); ok && one.Kind == token.INT && one.Value == "1" {
			found = append(found, fileSet.Position(call.Pos()).String())
		}
		return true
	})
	return found
}

// handDrawnIdentifiers relève les fonctions qui tirent des octets au sort
// (`rand.Read`) puis les écrivent en hexadécimal : un identifiant se tire
// par ident.
func handDrawnIdentifiers(fileSet *token.FileSet, file *ast.File) []string {
	var found []string
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Body == nil {
			continue
		}
		draws, encodes := false, false
		ast.Inspect(function.Body, func(node ast.Node) bool {
			if _, ok := isSelectorCall(node, "rand", "Read"); ok {
				draws = true
			}
			if _, ok := isSelectorCall(node, "hex", "EncodeToString"); ok {
				encodes = true
			}
			return true
		})
		if draws && encodes {
			found = append(found, fileSet.Position(function.Pos()).String()+": "+function.Name.Name)
		}
	}
	return found
}

// perFile compte les relevés par fichier (chemin relatif au module) : un
// relevé commence par sa position, « chemin:ligne:colonne ».
func perFile(found []string) map[string]int {
	counts := map[string]int{}
	for _, position := range found {
		counts[relativeToModule(strings.SplitN(position, ":", 2)[0])]++
	}
	return counts
}

// inventoryProblems compare les comptes du jour à l'inventaire : même logique
// que ceilingProblems du front (composition.test.ts).
func inventoryProblems(counts, inventory map[string]int) []string {
	var problems []string
	for key := range counts {
		if _, listed := inventory[key]; !listed {
			problems = append(problems, fmt.Sprintf("%s : %d, absent de l'inventaire", key, counts[key]))
		}
	}
	for key, listed := range inventory {
		switch found := counts[key]; {
		case found > listed:
			problems = append(problems, fmt.Sprintf("%s : %d, l'inventaire dit %d", key, found, listed))
		case found < listed:
			problems = append(problems, fmt.Sprintf("%s : %d, l'inventaire dit encore %d : le baisser (ou retirer l'entrée)", key, found, listed))
		}
	}
	sort.Strings(problems)
	return problems
}

func checkInventory(t *testing.T, gesture, home string, counts, inventory map[string]int) {
	t.Helper()
	if problems := inventoryProblems(counts, inventory); len(problems) > 0 {
		t.Errorf("%s (utiliser %s) :\n%s", gesture, home, strings.Join(problems, "\n"))
	}
}

func TestOneDefinition_NoGestureWrittenAgain(t *testing.T) {
	literals := map[string][]string{}
	var transports, reads, identifiers []string
	checked := 0
	forEachGoFile(t, moduleRoot(), false, func(path string, fileSet *token.FileSet, file *ast.File) {
		checked++
		for literal, places := range regexpLiterals(fileSet, file) {
			literals[literal] = append(literals[literal], places...)
		}
		if !isUnder(path, transportHomes...) {
			transports = append(transports, handBuiltTransports(fileSet, file)...)
		}
		if !isUnder(path, boundedReadHome) {
			reads = append(reads, handBoundedReads(fileSet, file)...)
		}
		if !isUnder(path, identifierHome) {
			identifiers = append(identifiers, handDrawnIdentifiers(fileSet, file)...)
		}
	})
	if checked == 0 {
		t.Fatal("no source file seen: the guard no longer sees the code")
	}
	repeated := map[string]int{}
	for literal, places := range literals {
		if len(places) > 1 {
			repeated[literal] = len(places) - 1
		}
	}
	checkInventory(t, "un même littéral de regexp.MustCompile", "une définition partagée", repeated, repeatedRegexpInventory)
	checkInventory(t, "&http.Transport{", "egress", perFile(transports), handBuiltTransportInventory)
	checkInventory(t, "io.LimitReader(…+1)", "fsx", perFile(reads), handBoundedReadInventory)
	checkInventory(t, "rand.Read puis hex", "ident", perFile(identifiers), handDrawnIdentifierInventory)
}

func TestOneDefinition_CopyGuardsCatchTheirFault(t *testing.T) {
	const faulty = `package faulty

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"regexp"
	"sort"
)

var first = regexp.MustCompile("^a$")
var second = regexp.MustCompile("^a$")

var transport = &http.Transport{}

func read(r io.Reader, limit int64) { io.ReadAll(io.LimitReader(r, limit+1)) }

func draw() string {
	raw := make([]byte, 8)
	rand.Read(raw)
	return hex.EncodeToString(raw)
}
`
	fileSet := token.NewFileSet()
	file, err := parser.ParseFile(fileSet, "faulty.go", faulty, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	if got := regexpLiterals(fileSet, file); len(got[`"^a$"`]) != 2 {
		t.Errorf("repeated regexp literal not caught: %v", got)
	}
	if got := handBuiltTransports(fileSet, file); len(got) != 1 {
		t.Errorf("hand-built transport not caught: %v", got)
	}
	if got := handBoundedReads(fileSet, file); len(got) != 1 {
		t.Errorf("hand-bounded read not caught: %v", got)
	}
	if got := handDrawnIdentifiers(fileSet, file); len(got) != 1 {
		t.Errorf("hand-drawn identifier not caught: %v", got)
	}
	// Un échange (une faute ailleurs, une autre retirée) n'est pas un total constant.
	if got := inventoryProblems(map[string]int{"new.go": 1}, map[string]int{"old.go": 1}); len(got) != 2 {
		t.Errorf("swapped fault not caught: %v", got)
	}
	if got := inventoryProblems(map[string]int{"a.go": 2}, map[string]int{"a.go": 1}); len(got) != 1 {
		t.Errorf("raised count not caught: %v", got)
	}
	if got := inventoryProblems(map[string]int{"a.go": 1}, map[string]int{"a.go": 2}); len(got) != 1 {
		t.Errorf("lowered count not caught: %v", got)
	}
}
