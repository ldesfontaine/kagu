package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ldesfontaine/kagu/internal/wire/agentwire"
	"github.com/ldesfontaine/kagu/internal/wire/judge"
)

const (
	orderMachineID = "11111111-2222-4333-8444-555555555555"
	orderAgentID   = "agt_0000000000000001"
)

var orderNow = time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)

// orderBench est un juge d'ordres sur une identité écrite dans un dossier
// d'état, et la clé du serveur qu'elle a épinglée.
type orderBench struct {
	runner   *orderRunner
	results  *actionResults
	stateDir *os.Root
	private  ed25519.PrivateKey
}

// useHostChecks remplace ce que la machine du test dit des droits du compte :
// les bancs ne dépendent pas du compte qui lance les tests.
func useHostChecks(runner *orderRunner, checks hostChecks) {
	runner.checks = checks
	runner.docker.checks = checks
}

// allowTheAccount : le compte du test peut tout écrire et parler à Docker, mais
// agent.update garde son vrai juge (le binaire de test ne tourne pas depuis
// bin/), sur le lanceur de mises à jour que le test a mis en place.
func allowTheAccount(runner *orderRunner) {
	checks := allowAll()
	checks.agentUpdate = func() string { return runner.updater.unavailableReason(func(string) string { return "" }) }
	useHostChecks(runner, checks)
}

func newOrderBench(t *testing.T) *orderBench {
	t.Helper()
	return newOrderBenchWithRights(t, nil)
}

// newOrderBenchWithRights écrit une identité qui porte ces droits.
func newOrderBenchWithRights(t *testing.T, rights []string) *orderBench {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// 0700 explicite : t.TempDir suit le umask, et l'état de l'agent n'est sûr
	// que fermé aux autres comptes (CheckStateDir).
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	stateDir, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stateDir.Close() })
	identity := Identity{MachineID: orderMachineID, AgentID: orderAgentID, ServerKey: public, Rights: rights}
	if err := SaveIdentity(stateDir, identity); err != nil {
		t.Fatal(err)
	}
	results := newActionResults()
	runner := newOrderRunner(stateDir, identity, "v0.0.1", "", results, slog.New(slog.DiscardHandler))
	allowTheAccount(runner)
	runner.now = func() time.Time { return orderNow }
	return &orderBench{runner: runner, results: results, stateDir: stateDir, private: private}
}

// order rend un ordre ping valide de rang seq, à retoucher par le test.
func order(seq int64) agentwire.OrderBody {
	return agentwire.OrderBody{
		V: agentwire.OrderVersion, RunID: fmt.Sprintf("run-%d", seq), MachineID: orderMachineID, AgentID: orderAgentID, Kind: agentwire.KindAgentPing,
		NotAfter: orderNow.Add(time.Minute).Unix(), Seq: seq,
	}
}

// decodeOrder décode un ordre par le juge, avec le run et le rang du corps.
func decodeOrder(body agentwire.OrderBody) (judgedOrder, error) {
	order, err := judge.Decode(body)
	if err != nil {
		return judgedOrder{}, err
	}
	return judgedOrder{RunID: body.RunID, Seq: body.Seq, Order: order}, nil
}

// judgedOf décode un ordre comme le juge : ce que reçoit l'exécuteur de son
// genre.
func judgedOf(t *testing.T, body agentwire.OrderBody) judgedOrder {
	t.Helper()
	judged, err := decodeOrder(body)
	if err != nil {
		t.Fatal(err)
	}
	return judged
}

func (b *orderBench) send(t *testing.T, body agentwire.OrderBody, signer ed25519.PrivateKey) agentwire.ActionResult {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	signed := agentwire.SignedOrder{Body: encoded, Signature: ed25519.Sign(signer, agentwire.OrderSigningBytes(agentwire.OrderVersion, encoded))}
	data, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	b.runner.receive(data)
	report := b.results.take()
	if report == nil || len(report.Results) != 1 {
		t.Fatalf("one result expected, got %+v", report)
	}
	return report.Results[0]
}

// Un ordre signé par la clé épinglée, pour cette machine et cet agent, à
// temps et au rang suivant, s'exécute ; son rang est écrit avant.
func TestOrderRunner_ExecutesAValidPingAndKeepsItsSeq(t *testing.T) {
	b := newOrderBench(t)
	result := b.send(t, order(1), b.private)
	if result.State != agentwire.ActionSucceeded || result.RunID != "run-1" || len(result.Output) != 1 || result.Output[0].Line != "pong v0.0.1" {
		t.Fatalf("result %+v", result)
	}
	select {
	case <-b.results.ready:
	default:
		t.Fatal("the stream loop was not woken")
	}
	saved, err := LoadIdentity(b.stateDir)
	if err != nil || saved.LastOrderSeq != 1 {
		t.Fatalf("saved seq %d %v", saved.LastOrderSeq, err)
	}
}

// Chaque garde refuse, avec sa raison, et le refus se rapporte au run.
func TestOrderRunner_RefusesAndReportsEachBadOrder(t *testing.T) {
	_, stranger, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		change func(*agentwire.OrderBody)
		signer func(b *orderBench) ed25519.PrivateKey
		reason string
	}{
		{"signed by another key", nil, func(*orderBench) ed25519.PrivateKey { return stranger }, agentwire.ReasonBadSignature},
		{"another machine", func(o *agentwire.OrderBody) { o.MachineID = "99999999-2222-4333-8444-555555555555" }, nil, agentwire.ReasonWrongMachine},
		{"another agent", func(o *agentwire.OrderBody) { o.AgentID = "agt_0000000000000002" }, nil, agentwire.ReasonWrongAgent},
		{"past its deadline", func(o *agentwire.OrderBody) { o.NotAfter = orderNow.Unix() }, nil, agentwire.ReasonExpired},
		{"replayed", func(o *agentwire.OrderBody) { o.Seq = 0 }, nil, agentwire.ReasonReplayed},
		{"unknown kind", func(o *agentwire.OrderBody) { o.Kind = "shell.exec" }, nil, agentwire.ReasonUnknownKind},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := newOrderBench(t)
			body := order(1)
			if c.change != nil {
				c.change(&body)
			}
			signer := b.private
			if c.signer != nil {
				signer = c.signer(b)
			}
			result := b.send(t, body, signer)
			if result.State != agentwire.ActionRefused || result.Reason != c.reason || result.RunID != body.RunID {
				t.Fatalf("result %+v, want refused %s", result, c.reason)
			}
			if saved, _ := LoadIdentity(b.stateDir); saved.LastOrderSeq != 0 {
				t.Fatalf("a refused order moved the seq to %d", saved.LastOrderSeq)
			}
		})
	}
}

// Le même ordre rejoué, même signé, est refusé : le rang ne recule pas, et
// survit au redémarrage de l'agent.
func TestOrderRunner_RefusesAReplayEvenAfterARestart(t *testing.T) {
	b := newOrderBench(t)
	if result := b.send(t, order(3), b.private); result.State != agentwire.ActionSucceeded {
		t.Fatalf("first %+v", result)
	}
	if result := b.send(t, order(3), b.private); result.Reason != agentwire.ReasonReplayed {
		t.Fatalf("replay %+v", result)
	}
	reloaded, err := LoadIdentity(b.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	b.runner = newOrderRunner(b.stateDir, reloaded, "v0.0.1", "", b.results, slog.New(slog.DiscardHandler))
	allowTheAccount(b.runner)
	b.runner.now = func() time.Time { return orderNow }
	if result := b.send(t, order(2), b.private); result.Reason != agentwire.ReasonReplayed {
		t.Fatalf("after restart %+v", result)
	}
}

// Sans clé épinglée, aucun ordre ne passe ; un corps illisible ne donne pas
// de run à qui répondre.
func TestOrderRunner_WithoutAPinnedKeyRefusesEverything(t *testing.T) {
	b := newOrderBench(t)
	b.runner.identity.ServerKey = nil
	if result := b.send(t, order(1), b.private); result.Reason != agentwire.ReasonServerKeyMissing {
		t.Fatalf("result %+v", result)
	}
	b.runner.receive([]byte("pas du json"))
	if report := b.results.take(); report != nil {
		t.Fatalf("an unreadable envelope was reported: %+v", report)
	}
}

// L'agent applique les droits de son fichier : un ordre dont le droit
// manque est refusé avec ce droit, sans prendre son rang ; avec le droit,
// agent.update est jugé par l'agent : celui du test ne tourne pas depuis son
// dossier bin/.
func TestOrderRunner_AppliesTheRightsOfItsFile(t *testing.T) {
	b := newOrderBench(t)
	update := order(1)
	update.Kind = agentwire.KindAgentUpdate
	update.Params, _ = json.Marshal(agentwire.AgentUpdateParams{Version: "v0.0.2", Parcel: "colis1"})
	result := b.send(t, update, b.private)
	if result.State != agentwire.ActionRefused || result.Reason != "right_missing:agent.update" {
		t.Fatalf("without the right: %+v", result)
	}
	if saved, _ := LoadIdentity(b.stateDir); saved.LastOrderSeq != 0 {
		t.Fatalf("a refused order took its seq: %d", saved.LastOrderSeq)
	}
	if result := b.send(t, order(1), b.private); result.State != agentwire.ActionSucceeded {
		t.Fatalf("ping needs observe only: %+v", result)
	}

	granted := newOrderBenchWithRights(t, []string{"observe", "agent.update"})
	result = granted.send(t, update, granted.private)
	if result.State != agentwire.ActionRefused || result.Reason != agentwire.ReasonNotSelfUpdatable {
		t.Fatalf("with the right: %+v", result)
	}
	// Un fichier illisible vaut observe seul, le plus étroit.
	unreadable := newOrderBenchWithRights(t, []string{"agent.update=/nope"})
	if result := unreadable.send(t, update, unreadable.private); result.Reason != "right_missing:agent.update" {
		t.Fatalf("unreadable rights: %+v", result)
	}
}

// agent.server_key, signé par la clé épinglée, la remplace par la neuve : sur
// disque comme en mémoire. Les ordres suivants ne se vérifient qu'avec la
// neuve ; une clé mal formée ne remplace rien.
func TestOrderRunner_PinsTheNewServerKey(t *testing.T) {
	b := newOrderBench(t)
	newPublic, newPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rekey := func(seq int64, key []byte) agentwire.OrderBody {
		body := order(seq)
		body.Kind = agentwire.KindServerKey
		body.Params, _ = json.Marshal(agentwire.ServerKeyParams{PublicKey: base64.StdEncoding.EncodeToString(key)})
		return body
	}
	if result := b.send(t, rekey(1, []byte("short")), b.private); result.State != agentwire.ActionFailed || result.Reason != agentwire.ReasonBadOrder {
		t.Fatalf("a malformed key: %+v", result)
	}
	if result := b.send(t, rekey(2, newPublic), b.private); result.State != agentwire.ActionSucceeded {
		t.Fatalf("rekey %+v", result)
	}
	saved, err := LoadIdentity(b.stateDir)
	if err != nil || !newPublic.Equal(ed25519.PublicKey(saved.ServerKey)) || !newPublic.Equal(ed25519.PublicKey(b.runner.serverKey())) {
		t.Fatalf("the new key was not pinned: %v", err)
	}
	if result := b.send(t, order(3), b.private); result.Reason != agentwire.ReasonBadSignature {
		t.Fatalf("the previous key still signs: %+v", result)
	}
	if result := b.send(t, order(4), newPrivate); result.State != agentwire.ActionSucceeded {
		t.Fatalf("the new key does not sign: %+v", result)
	}
}

// Les ordres forgés qui viseraient à effacer un dépôt restic. Une signature
// d'une autre clé est refusée pour tous les genres de restic, y compris la
// rétention ; une clé valide ne rend pas un genre inventé exécutable : il
// n'y a ni restic.forget, ni restic.prune, ni restic.delete, et le refus ne
// lance rien.
func TestOrderRunner_ForgedResticOrdersAreRefused(t *testing.T) {
	_, stranger, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []agentwire.Kind{agentwire.KindResticRetain, agentwire.KindResticBackup, agentwire.KindResticRestore, agentwire.KindResticUserRemove} {
		t.Run("signed by another key "+string(kind), func(t *testing.T) {
			b := newOrderBench(t)
			body := order(1)
			body.Kind = kind
			result := b.send(t, body, stranger)
			if result.State != agentwire.ActionRefused || result.Reason != agentwire.ReasonBadSignature {
				t.Fatalf("result %+v", result)
			}
		})
	}
	for _, kind := range []agentwire.Kind{"restic.forget", "restic.prune", "restic.delete", "restic.unlock", "restic.rest.delete", "restic.retain ", "RESTIC.RETAIN", "restic.retain/../x"} {
		t.Run("signed but invented "+string(kind), func(t *testing.T) {
			b := newOrderBench(t)
			body := order(1)
			body.Kind = kind
			result := b.send(t, body, b.private)
			if result.State != agentwire.ActionRefused || result.Reason != agentwire.ReasonUnknownKind {
				t.Fatalf("result %+v", result)
			}
		})
	}
}

// sendBody signe des octets tels quels, comme un serveur qui les aurait écrits
// à la main.
func (b *orderBench) sendBody(t *testing.T, encoded []byte) agentwire.ActionResult {
	t.Helper()
	data, err := json.Marshal(agentwire.SignedOrder{Body: encoded, Signature: ed25519.Sign(b.private, agentwire.OrderSigningBytes(agentwire.OrderVersion, encoded))})
	if err != nil {
		t.Fatal(err)
	}
	b.runner.receive(data)
	report := b.results.take()
	if report == nil || len(report.Results) != 1 {
		t.Fatalf("one result expected, got %+v", report)
	}
	return report.Results[0]
}

// L'enveloppe signée et le champ secret se lisent comme les paramètres : une
// clé répétée, d'une autre casse, inconnue, ou une autre écriture des mêmes
// valeurs est refusée bad_order, même sous la bonne signature, sans prendre
// de rang.
func TestR_A1_4_TheEnvelopeAndTheSecretAreReadStrictly(t *testing.T) {
	canonical, err := json.Marshal(order(1))
	if err != nil {
		t.Fatal(err)
	}
	body := strings.TrimSuffix(string(canonical), "}")
	envelopes := map[string]string{
		"kind repeated":        body + `,"kind":"agent.update"}`,
		"kind of another case": body + `,"Kind":"agent.update"}`,
		"seq repeated":         body + `,"seq":99}`,
		"an unknown field":     body + `,"level":4}`,
		"a space":              "{ " + string(canonical[1:]),
	}
	for name, envelope := range envelopes {
		b := newOrderBench(t)
		if result := b.sendBody(t, []byte(envelope)); result.State != agentwire.ActionRefused || result.Reason != agentwire.ReasonBadOrder {
			t.Errorf("%s: %+v", name, result)
		}
		if saved, _ := LoadIdentity(b.stateDir); saved.LastOrderSeq != 0 {
			t.Errorf("%s: a refused order moved the seq to %d", name, saved.LastOrderSeq)
		}
	}

	b := newOrderBenchWithRights(t, []string{"observe", "docker.deploy"})
	deploy := agentwire.DockerParams{ServiceID: "svc_1", Project: "wiki", Compose: "x", EnvSent: true}
	secrets := map[string]json.RawMessage{
		"env of another case":            json.RawMessage(`{"Env":"A=1"}`),
		"env repeated":                   json.RawMessage(`{"env":"A=1","env":"B=2"}`),
		"an unknown field in the secret": json.RawMessage(`{"env":"A=1","rest_password":"x"}`),
		"a space in the secret":          json.RawMessage(`{"env": "A=1"}`),
	}
	// Le secret est posé à sa place dans le corps signé, puis réécrit tel quel :
	// json.Marshal compacterait les espaces.
	const placeholder = `{"env":"PLACEHOLDER"}`
	signedWith := func(seq int64, secret string) []byte {
		withSecret := longOrder(seq, agentwire.KindDockerDeploy, deploy)
		withSecret.Secret = json.RawMessage(placeholder)
		encoded, _ := json.Marshal(withSecret)
		return []byte(strings.Replace(string(encoded), placeholder, secret, 1))
	}
	// Le témoin : le même corps, avec le secret tel que le serveur l'écrit, passe le juge.
	var good agentwire.OrderBody
	if err := json.Unmarshal(signedWith(1, `{"env":"A=1"}`), &good); err != nil {
		t.Fatal(err)
	}
	if _, reason := b.runner.judge(b.signedOrder(t, good)); reason != "" {
		t.Fatalf("the server's secret is refused: %s", reason)
	}
	seq := int64(1)
	for name, secret := range secrets {
		seq++
		if result := b.sendBody(t, signedWith(seq, string(secret))); result.State != agentwire.ActionRefused || result.Reason != agentwire.ReasonBadOrder {
			t.Errorf("%s: %+v", name, result)
		}
	}
	seq++
	ping := order(seq)
	ping.Secret = json.RawMessage(`{"env":"A=1"}`)
	if result := b.send(t, ping, b.private); result.State != agentwire.ActionRefused || result.Reason != agentwire.ReasonBadOrder {
		t.Errorf("a secret on a kind that carries none: %+v", result)
	}
	if saved, _ := LoadIdentity(b.stateDir); saved.LastOrderSeq != 1 {
		t.Fatalf("a refused order moved the seq to %d", saved.LastOrderSeq)
	}
}

// Un genre hors du registre est refusé unknown_kind, même signé par la clé
// épinglée : une observation non plus n'est pas un ordre.
func TestR_A1_6_AKindOutsideTheRegistryIsUnknownEvenSigned(t *testing.T) {
	b := newOrderBenchWithRights(t, []string{"observe", "restic.target=/srv/restic"})
	kinds := []agentwire.Kind{"docker.purge", "shell.exec", "Agent.Ping", agentwire.KindLogs, agentwire.KindProbes, agentwire.KindResticRelay}
	for index, kind := range kinds {
		body := order(int64(index + 1))
		body.Kind = kind
		if result := b.send(t, body, b.private); result.State != agentwire.ActionRefused || result.Reason != agentwire.ReasonUnknownKind {
			t.Errorf("%s: %+v", kind, result)
		}
	}
	if saved, _ := LoadIdentity(b.stateDir); saved.LastOrderSeq != 0 {
		t.Fatalf("a refused order moved the seq to %d", saved.LastOrderSeq)
	}
}

// Chaque genre du registre a son exécuteur, et la table n'en a pas d'autre :
// un genre ajouté sans exécuteur, ou un exécuteur sans genre, se voit ici.
func TestExecutors_EveryDeclaredKindHasItsExecutor(t *testing.T) {
	declared := map[agentwire.Kind]bool{}
	for _, kind := range agentwire.OrderKinds() {
		declared[kind] = true
		if executors[kind] == nil {
			t.Errorf("%s is declared but has no executor", kind)
		}
	}
	for kind := range executors {
		if !declared[kind] {
			t.Errorf("%s has an executor but is not a declared kind", kind)
		}
	}
}

// countExecutors remplace chaque exécuteur par un compteur, le temps du test.
func countExecutors(t *testing.T) map[agentwire.Kind]int {
	t.Helper()
	called := map[agentwire.Kind]int{}
	saved := executors
	executors = map[agentwire.Kind]executor{}
	for kind := range saved {
		executors[kind] = func(r *orderRunner, order judgedOrder) (agentwire.ActionResult, func(ctx context.Context)) {
			called[order.Kind]++
			return agentwire.ActionResult{RunID: order.RunID, State: agentwire.ActionSucceeded}, nil
		}
	}
	t.Cleanup(func() { executors = saved })
	return called
}

// Pour chaque genre, un ordre dont les paramètres ou le secret ne se décodent
// pas est refusé bad_order par le juge : l'exécuteur n'est jamais appelé. Un
// ordre qui se décode, lui, l'atteint (le compteur compte bien).
func TestExecutors_NeverSeeAnOrderThatDoesNotDecode(t *testing.T) {
	b := newOrderBenchWithRights(t, everyRight)
	called := countExecutors(t)
	seq := int64(0)
	for _, kind := range agentwire.OrderKinds() {
		for name, change := range map[string]func(*agentwire.OrderBody){
			"an unknown field":          func(o *agentwire.OrderBody) { o.Params = json.RawMessage(`{"unknown":1}`) },
			"not an object":             func(o *agentwire.OrderBody) { o.Params = json.RawMessage(`"text"`) },
			"an unreadable secret":      func(o *agentwire.OrderBody) { o.Secret = json.RawMessage(`{"Env":"A=1","env":"B=2"}`) },
			"a key in another case too": func(o *agentwire.OrderBody) { o.Params = json.RawMessage(`{"Kind":"x","kind":"y"}`) },
		} {
			seq++
			body := order(seq)
			body.Kind = kind
			change(&body)
			if result := b.send(t, body, b.private); result.State != agentwire.ActionRefused || result.Reason != agentwire.ReasonBadOrder {
				t.Errorf("%s, %s: %+v", kind, name, result)
			}
		}
	}
	if len(called) != 0 {
		t.Fatalf("an executor saw an order that does not decode: %v", called)
	}
	seq++
	if result := b.send(t, order(seq), b.private); result.State != agentwire.ActionSucceeded || called[agentwire.KindAgentPing] != 1 {
		t.Fatalf("a decoded ping must reach its executor: %+v %v", result, called)
	}
}

// R-A1-5 : le juge, les ancres, le journal et l'exécuteur lisent le même objet
// décodé. Dans le source de l'agent, aucun appel ne reçoit les octets d'un
// champ Params ou Secret, hors decodeOrder, la seule lecture : ni
// json.Unmarshal, ni un décodeur, ni agentwire.StrictDecode, quel que soit le
// nom de la variable.
func TestR_A1_5_NoExecutorRereadsTheParams(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		source, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, found := range rawFieldReads(t, name, source) {
			t.Errorf("%s: the executor must take the decoded order, not reread its bytes", found)
		}
	}

	// Le témoin : chaque forme de relecture est vue, et decodeOrder seul passe.
	witness := `package agent
func decodeOrder(body agentwire.OrderBody) { agentwire.Decode(body.Kind, body.Params); agentwire.DecodeSecret(body.Kind, body.Secret) }
func a(body agentwire.OrderBody) { json.Unmarshal(body.Params, &p) }
func b(body agentwire.OrderBody) { json.Unmarshal(body.Secret, &s) }
func c(body agentwire.OrderBody) { json.NewDecoder(bytes.NewReader(body.Params)).Decode(&p) }
func d(body agentwire.OrderBody) { agentwire.StrictDecode(body.Params, &p) }
func e(order agentwire.OrderBody) { agentwire.StrictDecode(order.Secret, &s) }
`
	if found := rawFieldReads(t, "witness.go", []byte(witness)); len(found) != 5 {
		t.Fatalf("the witness has five rereads, the search sees %d: %v", len(found), found)
	}
}

// rawFieldReads rend chaque appel d'un source qui reçoit un champ Params ou
// Secret, hors de decodeOrder.
func rawFieldReads(t *testing.T, name string, source []byte) []string {
	t.Helper()
	fileSet := token.NewFileSet()
	parsed, err := parser.ParseFile(fileSet, name, source, 0)
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name == "decodeOrder" {
			continue
		}
		ast.Inspect(function, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			for _, argument := range call.Args {
				if field, ok := argument.(*ast.SelectorExpr); ok && (field.Sel.Name == "Params" || field.Sel.Name == "Secret") {
					found = append(found, fileSet.Position(call.Pos()).String())
				}
			}
			return true
		})
	}
	return found
}

// Un agent v2 ne lit que l'enveloppe v2 (R-A1-9) : le corps v1, même signé
// par la vraie clé sous son étiquette, un corps sans « v » ou d'une autre
// version sont refusés, sans prendre de rang ni atteindre l'exécuteur.
// L'exception agent.update ne vaut que pour un agent du protocole 2.
func TestR_A1_9_AV2AgentRefusesABodyWithoutVOrOfAnotherVersion(t *testing.T) {
	b := newOrderBenchWithRights(t, everyRight)
	called := countExecutors(t)
	signedUnder := func(version int, encoded []byte) agentwire.ActionResult {
		t.Helper()
		data, err := json.Marshal(agentwire.SignedOrder{Body: encoded, Signature: ed25519.Sign(b.private, agentwire.OrderSigningBytes(version, encoded))})
		if err != nil {
			t.Fatal(err)
		}
		b.runner.receive(data)
		report := b.results.take()
		if report == nil || len(report.Results) != 1 {
			t.Fatalf("one result expected, got %+v", report)
		}
		return report.Results[0]
	}
	legacyOf := func(kind agentwire.Kind) []byte {
		current := order(1)
		encoded, err := json.Marshal(agentwire.OrderBodyV1{
			RunID: current.RunID, MachineID: current.MachineID, AgentID: current.AgentID, Kind: kind,
			NotAfter: current.NotAfter, Seq: current.Seq,
		})
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	versioned := func(version int) []byte {
		body := order(1)
		body.V = version
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	withoutV, found := strings.CutPrefix(string(versioned(agentwire.OrderVersion)), `{"v":2,`)
	if !found {
		t.Fatal("the v2 body does not start with its version")
	}
	cases := []struct {
		name    string
		version int
		body    []byte
		reason  string
	}{
		{"agent.update v1 under the v1 label", agentwire.LegacyOrderVersion, legacyOf(agentwire.KindAgentUpdate), agentwire.ReasonBadSignature},
		{"agent.ping v1 under the v1 label", agentwire.LegacyOrderVersion, legacyOf(agentwire.KindAgentPing), agentwire.ReasonBadSignature},
		{"agent.update v1 under the v2 label", agentwire.OrderVersion, legacyOf(agentwire.KindAgentUpdate), agentwire.ReasonBadOrder},
		{"no v", agentwire.OrderVersion, []byte("{" + withoutV), agentwire.ReasonBadOrder},
		{"v 0", agentwire.OrderVersion, versioned(0), agentwire.ReasonBadOrder},
		{"v 1", agentwire.OrderVersion, versioned(1), agentwire.ReasonBadOrder},
		{"v 3", agentwire.OrderVersion, versioned(3), agentwire.ReasonBadOrder},
		{"v 2 under the v1 label", agentwire.LegacyOrderVersion, versioned(agentwire.OrderVersion), agentwire.ReasonBadSignature},
	}
	for _, c := range cases {
		if result := signedUnder(c.version, c.body); result.State != agentwire.ActionRefused || result.Reason != c.reason {
			t.Errorf("%s: %+v", c.name, result)
		}
	}
	if len(called) != 0 {
		t.Fatalf("an executor ran: %v", called)
	}
	if saved, _ := LoadIdentity(b.stateDir); saved.LastOrderSeq != 0 {
		t.Fatalf("a refused order moved the seq to %d", saved.LastOrderSeq)
	}
	// Le témoin : le même ordre en v2, sous l'étiquette v2, atteint l'exécuteur.
	if result := signedUnder(agentwire.OrderVersion, versioned(agentwire.OrderVersion)); result.State != agentwire.ActionSucceeded || called[agentwire.KindAgentPing] != 1 {
		t.Fatalf("the v2 order: %+v, called %v", result, called)
	}
}

// L'agent juge l'agent visé et le rang à leur place parmi les contrôles de
// judge.Judge : un ordre fautif deux fois est refusé pour la première faute,
// dans l'ordre d'avant le juge unique.
func TestOrderJudge_TheAgentChecksKeepTheirPlace(t *testing.T) {
	cases := []struct {
		name   string
		change func(*agentwire.OrderBody)
		reason string
	}{
		{"another machine and another agent", func(o *agentwire.OrderBody) {
			o.MachineID, o.AgentID = "99999999-2222-4333-8444-555555555555", "agt_0000000000000002"
		}, agentwire.ReasonWrongMachine},
		{"another agent, past its deadline", func(o *agentwire.OrderBody) {
			o.AgentID, o.NotAfter = "agt_0000000000000002", orderNow.Unix()
		}, agentwire.ReasonWrongAgent},
		{"past its deadline and replayed", func(o *agentwire.OrderBody) { o.NotAfter, o.Seq = orderNow.Unix(), 0 }, agentwire.ReasonExpired},
		{"replayed, of an unknown kind", func(o *agentwire.OrderBody) { o.Seq, o.Kind = 0, "shell.exec" }, agentwire.ReasonReplayed},
		{"replayed, without its right", func(o *agentwire.OrderBody) { o.Seq, o.Kind = 0, agentwire.KindAgentRollback }, agentwire.ReasonReplayed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := newOrderBench(t)
			body := order(1)
			c.change(&body)
			if result := b.send(t, body, b.private); result.State != agentwire.ActionRefused || result.Reason != c.reason {
				t.Fatalf("result %+v, want refused %s", result, c.reason)
			}
		})
	}
}
