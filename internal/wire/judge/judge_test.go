package judge

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"go/parser"
	"go/token"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/fact/anchor"
	"github.com/ldesfontaine/kagu/internal/wire/agentwire"
)

const judgeMachineID = "11111111-2222-4333-8444-555555555555"

var judgeNow = time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)

// judgeBench est une politique et la clé privée du serveur qu'elle accepte.
type judgeBench struct {
	policy  agentpolicy.Policy
	private ed25519.PrivateKey
}

func newJudgeBench(t *testing.T, rights string) judgeBench {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	capabilities, err := agentpolicy.ParseCapabilities(rights)
	if err != nil {
		t.Fatal(err)
	}
	return judgeBench{policy: agentpolicy.Policy{MachineID: judgeMachineID, ServerKeys: [][]byte{public}, Rights: capabilities}, private: private}
}

// ping rend un ordre agent.ping valide, à retoucher par le test.
func ping() agentwire.OrderBody {
	return agentwire.OrderBody{
		V: agentwire.OrderVersion, RunID: "run-1", MachineID: judgeMachineID, AgentID: "agt_1", Kind: agentwire.KindAgentPing,
		NotAfter: judgeNow.Add(time.Minute).Unix(), Seq: 1,
	}
}

// vmBackup rend un ordre restic.backup d'un invité, borné par l'ancre
// backup.guest.
func vmBackup(t *testing.T, vmid int) agentwire.OrderBody {
	t.Helper()
	body := ping()
	body.Kind = agentwire.KindResticBackup
	params, err := json.Marshal(agentwire.ResticBackupParams{Target: "cible", Scope: agentwire.ResticScopeVM, VMID: vmid, GuestType: "qemu"})
	if err != nil {
		t.Fatal(err)
	}
	body.Params = params
	return body
}

func sign(t *testing.T, body agentwire.OrderBody, signer ed25519.PrivateKey) agentwire.SignedOrder {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return agentwire.SignedOrder{Body: encoded, Signature: ed25519.Sign(signer, agentwire.OrderSigningBytes(agentwire.OrderVersion, encoded))}
}

// Un ordre signé par la clé de la politique, pour sa machine, à temps et
// dont la politique porte le droit, passe, lu et décodé.
func TestJudge_AValidOrderPassesReadAndDecoded(t *testing.T) {
	b := newJudgeBench(t, "")
	verdict := Judge(sign(t, ping(), b.private), b.policy, judgeNow)
	if verdict.Reason != "" || !verdict.Read || verdict.Body.RunID != "run-1" || verdict.Order.Kind != agentwire.KindAgentPing {
		t.Fatalf("verdict %+v", verdict)
	}
}

// Chaque contrôle refuse avec sa raison ; un ordre refusé avant d'être lu
// n'a pas de corps.
func TestJudge_EachCheckRefusesWithItsReason(t *testing.T) {
	_, stranger, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		change func(*agentwire.OrderBody)
		signer ed25519.PrivateKey
		read   bool
		reason string
	}{
		{"signed by another key", nil, stranger, false, agentwire.ReasonBadSignature},
		{"without v", func(o *agentwire.OrderBody) { o.V = 0 }, nil, false, agentwire.ReasonBadOrder},
		{"without run", func(o *agentwire.OrderBody) { o.RunID = "" }, nil, false, agentwire.ReasonBadOrder},
		{"another machine", func(o *agentwire.OrderBody) { o.MachineID = "99999999-2222-4333-8444-555555555555" }, nil, true, agentwire.ReasonWrongMachine},
		{"past its deadline", func(o *agentwire.OrderBody) { o.NotAfter = judgeNow.Unix() }, nil, true, agentwire.ReasonExpired},
		{"unknown kind", func(o *agentwire.OrderBody) { o.Kind = "shell.exec" }, nil, true, agentwire.ReasonUnknownKind},
		{"right missing", func(o *agentwire.OrderBody) { o.Kind = agentwire.KindDockerRollback }, nil, true, "right_missing:docker.update"},
		{"params on a kind without", func(o *agentwire.OrderBody) { o.Params = json.RawMessage(`{"x":1}`) }, nil, true, agentwire.ReasonBadOrder},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := newJudgeBench(t, "")
			body := ping()
			if c.change != nil {
				c.change(&body)
			}
			signer := b.private
			if c.signer != nil {
				signer = c.signer
			}
			verdict := Judge(sign(t, body, signer), b.policy, judgeNow)
			if verdict.Reason != c.reason || verdict.Read != c.read {
				t.Fatalf("verdict %+v, want %s (read %t)", verdict, c.reason, c.read)
			}
		})
	}
}

// Sans clé du serveur dans la politique, rien ne passe.
func TestJudge_WithoutAServerKeyNothingPasses(t *testing.T) {
	b := newJudgeBench(t, "")
	b.policy.ServerKeys = nil
	if verdict := Judge(sign(t, ping(), b.private), b.policy, judgeNow); verdict.Reason != agentwire.ReasonServerKeyMissing || verdict.Read {
		t.Fatalf("verdict %+v", verdict)
	}
}

// Pendant un --keep-old, la politique porte deux clés : chacune signe, et le
// verdict nomme celle qui a signé ; une clé hors de la politique ne signe pas.
func TestJudge_EitherKeyOfThePolicySigns(t *testing.T) {
	keptPublic, kept, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, stranger, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b := newJudgeBench(t, "")
	b.policy.ServerKeys = append(b.policy.ServerKeys, keptPublic)
	for _, signer := range []ed25519.PrivateKey{b.private, kept} {
		verdict := Judge(sign(t, ping(), signer), b.policy, judgeNow)
		if verdict.Reason != "" || !signer.Public().(ed25519.PublicKey).Equal(ed25519.PublicKey(verdict.SigningKey)) {
			t.Fatalf("verdict %+v", verdict)
		}
	}
	if verdict := Judge(sign(t, ping(), stranger), b.policy, judgeNow); verdict.Reason != agentwire.ReasonBadSignature || verdict.SigningKey != nil {
		t.Fatalf("a stranger signed: %+v", verdict)
	}
}

// La première raison l'emporte, dans l'ordre des contrôles d'aujourd'hui :
// la signature avant la machine, la machine avant l'échéance, l'échéance
// avant le genre, le droit avant les paramètres.
func TestJudge_TheFirstReasonWins(t *testing.T) {
	_, stranger, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b := newJudgeBench(t, "")
	elsewhere := ping()
	elsewhere.MachineID, elsewhere.NotAfter, elsewhere.Kind = "99999999-2222-4333-8444-555555555555", judgeNow.Unix(), "shell.exec"
	if verdict := Judge(sign(t, elsewhere, stranger), b.policy, judgeNow); verdict.Reason != agentwire.ReasonBadSignature {
		t.Errorf("signature first: %+v", verdict)
	}
	if verdict := Judge(sign(t, elsewhere, b.private), b.policy, judgeNow); verdict.Reason != agentwire.ReasonWrongMachine {
		t.Errorf("machine before deadline: %+v", verdict)
	}
	late := ping()
	late.NotAfter, late.Kind = judgeNow.Unix(), "shell.exec"
	if verdict := Judge(sign(t, late, b.private), b.policy, judgeNow); verdict.Reason != agentwire.ReasonExpired {
		t.Errorf("deadline before kind: %+v", verdict)
	}
	unreadable := ping()
	unreadable.Kind, unreadable.Params = agentwire.KindAgentUpdate, json.RawMessage(`{"nope":1}`)
	if verdict := Judge(sign(t, unreadable, b.private), b.policy, judgeNow); verdict.Reason != "right_missing:agent.update" {
		t.Errorf("right before params: %+v", verdict)
	}
}

// Les ancres de la politique bornent l'ordre décodé : sans ancre, ou hors
// d'elle, il est refusé ; dedans, il passe.
func TestJudge_TheAnchorsOfThePolicyBoundTheOrder(t *testing.T) {
	b := newJudgeBench(t, "restic.produce")
	order := sign(t, vmBackup(t, 312), b.private)
	if verdict := Judge(order, b.policy, judgeNow); verdict.Reason != "anchor_missing:"+anchor.BackupGuest || verdict.Order.Params == nil {
		t.Fatalf("no anchor: %+v", verdict)
	}
	b.policy.Anchors = map[string][]string{anchor.BackupGuest: {"313"}}
	if verdict := Judge(order, b.policy, judgeNow); verdict.Reason != "anchor_outside:"+anchor.BackupGuest {
		t.Fatalf("outside: %+v", verdict)
	}
	b.policy.Anchors = map[string][]string{anchor.BackupGuest: {strconv.Itoa(312)}}
	if verdict := Judge(order, b.policy, judgeNow); verdict.Reason != "" {
		t.Fatalf("inside: %+v", verdict)
	}
}

// Judge ne lit aucun fichier : il reçoit la politique (la porte root, A5,
// importera ce code). Le paquet n'importe rien qui ouvre un fichier.
func TestJudge_ReadsNoFile(t *testing.T) {
	fileSet := token.NewFileSet()
	sources, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	forbidden := []string{"os", "io/fs", "io/ioutil", "path/filepath", "syscall"}
	checked := 0
	for _, source := range sources {
		if strings.HasSuffix(source, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fileSet, source, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		checked++
		for _, spec := range file.Imports {
			if path, _ := strconv.Unquote(spec.Path.Value); slices.Contains(forbidden, path) {
				t.Errorf("%s imports %s: the judge receives the policy, it reads no file", source, path)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no source seen")
	}
}

// rightRequest rend un ordre right.request valide, qui demande ce droit.
func rightRequest(t *testing.T, params agentwire.RightRequestParams) agentwire.OrderBody {
	t.Helper()
	body := ping()
	body.Kind = agentwire.KindRightRequest
	encoded, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	body.Params = encoded
	return body
}

// ARB-1 : le droit de right.request est celui qu'il demande, calculé sur les
// paramètres décodés. Sans lui, refusé right_missing:<droit>, l'ordre décodé
// (l'agent en note la valeur) ; avec lui, il passe. Un nom hors d'agentpolicy,
// une valeur qui n'est pas un producteur de la liste fermée, un champ
// inconnu : l'ordre ne se lit pas.
func TestARB1_TheRightOfARightRequestIsTheRightItNames(t *testing.T) {
	b := newJudgeBench(t, "")
	asked := agentwire.RightRequestParams{Right: agentpolicy.CapabilityBackupProduce, Value: agentpolicy.ProducerProxmoxVzdump}
	verdict := Judge(sign(t, rightRequest(t, asked), b.private), b.policy, judgeNow)
	if verdict.Reason != "right_missing:backup.produce" || verdict.Order.Params != asked {
		t.Fatalf("without the right: %+v", verdict)
	}
	held := newJudgeBench(t, "docker.deploy")
	deploy := rightRequest(t, agentwire.RightRequestParams{Right: agentpolicy.CapabilityDockerDeploy})
	if verdict := Judge(sign(t, deploy, held.private), held.policy, judgeNow); verdict.Reason != "" {
		t.Fatalf("with the right: %+v", verdict)
	}
	unreadable := map[string]agentwire.OrderBody{
		"unknown right":   rightRequest(t, agentwire.RightRequestParams{Right: "shell.exec"}),
		"path value":      rightRequest(t, agentwire.RightRequestParams{Right: agentpolicy.CapabilityFilesWrite, Value: "/etc"}),
		"other producer":  rightRequest(t, agentwire.RightRequestParams{Right: agentpolicy.CapabilityBackupProduce, Value: "dd"}),
		"value elsewhere": rightRequest(t, agentwire.RightRequestParams{Right: agentpolicy.CapabilityDockerDeploy, Value: agentpolicy.ProducerProxmoxVzdump}),
	}
	extra := ping()
	extra.Kind, extra.Params = agentwire.KindRightRequest, json.RawMessage(`{"right":"docker.deploy","yes":true}`)
	unreadable["unknown field"] = extra
	for name, body := range unreadable {
		if verdict := Judge(sign(t, body, b.private), b.policy, judgeNow); verdict.Reason != agentwire.ReasonBadOrder {
			t.Errorf("%s: %+v", name, verdict)
		}
	}
}
