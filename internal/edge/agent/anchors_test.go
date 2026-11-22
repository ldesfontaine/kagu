package agent

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"filippo.io/age"

	"github.com/ldesfontaine/kagu/internal/fact/anchor"
	"github.com/ldesfontaine/kagu/internal/fact/machine"
	"github.com/ldesfontaine/kagu/internal/kit/testkit"
	"github.com/ldesfontaine/kagu/internal/wire/agentwire"
)

// Les ancres de confiance locales : un ordre dont un paramètre sort de ce que
// l'administrateur de la machine a posé est refusé, sans ancre aussi, et aucun
// ordre ne peut en écrire une. Chaque test échoue si on retire la garde qu'il
// vise (anchor.Judge dans le juge des ordres).

func newAgeRecipient(t *testing.T) string {
	t.Helper()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return identity.Recipient().String()
}

func TestAnchors_ARecipientOutsideTheAnchorsIsRefusedAndNothingRuns(t *testing.T) {
	b := newProduceRig(t)
	b.countingProducer([]byte("x"))
	params := produceParams(b.identity)
	params.Recipient = newAgeRecipient(t)
	results := b.run(t, 1, params)
	expectResult(t, results, agentwire.ActionRefused, "anchor_outside:backup.recipient")
	if len(b.produced) != 0 {
		t.Fatalf("the producer ran for an untrusted recipient: %v", b.produced)
	}
	if _, puts := b.server.received(); len(puts) != 0 {
		t.Fatalf("something was uploaded: %+v", puts)
	}
}

func TestAnchors_AGuestOutsideTheAnchorsIsRefusedAndNothingRuns(t *testing.T) {
	b := newProduceRig(t)
	b.countingProducer([]byte("x"))
	params := produceParams(b.identity)
	params.Target = "100"
	expectResult(t, b.run(t, 1, params), agentwire.ActionRefused, "anchor_outside:backup.guest")
	if len(b.produced) != 0 {
		t.Fatalf("the producer ran for an untrusted guest: %v", b.produced)
	}
}

func TestAnchors_AnAnchoredOrderStillRuns(t *testing.T) {
	b := newProduceRig(t)
	b.countingProducer([]byte("x"))
	results := b.run(t, 1, produceParams(b.identity))
	if final := results[len(results)-1]; final.State != agentwire.ActionSucceeded {
		t.Fatalf("results %+v", results)
	}
	if !slices.Equal(b.produced, []string{"5012"}) {
		t.Fatalf("produced %v", b.produced)
	}
}

func TestAnchors_NoAnchorMeansRefusalNamingTheMissingOne(t *testing.T) {
	b := newProduceRig(t)
	b.countingProducer([]byte("x"))
	// L'administrateur n'a rien posé de la clé : l'ordre est refusé sur elle.
	b.trust(t, map[string][]string{anchor.BackupRecipient: nil})
	expectResult(t, b.run(t, 1, produceParams(b.identity)), agentwire.ActionRefused, "anchor_missing:backup.recipient")
	b.trust(t, map[string][]string{anchor.BackupRecipient: {b.identity.Recipient().String()}, anchor.BackupGuest: nil})
	expectResult(t, b.run(t, 2, produceParams(b.identity)), agentwire.ActionRefused, "anchor_missing:backup.guest")
	if len(b.produced) != 0 {
		t.Fatalf("the producer ran without an anchor: %v", b.produced)
	}
}

func TestAnchors_UnreadableAnchorsAreADifferentRefusal(t *testing.T) {
	b := newProduceRig(t)
	b.countingProducer([]byte("x"))
	b.trust(t, map[string][]string{anchor.BackupGuest: {"5012", "not a guest"}})
	expectResult(t, b.run(t, 1, produceParams(b.identity)), agentwire.ActionRefused, "anchor_unreadable:backup.guest")
	if len(b.produced) != 0 {
		t.Fatalf("the producer ran on unreadable anchors: %v", b.produced)
	}
	if state := b.storedAnchors(t); !state.Unreadable[anchor.BackupGuest] || state.Unreadable[anchor.BackupRecipient] {
		t.Fatalf("only the faulty kind is unreadable: %+v", state)
	}
}

func TestAnchors_ACertificateOutsideTheAnchorsIsRefusedAndNoLinkIsWritten(t *testing.T) {
	b := newResticBench(t, "restic.produce")
	b.withoutTrust = true
	trusted, foreign := mustCertificate(t), mustCertificate(t)
	params := agentwire.ResticProvisionParams{Target: resticTargetID, Host: "pi.lan", Port: 8000, User: resticUser, Certificate: foreign}

	// Sans ancre : refusé, avec le type qui manque.
	expectResult(t, b.runWithSecret(t, agentwire.KindResticProvision, params, seededLink()), agentwire.ActionRefused, "anchor_missing:restic.target-cert")
	b.trust(t, map[string][]string{anchor.ResticTargetCert: {fingerprintOfPEM(trusted)}})
	expectResult(t, b.runWithSecret(t, agentwire.KindResticProvision, params, seededLink()), agentwire.ActionRefused, "anchor_outside:restic.target-cert")
	// Avant isProvisioned, qui crée le dossier du lien pour le lire.
	if entries, err := os.ReadDir(filepath.Join(b.stateDir.Name(), "restic", "links")); err == nil && len(entries) != 0 {
		t.Fatalf("a link directory was written: %v", entries)
	}
	if b.runner.restic.source.isProvisioned(resticTargetID) {
		t.Fatal("the source linked itself to a target whose certificate it does not trust")
	}

	params.Certificate = trusted
	expectResult(t, b.runWithSecret(t, agentwire.KindResticProvision, params, seededLink()), agentwire.ActionSucceeded, "")
}

// Un agent d'avant les ancres, ou sans ancre posée, fait tout le reste.
func TestAnchors_NothingElseDependsOnThem(t *testing.T) {
	b := newOrderBenchWithRights(t, []string{"observe", "agent.update", "docker.deploy"})
	if result := b.send(t, order(1), b.private); result.State != agentwire.ActionSucceeded {
		t.Fatalf("ping: %+v", result)
	}
	for _, kind := range agentwire.OrderKinds() {
		if spec, _ := agentwire.SpecOf(kind); len(spec.Anchors) != 0 && kind != agentwire.KindBackupProduce && kind != agentwire.KindResticProvision && kind != agentwire.KindResticBackup {
			t.Errorf("%s is bounded by an anchor kind the tests do not know", kind)
		}
	}
}

// Une ancre posée pendant que l'agent tourne vaut à l'ordre suivant, sans
// redémarrage, et les écritures de l'agent (le rang des ordres) ne l'effacent
// pas.
func TestAnchors_ATrustAddIsReadByTheRunningAgentAndSurvivesItsWrites(t *testing.T) {
	b := newProduceRig(t)
	b.countingProducer([]byte("x"))
	b.trust(t, map[string][]string{anchor.BackupGuest: nil})
	expectResult(t, b.run(t, 1, produceParams(b.identity)), agentwire.ActionRefused, "anchor_missing:backup.guest")

	result, err := Trust(TrustOptions{StateDir: b.stateDir, StatePath: b.stateDir.Name(), EUID: 0}, TrustAdd, anchor.BackupGuest, "5012")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(result.Stored[anchor.BackupGuest], []string{"5012"}) {
		t.Fatalf("stored %v", result.Stored)
	}
	results := b.run(t, 2, produceParams(b.identity))
	if final := results[len(results)-1]; final.State != agentwire.ActionSucceeded {
		t.Fatalf("after the trust add: %+v", results)
	}
	saved, err := LoadIdentity(b.stateDir)
	if err != nil || saved.LastOrderSeq != 2 || !slices.Equal(saved.Anchors[anchor.BackupGuest], []string{"5012"}) {
		t.Fatalf("an order write must keep both the rank and the anchors: seq %d anchors %v (%v)", saved.LastOrderSeq, saved.Anchors, err)
	}

	// Et l'inverse : la commande ne remet pas à zéro le rang écrit par l'agent.
	if _, err := Trust(TrustOptions{StateDir: b.stateDir, StatePath: b.stateDir.Name(), EUID: 0}, TrustRemove, anchor.BackupGuest, "5012"); err != nil {
		t.Fatal(err)
	}
	if saved, _ = LoadIdentity(b.stateDir); saved.LastOrderSeq != 2 || len(saved.ServerKey) == 0 {
		t.Fatalf("trust remove rewrote the rank or the server key: %+v", saved)
	}
}

// everyRight : un agent qui porte tous les droits, pour qu'aucun ordre ne
// s'arrête au droit.
var everyRight = []string{"observe", "agent.update", "docker.deploy", "docker.update", "backup.receive=/srv/receive", "backup.produce=" + machine.ProducerProxmoxVzdump,
	"files.write=/srv/write", "proxmox.power", "proxmox.snapshot", "restic.target=/srv/restic", "restic.produce", "restic.docker", "restic.verify", "restic.browse", "restic.restore"}

// Aucun genre d'ordre n'écrit une ancre : on envoie à chacun des paramètres et
// un secret qui en réclament, avec tous les droits, et le fichier garde ses
// ancres à l'identique.
func TestAnchors_NoOrderKindWritesAnAnchor(t *testing.T) {
	b := newOrderBenchWithRights(t, everyRight)
	posed := map[string][]string{anchor.BackupGuest: {"5012"}, anchor.BackupRecipient: {newAgeRecipient(t)}, anchor.ResticTargetCert: {strings.Repeat("ab", 32)}}
	b.trust(t, posed)
	hostile := map[string]any{
		"anchors": map[string][]string{anchor.BackupGuest: {"1"}}, "anchor": "backup.guest", "backup.guest": []string{"1"},
		"recipient": newAgeRecipient(t), "target": "1", "certificate": "x", "trust": true,
	}
	secret, _ := json.Marshal(map[string]any{"anchors": map[string][]string{anchor.BackupGuest: {"1"}}, "rest_password": "x"})
	seq := int64(0)
	for _, kind := range agentwire.OrderKinds() {
		if kind == agentwire.KindAgentUpdate || kind == agentwire.KindAgentRollback {
			continue // ils relancent l'agent ; leur exécuteur n'écrit pas dans l'identité (vérifié ci-dessous).
		}
		seq++
		body := longOrder(seq, kind, hostile)
		body.Secret = secret
		b.runner.receive(b.signed(t, body))
		b.drain()
		if got := b.storedAnchors(t); !equalValues(got.Values, posed) {
			t.Fatalf("%s changed the anchors: %+v", kind, got)
		}
	}
	stored, err := LoadIdentity(b.stateDir)
	if err != nil || !equalValues(anchor.FromFile(stored.Anchors).Values, posed) {
		t.Fatalf("anchors after every kind: %v %v", stored.Anchors, err)
	}
}

func equalValues(got, want map[string][]string) bool {
	if len(got) != len(want) {
		return false
	}
	for name, values := range want {
		if !slices.Equal(got[name], values) {
			return false
		}
	}
	return true
}

// drain vide les résultats rapportés, sans attendre un ordre en particulier.
func (b *orderBench) drain() {
	b.results.take()
}

// Le versant statique : le code de l'agent n'a que trois endroits où le champ
// Anchors reçoit une valeur (la lecture du disque, l'enrôlement, la copie sous
// verrou), et une seule voie qui appelle UpdateIdentity, la commande locale.
// Ajouter une écriture, c'est modifier ces listes, donc le dire en revue.
func TestAnchors_OnlyTheLocalCommandWritesThem(t *testing.T) {
	assignsAnchors := map[string]bool{"orders.go": true, "run.go": true, "identity.go": true, "trust.go": true}
	callsUpdateIdentity := map[string]bool{"trust.go": true}
	err := filepath.WalkDir(".", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return walkErr
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			switch typed := node.(type) {
			case *ast.AssignStmt:
				for _, left := range typed.Lhs {
					if selector, ok := left.(*ast.SelectorExpr); ok && selector.Sel.Name == "Anchors" && !assignsAnchors[path] {
						t.Errorf("%s assigns Anchors: only the local command may write them", path)
					}
				}
			case *ast.CallExpr:
				if ident, ok := typed.Fun.(*ast.Ident); ok && ident.Name == "UpdateIdentity" && !callsUpdateIdentity[path] {
					t.Errorf("%s calls UpdateIdentity: an order executor must not rewrite the identity this way", path)
				}
			case *ast.KeyValueExpr:
				if ident, ok := typed.Key.(*ast.Ident); ok && ident.Name == "Anchors" && !assignsAnchors[path] {
					t.Errorf("%s builds an Identity with Anchors", path)
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Un ordre exécuté ou refusé laisse au journal local de quoi le retrouver : le
// run, le genre, le rang, le SHA-256 du corps signé, l'empreinte de la clé qui
// l'a signé, et ses paramètres non secrets. Jamais le secret, ni un champ hors
// de la liste blanche, quel que soit le chemin de l'ordre.
func TestJournal_RecordsWhatWasSignedAndNeverASecret(t *testing.T) {
	logs := &lockedBuffer{}
	b := newProduceRig(t)
	b.runner.logger = slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	b.countingProducer([]byte("x"))
	const seeded = "SEEDED-SECRET-never-in-the-journal"

	// Un ordre exécuté.
	params := produceParams(b.identity)
	body := longOrder(1, agentwire.KindBackupProduce, params)
	encoded, _ := json.Marshal(body)
	b.runner.receive(b.signed(t, body))
	b.until(t, body.RunID)

	// Un refusé par la lecture stricte (un secret signé sur un genre qui n'en
	// porte pas, des champs hors liste blanche), un refusé par ancre, un refusé
	// par la signature.
	unread := longOrder(2, agentwire.KindBackupProduce, map[string]any{
		"producer": params.Producer, "target": params.Target, "prefix": params.Prefix, "recipient": params.Recipient, "parcel": params.Parcel,
		"password": seeded, "env": "TOKEN=" + seeded,
	})
	unread.Secret = json.RawMessage(`{"rest_password":"` + seeded + `"}`)
	b.runner.receive(b.signed(t, unread))
	b.until(t, unread.RunID)
	outside := params
	outside.Target = "100"
	other := longOrder(3, agentwire.KindBackupProduce, outside)
	b.runner.receive(b.signed(t, other))
	b.until(t, other.RunID)
	_, stranger, _ := ed25519.GenerateKey(rand.Reader)
	forged := longOrder(4, agentwire.KindAgentPing, map[string]any{"password": seeded})
	forgedEncoded, _ := json.Marshal(forged)
	forgedData, _ := json.Marshal(agentwire.SignedOrder{Body: forgedEncoded, Signature: ed25519.Sign(stranger, agentwire.OrderSigningBytes(forgedEncoded))})
	b.runner.receive(forgedData)
	b.until(t, forged.RunID)

	journal := logs.String()
	if strings.Contains(journal, seeded) {
		t.Fatalf("a secret reached the journal:\n%s", journal)
	}
	entries := journalEntries(t, journal)
	sum := factsOf(encoded, b.runner.identity.ServerKey)
	executed := findEntry(t, entries, "order executed", body.RunID)
	for field, want := range map[string]any{
		"kind": "backup.produce", "seq": float64(1), "body_sha256": sum.bodySHA256, "signing_key": sum.signingKey,
	} {
		if executed[field] != want {
			t.Errorf("order executed: %s = %v, expected %v", field, executed[field], want)
		}
	}
	logged, _ := executed["params"].(map[string]any)
	if logged["target"] != "5012" || logged["recipient"] != params.Recipient || logged["password"] != nil || logged["env"] != nil {
		t.Errorf("params %v", logged)
	}
	// Un ordre qui ne se décode pas n'a pas de valeur à écrire : le journal en
	// garde les empreintes, jamais les octets.
	if unreadable := findEntry(t, entries, "order refused", unread.RunID); unreadable["reason"] != agentwire.ReasonBadOrder || unreadable["body_sha256"] == nil || unreadable["params"] != nil {
		t.Errorf("strict reading refusal entry %v", unreadable)
	}
	refused := findEntry(t, entries, "order refused", other.RunID)
	if refused["reason"] != "anchor_outside:backup.guest" || refused["body_sha256"] == nil || refused["signing_key"] != sum.signingKey {
		t.Errorf("anchor refusal entry %v", refused)
	}
	bad := findEntry(t, entries, "order refused", forged.RunID)
	if bad["reason"] != agentwire.ReasonBadSignature || bad["body_sha256"] == nil || bad["signing_key"] != nil {
		t.Errorf("a forged order is logged with its hash and no signing key: %v", bad)
	}
}

// Le journal écrit les valeurs de l'ordre que le juge a décodé (R-A1-5) : une
// valeur changée sur l'objet décodé est celle qui s'écrit, et un ordre dont une
// clé d'une autre casse porte une autre valeur ne laisse au journal ni l'une ni
// l'autre, seulement ses empreintes.
func TestR_A1_5_TheJournalWritesTheDecodedValues(t *testing.T) {
	logs := &lockedBuffer{}
	b := newProduceRig(t)
	b.runner.logger = slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	params := produceParams(b.identity)

	judged := judgedOf(t, longOrder(1, agentwire.KindBackupProduce, params))
	decoded := judged.Params.(agentwire.BackupProduceParams)
	decoded.Target = "6000"
	judged.Params = decoded
	b.runner.journal.executed(judged)

	unread := longOrder(2, agentwire.KindBackupProduce, nil)
	unread.Params = json.RawMessage(`{"producer":"` + params.Producer + `","target":"5012","Target":"OTHER-TARGET","prefix":"` + params.Prefix +
		`","recipient":"` + params.Recipient + `","parcel":"` + params.Parcel + `"}`)
	b.runner.receive(b.signed(t, unread))
	b.until(t, unread.RunID)

	entries := journalEntries(t, logs.String())
	logged, _ := findEntry(t, entries, "order executed", judged.RunID)["params"].(map[string]any)
	if logged["target"] != "6000" || logged["recipient"] != params.Recipient || logged["producer"] != params.Producer {
		t.Errorf("the journal must write the decoded object: %v", logged)
	}
	refused := findEntry(t, entries, "order refused", unread.RunID)
	if refused["reason"] != agentwire.ReasonBadOrder || refused["body_sha256"] == nil || refused["params"] != nil {
		t.Errorf("an order that does not decode keeps its hashes only: %v", refused)
	}
	if strings.Contains(logs.String(), "OTHER-TARGET") {
		t.Errorf("a value of an undecoded order reached the journal:\n%s", logs.String())
	}
}

func journalEntries(t *testing.T, journal string) []map[string]any {
	t.Helper()
	var entries []map[string]any
	for _, line := range bytes.Split([]byte(journal), []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var entry map[string]any
		if err := json.Unmarshal(line, &entry); err != nil {
			t.Fatalf("%q: %v", line, err)
		}
		entries = append(entries, entry)
	}
	return entries
}

func findEntry(t *testing.T, entries []map[string]any, message, runID string) map[string]any {
	t.Helper()
	for _, entry := range entries {
		if entry["msg"] == message && entry["run_id"] == runID {
			return entry
		}
	}
	t.Fatalf("no %q line for %s in %v", message, runID, entries)
	return nil
}

// --- La commande locale ---

func trustOptions(b *orderBench, euid int) TrustOptions {
	return TrustOptions{StateDir: b.stateDir, StatePath: b.stateDir.Name(), EUID: euid}
}

func TestTrust_RefusesAnythingButRoot(t *testing.T) {
	b := newOrderBenchWithRights(t, nil)
	for _, euid := range []int{1000, 1001, 65534} {
		if _, err := Trust(trustOptions(b, euid), TrustAdd, anchor.BackupGuest, "101"); !errors.Is(err, ErrTrustNotRoot) {
			t.Errorf("uid %d: %v", euid, err)
		}
		if _, err := Trust(trustOptions(b, euid), TrustList, "", ""); !errors.Is(err, ErrTrustNotRoot) {
			t.Errorf("uid %d list: %v", euid, err)
		}
	}
	if stored := b.storedAnchors(t); stored.HasAny() {
		t.Fatalf("a refused command wrote: %+v", stored)
	}
}

func TestTrust_RefusesAStateFileWithTheWrongModes(t *testing.T) {
	b := newOrderBenchWithRights(t, nil)
	path := filepath.Join(b.stateDir.Name(), "identity.json")
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	var unsafe *UnsafeStateError
	if _, err := Trust(trustOptions(b, 0), TrustAdd, anchor.BackupGuest, "101"); !errors.As(err, &unsafe) {
		t.Fatalf("a state file writable by others: %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(b.stateDir.Name(), 0o770); err != nil {
		t.Fatal(err)
	}
	if _, err := Trust(trustOptions(b, 0), TrustAdd, anchor.BackupGuest, "101"); !errors.As(err, &unsafe) {
		t.Fatalf("a state dir writable by its group: %v", err)
	}
	_ = os.Chmod(b.stateDir.Name(), 0o700)
	if stored := b.storedAnchors(t); stored.HasAny() {
		t.Fatalf("a refused command wrote: %+v", stored)
	}
}

func TestTrust_AddsListsAndRemovesWithTheRegistryBounds(t *testing.T) {
	b := newOrderBenchWithRights(t, nil)
	options := trustOptions(b, 0)
	var traces []string
	options.Audit = func(message string) error { traces = append(traces, message); return nil }

	if _, err := Trust(options, TrustAdd, "nothing.here", "1"); !errors.Is(err, ErrTrustUnknownKind) {
		t.Fatalf("unknown kind: %v", err)
	}
	if _, err := Trust(options, "frobnicate", anchor.BackupGuest, "1"); !errors.Is(err, ErrTrustUnknownVerb) {
		t.Fatalf("unknown verb: %v", err)
	}
	if _, err := Trust(options, TrustAdd, anchor.BackupGuest, "0101"); !errors.Is(err, anchor.ErrUnreadable) {
		t.Fatalf("bad value: %v", err)
	}
	for _, value := range []string{"101", "102", "101"} {
		if _, err := Trust(options, TrustAdd, anchor.BackupGuest, value); err != nil {
			t.Fatal(err)
		}
	}
	listed, err := Trust(options, TrustList, "", "")
	if err != nil || !slices.Equal(listed.Stored[anchor.BackupGuest], []string{"101", "102"}) {
		t.Fatalf("listed %v %v", listed.Stored, err)
	}
	if _, err := Trust(options, TrustRemove, anchor.BackupGuest, "103"); !errors.Is(err, anchor.ErrAbsent) {
		t.Fatalf("remove absent: %v", err)
	}
	if _, err := Trust(options, TrustRemove, anchor.BackupGuest, "101"); err != nil {
		t.Fatal(err)
	}
	if len(traces) != 4 || !strings.Contains(traces[0], "trust add backup.guest 101") || !strings.Contains(traces[3], "trust remove backup.guest 101") {
		t.Fatalf("the journal of the system got %v", traces)
	}
	// L'échec de la trace n'annule pas le changement, il se rapporte.
	options.Audit = func(string) error { return errors.New("no journal socket") }
	result, err := Trust(options, TrustAdd, anchor.BackupGuest, "104")
	if err != nil || result.AuditError == nil || !slices.Equal(result.Stored[anchor.BackupGuest], []string{"102", "104"}) {
		t.Fatalf("audit failure: %+v %v", result, err)
	}
}

// Le fichier réécrit par la commande reste à son propriétaire, en 0600, et
// aucun temporaire n'en traîne.
func TestTrust_KeepsTheFileOwnerAndModeAndLeavesNoTemporary(t *testing.T) {
	b := newOrderBenchWithRights(t, nil)
	before, err := os.Stat(filepath.Join(b.stateDir.Name(), "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Trust(trustOptions(b, 0), TrustAdd, anchor.BackupGuest, "101"); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(filepath.Join(b.stateDir.Name(), "identity.json"))
	if err != nil || after.Mode().Perm() != 0o600 || ownerIDOf(after) != ownerIDOf(before) {
		t.Fatalf("mode %v owner %d, was %d (%v)", after.Mode(), ownerIDOf(after), ownerIDOf(before), err)
	}
	entries, _ := os.ReadDir(b.stateDir.Name())
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".tmp-") {
			t.Errorf("leftover temporary %s", entry.Name())
		}
	}
}

// --- L'ouverture du flux ---

func TestClient_ReportsItsAnchorsOnOpeningTheStream(t *testing.T) {
	client := &Client{}
	client.SetAnchors(anchor.FromFile(nil))
	if client.anchors != "none" {
		t.Fatalf("an agent without anchors says so: %q", client.anchors)
	}
	client.SetAnchors(anchor.FromFile(map[string][]string{anchor.BackupGuest: {"101", "102"}, anchor.BackupRecipient: {"bad"}}))
	if client.anchors != "backup.recipient=!,backup.guest=101:102" {
		t.Fatalf("anchors %q", client.anchors)
	}
}

// Une identité qui porte une clé du serveur et une clé base64 reste lisible : la
// pose d'une clé par un ordre ne touche que la clé.
func TestAnchors_PinningTheServerKeyKeepsThem(t *testing.T) {
	b := newOrderBenchWithRights(t, nil)
	b.trust(t, map[string][]string{anchor.BackupGuest: {"101"}})
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	body := longOrder(1, agentwire.KindServerKey, agentwire.ServerKeyParams{PublicKey: base64.StdEncoding.EncodeToString(public)})
	b.runner.receive(b.signed(t, body))
	b.drain()
	stored, err := LoadIdentity(b.stateDir)
	if err != nil || !slices.Equal(stored.ServerKey, public) || !slices.Equal(stored.Anchors[anchor.BackupGuest], []string{"101"}) {
		t.Fatalf("server key %x anchors %v (%v)", stored.ServerKey, stored.Anchors, err)
	}
}

func ownerIDOf(info os.FileInfo) uint32 {
	return info.Sys().(*syscall.Stat_t).Uid
}

// withExtraKey ajoute une clé à la fin des paramètres d'un ordre : l'attaque
// B-H1, la clé ancrée d'abord, sa variante de casse ou sa répétition ensuite.
func withExtraKey(t *testing.T, params any, key string, value any) json.RawMessage {
	t.Helper()
	encoded := testkit.MustJSON(t, params)
	extra := testkit.MustJSON(t, value)
	return json.RawMessage(string(encoded[:len(encoded)-1]) + "," + strconv.Quote(key) + ":" + string(extra) + "}")
}

// B-H1 : backup.produce avec target et recipient ancrés, puis la même clé
// d'une autre casse (ou répétée) hors ancre : refusé bad_order, vzdump non lancé.
func TestR_A1_3_TheProducerIsNeverCalledOnAKeyOfAnotherCaseOrRepeated(t *testing.T) {
	b := newProduceRig(t)
	b.countingProducer([]byte("x"))
	params := produceParams(b.identity)
	cases := []struct {
		name  string
		key   string
		value string
	}{
		{"Target outside the anchors", "Target", "9999"},
		{"TARGET outside the anchors", "TARGET", "9999"},
		{"target repeated, other value", "target", "9999"},
		{"target repeated, same value", "target", "5012"},
		{"Recipient outside the anchors", "Recipient", testIdentity(t).Recipient().String()},
		{"recipient repeated, same value", "recipient", params.Recipient},
	}
	for seq, c := range cases {
		order := longOrder(int64(seq+1), agentwire.KindBackupProduce, withExtraKey(t, params, c.key, c.value))
		b.runner.receive(b.signed(t, order))
		report := b.results.take()
		if report == nil || len(report.Results) != 1 {
			t.Fatalf("%s: one answer expected: %+v", c.name, report)
		}
		// C-1, C-2 : refusé à la lecture, avant toute ancre ; aucun refus ne
		// nomme une ancre qu'il n'a pas jugée.
		if got := report.Results[0]; got.State != agentwire.ActionRefused || got.Reason != agentwire.ReasonBadOrder {
			t.Errorf("%s: %+v", c.name, got)
		}
	}
	if len(b.produced) != 0 {
		t.Fatalf("the producer ran for %v", b.produced)
	}
	if _, puts := b.server.received(); len(puts) != 0 {
		t.Fatalf("something was sent: %+v", puts)
	}
	expectResult(t, b.run(t, 100, params), agentwire.ActionSucceeded, "")
}

// B-M1 : restic.backup d'un invité lance sudo et vzdump sur le vmid de l'ordre ;
// backup.guest le borne comme backup.produce. Hors des ancres : refusé, sudo
// jamais cherché, restic jamais lancé. La portée service n'est pas bornée par
// cette ancre, même sur une machine qui n'en a posé aucune.
func TestR_A1_7_ResticBackupOfAGuestOutsideTheAnchorsNeverRunsSudo(t *testing.T) {
	b := newResticBench(t, "restic.produce", "backup.produce=proxmox-vzdump")
	b.runner.restic.source.dialer = &refusingDialer{}
	b.provision(t, "nas", 8000, mustCertificate(t))
	var looked []string
	b.runner.checks.lookPath = func(name string) (string, error) {
		looked = append(looked, name)
		return "/usr/bin/" + name, nil
	}
	guest := func(vmid int) agentwire.ResticBackupParams {
		return agentwire.ResticBackupParams{Target: resticTargetID, Scope: agentwire.ResticScopeVM, VMID: vmid, GuestType: agentwire.GuestQEMU}
	}
	refusedWithoutRunning := func(label string, params any, reason string) {
		t.Helper()
		expectResult(t, b.run(t, agentwire.KindResticBackup, params), agentwire.ActionRefused, reason)
		if slices.Contains(looked, "sudo") || len(b.restic.callsMade()) != 0 {
			t.Fatalf("%s: sudo looked up %v, restic ran %d times", label, looked, len(b.restic.callsMade()))
		}
	}

	// Une machine sans ancre refuse tout invité, et dit laquelle manque.
	refusedWithoutRunning("no anchor", guest(105), "anchor_missing:backup.guest")
	b.trust(t, map[string][]string{anchor.BackupGuest: {"101"}})
	refusedWithoutRunning("vmid outside", guest(105), "anchor_outside:backup.guest")
	// La portée service passe sans que backup.guest la juge.
	b.trust(t, map[string][]string{anchor.BackupGuest: nil})
	dir := b.service(t, "forgejo")
	if err := os.WriteFile(filepath.Join(dir, "data"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	expectResult(t, b.run(t, agentwire.KindResticBackup, serviceBackup("forgejo")), agentwire.ActionSucceeded, "")
	if slices.Contains(looked, "sudo") {
		t.Fatalf("a service backup looked up sudo: %v", looked)
	}

	// Le vmid ancré passe : sudo est enfin cherché.
	b.trust(t, map[string][]string{anchor.BackupGuest: {"105"}})
	expectResult(t, b.run(t, agentwire.KindResticBackup, guest(105)), agentwire.ActionSucceeded, "")
	if !slices.Contains(looked, "sudo") {
		t.Fatal("an anchored guest did not reach sudo")
	}
}

// Même attaque sur restic.provision/certificate : refusé bad_order, aucun lien
// n'est écrit.
func TestR_A1_7_TheResticLinkIsNeverWrittenOnAnotherCaseOfTheCertificateKey(t *testing.T) {
	b := newResticBench(t, "restic.produce")
	b.withoutTrust = true
	trusted, foreign := mustCertificate(t), mustCertificate(t)
	b.trust(t, map[string][]string{anchor.ResticTargetCert: {fingerprintOfPEM(trusted)}})
	params := agentwire.ResticProvisionParams{Target: resticTargetID, Host: "pi.lan", Port: 8000, User: resticUser, Certificate: trusted}
	for _, c := range []struct{ name, key, value string }{
		{"Certificate outside the anchors", "Certificate", foreign},
		{"CERTIFICATE outside the anchors", "CERTIFICATE", foreign},
		{"certificate repeated, same value", "certificate", trusted},
	} {
		expectResult(t, b.runWithSecret(t, agentwire.KindResticProvision, withExtraKey(t, params, c.key, c.value), seededLink()),
			agentwire.ActionRefused, agentwire.ReasonBadOrder)
		if b.runner.restic.source.isProvisioned(resticTargetID) {
			t.Fatalf("%s: the source linked itself", c.name)
		}
	}
	expectResult(t, b.runWithSecret(t, agentwire.KindResticProvision, params, seededLink()), agentwire.ActionSucceeded, "")
}
