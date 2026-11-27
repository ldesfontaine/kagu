package agent

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
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

	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/fact/anchor"
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
	if !slices.Equal(b.produced, []string{"312"}) {
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
	b.trust(t, map[string][]string{anchor.BackupGuest: {"312", "not a guest"}})
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

// Une ancre posée par « agent trust » pendant que l'agent tourne vaut à
// l'ordre suivant, sans redémarrage ; les écritures de l'agent (le rang des
// ordres) ne la touchent pas, et la commande ne remet pas à zéro le rang.
func TestAnchors_ATrustAddIsReadByTheRunningAgentAndSurvivesItsWrites(t *testing.T) {
	rig := newProduceRig(t)
	rig.countingProducer([]byte("x"))
	rig.trust(t, map[string][]string{anchor.BackupGuest: nil})
	b := migrate(t, rig.orderBench)
	expectResult(t, rig.run(t, 1, produceParams(rig.identity)), agentwire.ActionRefused, "anchor_missing:backup.guest")

	change, err := Trust(b.opts, TrustRequest{Verb: TrustAdd, Kind: anchor.BackupGuest, Value: "312"}, accept)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(change.After.Anchors[anchor.BackupGuest], []string{"312"}) {
		t.Fatalf("stored %v", change.After.Anchors)
	}
	results := rig.run(t, 2, produceParams(rig.identity))
	if final := results[len(results)-1]; final.State != agentwire.ActionSucceeded {
		t.Fatalf("after the trust add: %+v", results)
	}
	if _, err := Trust(b.opts, TrustRequest{Verb: TrustRemove, Kind: anchor.BackupGuest, Value: "312"}, accept); err != nil {
		t.Fatal(err)
	}
	saved, err := LoadIdentity(b.stateDir)
	if err != nil || saved.LastOrderSeq != 2 || saved.Anchors != nil || saved.ServerKey != nil {
		t.Fatalf("the rank is kept, nothing comes back to identity.json: %+v %v", saved, err)
	}
	if stored := (&policyBench{opts: b.opts}).stored(t); len(stored.Anchors[anchor.BackupGuest]) != 0 || len(stored.ServerKeys) != 1 {
		t.Fatalf("policy after the remove: %+v", stored)
	}
}

// everyRight : un agent qui porte tous les droits, pour qu'aucun ordre ne
// s'arrête au droit.
var everyRight = []string{"observe", "agent.update", "docker.deploy", "docker.update", "backup.receive=/srv/receive", "backup.produce=" + agentpolicy.ProducerProxmoxVzdump,
	"files.write=/srv/write", "proxmox.power", "proxmox.snapshot", "restic.target=/srv/restic", "restic.produce", "restic.docker", "restic.verify", "restic.browse", "restic.restore"}

// Aucun genre d'ordre n'écrit une ancre : on envoie à chacun des paramètres et
// un secret qui en réclament, avec tous les droits, et le fichier garde ses
// ancres à l'identique.
func TestAnchors_NoOrderKindWritesAnAnchor(t *testing.T) {
	b := newOrderBenchWithRights(t, everyRight)
	posed := map[string][]string{anchor.BackupGuest: {"312"}, anchor.BackupRecipient: {newAgeRecipient(t)}, anchor.ResticTargetCert: {strings.Repeat("ab", 32)}}
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

// Le versant statique : le code de l'agent n'a que ces endroits où un champ
// Anchors reçoit une valeur (la lecture du disque et de la politique,
// l'enrôlement, la copie sous verrou, « agent trust », l'effacement de
// « policy migrate »), et une seule voie qui appelle UpdateIdentity,
// « policy migrate ». Ajouter une écriture, c'est modifier ces listes, donc
// le dire en revue.
func TestAnchors_OnlyTheLocalCommandWritesThem(t *testing.T) {
	assignsAnchors := map[string]bool{"orders.go": true, "run.go": true, "identity.go": true, "trust.go": true, "policy.go": true, "migrate.go": true}
	callsUpdateIdentity := map[string]bool{"migrate.go": true}
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
	forgedData, _ := json.Marshal(agentwire.SignedOrder{Body: forgedEncoded, Signature: ed25519.Sign(stranger, agentwire.OrderSigningBytes(agentwire.OrderVersion, forgedEncoded))})
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
	if logged["target"] != "312" || logged["recipient"] != params.Recipient || logged["password"] != nil || logged["env"] != nil {
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
	unread.Params = json.RawMessage(`{"producer":"` + params.Producer + `","target":"312","Target":"OTHER-TARGET","prefix":"` + params.Prefix +
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

// trustBench est un banc passé à la politique, dont root change les ancres.
func trustBench(t *testing.T) *migratedBench {
	t.Helper()
	return migrate(t, newOrderBenchWithRights(t, nil))
}

func (b *migratedBench) storedAnchors(t *testing.T) anchor.State {
	t.Helper()
	return anchor.FromFile((&policyBench{opts: b.opts}).stored(t).Anchors)
}

func trustAdd(value string) TrustRequest {
	return TrustRequest{Verb: TrustAdd, Kind: anchor.BackupGuest, Value: value}
}

func TestTrust_RefusesAnythingButRoot(t *testing.T) {
	b := trustBench(t)
	for _, euid := range []int{1000, 1001, 65534} {
		options := b.opts
		options.EUID = euid
		if _, err := Trust(options, trustAdd("101"), accept); !errors.Is(err, ErrTrustNotRoot) {
			t.Errorf("uid %d: %v", euid, err)
		}
		if _, err := ReadPolicyAsRoot(options); !errors.Is(err, ErrTrustNotRoot) {
			t.Errorf("uid %d list: %v", euid, err)
		}
	}
	if stored := b.storedAnchors(t); stored.HasAny() {
		t.Fatalf("a refused command wrote: %+v", stored)
	}
}

func TestTrust_RefusesAStateFileWithTheWrongModes(t *testing.T) {
	b := trustBench(t)
	path := filepath.Join(b.stateDir.Name(), "identity.json")
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	var unsafe *UnsafeStateError
	if _, err := Trust(b.opts, trustAdd("101"), accept); !errors.As(err, &unsafe) {
		t.Fatalf("a state file writable by others: %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(b.stateDir.Name(), 0o770); err != nil {
		t.Fatal(err)
	}
	if _, err := Trust(b.opts, trustAdd("101"), accept); !errors.As(err, &unsafe) {
		t.Fatalf("a state dir writable by its group: %v", err)
	}
	_ = os.Chmod(b.stateDir.Name(), 0o700)
	if stored := b.storedAnchors(t); stored.HasAny() {
		t.Fatalf("a refused command wrote: %+v", stored)
	}
}

func TestTrust_AddsListsAndRemovesWithTheRegistryBounds(t *testing.T) {
	b := trustBench(t)
	options := b.opts
	var traces []string
	options.Audit = func(message string) error { traces = append(traces, message); return nil }

	if _, err := Trust(options, TrustRequest{Verb: TrustAdd, Kind: "nothing.here", Value: "1"}, accept); !errors.Is(err, ErrTrustUnknownKind) {
		t.Fatalf("unknown kind: %v", err)
	}
	if _, err := Trust(options, TrustRequest{Verb: "frobnicate", Kind: anchor.BackupGuest, Value: "1"}, accept); !errors.Is(err, ErrTrustUnknownVerb) {
		t.Fatalf("unknown verb: %v", err)
	}
	if _, err := Trust(options, trustAdd("0101"), accept); !errors.Is(err, anchor.ErrUnreadable) {
		t.Fatalf("bad value: %v", err)
	}
	for _, value := range []string{"101", "102", "101"} {
		if _, err := Trust(options, trustAdd(value), accept); err != nil {
			t.Fatal(err)
		}
	}
	listed, err := ReadPolicyAsRoot(options)
	if err != nil || !slices.Equal(listed.Applied.Anchors[anchor.BackupGuest], []string{"101", "102"}) {
		t.Fatalf("listed %v %v", listed.Applied.Anchors, err)
	}
	if _, err := Trust(options, TrustRequest{Verb: TrustRemove, Kind: anchor.BackupGuest, Value: "103"}, accept); !errors.Is(err, anchor.ErrAbsent) {
		t.Fatalf("remove absent: %v", err)
	}
	if _, err := Trust(options, TrustRequest{Verb: TrustRemove, Kind: anchor.BackupGuest, Value: "101"}, accept); err != nil {
		t.Fatal(err)
	}
	// Ajouter une valeur déjà posée ne change rien : ni écriture ni trace.
	if len(traces) != 3 || !strings.Contains(traces[0], "trust add backup.guest 101") || !strings.Contains(traces[2], "trust remove backup.guest 101") {
		t.Fatalf("the journal of the system got %v", traces)
	}
	// L'échec de la trace n'annule pas le changement, il se rapporte.
	options.Audit = func(string) error { return errors.New("no journal socket") }
	result, err := Trust(options, trustAdd("104"), accept)
	if err != nil || result.AuditError == nil || !slices.Equal(result.After.Anchors[anchor.BackupGuest], []string{"102", "104"}) {
		t.Fatalf("audit failure: %+v %v", result, err)
	}
}

// identity.json réécrit par « policy migrate » reste à son propriétaire, en
// 0600, et aucun temporaire n'en traîne.
func TestMigratePolicy_KeepsTheIdentityOwnerAndModeAndLeavesNoTemporary(t *testing.T) {
	b := newOrderBenchWithRights(t, nil)
	before, err := os.Stat(filepath.Join(b.stateDir.Name(), "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	migrate(t, b)
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
		{"target repeated, same value", "target", "312"},
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

// B-M1 : restic.backup d'un invité demande vzdump à la porte sur le vmid de
// l'ordre ; backup.guest le borne comme backup.produce. Hors des ancres :
// refusé, la porte jamais jugée, restic jamais lancé. La portée service n'est pas bornée par
// cette ancre, même sur une machine qui n'en a posé aucune.
func TestR_A1_7_ResticBackupOfAGuestOutsideTheAnchorsNeverReachesTheGate(t *testing.T) {
	b := newResticBench(t, "restic.produce", "backup.produce=proxmox-vzdump")
	b.runner.restic.source.dialer = &refusingDialer{}
	b.provision(t, "nas", 8000, mustCertificate(t))
	gateAsked := 0
	b.runner.checks.vzdumpGate = func() string {
		gateAsked++
		return ""
	}
	guest := func(vmid int) agentwire.ResticBackupParams {
		return agentwire.ResticBackupParams{Target: resticTargetID, Scope: agentwire.ResticScopeVM, VMID: vmid, GuestType: agentwire.GuestQEMU}
	}
	refusedWithoutRunning := func(label string, params any, reason string) {
		t.Helper()
		expectResult(t, b.run(t, agentwire.KindResticBackup, params), agentwire.ActionRefused, reason)
		if gateAsked != 0 || len(b.restic.callsMade()) != 0 {
			t.Fatalf("%s: the gate judged %d times, restic ran %d times", label, gateAsked, len(b.restic.callsMade()))
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
	if gateAsked != 0 {
		t.Fatal("a service backup judged the gate")
	}

	// Le vmid ancré passe : la porte est enfin jugée.
	b.trust(t, map[string][]string{anchor.BackupGuest: {"105"}})
	expectResult(t, b.run(t, agentwire.KindResticBackup, guest(105)), agentwire.ActionSucceeded, "")
	if gateAsked == 0 {
		t.Fatal("an anchored guest did not reach the gate")
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
