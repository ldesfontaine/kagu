package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"maps"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ldesfontaine/kagu/internal/kit/testkit"
	"github.com/ldesfontaine/kagu/internal/wire/agentwire"
)

const (
	parcelSession = "session-de-test"
	archiveName   = "opencloud-20261021-030000.tar.age"
	keyName       = "opencloud-key-0123456789abcdef.age"
)

// Un faux contenu age : l'en-tête suffit à l'agent, qui n'a pas la clé.
func ageLike(text string) string {
	return ageHeader + text
}

// parcelServer sert un colis et exige le jeton de session et la version du
// protocole, comme la route du serveur. Il reçoit aussi un fichier téléversé
// (PUT) dans le colis « colis1 » et le garde, sommes vérifiées.
type parcelServer struct {
	files    map[string]string
	requests []string

	mu sync.Mutex
	// Ce que les PUT ont livré, par nom ; et ce que le serveur en a vu.
	uploaded map[string][]byte
	puts     []putRecord
	// putAnswers donne, dans l'ordre des PUT, ce que le serveur fait : 0 le
	// traite, un code HTTP le répond sans lire le corps, -1 coupe la connexion.
	putAnswers []int
}

// putRecord est ce qu'un PUT a montré au serveur.
type putRecord struct {
	name          string
	contentLength int64
	sum           string
	expect        string
}

func (p *parcelServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /agent/parcels/{parcel}/{name}", func(w http.ResponseWriter, r *http.Request) {
		p.requests = append(p.requests, r.PathValue("parcel")+"/"+r.PathValue("name"))
		if r.Header.Get(agentwire.HeaderProtocol) != agentwire.ProtocolVersion || r.Header.Get("Authorization") != "Bearer "+parcelSession {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		content, found := p.files[r.PathValue("name")]
		if !found || r.PathValue("parcel") != "colis1" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(content))
	})
	mux.HandleFunc("PUT /agent/parcels/{parcel}/{name}", p.put)
	return mux
}

func (p *parcelServer) put(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	attempt := len(p.puts)
	p.puts = append(p.puts, putRecord{
		name: r.PathValue("name"), contentLength: r.ContentLength,
		sum: r.Header.Get(agentwire.HeaderParcelSHA256), expect: r.Header.Get("Expect"),
	})
	answer := 0
	if attempt < len(p.putAnswers) {
		answer = p.putAnswers[attempt]
	}
	p.mu.Unlock()
	switch {
	case answer < 0:
		connection, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			_ = connection.Close()
		}
		return
	case answer > 0:
		w.WriteHeader(answer)
		_, _ = w.Write([]byte(`{"error":"refused"}`))
		return
	}
	if r.Header.Get(agentwire.HeaderProtocol) != agentwire.ProtocolVersion || r.Header.Get("Authorization") != "Bearer "+parcelSession {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if r.PathValue("parcel") != "colis1" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	content, err := io.ReadAll(r.Body)
	sum := sha256.Sum256(content)
	if err != nil || hex.EncodeToString(sum[:]) != r.Header.Get(agentwire.HeaderParcelSHA256) || int64(len(content)) != r.ContentLength {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}
	p.mu.Lock()
	if p.uploaded == nil {
		p.uploaded = map[string][]byte{}
	}
	p.uploaded[r.PathValue("name")] = content
	p.mu.Unlock()
	w.WriteHeader(http.StatusCreated)
}

func (p *parcelServer) received() (map[string][]byte, []putRecord) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return maps.Clone(p.uploaded), slices.Clone(p.puts)
}

func (p *parcelServer) client(t *testing.T) *Client {
	t.Helper()
	server := httptest.NewServer(p.handler())
	t.Cleanup(server.Close)
	client, err := NewClient(server.URL, "", "v0.0.1", false)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func listed(files map[string]string) []agentwire.ParcelFile {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	slices.Sort(names)
	out := make([]agentwire.ParcelFile, 0, len(names))
	for _, name := range names {
		sum := sha256.Sum256([]byte(files[name]))
		out = append(out, agentwire.ParcelFile{Name: name, Size: int64(len(files[name])), SHA256: hex.EncodeToString(sum[:])})
	}
	return out
}

// backupDir rend un dossier de destination hors du dossier d'essai, d'un
// nom que le motif d'un chemin de droit accepte.
func backupDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "backups")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// sourceFor branche receiveBackup sur un faux serveur, sans passer par le juge.
func sourceFor(t *testing.T, server *parcelServer) *fetcher {
	t.Helper()
	source := &fetcher{}
	source.use(server.client(t))
	source.setSession(parcelSession)
	return source
}

func TestBackupReceive_WritesVerifiesAndReportsEachFile(t *testing.T) {
	dir := filepath.Join(backupDir(t), "opencloud")
	files := map[string]string{archiveName: ageLike("sauvegarde chiffrée de test"), keyName: ageLike("clé scellée de test")}
	server := &parcelServer{files: files}

	output, err := receiveBackup(context.Background(), discardLogger, sourceFor(t, server), filepath.Dir(dir), agentwire.BackupReceiveParams{Parcel: "colis1", Path: dir, Files: listed(files)})
	if err != nil {
		t.Fatal(err)
	}
	wantLines := []string{}
	for _, file := range listed(files) {
		wantLines = append(wantLines, "written "+file.Name+" "+itoa(file.Size)+" sha256:"+file.SHA256)
	}
	var gotLines []string
	for _, line := range output {
		gotLines = append(gotLines, line.Line)
	}
	if !slices.Equal(gotLines, wantLines) {
		t.Fatalf("output %v, want %v", gotLines, wantLines)
	}
	// Le dossier a été créé, fermé aux autres comptes ; les fichiers aussi.
	info, err := os.Stat(dir)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("dir %v %v", info, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 2 {
		t.Fatalf("entries %v %v", entries, err)
	}
	for _, entry := range entries {
		info, _ := entry.Info()
		content, _ := os.ReadFile(filepath.Join(dir, entry.Name()))
		if info.Mode().Perm() != 0o600 || string(content) != files[entry.Name()] || strings.HasSuffix(entry.Name(), partSuffix) {
			t.Errorf("%s: %v %q", entry.Name(), info.Mode(), content)
		}
	}
}

// Ce que le disque garde doit être ce que l'ordre a signé : une somme qui
// diffère, une taille de trop ou de moins, et rien n'est gardé.
func TestBackupReceive_DigestMismatchLeavesNoFile(t *testing.T) {
	for name, change := range map[string]func(file *agentwire.ParcelFile){
		"another sum":  func(file *agentwire.ParcelFile) { file.SHA256 = strings.Repeat("0", 64) },
		"size too big": func(file *agentwire.ParcelFile) { file.Size += 5 },
		"size too low": func(file *agentwire.ParcelFile) { file.Size -= 5 },
	} {
		t.Run(name, func(t *testing.T) {
			dir := backupDir(t)
			files := map[string]string{archiveName: ageLike("sauvegarde chiffrée de test")}
			files2 := listed(files)
			change(&files2[0])
			_, err := receiveBackup(context.Background(), discardLogger, sourceFor(t, &parcelServer{files: files}), dir, agentwire.BackupReceiveParams{Parcel: "colis1", Path: dir, Files: files2})
			assertReason(t, err, agentwire.ReasonDigestMismatch)
			assertDirEmpty(t, dir)
		})
	}
}

func TestBackupReceive_RefusesANonAgeFile(t *testing.T) {
	dir := backupDir(t)
	files := map[string]string{archiveName: "#!/bin/sh\necho pas du age\n"}
	_, err := receiveBackup(context.Background(), discardLogger, sourceFor(t, &parcelServer{files: files}), dir, agentwire.BackupReceiveParams{Parcel: "colis1", Path: dir, Files: listed(files)})
	assertReason(t, err, agentwire.ReasonNotAgeFile)
	assertDirEmpty(t, dir)
}

func TestBackupReceive_ReportsADownloadThatFails(t *testing.T) {
	dir := backupDir(t)
	files := map[string]string{archiveName: ageLike("x")}
	server := &parcelServer{files: map[string]string{}}
	_, err := receiveBackup(context.Background(), discardLogger, sourceFor(t, server), dir, agentwire.BackupReceiveParams{Parcel: "colis1", Path: dir, Files: listed(files)})
	assertReason(t, err, agentwire.ReasonDownloadFailed)
	assertDirEmpty(t, dir)

	// Hors connexion, aucun jeton : rien n'est demandé au serveur.
	offline := &fetcher{}
	offline.use(server.client(t))
	before := len(server.requests)
	_, err = receiveBackup(context.Background(), discardLogger, offline, dir, agentwire.BackupReceiveParams{Parcel: "colis1", Path: dir, Files: listed(files)})
	assertReason(t, err, agentwire.ReasonDownloadFailed)
	if len(server.requests) != before {
		t.Fatalf("a request left without a session: %v", server.requests)
	}
}

// Un dossier que l'unité de l'agent ne laisse pas écrire (0500) est dit
// path_unwritable. Root passe outre les droits d'un dossier : le test ne dit
// rien de lui.
func TestBackupReceive_ReportsAnUnwritablePath(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes anywhere")
	}
	dir := backupDir(t)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	files := map[string]string{archiveName: ageLike("x")}
	_, err := receiveBackup(context.Background(), discardLogger, sourceFor(t, &parcelServer{files: files}), dir, agentwire.BackupReceiveParams{Parcel: "colis1", Path: dir, Files: listed(files)})
	assertReason(t, err, agentwire.ReasonPathUnwritable)
}

// L'élagage garde les plus récentes par le nom, et ne touche à rien d'autre :
// ni une clé déposée, ni un .part, ni un fichier de l'opérateur, ni un
// dossier de la bonne forme.
func TestBackupPrune_KeepsTheNewestAndTouchesNothingElse(t *testing.T) {
	dir := backupDir(t)
	backups := []string{
		"opencloud-20261018-030000.tar.age", "opencloud-20261019-030000.tar.age", "opencloud-20261020-030000.tar.age",
		"opencloud-20261021-030000.tar.age",
	}
	others := []string{keyName, ".opencloud-20261001-030000.tar.age.part", "notes.txt", "opencloud-20261001-030000.tar", "opencloud-2026-030000.tar.age"}
	for _, name := range append(slices.Clone(backups), others...) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "opencloud-20260101-030000.tar.age"), 0o700); err != nil {
		t.Fatal(err)
	}

	output, err := pruneBackups(dir, agentwire.BackupPruneParams{Path: dir, Prefix: "opencloud", Keep: 2})
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, line := range output {
		lines = append(lines, line.Line)
	}
	want := []string{"removed opencloud-20261018-030000.tar.age", "removed opencloud-20261019-030000.tar.age", "kept 2"}
	if !slices.Equal(lines, want) {
		t.Fatalf("output %v, want %v", lines, want)
	}
	left, _ := fs.ReadDir(os.DirFS(dir), ".")
	var names []string
	for _, entry := range left {
		names = append(names, entry.Name())
	}
	slices.Sort(names)
	wantLeft := append([]string{backups[2], backups[3], "opencloud-20260101-030000.tar.age"}, others...)
	slices.Sort(wantLeft)
	if !slices.Equal(names, wantLeft) {
		t.Fatalf("left %v, want %v", names, wantLeft)
	}

	// Rien à élaguer, ou un dossier qui n'existe pas encore : réussi.
	if output, err := pruneBackups(dir, agentwire.BackupPruneParams{Path: dir, Prefix: "opencloud", Keep: 30}); err != nil || output[len(output)-1].Line != "kept 2" {
		t.Fatalf("nothing to prune: %v %v", output, err)
	}
	if output, err := pruneBackups(dir, agentwire.BackupPruneParams{Path: filepath.Join(dir, "absent"), Prefix: "opencloud", Keep: 3}); err != nil || output[0].Line != "kept 0" {
		t.Fatalf("a folder that does not exist: %v %v", output, err)
	}
}

// Deux plans partagent un dossier : l'élagage de l'un ne touche ni aux
// archives de l'autre, ni à celles d'un préfixe qui commence pareil.
func TestBackupPrune_OnlyTouchesItsOwnPrefix(t *testing.T) {
	dir := backupDir(t)
	names := []string{
		"opencloud-20261001-030000.tar.age", "opencloud-20261002-030000.tar.age", "opencloud-20261003-030000.tar.age",
		"pve-20261001-030000.tar.age", "pve-20261002-030000.tar.age", "pve-20261003-030000.tar.age",
		"pve-vm-100-20261001-030000.tar.age", "pve-vm-100-20261002-030000.tar.age",
		"pve2-20261001-030000.tar.age",
	}
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	output, err := pruneBackups(dir, agentwire.BackupPruneParams{Path: dir, Prefix: "pve", Keep: 1})
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, line := range output {
		lines = append(lines, line.Line)
	}
	if want := []string{"removed pve-20261001-030000.tar.age", "removed pve-20261002-030000.tar.age", "kept 1"}; !slices.Equal(lines, want) {
		t.Fatalf("output %v, want %v", lines, want)
	}
	left, _ := os.ReadDir(dir)
	if len(left) != len(names)-2 {
		t.Fatalf("%d files left, want %d", len(left), len(names)-2)
	}

	// Le préfixe d'une machine virtuelle ne prend que ses archives.
	if _, err := pruneBackups(dir, agentwire.BackupPruneParams{Path: dir, Prefix: "pve-vm-100", Keep: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "pve-vm-100-20261001-030000.tar.age")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the older archive of pve-vm-100 stayed: %v", err)
	}
	for _, name := range []string{"opencloud-20261001-030000.tar.age", "pve-20261003-030000.tar.age", "pve-vm-100-20261002-030000.tar.age", "pve2-20261001-030000.tar.age"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s was touched: %v", name, err)
		}
	}
}

// Le préfixe de la base et un sujet qui commence pareil (« opencloud-x ») :
// aucun n'élague l'autre, et la clé déposée ne part jamais.
func TestBackupPrune_TheDatabasePrefixAndALookalikeStayApart(t *testing.T) {
	dir := backupDir(t)
	database := []string{"opencloud-20261001-030000.tar.age", "opencloud-20261002-030000.tar.age"}
	lookalike := []string{"opencloud-x-20261001-030000.tar.age", "opencloud-x-20261002-030000.tar.age", "opencloud-x-20261003-030000.tar.age"}
	for _, name := range append(append([]string{keyName}, database...), lookalike...) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	prune := func(prefix string) []string {
		t.Helper()
		output, err := pruneBackups(dir, agentwire.BackupPruneParams{Path: dir, Prefix: prefix, Keep: 1})
		if err != nil {
			t.Fatal(err)
		}
		var lines []string
		for _, line := range output {
			lines = append(lines, line.Line)
		}
		return lines
	}
	if got, want := prune("opencloud"), []string{"removed " + database[0], "kept 1"}; !slices.Equal(got, want) {
		t.Fatalf("opencloud: %v, want %v", got, want)
	}
	if got, want := prune("opencloud-x"), []string{"removed " + lookalike[0], "removed " + lookalike[1], "kept 1"}; !slices.Equal(got, want) {
		t.Fatalf("opencloud-x: %v, want %v", got, want)
	}
	for _, name := range []string{keyName, database[1], lookalike[2]} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s was touched: %v", name, err)
		}
	}
}

// Un ordre d'élagage sans préfixe, ou avec un préfixe qui n'en est pas un,
// est un ordre faux : rien n'est effacé.
func TestBackupPrune_WithoutAValidPrefixIsABadOrder(t *testing.T) {
	b := newLongBench(t, nil)
	names := []string{"opencloud-20261001-030000.tar.age", "opencloud-20261002-030000.tar.age"}
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(b.dir, name), []byte(ageHeader), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for name, prefix := range map[string]string{"none": "", "a path": "../opencloud", "upper case": "OpenCloud", "a dash first": "-opencloud"} {
		b.runner.identity.LastOrderSeq = 0
		body := longOrder(1, agentwire.KindBackupPrune, agentwire.BackupPruneParams{Path: b.dir, Prefix: prefix, Keep: 1})
		b.runner.receive(b.signed(t, body))
		report := b.results.take()
		if report == nil || len(report.Results) != 1 || report.Results[0].State != agentwire.ActionFailed || report.Results[0].Reason != agentwire.ReasonBadOrder {
			t.Fatalf("%s: %+v", name, report)
		}
	}
	if entries, err := os.ReadDir(b.dir); err != nil || len(entries) != len(names) {
		t.Fatalf("a bad order touched the folder: %d entries (%v)", len(entries), err)
	}
}

// Beaucoup à effacer : la sortie reste dans ce qu'un rapport accepte, sans
// quoi le serveur refuserait le rapport entier.
func TestBackupPrune_KeepsItsOutputWithinWhatAReportAccepts(t *testing.T) {
	dir := backupDir(t)
	for day := range 120 {
		name := "opencloud-2026" + twoDigits(1+day/28) + twoDigits(1+day%28) + "-030000.tar.age"
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	output, err := pruneBackups(dir, agentwire.BackupPruneParams{Path: dir, Prefix: "opencloud", Keep: 1})
	if err != nil || len(output) > agentwire.MaxOutputLines {
		t.Fatalf("%d lines, %v", len(output), err)
	}
	last := output[len(output)-1].Line
	if last != "kept 1" || !strings.HasPrefix(output[len(output)-2].Line, "removed ") {
		t.Fatalf("tail %q", last)
	}
	if left, _ := os.ReadDir(dir); len(left) != 1 {
		t.Fatalf("%d files left", len(left))
	}
}

func twoDigits(n int) string {
	return string([]byte{byte('0' + n/10), byte('0' + n%10)})
}

func itoa(n int64) string {
	data, _ := json.Marshal(n)
	return string(data)
}

func assertReason(t *testing.T, err error, reason string) {
	t.Helper()
	if result := resultOf("run", nil, err); result.State != agentwire.ActionFailed || result.Reason != reason {
		t.Fatalf("result %+v (%v), want failed %s", result, err, reason)
	}
}

func assertDirEmpty(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		var names []string
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Fatalf("the folder holds %v (%v)", names, err)
	}
}

// longBench est un juge d'ordres dont le worker tourne et dont les colis
// viennent d'un faux serveur ; l'agent a le droit de recevoir sous dir.
type longBench struct {
	*orderBench
	dir    string
	server *parcelServer
}

func newLongBench(t *testing.T, files map[string]string) *longBench {
	t.Helper()
	dir := backupDir(t)
	b := newOrderBenchWithRights(t, []string{"observe", "backup.receive=" + dir})
	server := &parcelServer{files: files}
	b.runner.fetch.use(server.client(t))
	b.runner.fetch.setSession(parcelSession)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { b.runner.worker.run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return &longBench{orderBench: b, dir: dir, server: server}
}

// signed encode et signe un ordre comme le serveur.
func (b *orderBench) signed(t *testing.T, body agentwire.OrderBody) []byte {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(agentwire.SignedOrder{Body: encoded, Signature: ed25519.Sign(b.private, agentwire.OrderSigningBytes(encoded))})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// until reçoit les résultats rapportés jusqu'à celui d'un état fini pour ce
// run ; il se règle sur le réveil de la boucle du flux, pas sur une pause.
func (b *orderBench) until(t *testing.T, runID string) []agentwire.ActionResult {
	t.Helper()
	var seen []agentwire.ActionResult
	timeout := time.After(10 * time.Second)
	for {
		if report := b.results.take(); report != nil {
			for _, result := range report.Results {
				if result.RunID != runID {
					continue
				}
				seen = append(seen, result)
				if result.State != agentwire.ActionAccepted {
					return seen
				}
			}
		}
		select {
		case <-b.results.ready:
		case <-timeout:
			t.Fatalf("no final result for %s, seen %+v", runID, seen)
		}
	}
}

func longOrder(seq int64, kind agentwire.Kind, params any) agentwire.OrderBody {
	body := order(seq)
	body.Kind = kind
	body.Params, _ = json.Marshal(params)
	return body
}

// Un ordre long est accepté tout de suite, puis fait par le worker : la
// réponse finale suit « accepté », jamais l'inverse.
func TestBackupReceive_IsAcceptedThenDoneByTheWorker(t *testing.T) {
	files := map[string]string{archiveName: ageLike("sauvegarde chiffrée de test")}
	b := newLongBench(t, files)
	body := longOrder(1, agentwire.KindBackupReceive, agentwire.BackupReceiveParams{Parcel: "colis1", Path: b.dir, Files: listed(files)})
	b.runner.receive(b.signed(t, body))
	results := b.until(t, body.RunID)
	if len(results) != 2 || results[0].State != agentwire.ActionAccepted || results[1].State != agentwire.ActionSucceeded {
		t.Fatalf("results %+v", results)
	}
	if !strings.HasPrefix(results[1].Output[0].Line, "written "+archiveName) {
		t.Fatalf("output %+v", results[1].Output)
	}
	if content, err := os.ReadFile(filepath.Join(b.dir, archiveName)); err != nil || string(content) != files[archiveName] {
		t.Fatalf("file %q %v", content, err)
	}
	if saved, _ := LoadIdentity(b.stateDir); saved.LastOrderSeq != 1 {
		t.Fatalf("seq %d", saved.LastOrderSeq)
	}
}

// Le juge applique le chemin du droit : un dossier hors de lui est refusé
// tout de suite, sans être accepté, et rien n'est demandé au serveur.
func TestBackupReceive_RefusesAPathOutsideItsRight(t *testing.T) {
	files := map[string]string{archiveName: ageLike("x")}
	b := newLongBench(t, files)
	for name, path := range map[string]string{"a neighbour": b.dir + "2", "above": filepath.Dir(b.dir), "dots": b.dir + "/../etc"} {
		body := longOrder(1, agentwire.KindBackupReceive, agentwire.BackupReceiveParams{Parcel: "colis1", Path: path, Files: listed(files)})
		b.runner.receive(b.signed(t, body))
		report := b.results.take()
		if report == nil || len(report.Results) != 1 || report.Results[0].State != agentwire.ActionRefused || report.Results[0].Reason != agentwire.ReasonPathOutsideRight {
			t.Fatalf("%s: %+v", name, report)
		}
		b.runner.identity.LastOrderSeq = 0
	}
	prune := longOrder(1, agentwire.KindBackupPrune, agentwire.BackupPruneParams{Path: b.dir + "2", Prefix: "opencloud", Keep: 3})
	b.runner.receive(b.signed(t, prune))
	if report := b.results.take(); report == nil || report.Results[0].Reason != agentwire.ReasonPathOutsideRight {
		t.Fatalf("prune: %+v", report)
	}
	if len(b.server.requests) != 0 {
		t.Fatalf("the server was asked: %v", b.server.requests)
	}
}

// Un lien symbolique posé sous le chemin du droit ne fait pas sortir
// l'écriture ni l'élagage : le chemin qui le traverse est refusé, et rien
// n'est écrit ni effacé dans le dossier vers lequel il pointe.
func TestBackupReceive_RefusesASymlinkLeavingTheRight(t *testing.T) {
	granted := backupDir(t)
	outside := backupDir(t)
	if err := os.Symlink(outside, filepath.Join(granted, "sortie")); err != nil {
		t.Fatal(err)
	}
	old := "opencloud-20200101-030000.tar.age"
	for _, name := range []string{old, "opencloud-20200102-030000.tar.age"} {
		if err := os.WriteFile(filepath.Join(outside, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{archiveName: ageLike("sauvegarde chiffrée de test")}
	server := &parcelServer{files: files}
	for _, destination := range []string{filepath.Join(granted, "sortie"), filepath.Join(granted, "sortie", "nuit")} {
		_, err := receiveBackup(context.Background(), discardLogger, sourceFor(t, server), granted, agentwire.BackupReceiveParams{Parcel: "colis1", Path: destination, Files: listed(files)})
		assertReason(t, err, agentwire.ReasonPathOutsideRight)
		_, err = pruneBackups(granted, agentwire.BackupPruneParams{Path: destination, Prefix: "opencloud", Keep: 1})
		assertReason(t, err, agentwire.ReasonPathOutsideRight)
	}
	if len(server.requests) != 0 {
		t.Fatalf("the server was asked: %v", server.requests)
	}
	left, err := os.ReadDir(outside)
	if err != nil || len(left) != 2 || left[0].Name() != old {
		t.Fatalf("the folder behind the link changed: %v %v", left, err)
	}

	// Un .part laissé en lien vers un fichier du dossier n'est pas suivi :
	// il est remplacé, la cible reste intacte.
	target := filepath.Join(granted, "notes.txt")
	if err := os.WriteFile(target, []byte("à garder"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(granted, partPrefix+archiveName+partSuffix)); err != nil {
		t.Fatal(err)
	}
	if _, err := receiveBackup(context.Background(), discardLogger, sourceFor(t, server), granted, agentwire.BackupReceiveParams{Parcel: "colis1", Path: granted, Files: listed(files)}); err != nil {
		t.Fatal(err)
	}
	if content, _ := os.ReadFile(target); string(content) != "à garder" {
		t.Fatalf("the link was followed: %q", content)
	}
}

// Sans le droit backup.receive, l'ordre est refusé par le juge ; avec lui,
// des paramètres qui ne sont pas ceux d'une sauvegarde sont un ordre faux.
func TestBackupReceive_RefusesWhatIsNotABackup(t *testing.T) {
	b := newOrderBench(t)
	body := longOrder(1, agentwire.KindBackupReceive, agentwire.BackupReceiveParams{Parcel: "colis1", Path: "/srv/backups"})
	if result := b.send(t, body, b.private); result.Reason != "right_missing:backup.receive" {
		t.Fatalf("without the right: %+v", result)
	}
	files := map[string]string{"autre.txt": "x", "../opencloud-20261021-030000.tar.age": "x"}
	granted := newLongBench(t, files)
	for name, params := range map[string]agentwire.BackupReceiveParams{
		"no files":        {Parcel: "colis1", Path: granted.dir},
		"a free name":     {Parcel: "colis1", Path: granted.dir, Files: listed(map[string]string{"autre.txt": "x"})},
		"a path name":     {Parcel: "colis1", Path: granted.dir, Files: []agentwire.ParcelFile{{Name: "../" + archiveName, Size: 1, SHA256: strings.Repeat("a", 64)}}},
		"no parcel":       {Path: granted.dir, Files: listed(map[string]string{archiveName: "x"})},
		"a bad sum":       {Parcel: "colis1", Path: granted.dir, Files: []agentwire.ParcelFile{{Name: archiveName, Size: 1, SHA256: "xyz"}}},
		"a negative size": {Parcel: "colis1", Path: granted.dir, Files: []agentwire.ParcelFile{{Name: archiveName, Size: -1, SHA256: strings.Repeat("a", 64)}}},
	} {
		granted.runner.receive(granted.signed(t, longOrder(1, agentwire.KindBackupReceive, params)))
		report := granted.results.take()
		if report == nil || report.Results[0].State != agentwire.ActionFailed || report.Results[0].Reason != agentwire.ReasonBadOrder {
			t.Fatalf("%s: %+v", name, report)
		}
		granted.runner.identity.LastOrderSeq = 0
	}
}

// Le worker ne fait qu'un ordre long à la fois, dans l'ordre d'arrivée ; le
// juge, lui, ne les attend pas. Piloté par canaux.
func TestOrderWorker_RunsLongOrdersOneAtATime(t *testing.T) {
	worker := newOrderWorker()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { worker.run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	started := make(chan string, 4)
	release := make(chan struct{})
	finished := make(chan string, 4)
	job := func(name string) func(context.Context) {
		return func(context.Context) {
			started <- name
			<-release
			finished <- name
		}
	}
	for _, name := range []string{"first", "second", "third"} {
		if !worker.submit(job(name)) {
			t.Fatalf("%s was not queued", name)
		}
	}
	if got := <-started; got != "first" {
		t.Fatalf("started %s", got)
	}
	select {
	case got := <-started:
		t.Fatalf("%s started while the first still runs", got)
	default:
	}
	var order []string
	for range 3 {
		release <- struct{}{}
		order = append(order, <-finished)
	}
	if strings.Join(order, ",") != "first,second,third" {
		t.Fatalf("order %v", order)
	}
	if got := <-started; got != "second" {
		t.Fatalf("started %s", got)
	}
}

func TestOrderWorker_RefusesWhenItsQueueIsFull(t *testing.T) {
	worker := newOrderWorker()
	for range workerQueue {
		if !worker.submit(func(context.Context) {}) {
			t.Fatal("the queue refused before it was full")
		}
	}
	if worker.submit(func(context.Context) {}) {
		t.Fatal("a full queue accepted one more")
	}
}

// Le secret signé avec un ordre qui en porte passe le juge, intact ; sur un
// genre qui n'en porte pas, il fait refuser l'ordre (R-A1-4). Dans les deux
// cas il ne s'écrit nulle part : ni dans le journal de l'agent, ni dans
// l'identité sur disque, ni dans le résultat rapporté.
func TestJudge_KeepsTheSecretAndNeverLogsIt(t *testing.T) {
	var logs bytes.Buffer
	b := newOrderBenchWithRights(t, []string{"observe", "docker.deploy"})
	b.runner.logger = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	const value = "PHRASE=une valeur de test qui ne doit jamais sortir" // gitleaks:allow
	body := longOrder(1, agentwire.KindDockerDeploy, agentwire.DockerParams{ServiceID: "svc_1", Project: "wiki", Compose: "x", EnvSent: true})
	body.Secret, _ = json.Marshal(agentwire.DockerSecret{Env: value})

	judged, reason := b.runner.judge(b.signedOrder(t, body))
	if reason != "" || judged.Secret != (agentwire.DockerSecret{Env: value}) {
		t.Fatalf("judged %+v %q", judged, reason)
	}
	b.runner.receive(b.signed(t, order(2)))
	b.results.take()
	withSecret := order(3)
	withSecret.Secret = body.Secret
	b.runner.receive(b.signed(t, withSecret))
	report := b.results.take()
	reported, _ := json.Marshal(report)
	if report == nil || report.Results[0].Reason != agentwire.ReasonBadOrder || strings.Contains(string(reported), "PHRASE") {
		t.Fatalf("report %s", reported)
	}
	if strings.Contains(logs.String(), "PHRASE") || strings.Contains(logs.String(), "valeur de test") {
		t.Fatalf("the secret reached the log: %s", logs.String())
	}
	identity, _ := b.stateDir.ReadFile(identityFile)
	if strings.Contains(string(identity), "PHRASE") {
		t.Fatal("the secret reached the identity file")
	}
}

func (b *orderBench) signedOrder(t *testing.T, body agentwire.OrderBody) agentwire.SignedOrder {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return agentwire.SignedOrder{Body: encoded, Signature: ed25519.Sign(b.private, agentwire.OrderSigningBytes(encoded))}
}

// R-E3-17 : une archive reçue ne remplace jamais une archive gardée ; une
// archive plus grande que la taille annoncée est coupée et refusée ; la base et
// le pare-feu ont un plafond sur la taille annoncée, l'archive d'un invité non.
func TestR_E3_17(t *testing.T) {
	t.Run("a name already there is refused and the kept archive is intact", func(t *testing.T) {
		dir := backupDir(t)
		kept := ageLike("l'archive gardée")
		if err := os.WriteFile(filepath.Join(dir, archiveName), []byte(kept), 0o600); err != nil {
			t.Fatal(err)
		}
		files := map[string]string{archiveName: ageLike("une autre archive, même nom")}
		_, err := receiveBackup(context.Background(), discardLogger, sourceFor(t, &parcelServer{files: files}), dir, agentwire.BackupReceiveParams{Parcel: "colis1", Path: dir, Files: listed(files)})
		assertReason(t, err, agentwire.ReasonPathExists)
		assertOnlyFile(t, dir, archiveName, kept)
	})

	t.Run("a longer file than announced is cut and refused, nothing is renamed", func(t *testing.T) {
		dir := backupDir(t)
		content := ageLike(strings.Repeat("x", 4096))
		files := map[string]string{archiveName: content}
		announced := listed(files)
		announced[0].Size = 100
		_, err := receiveBackup(context.Background(), discardLogger, sourceFor(t, &parcelServer{files: files}), dir, agentwire.BackupReceiveParams{Parcel: "colis1", Path: dir, Files: announced})
		assertReason(t, err, agentwire.ReasonDigestMismatch)
		assertDirEmpty(t, dir)
	})

	t.Run("a refused name leaves the sealed key written and no part behind", func(t *testing.T) {
		dir := backupDir(t)
		kept := ageLike("l'archive gardée")
		if err := os.WriteFile(filepath.Join(dir, archiveName), []byte(kept), 0o600); err != nil {
			t.Fatal(err)
		}
		files := map[string]string{archiveName: ageLike("autre"), keyName: ageLike("clé")}
		_, err := receiveBackup(context.Background(), discardLogger, sourceFor(t, &parcelServer{files: files}), dir, agentwire.BackupReceiveParams{Parcel: "colis1", Path: dir, Files: listed(files)})
		assertReason(t, err, agentwire.ReasonPathExists)
		content, readErr := os.ReadFile(filepath.Join(dir, archiveName))
		if readErr != nil || string(content) != kept {
			t.Fatalf("the kept archive changed: %q %v", content, readErr)
		}
		entries, _ := os.ReadDir(dir)
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), partSuffix) {
				t.Fatalf("a part is left: %s", entry.Name())
			}
		}
	})
}

// Le plafond se juge à l'ordre, sur le type d'archive que le serveur a signé :
// absent, c'est la base ; un type inconnu est un ordre faux ; le nom du fichier
// n'y est pour rien.
func TestR_E3_17_TheCapFollowsTheSignedArchiveKind(t *testing.T) {
	big := []agentwire.ParcelFile{{Name: archiveName, Size: maxAnnouncedSize + 1, SHA256: strings.Repeat("a", 64)}}
	atCap := []agentwire.ParcelFile{{Name: archiveName, Size: maxAnnouncedSize, SHA256: strings.Repeat("a", 64)}}
	cover := func(path string) (string, bool) { return path, true }
	writable := func(string) string { return "" }
	for name, test := range map[string]struct {
		archive string
		files   []agentwire.ParcelFile
		want    string
	}{
		"no kind is the database, over the cap": {"", big, agentwire.ReasonArchiveTooLarge},
		"the database over the cap":             {agentwire.ArchiveDatabase, big, agentwire.ReasonArchiveTooLarge},
		"the firewall over the cap":             {agentwire.ArchiveFirewall, big, agentwire.ReasonArchiveTooLarge},
		"the database at the cap":               {agentwire.ArchiveDatabase, atCap, ""},
		"a guest has no cap":                    {agentwire.ArchiveGuest, big, ""},
		"an unknown kind":                       {"vm", atCap, agentwire.ReasonBadOrder},
	} {
		t.Run(name, func(t *testing.T) {
			raw, err := json.Marshal(agentwire.BackupReceiveParams{Parcel: "colis1", Path: "/srv/backups", Files: test.files, Archive: test.archive})
			if err != nil {
				t.Fatal(err)
			}
			_, _, refused := readBackupReceive(judgedOf(t, agentwire.OrderBody{RunID: "run", Kind: agentwire.KindBackupReceive, Params: raw}), cover, writable, plenty)
			got := ""
			if refused != nil {
				got = refused.Reason
			}
			if got != test.want {
				t.Fatalf("reason %q, want %q", got, test.want)
			}
		})
	}
}

// assertFolderHolds : le dossier porte exactement ces fichiers, avec ces
// contenus.
func assertFolderHolds(t *testing.T, dir string, want map[string]string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != len(want) {
		t.Fatalf("the folder holds %v (%v), want %d files", entries, err, len(want))
	}
	for name, content := range want {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || string(got) != content {
			t.Fatalf("%s holds %q (%v), want %q", name, got, err, content)
		}
	}
}

func assertOnlyFile(t *testing.T, dir, name, content string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != name {
		t.Fatalf("the folder holds %v (%v), want only %s", entries, err, name)
	}
	got, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil || string(got) != content {
		t.Fatalf("%s holds %q (%v), want %q", name, got, err, content)
	}
}

func plenty(string) (uint64, error) { return math.MaxUint64, nil }

// La place se juge à l'ordre, avant tout téléchargement : la somme des tailles
// annoncées, clé scellée comprise, doit tenir dans la place libre du dossier ;
// la place illisible refuse aussi.
func TestBackupReceive_RefusesWhenAnnouncedSizeExceedsFreeSpace(t *testing.T) {
	files := map[string]string{archiveName: ageLike("sauvegarde chiffrée de test"), keyName: ageLike("clé scellée de test")}
	var total uint64
	for _, file := range listed(files) {
		total += uint64(file.Size)
	}
	unreadable := errors.New("statfs failed")
	for name, test := range map[string]struct {
		free   uint64
		err    error
		reason string
	}{
		"room for the sum":             {free: total, reason: ""},
		"one byte short of the sum":    {free: total - 1, reason: agentwire.ReasonDiskFull},
		"no room at all":               {free: 0, reason: agentwire.ReasonDiskFull},
		"unreadable room is a refusal": {err: unreadable, reason: agentwire.ReasonPathUnwritable},
	} {
		t.Run(name, func(t *testing.T) {
			b := newLongBench(t, files)
			var asked []string
			b.runner.checks.freeBytes = func(path string) (uint64, error) {
				asked = append(asked, path)
				return test.free, test.err
			}
			body := longOrder(1, agentwire.KindBackupReceive, agentwire.BackupReceiveParams{Parcel: "colis1", Path: b.dir, Files: listed(files)})
			b.runner.receive(b.signed(t, body))
			report := b.results.take()
			if report == nil || len(report.Results) == 0 {
				t.Fatalf("report %+v", report)
			}
			if len(asked) != 1 || asked[0] != b.dir {
				t.Errorf("the room was measured on %v, not the granted folder %s", asked, b.dir)
			}
			if test.reason == "" {
				if report.Results[0].State != agentwire.ActionAccepted {
					t.Fatalf("results %+v", report.Results)
				}
				return
			}
			if report.Results[0].State != agentwire.ActionRefused || report.Results[0].Reason != test.reason {
				t.Fatalf("results %+v", report.Results)
			}
			if len(b.server.requests) != 0 {
				t.Errorf("the server was asked: %v", b.server.requests)
			}
			assertDirEmpty(t, b.dir)
		})
	}
}

// receiveKey reçoit une clé scellée seule sous dir et rend les lignes du
// résultat.
func receiveKey(t *testing.T, logger *slog.Logger, dir, content string) []string {
	t.Helper()
	files := map[string]string{keyName: content}
	output, err := receiveBackup(context.Background(), logger, sourceFor(t, &parcelServer{files: files}), dir, agentwire.BackupReceiveParams{Parcel: "colis1", Path: dir, Files: listed(files)})
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, line := range output {
		lines = append(lines, line.Line)
	}
	return lines
}

// TU-19 : une clé neuve se pose sous le nom envoyé.
func TestBackupReceive_ANewKeyTakesItsName(t *testing.T) {
	dir := backupDir(t)
	key := ageLike("la clé")
	lines := receiveKey(t, discardLogger, dir, key)
	want := fmt.Sprintf("written %s %d sha256:%s", keyName, len(key), testkit.SHA256Hex([]byte(key)))
	if len(lines) != 1 || lines[0] != want {
		t.Fatalf("output %q, want %q", lines, want)
	}
	assertOnlyFile(t, dir, keyName, key)
}

// TU-19 : le serveur renvoie la même clé avec chaque sauvegarde ; rien ne
// s'écrit, le fichier gardé n'est pas touché, la réception réussit.
func TestBackupReceive_TheSameKeyAgainWritesNothing(t *testing.T) {
	dir := backupDir(t)
	key := ageLike("la clé")
	kept := filepath.Join(dir, keyName)
	if err := os.WriteFile(kept, []byte(key), 0o600); err != nil {
		t.Fatal(err)
	}
	past := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := os.Chtimes(kept, past, past); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(kept)
	if err != nil {
		t.Fatal(err)
	}
	lines := receiveKey(t, discardLogger, dir, key)
	want := fmt.Sprintf("unchanged %s %d sha256:%s", keyName, len(key), testkit.SHA256Hex([]byte(key)))
	if len(lines) != 1 || lines[0] != want {
		t.Fatalf("output %q, want %q", lines, want)
	}
	after, err := os.Stat(kept)
	if err != nil || !os.SameFile(before, after) || !after.ModTime().Equal(past) {
		t.Fatalf("the kept key was touched: %v %v", after.ModTime(), err)
	}
	assertOnlyFile(t, dir, keyName, key)
}

// TU-19 : une clé qui diffère sous le même nom ne remplace jamais la clé
// gardée ; elle se pose à côté sous la version libre suivante, et toutes
// s'accumulent. Le journal dit l'empreinte et les deux sommes, jamais le
// contenu.
func TestBackupReceive_ADifferentKeyNeverReplacesAKeptOne(t *testing.T) {
	dir := backupDir(t)
	first := ageLike("la clé d'origine")
	if err := os.WriteFile(filepath.Join(dir, keyName), []byte(first), 0o600); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{keyName: first}
	for version := 1; version <= 3; version++ {
		var journal bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&journal, nil))
		key := ageLike(fmt.Sprintf("clé envoyée %d", version))
		versioned := agentwire.BackupKeyFileVersion(keyName, version)
		lines := receiveKey(t, logger, dir, key)
		wantLines := []string{
			fmt.Sprintf("kept %s sha256:%s: the received key differs", keyName, testkit.SHA256Hex([]byte(first))),
			fmt.Sprintf("written %s %d sha256:%s", versioned, len(key), testkit.SHA256Hex([]byte(key))),
		}
		if !slices.Equal(lines, wantLines) {
			t.Fatalf("version %d: output %q, want %q", version, lines, wantLines)
		}
		logged := journal.String()
		for _, part := range []string{"level=WARN", "fingerprint=0123456789abcdef", "kept_sha256=" + testkit.SHA256Hex([]byte(first)), "received_sha256=" + testkit.SHA256Hex([]byte(key))} {
			if !strings.Contains(logged, part) {
				t.Fatalf("version %d: the journal %q misses %q", version, logged, part)
			}
		}
		if strings.Contains(logged, "clé") {
			t.Fatalf("the journal holds a key content: %q", logged)
		}
		want[versioned] = key
		assertFolderHolds(t, dir, want)
	}

	// Une clé déjà gardée sous une version ne s'écrit pas une seconde fois.
	again := want[agentwire.BackupKeyFileVersion(keyName, 2)]
	lines := receiveKey(t, discardLogger, dir, again)
	if len(lines) != 2 || lines[1] != fmt.Sprintf("unchanged %s %d sha256:%s", agentwire.BackupKeyFileVersion(keyName, 2), len(again), testkit.SHA256Hex([]byte(again))) {
		t.Fatalf("output %q", lines)
	}
	assertFolderHolds(t, dir, want)
}

// TU-19 : un ordre ne nomme jamais une version ; seul l'agent numérote.
func TestBackupReceive_RefusesAKeyVersionInTheOrder(t *testing.T) {
	files := map[string]string{agentwire.BackupKeyFileVersion(keyName, 1): ageLike("clé")}
	if isReceivable(agentwire.BackupReceiveParams{Parcel: "colis1", Path: "/srv/backups", Files: listed(files)}) {
		t.Fatal("a versioned key name was accepted from an order")
	}
}

// TU-19 : l'élagage ne touche aucune clé, quelle que soit sa version, même
// sous un préfixe qui ressemble au nom d'une clé.
func TestBackupPrune_NeverTouchesAKey(t *testing.T) {
	dir := backupDir(t)
	want := map[string]string{
		keyName: ageLike("k0"),
		agentwire.BackupKeyFileVersion(keyName, 1):  ageLike("k1"),
		agentwire.BackupKeyFileVersion(keyName, 2):  ageLike("k2"),
		agentwire.BackupKeyFileVersion(keyName, 10): ageLike("k10"),
		"opencloud-20261023-030000.tar.age":         ageLike("la plus récente"),
	}
	for name, content := range want {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "opencloud-20261021-030000.tar.age"), []byte(ageLike("ancienne")), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, prefix := range []string{"opencloud", "opencloud-key", "opencloud-key-0123456789abcdef"} {
		if _, err := pruneBackups(dir, agentwire.BackupPruneParams{Path: dir, Prefix: prefix, Keep: 1}); err != nil {
			t.Fatalf("%s: %v", prefix, err)
		}
	}
	assertFolderHolds(t, dir, want)
}

// TU-19 : deux réceptions croisées de clés différentes sous le même nom ne
// perdent rien : chacune prend son nom en exclusif. À lancer avec -race.
func TestPublishKey_ConcurrentReceptionsLoseNothing(t *testing.T) {
	dir := backupDir(t)
	const receptions = 8
	contents := map[string]bool{}
	var wait sync.WaitGroup
	errs := make(chan error, receptions)
	for index := range receptions {
		key := ageLike(fmt.Sprintf("clé %d", index))
		contents[key] = true
		part := fmt.Sprintf(".part-%d", index)
		if err := os.WriteFile(filepath.Join(dir, part), []byte(key), 0o600); err != nil {
			t.Fatal(err)
		}
		file := agentwire.ParcelFile{Name: keyName, Size: int64(len(key)), SHA256: testkit.SHA256Hex([]byte(key))}
		wait.Add(1)
		go func() {
			defer wait.Done()
			root, err := os.OpenRoot(dir)
			if err != nil {
				errs <- err
				return
			}
			defer root.Close()
			_, err = publishKey(discardLogger, root, part, file)
			errs <- err
		}()
	}
	wait.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != receptions {
		t.Fatalf("the folder holds %v (%v), want %d keys", entries, err, receptions)
	}
	for _, entry := range entries {
		content, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil || !agentwire.IsBackupKeyFile(entry.Name()) || !contents[string(content)] {
			t.Fatalf("%s holds %q (%v)", entry.Name(), content, err)
		}
		delete(contents, string(content))
	}
}
