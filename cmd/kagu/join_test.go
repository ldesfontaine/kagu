package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ldesfontaine/kagu/internal/edge/agent"
	"github.com/ldesfontaine/kagu/internal/edge/store"
	"github.com/ldesfontaine/kagu/internal/fact/machine"
	"github.com/ldesfontaine/kagu/internal/gesture/action"
	"github.com/ldesfontaine/kagu/internal/kit/ident"
	"github.com/ldesfontaine/kagu/internal/kit/step"
	"github.com/ldesfontaine/kagu/internal/wire/agentwire"
)

// Les serveurs TLS des bancs ont tous le certificat de test de httptest :
// le magasin du système de ce binaire de test est ce seul certificat, lu
// une fois, avant toute connexion. join ne connaît que les autorités du
// système, comme sur une vraie machine.
func TestMain(m *testing.M) {
	trusted := httptest.NewTLSServer(http.NotFoundHandler())
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: trusted.Certificate().Raw})
	trusted.Close()
	dir, err := os.MkdirTemp("", "kgtls")
	if err != nil {
		panic(err)
	}
	bundle := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(bundle, certificate, 0o600); err != nil {
		panic(err)
	}
	if err := os.Setenv("SSL_CERT_FILE", bundle); err != nil {
		panic(err)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// joinBench est une machine qui s'ajoute (le faux système de setup, sans
// serveur) et, ailleurs, un vrai serve joint en HTTPS au travers d'un
// intermédiaire qui peut remplacer la clé du serveur.
type joinBench struct {
	*setupBench
	db     *store.DB
	server *components
	proxy  *keyProxy
	url    string
	token  string
	key    string
}

// keyProxy relaie tout vers serve et remplace la clé du serveur là où on le
// lui dit ; il compte les enrôlements qui passent : un jeton parti se voit.
type keyProxy struct {
	next        http.Handler
	forged      string
	inServerKey bool
	inEnroll    bool
	enrollments atomic.Int32
}

func (p *keyProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/agent/enroll" {
		p.enrollments.Add(1)
	}
	recorded := httptest.NewRecorder()
	p.next.ServeHTTP(recorded, r)
	body := recorded.Body.Bytes()
	switch {
	case r.URL.Path == agentwire.ServerKeyRoute && p.inServerKey:
		body, _ = json.Marshal(agentwire.ServerKeyResponse{ServerKey: p.forged})
	case r.URL.Path == "/agent/enroll" && p.inEnroll && recorded.Code == http.StatusCreated:
		var answer agentwire.EnrollResponse
		_ = json.Unmarshal(body, &answer)
		answer.ServerKey = p.forged
		body, _ = json.Marshal(answer)
	}
	w.WriteHeader(recorded.Code)
	_, _ = w.Write(body)
}

func newJoinBench(t *testing.T) *joinBench {
	t.Helper()
	b := &joinBench{setupBench: newSetupBench(t)}
	b.system.server = false
	serverState := filepath.Join(b.dir, "serve")
	if err := os.Mkdir(serverState, 0o700); err != nil {
		t.Fatal(err)
	}
	db, parts, srv := realServerLogging(t, serverState, slog.New(slog.NewTextHandler(b.logs, nil)))
	parts.actions.SetKey(action.GenerateKey())
	forged, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	b.db, b.server = db, parts
	b.proxy = &keyProxy{next: srv, forged: base64.StdEncoding.EncodeToString(forged)}
	remote := httptest.NewTLSServer(b.proxy)
	t.Cleanup(remote.Close)
	b.url = remote.URL
	if b.token, _, err = parts.machines.CreateToken(context.Background(), "web-1", machine.RoleGeneric, nil); err != nil {
		t.Fatal(err)
	}
	_, b.key, _ = parts.actions.ServerKey()
	return b
}

// line est la ligne d'ajout de l'écran, sans le jeton.
func (b *joinBench) line(set string) []string {
	return []string{"--server", b.url, "--server-key", b.key, "--rights", set}
}

// run joue join en root ; secret est le terminal sans écho (le jeton),
// terminal celui de la question.
func (b *joinBench) run(secret, terminal terminalOpener, args ...string) (string, error) {
	b.t.Helper()
	var out bytes.Buffer
	paths := b.paths
	paths.stateFile = ""
	run := joinRun{
		setupRun: setupRun{
			out: &out, openTerminal: terminal, euid: 0, system: b.system, paths: paths,
			place: func(*os.Root) (agent.PolicyPlace, error) { return b.place, nil }, wait: 5 * time.Second, poll: 10 * time.Millisecond,
		},
		openSilent: secret,
	}
	err := run.command(context.Background(), args)
	return out.String(), err
}

// tokenPending dit si le jeton attend encore : enrollment_tokens.consumed_at
// est vide.
func (b *joinBench) tokenPending(t *testing.T) bool {
	t.Helper()
	pending, err := b.db.ListPendingTokens(context.Background(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return len(pending) == 1
}

// nothingWritten : ni compte, ni identité, ni politique sur la machine.
func (b *joinBench) nothingWritten(t *testing.T) {
	t.Helper()
	if b.system.count("useradd") != 0 || len(b.system.enrollments) != 0 {
		t.Errorf("join touched the machine: %v", b.system.calls)
	}
	if _, err := os.Stat(b.paths.agentStateDir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the agent state was written: %v", err)
	}
}

// R-B1-13, N-M1, R-DROIT-9 : la clé du serveur est comparée à la ligne avant
// que le jeton parte. Remplacée sur /agent/server-key : server_key_mismatch,
// rien n'est envoyé, le jeton attend encore (consumed_at vide), rien n'est
// écrit. Remplacée dans la réponse d'enrôlement : arrêt aussi, sans identité.
// La bonne clé : la machine s'ajoute, et la clé de l'agent que le terminal
// affiche est celle que la fiche affiche (W-F4). -allow-plain et -pin
// n'existent plus ; --server en http:// est refusé.
func TestR_B1_13_ServerKeyIsComparedBeforeTheTokenLeaves(t *testing.T) {
	t.Run("another key on server-key", func(t *testing.T) {
		b := newJoinBench(t)
		b.proxy.inServerKey = true
		out, err := b.run(fakeTerminal(b.token+"\n"), fakeTerminal("o\n"), b.line("manage")...)
		var refused *refusal
		if !errors.As(err, &refused) || refused.message != b.text(t).Get("agent.server_key_mismatch") {
			t.Fatalf("got %v\n%s", err, out)
		}
		if b.proxy.enrollments.Load() != 0 || !b.tokenPending(t) {
			t.Fatalf("the token left: %d enrollments, pending %v", b.proxy.enrollments.Load(), b.tokenPending(t))
		}
		b.nothingWritten(t)
	})

	t.Run("another key in the enrollment answer", func(t *testing.T) {
		b := newJoinBench(t)
		b.proxy.inEnroll = true
		out, err := b.run(fakeTerminal(b.token+"\n"), fakeTerminal("o\n"), b.line("manage")...)
		if err == nil || !strings.Contains(out, agent.ErrServerKeyMismatch.Error()) {
			t.Fatalf("got %v\n%s", err, out)
		}
		root, rootErr := os.OpenRoot(b.paths.agentStateDir)
		if rootErr != nil {
			t.Fatal(rootErr)
		}
		defer root.Close()
		if _, err := agent.LoadIdentity(root); !errors.Is(err, agent.ErrNotEnrolled) {
			t.Fatalf("an identity was written with the forged key: %v", err)
		}
		if _, err := os.Stat(filepath.Join(b.paths.policyDir, "policy.toml")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("a policy was written: %v", err)
		}
	})

	t.Run("the right key", func(t *testing.T) {
		b := newJoinBench(t)
		out, err := b.run(fakeTerminal(b.token+"\n"), fakeTerminal("o\n"), b.line("manage")...)
		if err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		if !strings.Contains(lineOf(t, out, b.text(t).Format("join.server_key_ok", "")), b.key) {
			t.Fatalf("the accepted server key is not printed:\n%s", out)
		}
		if b.tokenPending(t) {
			t.Fatal("the token was not used")
		}
		machines, err := b.server.machines.List(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		var tile string
		for _, listed := range machines {
			if listed.Name == "web-1" {
				tile = ident.KeyFingerprint(listed.Agent.PublicKey)
			}
		}
		if tile == "" || !strings.Contains(lineOf(t, out, b.text(t).Get("step.enroll.enrolled")), tile) {
			t.Fatalf("the terminal does not show the key the page shows (%q):\n%s", tile, out)
		}
	})

	t.Run("no plain http", func(t *testing.T) {
		b := newJoinBench(t)
		plain := "http" + strings.TrimPrefix(b.url, "https")
		_, err := b.run(fakeTerminal(b.token+"\n"), fakeTerminal("o\n"), "--server", plain, "--server-key", b.key, "--rights", "manage")
		var refused *refusal
		if !errors.As(err, &refused) || refused.message != b.text(t).Get("join.server_not_https") || !b.tokenPending(t) {
			t.Fatalf("got %v", err)
		}
		for _, removed := range []string{"-allow-plain", "-pin"} {
			if err := runAgent([]string{removed, "x", "-state", t.TempDir()}); err == nil || !strings.Contains(err.Error(), "flag provided but not defined: "+removed) {
				t.Errorf("agent %s: %v", removed, err)
			}
		}
	})
}

// R-B1-10, W-F4 : le jeton n'est jamais dans la ligne de commande. --token
// n'existe pas ; le jeton se lit sur le terminal sans écho, avant la
// question (un seul flux pour les deux : lu après, la réponse prendrait le
// jeton), ou dans --token-file, effacé aussitôt, et refusé s'il n'est pas
// fermé aux autres. L'agent le reçoit sur son entrée standard ; il n'est ni
// dans la sortie, ni dans un argument, ni au journal de serve.
func TestR_B1_10_TheTokenIsNeverInTheCommandLine(t *testing.T) {
	t.Run("no token option", func(t *testing.T) {
		b := newJoinBench(t)
		_, err := b.run(noTerminal, noTerminal, append(b.line("observe"), "--token", b.token)...)
		var refused *refusal
		if !errors.As(err, &refused) || refused.message != b.text(t).Get("join.usage") || strings.Contains(refused.message, b.token) {
			t.Fatalf("got %v", err)
		}
		b.nothingWritten(t)
	})

	t.Run("the pasted second line, before the question", func(t *testing.T) {
		b := newJoinBench(t)
		pasted := &cookedTerminal{pending: b.token + "\no\n"}
		shared := func() (io.ReadCloser, error) { return io.NopCloser(pasted), nil }
		out, err := b.run(shared, shared, b.line("observe")...)
		if err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		if len(b.system.enrollments) != 1 || b.system.enrollments[0] != b.token {
			t.Fatalf("the agent received %v on its input", b.system.enrollments)
		}
		requireJoinTokenNowhere(t, b, out)
	})

	t.Run("token file, erased", func(t *testing.T) {
		b := newJoinBench(t)
		file := filepath.Join(b.dir, "token")
		if err := os.WriteFile(file, []byte(b.token+"\n"), tokenFileMode); err != nil {
			t.Fatal(err)
		}
		out, err := b.run(noTerminal, noTerminal, append(b.line("observe"), "--token-file", file, "--yes")...)
		if err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		if _, err := os.Stat(file); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the token file is still there: %v", err)
		}
		requireJoinTokenNowhere(t, b, out)
	})

	t.Run("token file open to others", func(t *testing.T) {
		b := newJoinBench(t)
		file := filepath.Join(b.dir, "token")
		if err := os.WriteFile(file, []byte(b.token+"\n"), 0o644); err != nil { // #nosec G306 -- le fichier ouvert que join doit refuser.
			t.Fatal(err)
		}
		_, err := b.run(noTerminal, noTerminal, append(b.line("observe"), "--token-file", file, "--yes")...)
		var refused *refusal
		if !errors.As(err, &refused) || refused.message != b.text(t).Format("join.token_file_open", file) {
			t.Fatalf("got %v", err)
		}
		if _, err := os.Stat(file); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("the refused token file is still there")
		}
		b.nothingWritten(t)
	})

	t.Run("no terminal and no file", func(t *testing.T) {
		b := newJoinBench(t)
		_, err := b.run(noTerminal, noTerminal, append(b.line("observe"), "--yes")...)
		var refused *refusal
		if !errors.As(err, &refused) || refused.message != b.text(t).Get("join.token_needs_file") {
			t.Fatalf("got %v", err)
		}
		b.nothingWritten(t)
	})
}

// cookedTerminal rend une ligne par lecture, comme un terminal en mode
// canonique : le collage de deux lignes y attend, la seconde après la
// première.
type cookedTerminal struct {
	pending string
}

func (c *cookedTerminal) Read(buffer []byte) (int, error) {
	if c.pending == "" {
		return 0, io.EOF
	}
	line, rest, found := strings.Cut(c.pending, "\n")
	if found {
		line += "\n"
	}
	n := copy(buffer, line)
	c.pending = line[n:] + rest
	return n, nil
}

// requireJoinTokenNowhere : ni dans la sortie, ni dans un argument passé à
// un processus, ni au journal de serve.
func requireJoinTokenNowhere(t *testing.T, b *joinBench, output string) {
	t.Helper()
	for place, text := range map[string]string{
		"the output": output, "the process arguments": strings.Join(b.system.calls, "\n"), "the serve log": b.logs.String(),
	} {
		if strings.Contains(text, b.token) {
			t.Errorf("the token is in %s", place)
		}
	}
}

// Le jeu vient de la ligne : sans --rights, join s'arrête avant d'écrire la
// politique, avant même de lire le jeton ; avec, la politique porte ce jeu
// et la clé du serveur de la ligne. Un refus à la question n'écrit rien.
func TestJoin_TheSetComesFromTheLine(t *testing.T) {
	b := newJoinBench(t)
	_, err := b.run(fakeTerminal(b.token+"\n"), fakeTerminal("o\n"), "--server", b.url, "--server-key", b.key)
	var refused *refusal
	if !errors.As(err, &refused) || refused.message != b.text(t).Get("join.rights_missing") {
		t.Fatalf("got %v", err)
	}
	b.nothingWritten(t)

	if _, err := b.run(fakeTerminal(b.token+"\n"), fakeTerminal("n\n"), b.line("manage")...); !errors.As(err, &refused) {
		t.Fatalf("declined: %v", err)
	}
	b.nothingWritten(t)
	if !b.tokenPending(t) {
		t.Fatal("a declined join used the token")
	}

	out, err := b.run(fakeTerminal(b.token+"\n"), fakeTerminal("o\n"), b.line("manage")...)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	policy := storedPolicy(t, b.place)
	if len(policy.ServerKeys) != 1 || ident.KeyFingerprint(policy.ServerKeys[0].Key) != b.key {
		t.Fatalf("server keys %+v", policy.ServerKeys)
	}
	if !strings.Contains(lineOf(t, out, b.text(t).Get("step.enroll.rights")), b.text(t).Get("rights.manage")) {
		t.Fatalf("the rights line does not say the set:\n%s", out)
	}

	// Relancée, la ligne reprend : tout est déjà fait, le jeton consommé ne
	// part plus.
	again, err := b.run(fakeTerminal(b.token+"\n"), fakeTerminal("o\n"), b.line("manage")...)
	if err != nil {
		t.Fatalf("%v\n%s", err, again)
	}
	if b.proxy.enrollments.Load() != 1 || !strings.Contains(lineOf(t, again, b.text(t).Get("step.enroll.enrolled")), "déjà fait") {
		t.Fatalf("resumed: %d enrollments\n%s", b.proxy.enrollments.Load(), again)
	}
}

// R-GESTE-4, R-B1-11 : ce que join coche au terminal est ce que la tuile lit
// sur le jeton, ligne pour ligne : les étapes que le serveur rend,
// imprimées par step.Print, refont les coches du terminal. Toutes sont des
// neuf étapes d'arrivée, et le jeton n'a servi qu'à l'enrôlement.
func TestR_GESTE_4_TheTileAndTheTerminalTickTheSameNineSteps(t *testing.T) {
	b := newJoinBench(t)
	out, err := b.run(fakeTerminal(b.token+"\n"), fakeTerminal("o\n"), b.line("manage")...)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	arrival, err := b.server.machines.ArrivalOf(context.Background(), machine.TokenIDOf(b.token))
	if err != nil || arrival.State != machine.ArrivalEnrolled {
		t.Fatalf("arrival %+v %v", arrival, err)
	}
	nine := []step.Key{
		step.EnrollSystem, step.EnrollDocker, step.EnrollRestic, step.EnrollAccount, step.EnrollRights,
		step.EnrollEnrolled, step.EnrollUnit, step.EnrollWorkspace, step.EnrollReady,
	}
	var tile bytes.Buffer
	for _, ticked := range arrival.Steps {
		if !slices.Contains(nine, ticked.Key) {
			t.Fatalf("%s is not an arrival step", ticked.Key)
		}
		step.Print(&tile, b.text(t), ticked)
	}
	if len(arrival.Steps) != len(joinSteps(t)) || !strings.Contains(out, tile.String()) {
		t.Fatalf("the tile reads\n%s\nthe terminal printed\n%s", tile.String(), out)
	}
	if b.proxy.enrollments.Load() != 1 {
		t.Fatalf("%d enrollments", b.proxy.enrollments.Load())
	}
}

// joinSteps rend les étapes que join coche.
func joinSteps(t *testing.T) []setupStep {
	t.Helper()
	var run joinRun
	return run.steps()
}
