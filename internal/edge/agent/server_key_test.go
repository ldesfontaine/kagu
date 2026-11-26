package agent

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/ldesfontaine/kagu/internal/fact/machine"
	"github.com/ldesfontaine/kagu/internal/wire/agentwire"
)

// keyRewriter est un intermédiaire entre l'agent et le vrai serveur du banc :
// il relaie tout, et remplace la clé du serveur là où on le lui dit. Il
// compte les enrôlements qu'il a vus passer : un jeton qui part se voit ici.
type keyRewriter struct {
	next        http.Handler
	forged      []byte
	inServerKey bool
	inEnroll    bool
	enrollments atomic.Int32
}

func (p *keyRewriter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/agent/enroll" {
		p.enrollments.Add(1)
	}
	recorded := httptest.NewRecorder()
	p.next.ServeHTTP(recorded, r)
	body := recorded.Body.Bytes()
	forged := base64.StdEncoding.EncodeToString(p.forged)
	switch {
	case r.URL.Path == agentwire.ServerKeyRoute && p.inServerKey:
		body, _ = json.Marshal(agentwire.ServerKeyResponse{ServerKey: forged})
	case r.URL.Path == "/agent/enroll" && p.inEnroll && recorded.Code == http.StatusCreated:
		var answer agentwire.EnrollResponse
		_ = json.Unmarshal(body, &answer)
		answer.ServerKey = forged
		body, _ = json.Marshal(answer)
	}
	w.WriteHeader(recorded.Code)
	_, _ = w.Write(body)
}

// forgedKey est la clé d'un intermédiaire.
func forgedKey(t *testing.T) []byte {
	t.Helper()
	public, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return public
}

// R-DROIT-9, R-B1-13 : une clé du serveur qui n'est pas celle de la ligne
// arrête l'enrôlement. Vue sur /agent/server-key, le jeton ne part pas et
// reste valable ; vue dans la réponse d'enrôlement, rien n'est écrit. Avec la
// bonne clé, l'agent s'enrôle et épingle celle-là.
func TestR_DROIT_9_AServerPresentingAnotherKeyIsRefused(t *testing.T) {
	cases := []struct {
		name         string
		inServerKey  bool
		inEnroll     bool
		tokenLeft    bool
		wantMismatch bool
		wantEnrolled bool
	}{
		{name: "another key on server-key", inServerKey: true, tokenLeft: true, wantMismatch: true},
		{name: "another key in the enrollment answer", inEnroll: true, wantMismatch: true},
		{name: "the right key", wantEnrolled: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := newBench(t)
			proxy := &keyRewriter{next: b.handler, forged: forgedKey(t), inServerKey: c.inServerKey, inEnroll: c.inEnroll}
			relay := httptest.NewServer(proxy)
			defer relay.Close()
			token, _, err := b.machines.CreateToken(context.Background(), "web-1", machine.RoleGeneric, nil)
			if err != nil {
				t.Fatal(err)
			}
			options := b.options(token)
			options.Server, options.EnrollOnly, options.ServerKey = relay.URL, true, b.serverKey.Fingerprint()

			err = runBounded(options)
			if got := errors.Is(err, ErrServerKeyMismatch); got != c.wantMismatch {
				t.Fatalf("mismatch=%v, want %v: %v", got, c.wantMismatch, err)
			}
			if c.tokenLeft && proxy.enrollments.Load() != 0 {
				t.Fatalf("the token left before the key was compared")
			}
			identity, loadErr := LoadIdentity(b.stateDir)
			if !c.wantEnrolled {
				if !errors.Is(loadErr, ErrNotEnrolled) {
					t.Fatalf("identity written after a mismatch: %+v %v", identity, loadErr)
				}
				return
			}
			if loadErr != nil || !bytes.Equal(identity.ServerKey, b.serverKey.PublicKey()) {
				t.Fatalf("identity %+v %v", identity, loadErr)
			}
		})
	}

	// Le jeton refusé avant l'envoi est encore bon : le vrai serveur l'accepte.
	b := newBench(t)
	proxy := &keyRewriter{next: b.handler, forged: forgedKey(t), inServerKey: true}
	relay := httptest.NewServer(proxy)
	defer relay.Close()
	token, _, err := b.machines.CreateToken(context.Background(), "web-2", machine.RoleGeneric, nil)
	if err != nil {
		t.Fatal(err)
	}
	options := b.options(token)
	options.Server, options.EnrollOnly, options.ServerKey = relay.URL, true, b.serverKey.Fingerprint()
	if err := runBounded(options); !errors.Is(err, ErrServerKeyMismatch) {
		t.Fatalf("got %v", err)
	}
	options.Server = b.url
	if err := runBounded(options); err != nil {
		t.Fatalf("the token was burnt by the refused attempt: %v", err)
	}
}

// Un serveur distant ne s'enrôle pas sans l'empreinte de sa clé : rien ne
// part (N-M1). Par la boucle ou la socket locale, l'empreinte n'est pas
// exigée.
func TestEnroll_ARemoteServerNeedsItsKeyFingerprint(t *testing.T) {
	b := newBench(t)
	options := b.options("kg_never_sent")
	options.Server, options.EnrollOnly = "https://kagu.invalid", true
	if err := runBounded(options); !errors.Is(err, ErrServerKeyRequired) {
		t.Fatalf("got %v", err)
	}
	if _, err := LoadIdentity(b.stateDir); !errors.Is(err, ErrNotEnrolled) {
		t.Fatal("identity written")
	}
}

// R-B1-18 : l'enrôlement tire une paire X25519, envoie la moitié publique,
// que le serveur garde sur l'agent ; la moitié privée reste dans l'identité
// (0600) et ne part jamais.
func TestR_B1_18_JoinSendsThePublicHalfOfAnX25519Pair(t *testing.T) {
	b := newBench(t)
	var sent agentwire.EnrollRequest
	spy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/agent/enroll" {
			body := new(bytes.Buffer)
			_, _ = body.ReadFrom(r.Body)
			_ = json.Unmarshal(body.Bytes(), &sent)
			r.Body = io.NopCloser(bytes.NewReader(body.Bytes()))
		}
		b.handler.ServeHTTP(w, r)
	})
	relay := httptest.NewServer(spy)
	defer relay.Close()
	token, _, err := b.machines.CreateToken(context.Background(), "web-1", machine.RoleGeneric, nil)
	if err != nil {
		t.Fatal(err)
	}
	options := b.options(token)
	options.Server, options.EnrollOnly = relay.URL, true
	if err := runBounded(options); err != nil {
		t.Fatal(err)
	}
	identity, err := LoadIdentity(b.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	private, err := ecdh.X25519().NewPrivateKey(identity.SealPrivateKey)
	if err != nil {
		t.Fatalf("no X25519 private half in the identity: %v", err)
	}
	public := private.PublicKey().Bytes()
	if sent.SealPublicKey != base64.StdEncoding.EncodeToString(public) {
		t.Fatalf("sent %q, the identity holds the pair of %x", sent.SealPublicKey, public)
	}
	raw, _ := json.Marshal(sent)
	if bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString(identity.SealPrivateKey))) {
		t.Fatal("the private half left the machine")
	}
	enrolled, err := b.machines.Get(context.Background(), identity.MachineID)
	if err != nil || !bytes.Equal(enrolled.Agent.SealPublicKey, public) {
		t.Fatalf("the server kept %x, want %x (%v)", enrolled.Agent.SealPublicKey, public, err)
	}
	info, err := b.stateDir.Stat(identityFile)
	if err != nil || info.Mode().Perm() != identityMode {
		t.Fatalf("identity mode %v %v", info.Mode(), err)
	}
}
