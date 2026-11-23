package server

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ldesfontaine/kagu/internal/edge/store/storetest"
	"github.com/ldesfontaine/kagu/internal/fact/auth"
	"github.com/ldesfontaine/kagu/internal/fact/auth/authtest"
	"github.com/ldesfontaine/kagu/internal/kit/audit"
	"golang.org/x/crypto/bcrypt"
)

const enablePath = "/api/auth/setup"

// enableWithCode joue la création du compte de la première configuration avec
// le code donné.
func enableWithCode(ts *testServer, code string) *httptest.ResponseRecorder {
	return callSetupAPI(ts.Server, authSetupRequest{SetupCode: code, Username: testUsername, Password: testPassword})
}

// issueOnSocket tire un code comme le fait `admin setup-code` : par la socket.
func issueOnSocket(t *testing.T, ts *testServer) setupCodeResponse {
	t.Helper()
	recorder := httptest.NewRecorder()
	ts.ControlHandler().ServeHTTP(recorder, asRoot(httptest.NewRequest(http.MethodPost, "http://control/control/admin/setup-code", nil)))
	if recorder.Code != http.StatusCreated {
		t.Fatalf("issue on the socket: %d %s", recorder.Code, recorder.Body.String())
	}
	var issued setupCodeResponse
	decodeAPI(t, recorder, &issued)
	return issued
}

func requireStillAwaitingSetup(t *testing.T, ts *testServer) {
	t.Helper()
	state, err := ts.operator.State(context.Background())
	if err != nil || state.Mode != auth.ModeNone {
		t.Fatalf("an account was created without a valid code: %+v %v", state, err)
	}
}

func requireRefusal(t *testing.T, recorder *httptest.ResponseRecorder, status int, key string) {
	t.Helper()
	if recorder.Code != status || errorCode(t, recorder) != key {
		t.Fatalf("got %d %s, want %d %s", recorder.Code, recorder.Body.String(), status, key)
	}
}

// R-A2-5 : le code a huit chiffres, vaut trente minutes, ne sert qu'une fois,
// et brûle au cinquième essai faux, le bon compris. Sans code valable, rien
// ne crée le compte, en native comme en forward.
func TestR_A2_5(t *testing.T) {
	now := testNow
	newServer := func(t *testing.T) *testServer {
		ts := newFirstSetupServer(t)
		ts.operator.SetClock(func() time.Time { return now })
		now = testNow
		return ts
	}

	t.Run("the code is eight digits valid thirty minutes", func(t *testing.T) {
		ts := newServer(t)
		issued := issueOnSocket(t, ts)
		if !regexp.MustCompile(`^[0-9]{8}$`).MatchString(issued.Code) {
			t.Fatalf("code %q is not eight digits", issued.Code)
		}
		if !issued.ExpiresAt.Equal(testNow.Add(30 * time.Minute)) {
			t.Fatalf("expires at %v", issued.ExpiresAt)
		}
	})

	t.Run("no code, no account", func(t *testing.T) {
		ts := newServer(t)
		issueOnSocket(t, ts)
		requireRefusal(t, enableWithCode(ts, ""), http.StatusUnprocessableEntity, "auth.setup_code_required")
		requireStillAwaitingSetup(t, ts)
	})

	t.Run("a wrong code is refused", func(t *testing.T) {
		ts := newServer(t)
		issued := issueOnSocket(t, ts)
		requireRefusal(t, enableWithCode(ts, otherCode(issued.Code)), http.StatusUnprocessableEntity, "auth.setup_code_wrong")
		requireStillAwaitingSetup(t, ts)
	})

	t.Run("no code issued at all", func(t *testing.T) {
		ts := newServer(t)
		requireRefusal(t, enableWithCode(ts, "12345678"), http.StatusConflict, "auth.setup_code_unusable")
		requireStillAwaitingSetup(t, ts)
	})

	t.Run("an expired code is refused", func(t *testing.T) {
		ts := newServer(t)
		issued := issueOnSocket(t, ts)
		now = testNow.Add(30 * time.Minute)
		requireRefusal(t, enableWithCode(ts, issued.Code), http.StatusConflict, "auth.setup_code_unusable")
		requireStillAwaitingSetup(t, ts)
	})

	t.Run("the code works just before its expiry", func(t *testing.T) {
		ts := newServer(t)
		issued := issueOnSocket(t, ts)
		now = testNow.Add(30*time.Minute - time.Second)
		if got := enableWithCode(ts, issued.Code); got.Code != http.StatusOK {
			t.Fatalf("%d %s", got.Code, got.Body.String())
		}
	})

	t.Run("the fifth wrong try burns the code, the right one included", func(t *testing.T) {
		ts := newServer(t)
		issued := issueOnSocket(t, ts)
		wrong := otherCode(issued.Code)
		for try := 1; try <= auth.MaxSetupCodeFailures; try++ {
			requireRefusal(t, enableWithCode(ts, wrong), http.StatusUnprocessableEntity, "auth.setup_code_wrong")
		}
		requireRefusal(t, enableWithCode(ts, issued.Code), http.StatusConflict, "auth.setup_code_unusable")
		requireStillAwaitingSetup(t, ts)
	})

	t.Run("four wrong tries leave the right code valid", func(t *testing.T) {
		ts := newServer(t)
		issued := issueOnSocket(t, ts)
		for try := 1; try < auth.MaxSetupCodeFailures; try++ {
			enableWithCode(ts, otherCode(issued.Code))
		}
		if got := enableWithCode(ts, issued.Code); got.Code != http.StatusOK {
			t.Fatalf("%d %s", got.Code, got.Body.String())
		}
	})

	t.Run("a burnt code is replaced by issuing another", func(t *testing.T) {
		ts := newServer(t)
		burnt := issueOnSocket(t, ts)
		for try := 1; try <= auth.MaxSetupCodeFailures; try++ {
			enableWithCode(ts, otherCode(burnt.Code))
		}
		fresh := issueOnSocket(t, ts)
		requireRefusal(t, enableWithCode(ts, burnt.Code), http.StatusUnprocessableEntity, "auth.setup_code_wrong")
		if got := enableWithCode(ts, fresh.Code); got.Code != http.StatusOK {
			t.Fatalf("%d %s", got.Code, got.Body.String())
		}
	})

	t.Run("a rejected password does not spend the code", func(t *testing.T) {
		ts := newServer(t)
		issued := issueOnSocket(t, ts)
		short := callSetupAPI(ts.Server, authSetupRequest{SetupCode: issued.Code, Username: testUsername, Password: "short"})
		requireRefusal(t, short, http.StatusUnprocessableEntity, "auth.password_too_short")
		if got := enableWithCode(ts, issued.Code); got.Code != http.StatusOK {
			t.Fatalf("%d %s", got.Code, got.Body.String())
		}
	})

	t.Run("the code serves once", func(t *testing.T) {
		ts := newServer(t)
		issued := issueOnSocket(t, ts)
		if got := enableWithCode(ts, issued.Code); got.Code != http.StatusOK {
			t.Fatalf("%d %s", got.Code, got.Body.String())
		}
		ts.rescue(t)
		requireRefusal(t, enableWithCode(ts, issued.Code), http.StatusConflict, "auth.setup_code_unusable")
		requireStillAwaitingSetup(t, ts)
	})

	t.Run("forward needs the code too", func(t *testing.T) {
		ts := newServer(t)
		ts.trustedProxies = parsePrefixes(t, "192.0.2.0/24")
		issued := issueOnSocket(t, ts)
		body := `{"mode":"forward"}`
		requireRefusal(t, callForwardedJSON(ts.Server, http.MethodPost, enablePath, body, trustedPeer, auth.DefaultForwardHeader, testUsername),
			http.StatusUnprocessableEntity, "auth.setup_code_required")
		wrong := `{"mode":"forward","setup_code":"` + otherCode(issued.Code) + `"}`
		requireRefusal(t, callForwardedJSON(ts.Server, http.MethodPost, enablePath, wrong, trustedPeer, auth.DefaultForwardHeader, testUsername),
			http.StatusUnprocessableEntity, "auth.setup_code_wrong")
		requireStillAwaitingSetup(t, ts)
		right := `{"mode":"forward","setup_code":"` + issued.Code + `"}`
		if got := callForwardedJSON(ts.Server, http.MethodPost, enablePath, right, trustedPeer, auth.DefaultForwardHeader, testUsername); got.Code != http.StatusOK {
			t.Fatalf("%d %s", got.Code, got.Body.String())
		}
	})

	t.Run("the code outlives a restart until it expires", func(t *testing.T) {
		ts := newServer(t)
		issued := issueOnSocket(t, ts)
		restarted := auth.New(ts.db, ts.logger)
		restarted.SetClock(func() time.Time { return testNow.Add(10 * time.Minute) })
		restarted.SetHashCost(4)
		if _, err := restarted.EnableNative(context.Background(), auth.State{Mode: auth.ModeNone}, issued.Code, testUsername, testPassword); err != nil {
			t.Fatal(err)
		}
	})
}

// R-CNX-3 : sans le code que l'installation affiche, personne ne crée le
// compte, ni à l'installation, ni après que la commande de secours a rouvert la
// première configuration.
func TestR_CNX_3(t *testing.T) {
	t.Run("an installation without a code creates nothing", func(t *testing.T) {
		ts := newFirstSetupServer(t)
		for _, code := range []string{"", "00000000", "  "} {
			if got := enableWithCode(ts, code); got.Code == http.StatusOK {
				t.Fatalf("code %q created the account", code)
			}
		}
		requireStillAwaitingSetup(t, ts)
	})

	t.Run("the page cannot ask for a code", func(t *testing.T) {
		ts := newFirstSetupServer(t)
		for _, path := range []string{"/control/admin/setup-code", "/api/control/admin/setup-code", "/api/auth/setup-code"} {
			if got := callAPI(ts.Server, http.MethodPost, path, nil); got.Code == http.StatusCreated {
				t.Fatalf("%s served a code on the port", path)
			}
		}
		requireStillAwaitingSetup(t, ts)
	})

	t.Run("the socket issues no code once an account exists", func(t *testing.T) {
		ts := newFirstSetupServer(t)
		ts.enableNative(t)
		recorder := httptest.NewRecorder()
		ts.ControlHandler().ServeHTTP(recorder, asRoot(httptest.NewRequest(http.MethodPost, "http://control/control/admin/setup-code", nil)))
		requireRefusal(t, recorder, http.StatusConflict, "auth.already_enabled")
	})

	t.Run("the code leaves no trace in the database, the logs or the answers", func(t *testing.T) {
		ts := newFirstSetupServer(t)
		issued := issueOnSocket(t, ts)
		stored, err := ts.db.GetSetupCode(context.Background())
		if err != nil || stored.Hash == "" || strings.Contains(stored.Hash, issued.Code) {
			t.Fatalf("stored %+v %v", stored, err)
		}
		requireNoTrace := func(where, text string) {
			if strings.Contains(text, issued.Code) || strings.Contains(text, stored.Hash) {
				t.Errorf("%s carries the code or its hash", where)
			}
		}
		requireNoTrace("logs", ts.logs.String())
		requireNoTrace("GET /api/auth", callAPI(ts.Server, http.MethodGet, "/api/auth", nil).Body.String())
		refused := enableWithCode(ts, otherCode(issued.Code))
		requireNoTrace("a refusal", refused.Body.String())
		requireNoTrace("logs after a refusal", ts.logs.String())
	})
}

// otherCode rend un code de huit chiffres qui n'est pas celui-ci.
func otherCode(code string) string {
	if code == "00000000" {
		return "00000001"
	}
	return "00000000"
}

// Le tirage du code est au journal d'audit (qui, quand), jamais sa valeur : ni
// dans l'entrée, ni dans ce que l'API du journal rend, ni dans le journal
// applicatif, en clair, en base64 ou en hexadécimal.
func TestR_A2_5_AuditNeverHoldsSetupCode(t *testing.T) {
	ts := newFirstSetupServer(t)
	issued := issueOnSocket(t, ts)

	events, err := ts.db.ListAuditEvents(context.Background(), audit.Query{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	var entry *audit.Event
	for index := range events {
		if events[index].Action == audit.AuthSetupCodeIssue {
			entry = &events[index]
		}
	}
	if entry == nil {
		t.Fatalf("no audit entry for the issued code: %+v", events)
	}
	if entry.Actor.Kind != audit.ActorCLI || entry.At.IsZero() {
		t.Fatalf("the entry does not say who and when: %+v", entry)
	}
	rawEntry, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := ts.db.GetSetupCode(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	forms := []string{
		issued.Code,
		base64.StdEncoding.EncodeToString([]byte(issued.Code)),
		base64.RawStdEncoding.EncodeToString([]byte(issued.Code)),
		base64.URLEncoding.EncodeToString([]byte(issued.Code)),
		base64.RawURLEncoding.EncodeToString([]byte(issued.Code)),
		hex.EncodeToString([]byte(issued.Code)),
		strings.ToUpper(hex.EncodeToString([]byte(issued.Code))),
		stored.Hash,
	}
	outputs := map[string]string{
		"audit entry":     string(rawEntry),
		"GET /api/audit":  callAPI(ts.Server, http.MethodGet, "/api/audit?limit=200", nil).Body.String(),
		"application log": ts.logs.String(),
	}
	for where, text := range outputs {
		for _, form := range forms {
			if strings.Contains(text, form) {
				t.Errorf("%s holds the setup code (as %q)", where, form)
			}
		}
	}
}

// R-A2-5 : un seul code, une seule première configuration. N activations
// parties du même état avec le même code valable : une seule réussit, les
// autres sont refusées par « déjà activé » ou « l'état a changé », jamais par
// « code brûlé » (le code n'est brûlé que par celle qui a gagné).
func TestR_A2_5_OnlyOneActivationWins(t *testing.T) {
	db := storetest.Open(t)
	operator := auth.New(db, slog.New(slog.DiscardHandler))
	operator.SetHashCost(bcrypt.MinCost)
	ctx := context.Background()
	none := auth.State{Mode: auth.ModeNone}
	for _, contenders := range []int{2, 8} {
		for round := range 10 {
			code := authtest.SetupCode(t, operator)
			start := make(chan struct{})
			results := make(chan error, contenders)
			for i := range contenders {
				go func() {
					<-start
					_, err := operator.EnableNative(ctx, none, code, fmt.Sprintf("user%d", i), testPassword)
					results <- err
				}()
			}
			close(start)
			wins := 0
			for range contenders {
				err := <-results
				switch {
				case err == nil:
					wins++
				case errors.Is(err, auth.ErrAlreadyEnabled) || errors.Is(err, auth.ErrStateChanged):
				default:
					t.Fatalf("%d contenders, round %d: unexpected error: %v", contenders, round, err)
				}
			}
			if wins != 1 {
				t.Fatalf("%d contenders, round %d: %d activations succeeded, want 1", contenders, round, wins)
			}
			state, err := operator.State(ctx)
			if err != nil {
				t.Fatal(err)
			}
			// Retour à none par la base : aucun geste ne le fait plus.
			if _, err := db.SaveAuthStateIf(ctx, state, none, time.Now()); err != nil {
				t.Fatal(err)
			}
		}
	}
}
