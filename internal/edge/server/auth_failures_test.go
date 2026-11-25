package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ldesfontaine/kagu/internal/domain/alert"
	"github.com/ldesfontaine/kagu/internal/fact/auth"
	"github.com/ldesfontaine/kagu/internal/fact/auth/authtest"
	"github.com/ldesfontaine/kagu/internal/kit/audit"
	"github.com/ldesfontaine/kagu/internal/kit/brand"
)

// callLoginFrom joue la connexion depuis une adresse, avec le mot de passe et
// le code donnés.
func callLoginFrom(server *Server, peer, password, code string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(authLoginRequest{Username: testUsername, Password: password, Code: code})
	request := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(string(body)))
	request.RemoteAddr = peer
	request.TLS = &tls.ConnectionState{}
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(anonymousHeader, "1")
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	return recorder
}

// withTOTPServer rend un serveur en native dont le code est actif, sous une
// horloge réglable, avec la session ouverte avant l'activation ; le pas de
// l'activation est déjà servi.
func withTOTPServer(t *testing.T) (*testServer, *http.Cookie, string, *time.Time) {
	t.Helper()
	server := newTestServer(t)
	now := testNow
	server.operator.SetClock(func() time.Time { return now })
	session := signedInCookie(t, server.Server)
	var proposal totpProposal
	decodeAPI(t, readWith(server.Server, "/api/auth/totp/proposal", session, "192.0.2.1:1234"), &proposal)
	enable := writeWith(server.Server, http.MethodPost, "/api/auth/totp", `{"secret":"`+proposal.Secret+`","code":"`+authtest.TOTPCode(t, proposal.Secret, now)+`"}`, session)
	if enable.Code != http.StatusNoContent {
		t.Fatalf("enable: %d %s", enable.Code, enable.Body.String())
	}
	now = now.Add(auth.TOTPPeriod)
	return server, session, proposal.Secret, &now
}

// aWrongCode rend un code bien formé qu'aucun pas voisin de at n'accepte.
func aWrongCode(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	for _, candidate := range []string{"000000", "111111", "222222", "333333"} {
		taken := false
		for _, step := range []time.Duration{-auth.TOTPPeriod, 0, auth.TOTPPeriod} {
			taken = taken || authtest.TOTPCode(t, secret, at.Add(step)) == candidate
		}
		if !taken {
			return candidate
		}
	}
	t.Fatal("no wrong code found")
	return ""
}

func (ts *testServer) openAlerts(t *testing.T) []alert.Alert {
	t.Helper()
	open, err := ts.alerts.List(context.Background(), alert.StatusOpen)
	if err != nil {
		t.Fatal(err)
	}
	return open
}

// R-A2-16, critère W-M4 : six codes faux de six sources suspendent le code ;
// le septième, juste, est refusé avec auth.totp_locked et l'heure de la fin ;
// l'alerte est ouverte ; « admin unlock » par la socket rend le code valable.
func TestR_A2_16_SixWrongCodesFromSixSourcesLockTheCode(t *testing.T) {
	server, _, secret, now := withTOTPServer(t)
	wrong := aWrongCode(t, secret, *now)
	for index := 1; index <= 6; index++ {
		got := callLoginFrom(server.Server, fmt.Sprintf("203.0.113.%d:4000", index), testPassword, wrong)
		want := "auth.totp_wrong"
		if index >= 5 {
			want = "auth.totp_locked"
		}
		if got.Code != http.StatusUnauthorized || errorCode(t, got) != want {
			t.Fatalf("wrong code %d: %d %s, want 401 %s", index, got.Code, got.Body.String(), want)
		}
	}
	right := authtest.TOTPCode(t, secret, *now)
	refused := callLoginFrom(server.Server, "203.0.113.7:4000", testPassword, right)
	var body apiError
	decodeAPI(t, refused, &body)
	if refused.Code != http.StatusUnauthorized || body.Error != "auth.totp_locked" || cookieNamed(refused, brand.SessionCookie) != nil {
		t.Fatalf("the right code while suspended: %d %s", refused.Code, refused.Body.String())
	}
	if want := now.Add(auth.DefaultTOTPLock); !body.Until.Equal(want) {
		t.Fatalf("suspended until %v, want %v", body.Until, want)
	}

	open := server.openAlerts(t)
	if len(open) != 1 || open[0].Kind != alert.KindTOTPLocked || open[0].Object.Kind != alert.ObjectAccount || open[0].Object.ID != testUsername {
		t.Fatalf("alerts: %+v, want one totp_locked on the account", open)
	}
	if open[0].Details.Target != "203.0.113.5" || !open[0].Details.Until.Equal(body.Until) {
		t.Fatalf("the alert names %q until %v, want the source of the fifth wrong code and the end of the suspension", open[0].Details.Target, open[0].Details.Until)
	}

	// Négatif : un pair qui n'est pas root ne lève rien.
	if got := callControl(server, http.MethodPost, "/control/admin/unlock", `{}`, serviceUID); got.Code != http.StatusForbidden {
		t.Fatalf("unlock as uid %d: %d, want 403", serviceUID, got.Code)
	}
	if got := callLoginFrom(server.Server, "203.0.113.8:4000", testPassword, right); errorCode(t, got) != "auth.totp_locked" {
		t.Fatalf("after a refused unlock: %d %s", got.Code, got.Body.String())
	}

	if got := callControl(server, http.MethodPost, "/control/admin/unlock", `{}`, rootUID); got.Code != http.StatusNoContent {
		t.Fatalf("unlock as root: %d %s", got.Code, got.Body.String())
	}
	if got := callLoginFrom(server.Server, "203.0.113.9:4000", testPassword, right); got.Code != http.StatusOK || cookieNamed(got, brand.SessionCookie) == nil {
		t.Fatalf("the right code after unlock: %d %s", got.Code, got.Body.String())
	}
	if open := server.openAlerts(t); len(open) != 0 {
		t.Fatalf("the alert stayed open after the unlock: %+v", open)
	}
}

// La redemande du niveau 4 juge le même code : ses codes faux se comptent avec
// ceux de la connexion, sous le statut 403 de la redemande.
func TestR_A2_16_ReauthWrongCodesCountAgainstTheSameAccount(t *testing.T) {
	server, session, secret, now := withTOTPServer(t)
	wrong := aWrongCode(t, secret, *now)
	for range 4 {
		if got := writeWith(server.Server, http.MethodPost, "/api/auth/reauth", reauthBody(testPassword, wrong), session); errorCode(t, got) != "auth.totp_wrong" {
			t.Fatalf("reauth wrong code: %d %s", got.Code, got.Body.String())
		}
	}
	got := writeWith(server.Server, http.MethodPost, "/api/auth/reauth", reauthBody(testPassword, wrong), session)
	if got.Code != http.StatusForbidden || errorCode(t, got) != "auth.totp_locked" {
		t.Fatalf("fifth wrong code: %d %s, want 403 auth.totp_locked", got.Code, got.Body.String())
	}
	if got := callLoginFrom(server.Server, "203.0.113.1:4000", testPassword, authtest.TOTPCode(t, secret, *now)); errorCode(t, got) != "auth.totp_locked" {
		t.Fatalf("login after the reauth lock: %d %s", got.Code, got.Body.String())
	}
}

// R-A2-16 : 21 mots de passe faux de 21 sources, chacune sous son propre frein,
// ralentissent le compte : le suivant, même juste, répond 429
// auth.account_slowed avant trente secondes, et passe après.
func TestR_A2_16_TwentyWrongPasswordsSlowTheAccount(t *testing.T) {
	server := newFirstSetupServer(t)
	server.enableNative(t)
	now := testNow
	server.operator.SetClock(func() time.Time { return now })
	for index := 1; index <= auth.DefaultPasswordFailuresPerHour+1; index++ {
		got := callLoginFrom(server.Server, fmt.Sprintf("198.51.100.%d:4000", index), "guess", "")
		if got.Code != http.StatusUnauthorized || errorCode(t, got) != "auth.login_failed" {
			t.Fatalf("wrong password %d: %d %s", index, got.Code, got.Body.String())
		}
	}
	for _, password := range []string{"guess", testPassword} {
		got := callLoginFrom(server.Server, "198.51.100.200:4000", password, "")
		if got.Code != http.StatusTooManyRequests || errorCode(t, got) != "auth.account_slowed" || cookieNamed(got, brand.SessionCookie) != nil {
			t.Fatalf("after 21 wrong passwords (%q): %d %s, want 429 auth.account_slowed", password, got.Code, got.Body.String())
		}
	}
	now = now.Add(auth.DefaultPasswordPace - time.Second)
	if got := callLoginFrom(server.Server, "198.51.100.201:4000", testPassword, ""); got.Code != http.StatusTooManyRequests {
		t.Fatalf("29 s later: %d, want 429", got.Code)
	}
	now = now.Add(time.Second)
	if got := callLoginFrom(server.Server, "198.51.100.202:4000", testPassword, ""); got.Code != http.StatusOK {
		t.Fatalf("30 s later: %d %s", got.Code, got.Body.String())
	}
}

// R-A2-16 : l'instant du dernier essai d'un compte ralenti est en base. Un
// essai admis, puis serve redémarre (un service neuf sur la même base) : le
// suivant, même juste, est refusé jusqu'aux trente secondes. L'essai tombe sur
// une demi-seconde : la base garde la seconde, l'intervalle ne raccourcit pas.
func TestR_A2_16_ARestartGivesNoExtraAttempt(t *testing.T) {
	server := newFirstSetupServer(t)
	server.enableNative(t)
	now := testNow
	clock := func() time.Time { return now }
	server.operator.SetClock(clock)
	for index := 1; index <= auth.DefaultPasswordFailuresPerHour+1; index++ {
		callLoginFrom(server.Server, fmt.Sprintf("198.51.100.%d:4000", index), "guess", "")
	}
	now = now.Add(auth.DefaultPasswordPace + 500*time.Millisecond)
	if got := callLoginFrom(server.Server, "198.51.100.100:4000", "guess", ""); got.Code != http.StatusUnauthorized || errorCode(t, got) != "auth.login_failed" {
		t.Fatalf("the admitted try: %d %s", got.Code, got.Body.String())
	}

	ctx := context.Background()
	restarted := auth.New(server.db, server.logger)
	restarted.SetClock(clock)
	restarted.SetHashCost(4)
	state, err := server.db.GetAuthState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	login := func(source string) error {
		_, err := restarted.Login(ctx, state, testUsername, testPassword, "", auth.SessionClient{Address: source, Cookie: auth.CookieHost})
		return err
	}
	if err := login("198.51.100.101"); !errors.Is(err, auth.ErrAccountSlowed) {
		t.Fatalf("right after the restart: %v, want ErrAccountSlowed", err)
	}
	now = now.Add(auth.DefaultPasswordPace - 500*time.Millisecond)
	if err := login("198.51.100.102"); !errors.Is(err, auth.ErrAccountSlowed) {
		t.Fatalf("29.5 s after the admitted try: %v, want ErrAccountSlowed", err)
	}
	now = now.Add(time.Second)
	if err := login("198.51.100.103"); err != nil {
		t.Fatalf("30.5 s after the admitted try: %v", err)
	}
}

// R-A2-16 : des tentatives fausses lancées ensemble (deux suffisent à perdre un
// compte ; huit le montrent à coup sûr) se comptent toutes, et la suspension
// du code ne s'ouvre qu'une fois.
func TestR_A2_16_TwoAttemptsAtOnceCountTwice(t *testing.T) {
	server, _, secret, now := withTOTPServer(t)
	run := func(count int, attempt func(index int)) {
		var group sync.WaitGroup
		for index := range count {
			group.Add(1)
			go func() {
				defer group.Done()
				attempt(index)
			}()
		}
		group.Wait()
	}
	const attempts = 8
	run(attempts, func(index int) {
		callLoginFrom(server.Server, fmt.Sprintf("198.51.100.%d:4000", index+1), "guess", "")
	})
	failures, err := server.db.GetAccountFailures(context.Background())
	if err != nil || failures.Password.Count != attempts {
		t.Fatalf("%d wrong passwords at once: %+v %v, want %d", attempts, failures.Password, err, attempts)
	}

	wrong := aWrongCode(t, secret, *now)
	run(5, func(index int) {
		callLoginFrom(server.Server, fmt.Sprintf("203.0.113.%d:4000", index+1), testPassword, wrong)
	})
	failures, err = server.db.GetAccountFailures(context.Background())
	if err != nil || !failures.TOTP.Locked(*now) {
		t.Fatalf("five wrong codes at once: %+v %v, want the code suspended", failures.TOTP, err)
	}
	if open := server.openAlerts(t); len(open) != 1 {
		t.Fatalf("%d alerts for one suspension", len(open))
	}
}

// Le geste de root laisse sa ligne d'audit ; refusé (pas de compte à mot de
// passe), il n'en laisse aucune.
func TestUnlock_LeavesAnAuditLineOnlyWhenItRuns(t *testing.T) {
	server := newTestServer(t)
	before := server.latestAuditID(t)
	if got := callControl(server, http.MethodPost, "/control/admin/unlock", `{}`, rootUID); got.Code != http.StatusNoContent {
		t.Fatalf("unlock: %d %s", got.Code, got.Body.String())
	}
	events := server.auditSince(t, before)
	if len(events) != 1 || events[0].Action != audit.AuthUnlock {
		t.Fatalf("audit lines: %+v, want one auth.unlock", events)
	}

	forward := newFirstSetupServer(t)
	forward.enableForward(t)
	before = forward.latestAuditID(t)
	if got := callControl(forward, http.MethodPost, "/control/admin/unlock", `{}`, rootUID); got.Code != http.StatusConflict {
		t.Fatalf("unlock in forward: %d %s, want 409", got.Code, got.Body.String())
	}
	if events := forward.auditSince(t, before); len(events) != 0 {
		t.Fatalf("a refused unlock left %+v", events)
	}
}
