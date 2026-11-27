package agentapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ldesfontaine/kagu/internal/fact/machine"
	"github.com/ldesfontaine/kagu/internal/kit/brand"
	"github.com/ldesfontaine/kagu/internal/kit/step"
	"github.com/ldesfontaine/kagu/internal/wire/agentwire"
)

// nineSteps : les neuf étapes d'arrivée, dans l'ordre où join les envoie.
var nineSteps = []step.Key{
	step.EnrollSystem, step.EnrollDocker, step.EnrollRestic, step.EnrollAccount, step.EnrollRights,
	step.EnrollEnrolled, step.EnrollUnit, step.EnrollWorkspace, step.EnrollReady,
}

// course rend les n premières étapes, cochées faites.
func course(n int) []step.Step {
	steps := make([]step.Step, 0, n)
	for position, key := range nineSteps[:n] {
		steps = append(steps, step.Step{Key: key, State: step.StateDone, Detail: "ok", At: testNow.Add(time.Duration(position) * time.Second)})
	}
	return steps
}

// sent compte les envois, chacun d'une source à lui : le seau par source ne
// se mêle pas du seau par jeton.
var sent int

// postProgress envoie un parcours comme join, le jeton en en-tête.
func (b *bench) postProgress(token string, steps []step.Step) *httptest.ResponseRecorder {
	body, _ := json.Marshal(agentwire.JoinProgress{Steps: steps})
	request := httptest.NewRequest(http.MethodPost, agentwire.JoinProgressRoute, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(agentwire.HeaderProtocol, agentwire.ProtocolVersion)
	if token != "" {
		request.Header.Set(agentwire.HeaderEnrollmentToken, token)
	}
	sent++
	request.RemoteAddr = fmt.Sprintf("198.51.100.%d:4000", sent%250+1)
	recorder := httptest.NewRecorder()
	b.ServeHTTP(recorder, request)
	return recorder
}

// enrollWith enrôle une machine par la route de l'agent avec ce jeton.
func (b *bench) enrollWith(token string) *httptest.ResponseRecorder {
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	return b.postJSON("/agent/enroll", agentwire.EnrollRequest{
		MachineID: remoteID, PublicKey: base64.StdEncoding.EncodeToString(public), Token: token,
		Hostname: "vps", OS: "Debian 12", Arch: "amd64", AgentVersion: "v0.0.1",
	})
}

// keysOf rend les clés d'un parcours, dans l'ordre.
func keysOf(steps []step.Step) []step.Key {
	keys := make([]step.Key, 0, len(steps))
	for _, one := range steps {
		keys = append(keys, one.Key)
	}
	return keys
}

// where rend chaque table et colonne de la base dont une ligne contient
// needle, lue à part, en lecture seule.
func (b *bench) where(t *testing.T, needle string) []string {
	t.Helper()
	path := filepath.Join(b.stateDir.Name(), brand.DatabaseFile)
	reader, err := sql.Open("sqlite", "file:"+path+"?"+url.Values{"mode": {"ro"}}.Encode())
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	tables, err := reader.Query(`SELECT name FROM sqlite_master WHERE type = 'table'`)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for tables.Next() {
		var name string
		if err := tables.Scan(&name); err != nil {
			t.Fatal(err)
		}
		names = append(names, name)
	}
	tables.Close()
	var found []string
	for _, table := range names {
		columns, err := reader.Query(`SELECT name FROM pragma_table_info(?)`, table)
		if err != nil {
			t.Fatal(err)
		}
		var columnNames []string
		for columns.Next() {
			var column string
			if err := columns.Scan(&column); err != nil {
				t.Fatal(err)
			}
			columnNames = append(columnNames, column)
		}
		columns.Close()
		for _, column := range columnNames {
			var count int
			query := fmt.Sprintf(`SELECT count(*) FROM %q WHERE instr(CAST(%q AS TEXT), ?) > 0`, table, column)
			if err := reader.QueryRow(query, needle).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count > 0 {
				found = append(found, table+"."+column)
			}
		}
	}
	return found
}

// R-B1-11 : l'avancement d'une machine qui arrive vit sur son jeton, sous
// gesture_steps « enrollment:<id> » et nulle part ailleurs, sans le
// consommer ; enrôlée, sa fiche le relit. Dix envois par minute et par jeton.
// Un jeton expiré écrit « jeton expiré » avec l'heure, que la tuile lit.
func TestR_B1_11_ProgressLivesOnTheTokenThenOnTheMachine(t *testing.T) {
	b := newBench(t)
	ctx := context.Background()
	cleartext, token, err := b.machines.CreateToken(ctx, "vps-paris-1", machine.RoleGeneric, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Avant l'enrôlement : cinq envois, le jeton reste en attente.
	for n := 1; n <= 5; n++ {
		if got := b.postProgress(cleartext, course(n)); got.Code != http.StatusNoContent {
			t.Fatalf("progress %d: %d %s", n, got.Code, got.Body.String())
		}
	}
	pending, err := b.machines.PendingTokens(ctx)
	if err != nil || !slices.ContainsFunc(pending, func(one machine.Token) bool { return one.ID == token.ID }) {
		t.Fatalf("the progress consumed the token: %v %v", pending, err)
	}
	enrolled := b.enrollWith(cleartext)
	if enrolled.Code != http.StatusCreated {
		t.Fatalf("enroll after the progress: %d %s", enrolled.Code, enrolled.Body.String())
	}
	var response agentwire.EnrollResponse
	if err := json.Unmarshal(enrolled.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}

	// Après : le reste du parcours, qui dit « Agent enrôlé ».
	for n := 6; n <= 9; n++ {
		if got := b.postProgress(cleartext, course(n)); got.Code != http.StatusNoContent {
			t.Fatalf("progress %d: %d %s", n, got.Code, got.Body.String())
		}
	}
	arrival, err := b.machines.ArrivalOf(ctx, token.ID)
	if err != nil || arrival.State != machine.ArrivalEnrolled || !slices.Equal(keysOf(arrival.Steps), nineSteps) {
		t.Fatalf("arrival on the token: %+v %v", arrival, err)
	}
	sheet, err := b.machines.ArrivalSteps(ctx, response.AgentID)
	if err != nil || !slices.Equal(keysOf(sheet), nineSteps) {
		t.Fatalf("the sheet does not carry the steps: %v %v", sheet, err)
	}

	// Nulle part ailleurs : une seule table, un seul sujet ; le clair du
	// jeton n'est écrit nulle part.
	if found := b.where(t, string(step.EnrollWorkspace)); !slices.Equal(found, []string{"gesture_steps.key"}) {
		t.Fatalf("the steps live in %v", found)
	}
	if found := b.where(t, "enrollment:"); !slices.Equal(found, []string{"gesture_steps.subject"}) {
		t.Fatalf("the subject lives in %v", found)
	}
	if found := b.where(t, "enrollment:"+token.ID); len(found) != 1 {
		t.Fatalf("the steps are not under enrollment:%s: %v", token.ID, found)
	}
	if found := b.where(t, cleartext); len(found) != 0 {
		t.Fatalf("the token is written in %v", found)
	}

	// Le dixième envoi de la minute passe, le onzième est refusé.
	if got := b.postProgress(cleartext, course(9)); got.Code != http.StatusNoContent {
		t.Fatalf("tenth: %d %s", got.Code, got.Body.String())
	}
	if got := b.postProgress(cleartext, course(9)); got.Code != http.StatusTooManyRequests {
		t.Fatalf("eleventh: %d %s", got.Code, got.Body.String())
	}

	// Un jeton expiré : l'enrôlement refusé s'écrit sur lui, avec l'heure.
	late, lateToken, err := b.machines.CreateToken(ctx, "vps-paris-2", machine.RoleGeneric, nil)
	if err != nil {
		t.Fatal(err)
	}
	afterExpiry := testNow.Add(machine.TokenLifetime + time.Minute)
	b.machines.SetClock(func() time.Time { return afterExpiry })
	if got := b.postProgress(late, course(1)); got.Code != http.StatusConflict || !strings.Contains(got.Body.String(), machine.RefusedTokenExpired) {
		t.Fatalf("progress on an expired token: %d %s", got.Code, got.Body.String())
	}
	if got := b.enrollWith(late); got.Code != http.StatusConflict || !strings.Contains(got.Body.String(), machine.RefusedTokenExpired) {
		t.Fatalf("enroll with an expired token: %d %s", got.Code, got.Body.String())
	}
	expired, err := b.machines.ArrivalOf(ctx, lateToken.ID)
	refused := step.Step{Key: step.EnrollEnrolled, State: step.StateFailed, Detail: machine.RefusedTokenExpired, At: afterExpiry}
	if err != nil || expired.State != machine.ArrivalExpired || len(expired.Steps) != 1 || !sameStep(expired.Steps[0], refused) {
		t.Fatalf("the expired token says %+v %v", expired, err)
	}
}

// sameStep compare deux étapes à la seconde, ce que la base garde.
func sameStep(got, want step.Step) bool {
	return got.Key == want.Key && got.State == want.State && got.Detail == want.Detail && got.At.Unix() == want.At.Unix()
}

// La même ligne collée sur une autre machine après l'arrivée de la première :
// ses étapes n'écrasent pas la frise de celle qui est arrivée, et son
// enrôlement refusé s'écrit à la suite (E04-29).
func TestJoinProgress_AServedTokenKeepsTheFirstMachineCourse(t *testing.T) {
	b := newBench(t)
	ctx := context.Background()
	cleartext, token, err := b.machines.CreateToken(ctx, "vps-paris-1", machine.RoleGeneric, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := b.enrollWith(cleartext); got.Code != http.StatusCreated {
		t.Fatalf("enroll: %d %s", got.Code, got.Body.String())
	}
	if got := b.postProgress(cleartext, course(9)); got.Code != http.StatusNoContent {
		t.Fatalf("progress: %d %s", got.Code, got.Body.String())
	}
	if got := b.postProgress(cleartext, course(2)); got.Code != http.StatusConflict || !strings.Contains(got.Body.String(), machine.RefusedTokenConsumed) {
		t.Fatalf("a second machine overwrote the course: %d %s", got.Code, got.Body.String())
	}
	if got := b.enrollWith(cleartext); got.Code != http.StatusConflict || !strings.Contains(got.Body.String(), machine.RefusedTokenConsumed) {
		t.Fatalf("second enroll: %d %s", got.Code, got.Body.String())
	}
	arrival, err := b.machines.ArrivalOf(ctx, token.ID)
	want := append(slices.Clone(nineSteps), step.EnrollEnrolled)
	if err != nil || !slices.Equal(keysOf(arrival.Steps), want) || arrival.Steps[9].Detail != machine.RefusedTokenConsumed || arrival.Steps[5].State != step.StateDone {
		t.Fatalf("arrival %+v %v", arrival, err)
	}
}

// Ce que la route refuse : sans jeton, un jeton inconnu, une étape mal
// formée ou un parcours trop long ; rien ne s'écrit, et le clair d'un jeton
// ne revient dans aucune réponse.
func TestJoinProgress_RefusesWhatItCannotTie(t *testing.T) {
	b := newBench(t)
	ctx := context.Background()
	cleartext, token, err := b.machines.CreateToken(ctx, "vps-paris-1", machine.RoleGeneric, nil)
	if err != nil {
		t.Fatal(err)
	}
	tooLong := make([]step.Step, 0, machine.MaxArrivalSteps+1)
	for range machine.MaxArrivalSteps + 1 {
		tooLong = append(tooLong, course(1)...)
	}
	badKey := course(1)
	badKey[0].Key = "enroll.system"
	for name, refused := range map[string]struct {
		token  string
		steps  []step.Step
		status int
	}{
		"no token":      {"", course(1), http.StatusNotFound},
		"unknown token": {cleartext + "x", course(1), http.StatusNotFound},
		"bad key":       {cleartext, badKey, http.StatusBadRequest},
		"too long":      {cleartext, tooLong, http.StatusBadRequest},
		"empty":         {cleartext, nil, http.StatusBadRequest},
	} {
		got := b.postProgress(refused.token, refused.steps)
		if got.Code != refused.status || strings.Contains(got.Body.String(), cleartext) {
			t.Fatalf("%s: %d %s", name, got.Code, got.Body.String())
		}
	}
	arrival, err := b.machines.ArrivalOf(ctx, token.ID)
	if err != nil || len(arrival.Steps) != 0 || arrival.State != machine.ArrivalPending {
		t.Fatalf("a refused progress wrote %+v %v", arrival, err)
	}
}
