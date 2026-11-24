package server

import (
	"net/http"
	"strings"
	"testing"
)

// Essai E00-01 : l'acteur enregistré d'un ordre et d'un silence garde la
// session (A2 §5, signé avec l'ordre), mais ce que l'écran montre comme
// acteur est le compte. Le libellé est recopié au geste : fermer la session
// ensuite ne le perd pas.
func TestE00_01_TheScreenNamesTheAccountNeverTheSession(t *testing.T) {
	server := newTestServer(t)
	enrolled, private := server.enroll(t, "vps-paris-1", remoteID)
	resp, _, _, cancel := openStream(t, server, enrolled.ID, private)
	defer resp.Body.Close()
	defer cancel()

	got := callAPI(server.Server, http.MethodPost, "/api/machines/"+remoteID+"/actions/ping", map[string]any{})
	if got.Code != http.StatusCreated {
		t.Fatalf("ping: %d %s", got.Code, got.Body.String())
	}
	var sent actionRunJSON
	decodeAPI(t, got, &sent)
	if sent.RequestedBy != "operator:"+testSessionID {
		t.Fatalf("the recorded actor lost the session: %q", sent.RequestedBy)
	}
	assertShownAccount(t, "the sent order", sent.RequestedByLabel)

	got = callAPI(server.Server, http.MethodPost, "/api/alerts/mutes", map[string]any{"target_kind": "machine", "target_id": remoteID, "duration_minutes": 60})
	if got.Code != http.StatusCreated {
		t.Fatalf("mute: %d %s", got.Code, got.Body.String())
	}
	var mute muteJSON
	decodeAPI(t, got, &mute)
	if mute.CreatedByName != testSessionID {
		t.Fatalf("the recorded actor lost the session: %q", mute.CreatedByName)
	}
	assertShownAccount(t, "the new mute", mute.CreatedByLabel)

	// Relus après la fermeture de la session : le libellé vient de la ligne.
	if _, err := server.db.DeleteSession(t.Context(), testSessionID); err != nil {
		t.Fatal(err)
	}
	var listed actionsResponse
	decodeAPI(t, callAPI(server.Server, http.MethodGet, "/api/actions", nil), &listed)
	if len(listed.Runs) != 1 {
		t.Fatalf("runs %+v", listed.Runs)
	}
	assertShownAccount(t, "the listed order", listed.Runs[0].RequestedByLabel)
	var mutes struct {
		Mutes []muteJSON `json:"mutes"`
	}
	decodeAPI(t, callAPI(server.Server, http.MethodGet, "/api/alerts/mutes", nil), &mutes)
	if len(mutes.Mutes) != 1 {
		t.Fatalf("mutes %+v", mutes.Mutes)
	}
	assertShownAccount(t, "the listed mute", mutes.Mutes[0].CreatedByLabel)
}

// assertShownAccount : le nom montré est le compte, et l'identifiant de la
// session n'y paraît pas.
func assertShownAccount(t *testing.T, what, shown string) {
	t.Helper()
	if shown != testUsername || strings.Contains(shown, testSessionID) {
		t.Fatalf("%s shows %q as its actor, want the account %q", what, shown, testUsername)
	}
}
