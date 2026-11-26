package server

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ldesfontaine/kagu/internal/edge/store/storetest"
	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/gesture/apitoken"
	"github.com/ldesfontaine/kagu/internal/gesture/verb"
	"github.com/ldesfontaine/kagu/internal/kit/brand"
	"github.com/ldesfontaine/kagu/internal/wire/agentwire"
)

// requestRightSetup enrôle une machine dont l'agent, en ligne, rapporte observe
// seul et annonce les genres du registre.
func requestRightSetup(t *testing.T, server *testServer) {
	t.Helper()
	enrolled, _ := server.enroll(t, "vps-paris-1", remoteID)
	if _, err := server.machines.Connect(context.Background(), enrolled, "192.0.2.1", "v0.0.1", "observe", "", "", ""); err != nil {
		t.Fatal(err)
	}
	storetest.AnnounceKinds(t, server.machines, enrolled.Agent.ID)
}

// ARB-1 : le clic sur « Demander ce droit à la machine » d'un geste grisé fait
// partir un ordre right.request, et lui seul : le geste grisé reste refusé
// d'avance par le serveur (R-DROIT-4), aucun ordre d'un autre genre n'est
// écrit. Un droit qu'agentpolicy ne connaît pas est refusé sans run.
func TestARB1_AClickSendsARightRequestAndNothingElse(t *testing.T) {
	server := newTestServer(t)
	requestRightSetup(t, server)
	path := "/api/machines/" + remoteID + "/actions/request-right"

	got := callAPI(server.Server, http.MethodPost, path, map[string]any{"right": "docker.deploy"})
	var run actionRunJSON
	decodeAPI(t, got, &run)
	if got.Code != http.StatusCreated || run.Kind != string(agentwire.KindRightRequest) || string(run.Params) != `{"right":"docker.deploy"}` {
		t.Fatalf("request: %d %s", got.Code, got.Body.String())
	}
	if refused := callAPI(server.Server, http.MethodPost, "/api/machines/"+remoteID+"/actions/update-agent", map[string]any{}); refused.Code < 400 {
		t.Fatalf("agent.update without its right: %d %s", refused.Code, refused.Body.String())
	}
	if unknown := callAPI(server.Server, http.MethodPost, path, map[string]any{"right": "shell.exec"}); unknown.Code != http.StatusUnprocessableEntity || errorCode(t, unknown) != "machine.capability_unknown" {
		t.Fatalf("unknown right: %d %s", unknown.Code, unknown.Body.String())
	}
	if pathValue := callAPI(server.Server, http.MethodPost, path, map[string]any{"right": "files.write", "value": "/etc"}); pathValue.Code != http.StatusUnprocessableEntity {
		t.Fatalf("a path asked for: %d %s", pathValue.Code, pathValue.Body.String())
	}

	var list actionsResponse
	decodeAPI(t, callAPI(server.Server, http.MethodGet, "/api/actions?machine="+remoteID, nil), &list)
	if len(list.Runs) != 1 || list.Runs[0].Kind != string(agentwire.KindRightRequest) {
		t.Fatalf("runs %+v, want the right.request alone", list.Runs)
	}
}

// ARB-1, R-A4-2 : right.request est de niveau 3, interface seulement. Un jeton
// reçoit le refus du niveau 3 et rien ne part ; aucun jeton ne se crée avec lui.
func TestARB1_ATokenGetsTheLevelThreeRefusal(t *testing.T) {
	gesture, found := verb.Default.Lookup("right.request")
	if !found || gesture.Level != 3 || gesture.Token || gesture.Order != agentwire.KindRightRequest {
		t.Fatalf("verb %+v", gesture)
	}
	server := newTestServer(t)
	requestRightSetup(t, server)
	bearer, _ := server.issueWriteToken(t, "agent-ia", "agent.ping")
	got := callBearerBody(server.Server, http.MethodPost, "/api/machines/"+remoteID+"/actions/request-right", bearer, `{"right":"docker.deploy"}`)
	if got.Code != http.StatusForbidden || errorCode(t, got) != codeAPITokenRouteForbidden {
		t.Fatalf("token: %d %s", got.Code, got.Body.String())
	}
	var list actionsResponse
	decodeAPI(t, callAPI(server.Server, http.MethodGet, "/api/actions?machine="+remoteID, nil), &list)
	if len(list.Runs) != 0 {
		t.Fatalf("runs %+v, want none", list.Runs)
	}
	if _, _, err := server.apiTokens.Create(context.Background(), apitoken.Request{Name: "neuf", Scope: apitoken.ScopeWrite, Verbs: []string{"right.request"}}); !errors.Is(err, apitoken.ErrVerbUnknown) {
		t.Fatalf("a token was issued with right.request: %v", err)
	}
}

// R-DROIT-8 (ARB-1) : chaque ligne d'agent qu'une réponse figée de l'API
// donne à coller est celle qu'agentpolicy.AgentLine écrit pour ses mots :
// jamais -yes, sous aucune forme, ni enchaînement.
func TestR_DROIT_8_NoServedLineCarriesYes(t *testing.T) {
	goldens, err := filepath.Glob(filepath.Join("testdata", "*.golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	prefix := "sudo " + brand.Command + " agent "
	lines := 0
	for _, golden := range goldens {
		content, err := os.ReadFile(golden) // #nosec G304 -- les réponses figées du dépôt.
		if err != nil {
			t.Fatal(err)
		}
		for _, quoted := range strings.Split(string(content), `"`+prefix)[1:] {
			words, _, _ := strings.Cut(quoted, `"`)
			lines++
			if line := prefix + words; agentpolicy.AgentLine(strings.Fields(words)...) != line {
				t.Errorf("%s: a served line AgentLine refuses: %s", golden, line)
			}
		}
	}
	if lines == 0 {
		t.Fatal("no served line seen: the guard no longer sees the answers")
	}
	if agentpolicy.AgentLine("grant", "--set", "manage", "--yes") != "" {
		t.Fatal("AgentLine writes a line with --yes")
	}
}
