package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/fact/anchor"
	"github.com/ldesfontaine/kagu/internal/fact/machine"
	"github.com/ldesfontaine/kagu/internal/kit/audit"
	"github.com/ldesfontaine/kagu/internal/kit/brand"
	"github.com/ldesfontaine/kagu/internal/kit/step"
	"github.com/ldesfontaine/kagu/internal/kit/version"
	"github.com/ldesfontaine/kagu/internal/wire/agentwire"
)

// joinServer est un serveur qui a un domaine : la ligne d'ajout existe.
func joinServer(t *testing.T) *testServer {
	t.Helper()
	server := newTestServer(t)
	server.publicURL = "https://kagu.exemple.fr"
	return server
}

func TestAPI_CreateMachineToken_ShowsTheTokenOnceAndListsItAsPending(t *testing.T) {
	server := joinServer(t)
	recorder := callAPI(server.Server, http.MethodPost, "/api/machines/tokens", tokenRequest{Name: "vps-paris-1", Set: "manage"})
	if recorder.Code != http.StatusCreated {
		t.Fatalf("status %d: %s", recorder.Code, recorder.Body.String())
	}
	var response tokenResponse
	decodeAPI(t, recorder, &response)
	_, fingerprint, _ := server.actions.ServerKey()
	want := "curl -fsSL " + brand.ReleaseBaseURL + "/" + version.Number() + "/install.sh | sudo sh -s -- join --server https://kagu.exemple.fr --server-key " + fingerprint + " --rights manage"
	if !tokenValue.MatchString(response.Token) || response.Command != want || response.Set != "manage" || len(response.ReenrollLines) != 0 {
		t.Fatalf("token response %+v\nwant command %q", response, want)
	}
	pending, err := server.machines.PendingTokens(context.Background())
	if err != nil || len(pending) != 1 || pending[0].Name != "vps-paris-1" {
		t.Fatalf("pending %+v %v", pending, err)
	}
	list := callAPI(server.Server, http.MethodGet, "/api/machines", nil)
	if !strings.Contains(list.Body.String(), pending[0].Masked()) || tokenValue.MatchString(list.Body.String()) {
		t.Fatal("the list must show the masked token and never the cleartext")
	}

	if got := callAPI(server.Server, http.MethodDelete, "/api/machines/tokens/"+pending[0].ID, nil); got.Code != http.StatusNoContent {
		t.Fatalf("cancel: %d", got.Code)
	}
	if got := callAPI(server.Server, http.MethodDelete, "/api/machines/tokens/"+pending[0].ID, nil); got.Code != http.StatusNoContent {
		t.Fatalf("cancel again: %d", got.Code)
	}
	if pending, _ := server.machines.PendingTokens(context.Background()); len(pending) != 0 {
		t.Fatalf("still pending %+v", pending)
	}
}

// R-DROIT-6, N-M8 : le jeu est dans la ligne, en clair, jamais dans le
// jeton ; la ligne lance le script de l'adresse des versions, jamais une
// adresse du serveur en tête de curl, et ne porte pas le jeton. Le jeton ne
// garde que le jeu affiché, pour l'écran. Un jeu inconnu, ou pas de jeu, ne
// fait naître aucun jeton.
func TestR_DROIT_6_TheRightsSetIsInTheLineNeverInTheToken(t *testing.T) {
	for _, set := range agentpolicy.Sets() {
		server := joinServer(t)
		var response tokenResponse
		decodeAPI(t, callAPI(server.Server, http.MethodPost, "/api/machines/tokens", tokenRequest{Name: "vps-paris-1", Set: string(set)}), &response)
		if !strings.HasSuffix(response.Command, " --rights "+string(set)) {
			t.Errorf("%s: the line does not carry the set: %q", set, response.Command)
		}
		fetched := strings.Fields(response.Command)[2]
		if strings.Contains(response.Command, response.Token) || strings.HasPrefix(fetched, server.publicURL) || !strings.HasPrefix(fetched, brand.ReleaseBaseURL+"/") {
			t.Errorf("%s: the line carries the token or fetches from serve: %q", set, response.Command)
		}
		pending, _ := server.machines.PendingTokens(context.Background())
		shown, _ := agentpolicy.NormalizePolicyRights(setRightsShown(set))
		if len(pending) != 1 || agentpolicy.FormatCapabilities(pending[0].Capabilities) != agentpolicy.FormatCapabilities(shown) {
			t.Errorf("%s: the token keeps %+v", set, pending)
		}
	}
	server := joinServer(t)
	for _, request := range []map[string]any{{"name": "vps-lyon-2"}, {"name": "vps-lyon-2", "set": "everything"}, {"name": "vps-lyon-2", "capabilities": []map[string]any{{"name": "docker.deploy"}}}} {
		if got := callAPI(server.Server, http.MethodPost, "/api/machines/tokens", request); got.Code == http.StatusCreated {
			t.Errorf("%v: a token was issued", request)
		}
	}
	if pending, _ := server.machines.PendingTokens(context.Background()); len(pending) != 0 {
		t.Fatalf("tokens issued without a set: %+v", pending)
	}
}

// R-B1-13 : sans adresse publique en https, aucune ligne et aucun jeton ;
// la liste dit que l'ajout attend un domaine, avec la commande.
func TestAPI_CreateMachineToken_NeedsADomain(t *testing.T) {
	for _, address := range []string{"", "http://kagu.exemple.fr"} {
		server := newTestServer(t)
		server.publicURL = address
		got := callAPI(server.Server, http.MethodPost, "/api/machines/tokens", tokenRequest{Name: "vps-paris-1", Set: "observe"})
		if got.Code != http.StatusConflict || errorCode(t, got) != "machine.join_needs_domain" {
			t.Fatalf("%q: %d %s", address, got.Code, got.Body.String())
		}
		if pending, _ := server.machines.PendingTokens(context.Background()); len(pending) != 0 {
			t.Fatalf("%q: a token was issued", address)
		}
		var list machinesResponse
		decodeAPI(t, callAPI(server.Server, http.MethodGet, "/api/machines", nil), &list)
		if list.Join == nil || list.Join.Ready || list.Join.DomainLine != "sudo kagu setup --domain" || len(list.Join.Sets) != 3 {
			t.Fatalf("%q: join offer %+v", address, list.Join)
		}
	}
	var list machinesResponse
	decodeAPI(t, callAPI(joinServer(t).Server, http.MethodGet, "/api/machines", nil), &list)
	if list.Join == nil || !list.Join.Ready {
		t.Fatalf("join offer with a domain: %+v", list.Join)
	}
}

func TestAPI_CreateMachineToken_RefusesABadNameWithItsKey(t *testing.T) {
	server := joinServer(t)
	got := callAPI(server.Server, http.MethodPost, "/api/machines/tokens", tokenRequest{Name: "VPS Paris", Set: "observe"})
	if got.Code != http.StatusUnprocessableEntity || errorCode(t, got) != "machine.name_invalid" {
		t.Fatalf("%d %s", got.Code, got.Body.String())
	}
	if got := callAPI(server.Server, http.MethodPost, "/api/machines/tokens", map[string]any{"name": "x", "extra": 1}); got.Code != http.StatusBadRequest || errorCode(t, got) != codeBadJSON {
		t.Fatalf("unknown field: %d %s", got.Code, got.Body.String())
	}
}

func TestAPI_RemoveMachine_ForgetsItTheKaguOneToo(t *testing.T) {
	server := newTestServer(t)
	server.enroll(t, "vps-paris-1", remoteID)
	if got := callAPI(server.Server, http.MethodDelete, "/api/machines/"+remoteID, nil); got.Code != http.StatusNoContent {
		t.Fatalf("remove: %d %s", got.Code, got.Body.String())
	}
	if got := callAPI(server.Server, http.MethodGet, "/api/machines/"+remoteID, nil); got.Code != http.StatusNotFound {
		t.Fatalf("after remove: %d", got.Code)
	}
	if got := callAPI(server.Server, http.MethodDelete, "/api/machines/"+remoteID, nil); got.Code != http.StatusNotFound {
		t.Fatalf("remove again: %d", got.Code)
	}
	if got := callAPI(server.Server, http.MethodDelete, "/api/machines/local", nil); got.Code != http.StatusNoContent {
		t.Fatalf("remove local: %d %s", got.Code, got.Body.String())
	}
}

func TestAPI_Reenroll_IssuesATokenForTheSameMachine(t *testing.T) {
	server := joinServer(t)
	server.enroll(t, "vps-paris-1", remoteID)
	recorder := callAPI(server.Server, http.MethodPost, "/api/machines/"+remoteID+"/actions/reenroll", reenrollRequest{Set: "observe"})
	if recorder.Code != http.StatusCreated {
		t.Fatalf("status %d: %s", recorder.Code, recorder.Body.String())
	}
	var response tokenResponse
	decodeAPI(t, recorder, &response)
	if response.Name != "vps-paris-1" || !tokenValue.MatchString(response.Token) || !strings.HasSuffix(response.Command, " --rights observe") || !slices.Equal(response.ReenrollLines, machine.ReenrollLines()) {
		t.Fatalf("token response %+v", response)
	}
	pending, _ := server.machines.PendingTokens(context.Background())
	if len(pending) != 1 || pending[0].MachineID != remoteID {
		t.Fatalf("pending %+v", pending)
	}
	// La machine Kagu ne s'enrôle que par sa socket : setup la refait.
	if got := callAPI(server.Server, http.MethodPost, "/api/machines/local/actions/reenroll", reenrollRequest{Set: "observe"}); got.Code != http.StatusConflict || errorCode(t, got) != "machine.local_reenroll_by_setup" {
		t.Fatalf("reenroll local: %d %s", got.Code, got.Body.String())
	}
	if got := callAPI(server.Server, http.MethodPost, "/api/machines/nope/actions/reenroll", reenrollRequest{Set: "observe"}); got.Code != http.StatusNotFound {
		t.Fatalf("reenroll unknown: %d", got.Code)
	}
	if got := callAPI(server.Server, http.MethodPost, "/api/machines/"+remoteID+"/actions/reenroll", nil); got.Code == http.StatusCreated {
		t.Fatalf("reenroll without a set: %d", got.Code)
	}
}

// L'API rend le verdict de chaque droit connu (F-6) : un agent qui n'a pas
// parlé est inconnu quoi que son jeton demande, un droit porté mais
// inexerçable dit sa raison, un agent révoqué n'a aucun droit.
func TestAgentJSON_RendersTheFitOfEachRight(t *testing.T) {
	requested, err := agentpolicy.ParseCapabilities("docker.deploy")
	if err != nil {
		t.Fatal(err)
	}
	silent := machine.Agent{ID: "agt_1", Requested: requested}
	reported := machine.Agent{ID: "agt_1", Capabilities: requested, ReportedAt: testNow, Unavailable: map[string]string{agentpolicy.CapabilityDockerDeploy: "docker_denied"}}
	revoked := reported
	revoked.RevokedAt = testNow
	cases := []struct {
		name  string
		agent machine.Agent
		want  fitJSON
	}{
		{"silent", silent, fitJSON{State: "unknown"}},
		{"unavailable", reported, fitJSON{State: "unavailable", Reason: "docker_denied"}},
		{"revoked", revoked, fitJSON{State: "missing"}},
	}
	for _, c := range cases {
		fits := agentToJSON(c.agent).Fit
		if got := fits[agentpolicy.CapabilityDockerDeploy]; got != c.want {
			t.Errorf("%s: %+v, want %+v", c.name, got, c.want)
		}
		for _, right := range agentpolicy.Names() {
			if _, rendered := fits[right]; !rendered {
				t.Errorf("%s: no verdict for %s", c.name, right)
			}
		}
	}
}

// Supprimer sans corps (ou avec keep_history à faux) efface la machine ;
// avec keep_history elle reste, archivée : 204, la fiche dit l'agent révoqué,
// l'audit garde agent.revoke et jamais machine.delete ; une seconde fois, 409
// machine.no_agent. Ce qui retient le retrait (une sonde) ne retient pas
// l'archive. L'ancienne route de révocation n'existe plus. Ré-enrôler la désarchive :
// c'est TestRemove_KeepHistory_RefusesTheAgent…, au niveau du composant.
func TestAPI_RemoveMachine_KeepHistory_ArchivesItAndErasesNothing(t *testing.T) {
	server := newTestServer(t)
	server.enroll(t, "vps-paris-1", remoteID)
	if got := callAPI(server.Server, http.MethodPost, "/api/probes", probeRequest{Name: "site", Kind: "http", Target: "https://a.fr/", MachineID: remoteID}); got.Code != http.StatusCreated {
		t.Fatalf("probe: %d %s", got.Code, got.Body.String())
	}
	before := server.latestAuditID(t)

	if got := callAPI(server.Server, http.MethodDelete, "/api/machines/"+remoteID, removeMachineRequest{}); got.Code != http.StatusConflict {
		t.Fatalf("without history, held back by the probe: %d %s", got.Code, got.Body.String())
	}
	if got := callAPI(server.Server, http.MethodDelete, "/api/machines/"+remoteID, removeMachineRequest{KeepHistory: true}); got.Code != http.StatusNoContent {
		t.Fatalf("keep history: %d %s", got.Code, got.Body.String())
	}

	var archived machineJSON
	decodeAPI(t, callAPI(server.Server, http.MethodGet, "/api/machines/"+remoteID, nil), &archived)
	if archived.Agent == nil || archived.Agent.RevokedAt == nil || archived.Online {
		t.Fatalf("machine after archive %+v", archived)
	}
	actions := []audit.Action{}
	for _, event := range server.auditSince(t, before) {
		actions = append(actions, event.Action)
	}
	if !slices.Equal(actions, []audit.Action{audit.AgentRevoke}) {
		t.Fatalf("audit %v, want agent.revoke alone", actions)
	}
	if got := callAPI(server.Server, http.MethodDelete, "/api/machines/"+remoteID, removeMachineRequest{KeepHistory: true}); got.Code != http.StatusConflict || errorCode(t, got) != "machine.no_agent" {
		t.Fatalf("archive twice: %d %s", got.Code, got.Body.String())
	}
	if got := callAPI(server.Server, http.MethodDelete, "/api/machines/nobody", removeMachineRequest{KeepHistory: true}); got.Code != http.StatusNotFound {
		t.Fatalf("unknown machine: %d", got.Code)
	}
	if got := callAPI(server.Server, http.MethodDelete, "/api/machines/local", removeMachineRequest{KeepHistory: true}); got.Code != http.StatusNoContent {
		t.Fatalf("archive local: %d %s", got.Code, got.Body.String())
	}
	if got := callAPI(server.Server, http.MethodPost, "/api/machines/"+remoteID+"/actions/revoke", nil); got.Code < 400 {
		t.Fatalf("the revoke route is gone: %d", got.Code)
	}
}

// Un corps de retrait qui n'est pas celui du geste est refusé, rien n'est
// retiré.
func TestAPI_RemoveMachine_RefusesAnUnknownField(t *testing.T) {
	server := newTestServer(t)
	server.enroll(t, "vps-paris-1", remoteID)
	if got := callAPI(server.Server, http.MethodDelete, "/api/machines/"+remoteID, map[string]bool{"purge": true}); got.Code != http.StatusBadRequest {
		t.Fatalf("unknown field: %d %s", got.Code, got.Body.String())
	}
	if !server.machineExists(t, remoteID) {
		t.Fatal("a refused body removed the machine")
	}
}

// Un refus par ancre rend sa clé et la commande qui le lèverait, avec un 409 :
// l'écran montre la commande à lancer sur la machine.
func TestFailed_AnAnchorRefusalCarriesItsKeyAndCommand(t *testing.T) {
	server := newTestServer(t)
	params, _ := json.Marshal(agentwire.BackupProduceParams{Producer: "proxmox-vzdump", Target: "312", Recipient: "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"})
	finding := anchor.Judge(anchor.FromFile(map[string][]string{"backup.recipient": {"age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"}}), agentwire.PresentedOf(agentwire.KindBackupProduce, params))
	if finding == nil {
		t.Fatal("expected a finding")
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/anything", nil)
	wrapped := fmt.Errorf("send backup.produce: %w", &anchor.Refused{Finding: *finding})
	if !server.Server.failed(recorder, request, wrapped, nil) {
		t.Fatal("a refusal is a failure")
	}
	var body apiError
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if recorder.Code != http.StatusConflict || body.Error != "anchor.backup_guest_missing" || body.Fix == nil || !body.Fix.Exact || body.Fix.Command != "sudo "+brand.Command+" agent trust add backup.guest 312" {
		t.Fatalf("%d %+v", recorder.Code, body)
	}
}

// R-B1-11 : la tuile lit l'avancement sur le jeton par
// GET /api/machines/tokens/{id}/progress, sans le jeton ; un jeton d'API le
// lit aussi (niveau 0). Enrôlée, la fiche rend la même frise ; un jeton
// inconnu répond 404.
func TestAPI_TokenProgress_TheTileThenTheSheetReadTheSameSteps(t *testing.T) {
	server := joinServer(t)
	ctx := context.Background()
	cleartext, token, err := server.machines.CreateToken(ctx, "vps-paris-1", machine.RoleGeneric, nil)
	if err != nil {
		t.Fatal(err)
	}
	checked := []step.Step{{Key: step.EnrollSystem, State: step.StateDone, Detail: "Debian 12, amd64", At: time.Unix(1_800_000_000, 0)}}
	if err := server.machines.RecordJoinProgress(ctx, cleartext, checked); err != nil {
		t.Fatal(err)
	}
	var tile arrivalJSON
	read := callBearer(server.Server, "/api/machines/tokens/"+token.ID+"/progress", server.issueAPIToken(t, "mcp-maison"))
	decodeAPI(t, read, &tile)
	if tile.State != machine.ArrivalPending || len(tile.Steps) != 1 || tile.Steps[0].Detail != "Debian 12, amd64" || strings.Contains(read.Body.String(), cleartext) {
		t.Fatalf("progress %s", read.Body.String())
	}
	if got := callAPI(server.Server, http.MethodGet, "/api/machines/tokens/0000000000000000/progress", nil); got.Code != http.StatusNotFound {
		t.Fatalf("unknown token: %d", got.Code)
	}

	public, _, _ := ed25519.GenerateKey(rand.Reader)
	enrolled, err := server.machines.Enroll(ctx, machine.Enrollment{MachineID: remoteID, PublicKey: public, Token: cleartext, Hostname: "vps", OS: "Debian 12", Arch: "amd64", AgentVersion: "v0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	var sheet machineSheetJSON
	decodeAPI(t, callAPI(server.Server, http.MethodGet, "/api/machines/"+enrolled.ID, nil), &sheet)
	if len(sheet.Arrival) != 1 || sheet.Arrival[0].Key != step.EnrollSystem {
		t.Fatalf("sheet arrival %+v", sheet.Arrival)
	}
}

// R-B1-11 : setup écrit les étapes de l'agent de la machine Kagu par la
// socket de contrôle, sous le jeton que cet agent a consommé ; sa fiche les
// rend. Un parcours mal formé est refusé.
func TestControlLocalProgress_LandsOnTheServerMachineSheet(t *testing.T) {
	ts := newTestServer(t)
	body := `{"steps":[{"key":"step.enroll.system","state":"done","at":"2026-11-27T10:00:00Z"},{"key":"step.setup.agent","state":"done","detail":"Gérer","at":"2026-11-27T10:01:00Z"}]}`
	if got := callControl(ts, http.MethodPost, "/control/admin/local-enrollment/progress", body, rootUID); got.Code != http.StatusNoContent {
		t.Fatalf("progress: %d %s", got.Code, got.Body.String())
	}
	var sheet machineSheetJSON
	decodeAPI(t, callAPI(ts.Server, http.MethodGet, "/api/machines/"+machine.LocalID, nil), &sheet)
	if len(sheet.Arrival) != 2 || sheet.Arrival[1].Key != step.SetupAgent {
		t.Fatalf("local arrival %+v", sheet.Arrival)
	}
	bad := `{"steps":[{"key":"setup.agent","state":"done","at":"2026-11-27T10:00:00Z"}]}`
	if got := callControl(ts, http.MethodPost, "/control/admin/local-enrollment/progress", bad, rootUID); got.Code != http.StatusBadRequest {
		t.Fatalf("bad key: %d %s", got.Code, got.Body.String())
	}
}
