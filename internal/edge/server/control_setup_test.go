package server

import (
	"net/http"
	"testing"
)

// La machine Kagu a déjà son agent : la route ne donne plus de jeton, avec
// la clé du refus.
func TestControlLocalEnrollment_RefusesOnceTheServerMachineHasAnAgent(t *testing.T) {
	ts := newTestServer(t)
	requireRefusal(t, callControl(ts, http.MethodPost, "/control/admin/local-enrollment", ``, rootUID), http.StatusConflict, "machine.local_enrolled")
}

// L'agent de la machine Kagu est enrôlé, sans rien avoir rapporté : le
// verdict du déploiement est celui de agentpolicy.Fit, « unknown ».
func TestControlLocalAgent_SaysWhereTheAgentOfTheServerMachineStands(t *testing.T) {
	ts := newTestServer(t)
	got := callControl(ts, http.MethodGet, "/control/admin/local-agent", ``, rootUID)
	if got.Code != http.StatusOK {
		t.Fatalf("local-agent: %d %s", got.Code, got.Body.String())
	}
	var local localAgentResponse
	decodeAPI(t, got, &local)
	if !local.Enrolled || local.Reported || local.Deploy.State != "unknown" {
		t.Fatalf("local agent %+v", local)
	}
}
