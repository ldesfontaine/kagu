package agentapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ldesfontaine/kagu/internal/fact/machine"
	"github.com/ldesfontaine/kagu/internal/wire/agentwire"
)

// GET /agent/server-key rend, sans rien demander, la clé que l'enrôlement
// rend aussi : join compare les deux à la ligne (R-B1-13).
func TestServerKey_IsTheKeyTheEnrollmentHandsOver(t *testing.T) {
	server := newBench(t)
	request := httptest.NewRequest(http.MethodGet, agentwire.ServerKeyRoute, nil)
	request.Header.Set(agentwire.HeaderProtocol, agentwire.ProtocolVersion)
	recorder := httptest.NewRecorder()
	server.Handler.ServeHTTP(recorder, request)
	var answer agentwire.ServerKeyResponse
	if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &answer) != nil {
		t.Fatalf("status %d: %s", recorder.Code, recorder.Body.String())
	}
	serverKey, _, _ := server.actions.ServerKey()
	if answer.ServerKey != base64.StdEncoding.EncodeToString(serverKey) {
		t.Fatalf("server key %q", answer.ServerKey)
	}
}

// R-B1-18 : la moitié publique X25519 de l'agent est gardée sur l'agent ;
// une moitié qui n'a pas la taille d'une clé est refusée avant le jeton,
// qui reste valable.
func TestAgentEnroll_KeepsTheSealPublicKey(t *testing.T) {
	server := newBench(t)
	cleartext, _, err := server.machines.CreateToken(context.Background(), "vps-paris-1", machine.RoleGeneric, nil)
	if err != nil {
		t.Fatal(err)
	}
	public, _, _ := ed25519.GenerateKey(nil)
	request := agentwire.EnrollRequest{MachineID: remoteID, PublicKey: base64.StdEncoding.EncodeToString(public), Token: cleartext, Hostname: "vps", OS: "Debian 12", Arch: "amd64", AgentVersion: "v0.0.1"}
	for _, bad := range []string{base64.StdEncoding.EncodeToString(make([]byte, 31)), "%%%"} {
		refused := request
		refused.SealPublicKey = bad
		if got := server.postJSON("/agent/enroll", refused); got.Code != http.StatusBadRequest {
			t.Fatalf("seal key %q: %d %s", bad, got.Code, got.Body.String())
		}
	}
	seal := bytes.Repeat([]byte{7}, machine.SealKeySize)
	request.SealPublicKey = base64.StdEncoding.EncodeToString(seal)
	if got := server.postJSON("/agent/enroll", request); got.Code != http.StatusCreated {
		t.Fatalf("the refused attempts burnt the token: %d %s", got.Code, got.Body.String())
	}
	enrolled, err := server.machines.Get(context.Background(), remoteID)
	if err != nil || !bytes.Equal(enrolled.Agent.SealPublicKey, seal) {
		t.Fatalf("seal key kept %x %v", enrolled.Agent.SealPublicKey, err)
	}
}
