package machine_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"log/slog"
	"os"
	"testing"

	"github.com/ldesfontaine/kagu/internal/edge/store/storetest"
	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/fact/machine"
	"github.com/ldesfontaine/kagu/internal/kit/brand"
)

const serverFingerprint = "sha256:server"

func newMachines(t *testing.T) *machine.Service {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	machines := machine.New(storetest.Open(t), machine.NewSessions(), logger)
	machines.SetServerHost(serverFingerprint, "oc-host.example.org")
	return machines
}

// enrollFrom présente un jeton comme un agent qui arrive par la socket des
// agents locaux, avec l'empreinte donnée.
func enrollFrom(t *testing.T, machines *machine.Service, cleartext, fingerprint string) (machine.Machine, error) {
	t.Helper()
	return enrollThrough(t, machines, cleartext, fingerprint, true)
}

// enrollThrough présente un jeton comme un agent, avec l'empreinte donnée,
// par la socket des agents locaux ou par HTTPS.
func enrollThrough(t *testing.T, machines *machine.Service, cleartext, fingerprint string, viaLocalSocket bool) (machine.Machine, error) {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err := machine.NewID()
	if err != nil {
		t.Fatal(err)
	}
	return machines.Enroll(context.Background(), machine.Enrollment{
		MachineID: id, PublicKey: public, Token: cleartext, HostFingerprint: fingerprint, Hostname: "oc-host",
		ViaLocalSocket: viaLocalSocket,
	})
}

// machineIDFor ne rattache à LocalID que l'agent venu par la socket des
// agents locaux avec l'empreinte du serveur. Par HTTPS, la même empreinte,
// lisible de tous sur la machine, ne compte pas : l'agent garde l'identifiant
// qu'il a tiré (R-B1-7).
func TestMachineIDFor_TheServerFingerprintCountsOnlyThroughTheLocalSocket(t *testing.T) {
	cases := []struct {
		name           string
		fingerprint    string
		viaLocalSocket bool
		serverKnown    bool
		wantLocal      bool
	}{
		{"socket and server fingerprint", serverFingerprint, true, true, true},
		{"https and server fingerprint", serverFingerprint, false, true, false},
		{"socket and another fingerprint", "sha256:other", true, true, false},
		{"socket and no fingerprint", "", true, true, false},
		{"socket and the server fingerprint unknown", "", true, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			machines := newMachines(t)
			if !c.serverKnown {
				machines.SetServerHost("", "oc-host.example.org")
			}
			cleartext, _, err := machines.CreateToken(context.Background(), "oc-host", machine.RoleGeneric, nil)
			if err != nil {
				t.Fatal(err)
			}
			enrolled, err := enrollThrough(t, machines, cleartext, c.fingerprint, c.viaLocalSocket)
			if err != nil {
				t.Fatal(err)
			}
			if isLocal := enrolled.ID == machine.LocalID; isLocal != c.wantLocal {
				t.Fatalf("enrolled under %q, want local %v", enrolled.ID, c.wantLocal)
			}
			if !c.wantLocal && machine.ValidateID(enrolled.ID) != nil {
				t.Fatalf("a new machine keeps the id it drew: %q", enrolled.ID)
			}
		})
	}
}

// L'agent qui présente l'empreinte de la machine du serveur devient la
// machine openCloud, sous son identifiant stable ; les autres gardent le leur.
// Un second agent du serveur, par un jeton de machine neuve, est refusé tant
// que le premier est actif, sans consommer le jeton ; révoqué, le suivant
// reprend la même ligne et son historique.
func TestEnroll_FromTheServerMachine_TakesTheStableID(t *testing.T) {
	ctx := context.Background()
	machines := newMachines(t)
	cleartext, _, err := machines.CreateToken(ctx, "oc-host", machine.RoleGeneric, nil)
	if err != nil {
		t.Fatal(err)
	}
	local, err := enrollFrom(t, machines, cleartext, serverFingerprint)
	if err != nil || local.ID != machine.LocalID || local.Name != "oc-host" || !local.Agent.IsActive() {
		t.Fatalf("server machine: %+v %v", local, err)
	}

	elsewhere, _, _ := machines.CreateToken(ctx, "vps-paris-1", machine.RoleGeneric, nil)
	remote, err := enrollFrom(t, machines, elsewhere, "sha256:other")
	if err != nil || remote.ID == machine.LocalID {
		t.Fatalf("another machine keeps its own id: %+v %v", remote, err)
	}

	second, _, _ := machines.CreateToken(ctx, "twin", machine.RoleGeneric, nil)
	if _, err := enrollFrom(t, machines, second, serverFingerprint); !errors.Is(err, machine.ErrLocalAgentActive) {
		t.Fatalf("a second agent on the server machine: %v", err)
	}
	if pending, _ := machines.PendingTokens(ctx); len(pending) != 1 || pending[0].Name != "twin" {
		t.Fatalf("the refused token must stay pending: %+v", pending)
	}

	if err := machines.Remove(ctx, machine.LocalID, machine.RemoveOptions{KeepHistory: true}); err != nil {
		t.Fatal(err)
	}
	again, err := enrollFrom(t, machines, second, serverFingerprint)
	if err != nil || again.ID != machine.LocalID || again.Name != "oc-host" || !again.CreatedAt.Equal(local.CreatedAt) || again.Agent.ID == local.Agent.ID {
		t.Fatalf("the reinstalled agent takes the same row: %+v %v", again, err)
	}
}

// Tant que la machine openCloud n'a jamais eu d'agent, le serveur offre la
// ligne qui l'installe : la même tant qu'elle attend, avec observe et
// probe.lan, nommée d'après le nom d'hôte. Une fois l'agent enrôlé, plus rien n'est offert.
func TestOfferLocalEnrollment_UntilTheServerMachineHasAnAgent(t *testing.T) {
	ctx := context.Background()
	machines := newMachines(t)
	cleartext, token, err := machines.OfferLocalEnrollment(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if token.Name != "oc-host" || token.MachineID != "" || agentpolicy.FormatCapabilities(token.Capabilities) != "observe,probe.lan" {
		t.Fatalf("offered token %+v", token)
	}
	again, sameToken, err := machines.OfferLocalEnrollment(ctx)
	if err != nil || again != cleartext || sameToken.ID != token.ID {
		t.Fatalf("the waiting offer must be given again: %v", err)
	}
	if err := machines.CancelToken(ctx, token.ID); err != nil {
		t.Fatal(err)
	}
	renewed, renewedToken, err := machines.OfferLocalEnrollment(ctx)
	if err != nil || renewed == cleartext || renewedToken.ID == token.ID {
		t.Fatalf("a cancelled offer is renewed: %v", err)
	}
	local, err := enrollFrom(t, machines, renewed, serverFingerprint)
	if err != nil || local.ID != machine.LocalID {
		t.Fatalf("the offered line enrolls the server machine: %+v %v", local, err)
	}
	if _, _, err := machines.OfferLocalEnrollment(ctx); !errors.Is(err, machine.ErrLocalEnrolled) {
		t.Fatalf("after the agent: %v", err)
	}
	if err := machines.Remove(ctx, machine.LocalID, machine.RemoveOptions{KeepHistory: true}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := machines.OfferLocalEnrollment(ctx); !errors.Is(err, machine.ErrLocalEnrolled) {
		t.Fatalf("a revoked agent is not reinstalled by itself: %v", err)
	}
}

// Un nom d'hôte qui ne fait pas un nom de machine laisse celui du produit.
func TestOfferLocalEnrollment_FallsBackToTheProductName(t *testing.T) {
	machines := newMachines(t)
	machines.SetServerHost(serverFingerprint, "Mon_Serveur")
	_, token, err := machines.OfferLocalEnrollment(context.Background())
	if err != nil || token.Name != brand.LocalMachineName {
		t.Fatalf("token %+v %v", token, err)
	}
}
