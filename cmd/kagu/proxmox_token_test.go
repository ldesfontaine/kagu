package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ldesfontaine/kagu/internal/edge/agent"
)

const benchProxmoxSecret = "0b9e7c51-3f2a-4d68-9e1c-7a5b4c3d2e10"

// proxmoxHost est quietSystem sur un hôte Proxmox vide : pveum ne connaît
// rien, et donne benchProxmoxSecret au jeton qu'il crée.
type proxmoxHost struct {
	quietSystem
}

func (*proxmoxHost) Proxmox() bool { return true }
func (*proxmoxHost) ProxmoxCertificate() (string, error) {
	return strings.Repeat("ab", 32), nil
}
func (s *proxmoxHost) Output(name string, args ...string) ([]byte, error) {
	s.laid = append(s.laid, name+" "+strings.Join(args, " "))
	if strings.HasPrefix(strings.Join(args, " "), "user token add ") {
		return []byte(`{"full-tokenid":"kagu-agent@pve!agent","value":"` + benchProxmoxSecret + `"}`), nil
	}
	return []byte("[]"), nil
}

// runProxmoxToken lance « agent proxmox-token » sur cet hôte et ce terminal ;
// rend la sortie et ce que l'hôte a reçu.
func runProxmoxToken(t *testing.T, terminal terminalOpener, euid int, rights string, args ...string) (string, *proxmoxHost, string, error) {
	t.Helper()
	stateDir, place := policyState(t, rights)
	var out bytes.Buffer
	host := &proxmoxHost{}
	placer := func(*os.Root) (agent.PolicyPlace, error) { return place, nil }
	err := runAgentProxmoxToken(append([]string{"-state", stateDir}, args...), policyCommand{out: &out, openTerminal: terminal, euid: euid, place: placer, system: host})
	return out.String(), host, stateDir, err
}

// R-DROIT-8 (#902) : la commande dit le rôle et ses privilèges, le compte,
// /vms, le jeton et le fichier, puis demande [o/N] ; après « o », elle pose,
// et le secret n'est ni à l'écran ni dans une commande lancée.
func TestR_DROIT_8_T0409b_ProxmoxTokenAsksThenLaysWithoutShowingTheSecret(t *testing.T) {
	out, host, stateDir, err := runProxmoxToken(t, fakeTerminal("o\n"), 0, "proxmox.power")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, want := range []string{
		"Ce que la commande crée dans Proxmox", "KaguAgent (VM.Audit, VM.PowerMgmt, VM.Snapshot)", "kagu-agent@pve", "/vms",
		"kagu-agent@pve!agent", filepath.Join(stateDir, "proxmox.json"), "Continuer ? [o/N]", "✓", "Jeton Proxmox posé",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if laid := strings.Join(host.laid, "\n"); strings.Contains(out, benchProxmoxSecret) || strings.Contains(laid, benchProxmoxSecret) {
		t.Fatalf("the secret is shown or in a command:\n%s\n%s", out, laid)
	}
	content, err := os.ReadFile(filepath.Join(stateDir, "proxmox.json"))
	if err != nil || !strings.Contains(string(content), benchProxmoxSecret) {
		t.Fatalf("token file %q %v", content, err)
	}
}

// R-DROIT-8 : -yes ne vaut que sans terminal ; avec un terminal, la question
// est posée, et N par défaut ne crée rien. Sans terminal ni -yes : refus.
func TestR_DROIT_8_T0409b_ProxmoxTokenCreatesNothingWithoutConsent(t *testing.T) {
	cases := map[string]struct {
		terminal terminalOpener
		args     []string
		said     string
	}{
		"enter":           {terminal: fakeTerminal("\n"), said: "Continuer ? [o/N]"},
		"yes on terminal": {terminal: fakeTerminal("n\n"), args: []string{"-yes"}, said: "--yes ne vaut que sans terminal"},
		"no terminal":     {terminal: noTerminal},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			out, host, stateDir, err := runProxmoxToken(t, c.terminal, 0, "proxmox.snapshot", c.args...)
			var refused *refusal
			if !errors.As(err, &refused) || !strings.Contains(out, c.said) {
				t.Fatalf("err %v\n%s", err, out)
			}
			for _, laid := range host.laid {
				if !strings.Contains(laid, " list") {
					t.Errorf("created without consent: %s", laid)
				}
			}
			if _, err := os.Stat(filepath.Join(stateDir, "proxmox.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("token file: %v", err)
			}
		})
	}
}

// Un compte sans privilège, des mots en trop, une politique sans droit
// proxmox.* : refus avec la phrase de la commande, rien de lancé.
func TestR_DROIT_8_T0409b_ProxmoxTokenRefusals(t *testing.T) {
	cases := map[string]struct {
		euid   int
		rights string
		args   []string
		want   string
	}{
		"not root": {euid: 1000, rights: "proxmox.power", want: "en root sur l'hôte"},
		"extra":    {rights: "proxmox.power", args: []string{"now"}, want: "Usage : kagu agent proxmox-token"},
		"no right": {rights: "probe.lan", want: "kagu agent grant proxmox.power"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, host, _, err := runProxmoxToken(t, fakeTerminal("o\n"), c.euid, c.rights, c.args...)
			var refused *refusal
			if !errors.As(err, &refused) || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err %v, want %q", err, c.want)
			}
			if len(host.laid) != 0 {
				t.Fatalf("ran %v", host.laid)
			}
		})
	}
}
