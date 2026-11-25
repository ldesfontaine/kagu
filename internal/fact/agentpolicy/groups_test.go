package agentpolicy

import (
	"slices"
	"testing"
	"time"

	"github.com/ldesfontaine/kagu/internal/kit/brand"
)

// inPolicy est un agent actif qui a rapporté ces droits de sa politique.
func inPolicy(t *testing.T, text string) AgentStatus {
	t.Helper()
	rights, err := ParsePolicyRights(text)
	if err != nil {
		t.Fatal(err)
	}
	return AgentStatus{Active: true, Reported: true, Rights: rights}
}

func groupNamed(t *testing.T, fits []GroupFit, group Group) GroupFit {
	t.Helper()
	index := slices.IndexFunc(fits, func(fit GroupFit) bool { return fit.Group == group })
	if index < 0 {
		t.Fatalf("no group %s", group)
	}
	return fits[index]
}

// Un groupe est permis dès qu'un de ses droits s'exerce, pas permis quand il
// n'en porte aucun ; chaque groupe nomme le droit que sa ligne grant pose.
func TestGroupFits_AGroupIsAllowedWhenOneOfItsRightsIs(t *testing.T) {
	fits := GroupFits(inPolicy(t, "observe,probe.lan,terminal.host=root"), nil)
	if got := len(fits); got != 5 {
		t.Fatalf("%d groups, want 5", got)
	}
	want := map[Group]struct {
		state  FitState
		opener string
	}{
		GroupSee:     {FitOK, CapabilityObserve},
		GroupDeploy:  {FitMissing, CapabilityDockerDeploy},
		GroupBackup:  {FitMissing, CapabilityResticProduce},
		GroupEnter:   {FitOK, CapabilityTerminalContainer},
		GroupNetwork: {FitMissing, CapabilityNetworkPrivate},
	}
	for _, fit := range fits {
		if fit.State != want[fit.Group].state || fit.Opener != want[fit.Group].opener {
			t.Errorf("%s: %s opened by %s, want %v", fit.Group, fit.State, fit.Opener, want[fit.Group])
		}
	}
	if enter := groupNamed(t, fits, GroupEnter); !enter.HostTerminal || !slices.Equal(enter.HeldNames(), []string{CapabilityTerminalHost}) {
		t.Errorf("enter %+v", enter)
	}
}

// Un groupe dont un droit porté ne s'exerce pas, et aucun autre, est
// unavailable ; un agent qui n'a rien rapporté laisse chaque groupe inconnu.
func TestGroupFits_UnavailableAndUnknown(t *testing.T) {
	status := inPolicy(t, "observe,docker.deploy")
	status.Unavailable = map[string]string{CapabilityDockerDeploy: "docker_missing"}
	if deploy := groupNamed(t, GroupFits(status, nil), GroupDeploy); deploy.State != FitUnavailable || !deploy.WorthRoot {
		t.Errorf("deploy %+v", deploy)
	}
	status.Reported = false
	for _, fit := range GroupFits(status, nil) {
		if fit.State != FitUnknown {
			t.Errorf("%s: %s, want unknown", fit.Group, fit.State)
		}
	}
}

// « permis jusqu'à » : l'heure où le dernier droit exercé du groupe tombe ;
// aucune quand l'un d'eux est sans échéance.
func TestGroupFits_UntilIsTheLastExpiryOfTheGroup(t *testing.T) {
	early, late := time.Date(2026, 11, 25, 16, 42, 0, 0, time.UTC), time.Date(2026, 11, 25, 18, 0, 0, 0, time.UTC)
	status := inPolicy(t, "observe,terminal.container,terminal.host=root")
	until := map[string]time.Time{CapabilityTerminalHost: early, CapabilityTerminalContainer: late}
	if enter := groupNamed(t, GroupFits(status, until), GroupEnter); !enter.Until.Equal(late) {
		t.Errorf("enter until %v, want %v", enter.Until, late)
	}
	delete(until, CapabilityTerminalContainer)
	if enter := groupNamed(t, GroupFits(status, until), GroupEnter); !enter.Until.IsZero() {
		t.Errorf("enter until %v, want none", enter.Until)
	}
}

// Le jeu se reconnaît à ses droits de jeu, partout ou sur un hôte Proxmox ;
// les droits hors jeu n'y changent rien ; autre chose est personnalisé.
func TestSetOf_RecognisesTheSetPosed(t *testing.T) {
	cases := []struct {
		text string
		set  Set
		ok   bool
	}{
		{"observe,probe.lan", SetObserve, true},
		{"observe,probe.lan,observe.env,backup.receive=/srv/backups", SetObserve, true},
		{"observe,probe.lan,agent.update,docker.deploy,docker.update,restic.produce,restic.docker,restic.restore,files.write=/srv,terminal.container", SetManage, true},
		{"observe,probe.lan,agent.update,docker.deploy,docker.update,restic.produce,restic.docker,restic.restore,files.write=/srv,terminal.container,proxmox.power,proxmox.snapshot", SetManage, true},
		{"observe,probe.lan,agent.update,docker.deploy,docker.update,restic.produce,restic.docker,restic.restore,files.write=/srv,terminal.container,terminal.host=root,service.free,network.private=1", SetRoot, true},
		{"observe", "", false},
		{"observe,probe.lan,docker.deploy", "", false},
	}
	for _, c := range cases {
		set, ok := SetOf(inPolicy(t, c.text).Rights)
		if set != c.set || ok != c.ok {
			t.Errorf("%s: %q %v, want %q %v", c.text, set, ok, c.set, c.ok)
		}
	}
}

// Les lignes des jeux et du retrait passent par AgentLine ; observe ne se
// retire pas et n'entre pas dans la ligne revoke.
func TestSetAndRevokeLines(t *testing.T) {
	prefix := "sudo " + brand.Command + " agent "
	if got := GrantSetLine(SetManage); got != prefix+"grant --set manage" {
		t.Errorf("set line %q", got)
	}
	if got := RevokeLine([]string{CapabilityObserve, CapabilityProbeLAN}); got != prefix+"revoke probe.lan" {
		t.Errorf("revoke line %q", got)
	}
	if got := RevokeLine([]string{CapabilityObserve}); got != "" {
		t.Errorf("revoke observe alone %q, want no line", got)
	}
}
