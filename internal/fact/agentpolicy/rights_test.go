package agentpolicy

import (
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"
)

// formatSet écrit les droits d'un jeu tels que la fiche A3 (§5) les liste.
func formatSet(rights []SetRight) []string {
	formatted := make([]string, 0, len(rights))
	for _, right := range rights {
		switch {
		case right.ServicesRoot:
			formatted = append(formatted, right.Name+"=<services root>")
		case right.Value != "":
			formatted = append(formatted, right.Name+"="+right.Value)
		default:
			formatted = append(formatted, right.Name)
		}
	}
	return formatted
}

// R-A3-7 : trois jeux, et seulement trois ; la liste de chacun est figée ici.
func TestR_A3_7_ThreeSetsAndOnlyThree(t *testing.T) {
	names := slices.Sorted(maps.Keys(sets))
	if !slices.Equal(names, []Set{SetManage, SetObserve, SetRoot}) {
		t.Fatalf("sets %v", names)
	}
	observe := []string{"observe", "probe.lan"}
	manage := append(slices.Clone(observe), "agent.update", "docker.deploy", "docker.update",
		"restic.produce", "restic.docker", "restic.restore", "files.write=<services root>", "terminal.container")
	root := append(slices.Clone(manage), "terminal.host=root", "service.free", "network.private=1")
	want := map[Set][2][]string{
		SetObserve: {observe, {}},
		SetManage:  {manage, {"proxmox.power", "proxmox.snapshot"}},
		SetRoot:    {root, {"proxmox.power", "proxmox.snapshot", "backup.produce=proxmox-vzdump"}},
	}
	for set, lists := range want {
		if got := formatSet(sets[set].everywhere); !slices.Equal(got, lists[0]) {
			t.Errorf("%s: %v, want %v", set, got, lists[0])
		}
		if got := formatSet(sets[set].onProxmox); !slices.Equal(got, lists[1]) {
			t.Errorf("%s on Proxmox: %v, want %v", set, got, lists[1])
		}
	}
	// Les droits hors jeu ne sont posés par aucun jeu.
	for _, set := range sets {
		for _, right := range slices.Concat(set.everywhere, set.onProxmox) {
			if slices.Contains([]string{CapabilityObserveEnv, CapabilityBackupReceive, CapabilityResticTarget, CapabilityResticVerify, CapabilityResticBrowse}, right.Name) {
				t.Errorf("%s is set by a set", right.Name)
			}
			if !slices.Contains(Names(), right.Name) {
				t.Errorf("%s is not a known right", right.Name)
			}
		}
	}
}

// Chaque droit connu appartient à un des cinq groupes de l'onglet Droits, et
// à un seul (R-A3-13) ; les groupes sont ceux de la fiche A3 (§5).
func TestGroups_EveryRightHasExactlyOneGroup(t *testing.T) {
	want := map[Group][]string{
		GroupSee:     {"observe", "probe.lan", "observe.env"},
		GroupDeploy:  {"agent.update", "docker.deploy", "docker.update", "files.write", "proxmox.power", "proxmox.snapshot", "service.free"},
		GroupBackup:  {"backup.receive", "backup.produce", "restic.target", "restic.produce", "restic.docker", "restic.verify", "restic.browse", "restic.restore"},
		GroupEnter:   {"terminal.container", "terminal.host"},
		GroupNetwork: {"network.private"},
	}
	got := map[Group][]string{}
	seen := map[string]int{}
	for _, known := range knownRights {
		got[known.group] = append(got[known.group], known.name)
		seen[known.name]++
	}
	if !maps.EqualFunc(got, want, slices.Equal) {
		t.Errorf("groups %v, want %v", got, want)
	}
	for name, count := range seen {
		if count != 1 {
			t.Errorf("%s is listed %d times", name, count)
		}
	}
	if len(Names()) != 21 {
		t.Errorf("%d known rights, want the 17 of today and the 4 of the policy", len(Names()))
	}
}

// R-A3-10 : les droits nouveaux ne se lisent que dans la politique : ni
// identity.json ni -rights ne les acceptent.
func TestR_A3_10_PolicyOnlyRightsAreRefusedOutsideThePolicy(t *testing.T) {
	for _, text := range []string{"terminal.container", "terminal.host=root", "service.free", "network.private=1", "observe,terminal.host"} {
		if _, err := ParseCapabilities(text); !errors.Is(err, ErrCapabilityUnknown) {
			t.Errorf("%q: %v, want refused as unknown", text, err)
		}
	}
	if len(CapabilityNames()) != 17 || slices.Contains(CapabilityNames(), CapabilityTerminalHost) {
		t.Errorf("enrollment rights %v", CapabilityNames())
	}
}

// R-A3-10, dans la politique : terminal.host s'y lit, sous un compte (root
// sans valeur), et un compte mal formé est refusé ; les trois autres droits
// de la politique seule y restent inconnus tant que la table ne les ouvre
// pas. Ce que l'agent rapporte se lit avec la même grammaire.
func TestR_A3_10_TheHostTerminalIsReadInThePolicy(t *testing.T) {
	for text, want := range map[string]string{
		"terminal.host":        "observe,terminal.host=root",
		"terminal.host=admin":  "observe,terminal.host=admin",
		"terminal.host=_svc-1": "observe,terminal.host=_svc-1",
	} {
		rights, err := ParsePolicyRights(text)
		if err != nil || FormatCapabilities(rights) != want {
			t.Errorf("%q: %v %v, want %q", text, FormatCapabilities(rights), err, want)
		}
	}
	for _, text := range []string{"terminal.host=Root", "terminal.host=a:b", "terminal.host=/root", "terminal.host=1admin", "terminal.host=" + strings.Repeat("a", 33)} {
		if _, err := ParsePolicyRights(text); !errors.Is(err, ErrCapabilityAccount) {
			t.Errorf("%q: %v, want a bad account", text, err)
		}
	}
	for _, text := range []string{"terminal.container", "service.free", "network.private=1", "network.private"} {
		if _, err := ParsePolicyRights(text); !errors.Is(err, ErrCapabilityUnknown) {
			t.Errorf("%q: %v, want still closed", text, err)
		}
	}
	document, err := Decode([]byte("version = 1\nmachine_id = 'm'\n[[right]]\nname = 'terminal.host'\nvalue = 'admin'\n"))
	if err != nil || FormatCapabilities(document.Rights) != "observe,terminal.host=admin" {
		t.Fatalf("the policy does not read terminal.host: %+v %v", document, err)
	}
	if _, err := Decode([]byte("version = 1\nmachine_id = 'm'\n[[right]]\nname = 'service.free'\n")); !errors.Is(err, ErrUnreadable) {
		t.Fatalf("service.free read in the policy: %v", err)
	}
	if _, err := document.Revoke([]string{CapabilityTerminalHost}); err != nil {
		t.Fatalf("terminal.host does not revoke: %v", err)
	}
}
