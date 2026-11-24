package agentpolicy

import (
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"
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

// R-A3-10, dans la politique : les quatre droits de la politique seule s'y
// lisent avec leur grammaire, terminal.host sous un compte (root sans valeur),
// network.private sous un nombre de pairs (1 sans valeur) ; une valeur mal
// formée est refusée. Ce que l'agent rapporte se lit avec la même grammaire.
func TestR_A3_10_PolicyOnlyRightsAreReadInThePolicy(t *testing.T) {
	for text, want := range map[string]string{
		"terminal.host":                   "observe,terminal.host=root",
		"terminal.host=admin":             "observe,terminal.host=admin",
		"terminal.host=_svc-1":            "observe,terminal.host=_svc-1",
		"terminal.container":              "observe,terminal.container",
		"service.free":                    "observe,service.free",
		"network.private":                 "observe,network.private=1",
		"network.private=254":             "observe,network.private=254",
		"service.free,terminal.container": "observe,terminal.container,service.free",
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
	for _, text := range []string{"network.private=0", "network.private=255", "network.private=01", "network.private=+1", "network.private=1:2", "network.private=-1", "network.private=un"} {
		if _, err := ParsePolicyRights(text); !errors.Is(err, ErrCapabilityPeers) {
			t.Errorf("%q: %v, want a bad number of peers", text, err)
		}
	}
	for _, text := range []string{"service.free=/srv", "terminal.container=x"} {
		if _, err := ParsePolicyRights(text); !errors.Is(err, ErrCapabilityScope) {
			t.Errorf("%q: %v, want no value", text, err)
		}
	}
	document, err := Decode([]byte("version = 1\nmachine_id = 'm'\n[[right]]\nname = 'terminal.host'\nvalue = 'admin'\n[[right]]\nname = 'network.private'\nvalue = '2'\n"))
	if err != nil || FormatCapabilities(document.Rights) != "observe,terminal.host=admin,network.private=2" {
		t.Fatalf("the policy does not read its own rights: %+v %v", document, err)
	}
	if _, err := Decode([]byte("version = 1\nmachine_id = 'm'\n[[right]]\nname = 'network.private'\nvalue = '999'\n")); !errors.Is(err, ErrUnreadable) {
		t.Fatalf("a bad number of peers read in the policy: %v", err)
	}
	if _, err := document.Revoke([]string{CapabilityTerminalHost, CapabilityNetworkPrivate, CapabilityServiceFree}); err != nil {
		t.Fatalf("the policy-only rights do not revoke: %v", err)
	}
}

// R-A3-7 : --set remplace les droits des jeux par ceux du jeu, sans
// échéance, et garde le reste : ancres, clé du serveur, droits hors jeu et
// leur échéance, dont backup.receive de la machine du serveur.
func TestR_A3_7_GrantSetReplacesTheSetAndKeepsTheRest(t *testing.T) {
	clock := Clock{Now: time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC), Boot: "boot", Uptime: time.Hour}
	rights, err := ParsePolicyRights("files.write=/srv/static,terminal.host,backup.receive=/var/lib/opencloud-agent/database-backups,observe.env,docker.deploy")
	if err != nil {
		t.Fatal(err)
	}
	before := Document{MachineID: "m", Anchors: map[string][]string{"backup.guest": {"5012"}}, ServerKeys: []ServerKey{{Key: []byte("k")}}}
	before, err = before.Grant(rights, Term{}, clock)
	if err != nil {
		t.Fatal(err)
	}
	before, err = before.Grant([]Capability{{Name: CapabilityObserveEnv}}, Term{Duration: time.Hour}, clock)
	if err != nil {
		t.Fatal(err)
	}
	host := SetHost{ServicesRoot: "/srv/workspace"}
	for set, want := range map[Set]string{
		SetObserve: "observe,probe.lan,observe.env,backup.receive=/var/lib/opencloud-agent/database-backups",
		SetManage: "observe,probe.lan,observe.env,agent.update,docker.deploy,docker.update,backup.receive=/var/lib/opencloud-agent/database-backups," +
			"files.write=/srv/workspace,restic.produce,restic.docker,restic.restore,terminal.container",
		SetRoot: "observe,probe.lan,observe.env,agent.update,docker.deploy,docker.update,backup.receive=/var/lib/opencloud-agent/database-backups," +
			"files.write=/srv/workspace,restic.produce,restic.docker,restic.restore,terminal.container,terminal.host=root,service.free,network.private=1",
	} {
		after, err := before.GrantSet(set, host)
		if err != nil {
			t.Fatalf("%s: %v", set, err)
		}
		if got := FormatCapabilities(after.Rights); got != want {
			t.Errorf("%s: %s\nwant %s", set, got, want)
		}
		if !maps.EqualFunc(after.Anchors, before.Anchors, slices.Equal) || len(after.ServerKeys) != 1 || after.MachineID != "m" {
			t.Errorf("%s: anchors, key or machine lost: %+v", set, after)
		}
		// terminal.host, posé pour deux heures seul, est sans échéance dans
		// le jeu ; observe.env garde la sienne.
		if names := slices.Sorted(maps.Keys(after.Expiries)); !slices.Equal(names, []string{CapabilityObserveEnv}) {
			t.Errorf("%s: expiries %v, want observe.env alone", set, names)
		}
	}
	proxmox, err := before.GrantSet(SetRoot, SetHost{ServicesRoot: "/srv/workspace", Proxmox: true})
	if err != nil || !CoversProducer(proxmox.Rights, ProducerProxmoxVzdump) || !HasCapability(proxmox.Rights, CapabilityProxmoxSnapshot) {
		t.Errorf("root on Proxmox: %s %v", FormatCapabilities(proxmox.Rights), err)
	}
	// Un jeu reposé ne change rien ; un autre hôte retire ce qu'il posait.
	again, _ := proxmox.GrantSet(SetRoot, SetHost{ServicesRoot: "/srv/workspace", Proxmox: true})
	if !again.Same(proxmox) {
		t.Error("the same set twice changes the policy")
	}
	if manage, _ := proxmox.GrantSet(SetManage, host); HasCapability(manage.Rights, CapabilityBackupProduce) || HasCapability(manage.Rights, CapabilityProxmoxPower) {
		t.Errorf("manage off Proxmox keeps %s", FormatCapabilities(manage.Rights))
	}
	if _, err := before.GrantSet("admin", host); !errors.Is(err, ErrSetUnknown) {
		t.Errorf("unknown set: %v", err)
	}
	if _, err := before.GrantSet(SetManage, SetHost{ServicesRoot: "/"}); !errors.Is(err, ErrCapabilityPath) {
		t.Errorf("a bad services root: %v", err)
	}
	if !CoversSet(proxmox.Rights, SetRoot) || CoversSet(before.Rights, SetManage) {
		t.Error("CoversSet")
	}
}

// R-A3-8, R-A3-12 : ce que chaque droit demande au système est figé ici :
// le groupe docker (qui vaut root) et la porte root (A5).
func TestR_A3_8_WhatEachRightAsksOfTheSystem(t *testing.T) {
	var docker, gate []string
	for _, name := range Names() {
		if NeedsDockerGroup([]Capability{{Name: name}}) {
			docker = append(docker, name)
		}
		gate = append(gate, RootGateRights([]Capability{{Name: name}})...)
	}
	if want := []string{"docker.deploy", "docker.update", "restic.docker", "terminal.container", "service.free"}; !slices.Equal(docker, want) {
		t.Errorf("docker group: %v, want %v", docker, want)
	}
	if want := []string{"backup.produce", "terminal.host", "network.private"}; !slices.Equal(gate, want) {
		t.Errorf("root gate: %v, want %v", gate, want)
	}
	for _, name := range docker {
		if NoticeOf(Capability{Name: name}).RiskKey != manageRisk {
			t.Errorf("%s does not say it is worth root", name)
		}
	}
}
