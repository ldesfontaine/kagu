package server

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/fact/machine"
)

// reportingAgent est l'agent actif d'une machine qui a rapporté ces droits
// de sa politique.
func reportingAgent(t *testing.T, machineID, rights string) machine.Agent {
	t.Helper()
	capabilities, err := agentpolicy.ParsePolicyRights(rights)
	if err != nil {
		t.Fatal(err)
	}
	return machine.Agent{
		ID: "agt_1", MachineID: machineID, EnrolledAt: time.Unix(1, 0), ReportedAt: time.Unix(2, 0),
		Capabilities: capabilities, PolicySource: agentpolicy.SourcePolicy,
	}
}

func rightsGroup(t *testing.T, rights *rightsJSON, name agentpolicy.Group) rightsGroupJSON {
	t.Helper()
	index := slices.IndexFunc(rights.Groups, func(group rightsGroupJSON) bool { return group.Name == string(name) })
	if index < 0 {
		t.Fatalf("no group %s in %+v", name, rights.Groups)
	}
	return rights.Groups[index]
}

// R-A3-13 : l'onglet Droits montre cinq groupes, jamais une liste à plat :
// chaque droit qu'agentpolicy connaît sort dans un, et un seul, groupe du
// JSON ; le bloc ne porte aucune autre liste de droits.
func TestR_A3_13_RightsAreGroupedNeverFlat(t *testing.T) {
	rights := agentToJSON(reportingAgent(t, "web-1", "observe,probe.lan,docker.deploy")).Rights
	if rights == nil {
		t.Fatal("no rights block for an agent that reported its rights")
	}
	var groupNames []string
	seen := map[string]int{}
	for _, group := range rights.Groups {
		groupNames = append(groupNames, group.Name)
		for _, right := range group.Rights {
			seen[right.Name]++
		}
	}
	if want := []string{"see", "deploy", "backup", "enter", "network"}; !slices.Equal(groupNames, want) {
		t.Errorf("groups %v, want %v", groupNames, want)
	}
	for _, name := range agentpolicy.Names() {
		if seen[name] != 1 {
			t.Errorf("%s is in %d groups, want 1", name, seen[name])
		}
	}
	if len(seen) != len(agentpolicy.Names()) {
		t.Errorf("%d rights in the groups, want the %d known", len(seen), len(agentpolicy.Names()))
	}
	if rights.Set != "" || len(rights.SetLines) != 3 {
		t.Errorf("custom set %q with lines %v, want custom with the three sets", rights.Set, rights.SetLines)
	}
}

// Sans rapport, ou révoqué, l'agent n'a pas d'onglet Droits à montrer : le
// serveur ne sait pas ses droits, il ne les devine pas.
func TestRightsBlock_AbsentUntilTheAgentReports(t *testing.T) {
	unreported := reportingAgent(t, "web-1", "observe")
	unreported.ReportedAt = time.Time{}
	revoked := reportingAgent(t, "web-1", "observe")
	revoked.RevokedAt = time.Unix(3, 0)
	for _, agent := range []machine.Agent{unreported, revoked} {
		if rights := agentToJSON(agent).Rights; rights != nil {
			t.Errorf("rights %+v, want none", rights)
		}
	}
}

// R-DROIT-3 : l'onglet Droits donne la ligne exacte à coller, écrite par
// agentpolicy (PendingLine pour un groupe pas permis, GrantSetLine pour les
// autres jeux, RevokeLine pour retirer), jamais par l'écran.
func TestR_DROIT_3_TheRightsTabGivesTheLineToPaste(t *testing.T) {
	manage := "observe,probe.lan,agent.update,docker.deploy,docker.update,restic.produce,restic.docker,restic.restore,files.write=/srv,terminal.container"
	rights := agentToJSON(reportingAgent(t, "web-1", manage)).Rights
	if rights.Set != string(agentpolicy.SetManage) {
		t.Fatalf("set %q, want manage", rights.Set)
	}
	wantSets := []setLineJSON{
		{Set: "observe", Line: agentpolicy.GrantSetLine(agentpolicy.SetObserve)},
		{Set: "root", Line: agentpolicy.GrantSetLine(agentpolicy.SetRoot)},
	}
	if !slices.Equal(rights.SetLines, wantSets) {
		t.Errorf("set lines %v, want %v", rights.SetLines, wantSets)
	}
	network := rightsGroup(t, rights, agentpolicy.GroupNetwork)
	if network.State != "missing" || network.GrantLine != agentpolicy.PendingLine() || network.GrantLine == "" {
		t.Errorf("network %+v, want missing with its grant line", network)
	}
	deploy := rightsGroup(t, rights, agentpolicy.GroupDeploy)
	wantRevoke := agentpolicy.RevokeLine([]string{"agent.update", "docker.deploy", "docker.update", "files.write"})
	if deploy.State != "ok" || deploy.GrantLine != "" || deploy.RevokeLine != wantRevoke || !deploy.WorthRoot {
		t.Errorf("deploy %+v, want allowed, worth root, with revoke %q", deploy, wantRevoke)
	}
	if see := rightsGroup(t, rights, agentpolicy.GroupSee); see.RevokeLine != agentpolicy.RevokeLine([]string{"probe.lan"}) {
		t.Errorf("see revoke %q, observe never revoked", see.RevokeLine)
	}
}

// R-A3-12 côté serveur : sous Entrer, terminal.host posé est dit ; une
// échéance de droit passe dans « permis jusqu'à ».
func TestRightsBlock_HostTerminalAndUntil(t *testing.T) {
	agent := reportingAgent(t, "web-1", "observe,probe.lan,terminal.host=root")
	until := time.Date(2026, 11, 25, 16, 42, 0, 0, time.UTC)
	agent.RightsUntil = map[string]time.Time{agentpolicy.CapabilityTerminalHost: until}
	enter := rightsGroup(t, agentToJSON(agent).Rights, agentpolicy.GroupEnter)
	if !enter.HostTerminal || enter.State != "ok" || enter.Until == nil || !enter.Until.Equal(until) {
		t.Errorf("enter %+v, want allowed until %v with the host terminal risk", enter, until)
	}
	if deploy := rightsGroup(t, agentToJSON(agent).Rights, agentpolicy.GroupDeploy); deploy.WorthRoot {
		t.Errorf("deploy worth root without the docker group")
	}
}

// R-DROIT-5 : la machine du serveur en « Gérer en root » le dit ; une autre
// machine au même jeu non.
func TestR_DROIT_5_RootOnTheServerMachineIsSaid(t *testing.T) {
	root := "observe,probe.lan,agent.update,docker.deploy,docker.update,restic.produce,restic.docker,restic.restore,files.write=/srv,terminal.container,terminal.host=root,service.free,network.private=1"
	if rights := agentToJSON(reportingAgent(t, machine.LocalID, root)).Rights; !rights.RootHere || rights.Set != "root" {
		t.Errorf("server machine in root: %+v", rights)
	}
	if rights := agentToJSON(reportingAgent(t, "web-1", root)).Rights; rights.RootHere {
		t.Errorf("another machine in root says root here")
	}
}

// Ce que l'agent rapporte (ses valeurs) n'entre jamais dans une ligne à
// coller : les lignes ne portent que des noms de la table d'agentpolicy.
func TestRightsBlock_ReportedValuesNeverEnterALine(t *testing.T) {
	agent := reportingAgent(t, "web-1", "observe,files.write=/srv/evil-path,backup.receive=/srv/other-evil")
	rights := agentToJSON(agent).Rights
	lines := []string{}
	for _, set := range rights.SetLines {
		lines = append(lines, set.Line)
	}
	for _, group := range rights.Groups {
		lines = append(lines, group.GrantLine, group.RevokeLine)
	}
	for _, line := range lines {
		if strings.Contains(line, "evil") {
			t.Errorf("line %q carries a reported value", line)
		}
	}
}

// E03-10 : un droit de « Gérer » que Docker refuse au compte de l'agent ;
// l'écran donne la ligne du jeu, que grant rejoue pour poser le groupe
// docker. Sans refus de Docker, ou pour des droits personnalisés, rien.
func TestE03_10_DockerDeniedGivesTheLineOfTheSet(t *testing.T) {
	const manage = "observe,probe.lan,agent.update,docker.deploy,docker.update,files.write=/srv/workspace,restic.produce,restic.docker,restic.restore,terminal.container"
	denied := reportingAgent(t, "web-1", manage)
	denied.Unavailable = map[string]string{agentpolicy.CapabilityDockerDeploy: "docker_denied"}
	if got := agentToJSON(denied).Rights.PrepareLine; got != agentpolicy.GrantSetLine(agentpolicy.SetManage) {
		t.Fatalf("prepare line %q, want the manage line", got)
	}
	pathDenied := reportingAgent(t, "web-1", manage)
	pathDenied.Unavailable = map[string]string{agentpolicy.CapabilityFilesWrite: "path_denied"}
	custom := reportingAgent(t, "web-1", "observe,docker.deploy")
	custom.Unavailable = denied.Unavailable
	for name, agent := range map[string]machine.Agent{"all exercised": reportingAgent(t, "web-1", manage), "path denied": pathDenied, "custom": custom} {
		if got := agentToJSON(agent).Rights.PrepareLine; got != "" {
			t.Errorf("%s: prepare line %q, want none", name, got)
		}
	}
}

// Essai E03-08 : une politique refusée se dit avec sa raison, sa commande
// quand elle existe ; le jeu posé est « refusée », jamais « personnalisé ».
// Une raison sans source refused ne sort pas.
func TestE03_08_TheRightsTabSaysWhyThePolicyIsRefused(t *testing.T) {
	refusedWith := func(refused agentpolicy.Refusal) *agentJSON {
		agent := reportingAgent(t, "web-1", "observe")
		agent.PolicySource, agent.PolicyRefusal = agentpolicy.SourceRefused, refused
		return agentToJSON(agent)
	}
	owner := refusedWith(agentpolicy.Refusal{Reason: agentpolicy.RefusedOwner, Detail: agentpolicy.FilePath()})
	wantOwner := policyRefusalJSON{Reason: "owner", Detail: agentpolicy.FilePath(), FixLine: "sudo chown root " + agentpolicy.FilePath()}
	if owner.PolicyRefusal == nil || *owner.PolicyRefusal != wantOwner {
		t.Errorf("owner: %+v, want %+v", owner.PolicyRefusal, wantOwner)
	}
	if owner.Rights.Set != agentpolicy.SourceRefused {
		t.Errorf("set %q, want refused", owner.Rights.Set)
	}
	mode := refusedWith(agentpolicy.Refusal{Reason: agentpolicy.RefusedMode, Detail: agentpolicy.FilePath()})
	if want := "sudo chmod 640 " + agentpolicy.FilePath(); mode.PolicyRefusal.FixLine != want {
		t.Errorf("mode fix %q, want %q", mode.PolicyRefusal.FixLine, want)
	}
	// Un autre chemin ne se remet pas d'ici : la raison sans commande.
	elsewhere := refusedWith(agentpolicy.Refusal{Reason: agentpolicy.RefusedMode, Detail: "/etc"})
	if elsewhere.PolicyRefusal.FixLine != "" {
		t.Errorf("fix %q for a path the server does not know", elsewhere.PolicyRefusal.FixLine)
	}
	unknown := refusedWith(agentpolicy.Refusal{Reason: agentpolicy.RefusedUnknownKey, Detail: "foo"})
	if unknown.PolicyRefusal.Detail != "foo" || unknown.PolicyRefusal.FixLine != "" {
		t.Errorf("unknown key %+v", unknown.PolicyRefusal)
	}
	// Un agent d'avant ne dit pas la raison : null, l'écran garde sa phrase.
	if before := refusedWith(agentpolicy.Refusal{}); before.PolicyRefusal != nil || before.Rights.Set != agentpolicy.SourceRefused {
		t.Errorf("an older agent: %+v %q", before.PolicyRefusal, before.Rights.Set)
	}
	held := reportingAgent(t, "web-1", "observe")
	held.PolicySource, held.PolicyRefusal = agentpolicy.SourcePolicy, agentpolicy.Refusal{Reason: agentpolicy.RefusedOwner}
	if got := agentToJSON(held).PolicyRefusal; got != nil {
		t.Errorf("a held policy says a refusal: %+v", got)
	}
}
