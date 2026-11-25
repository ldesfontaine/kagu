package agent

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os/user"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/fact/machine"
	"github.com/ldesfontaine/kagu/internal/kit/fsx"
)

// recordingSystem est un faux système : il tient le groupe docker et les
// drop-ins de l'unité, et enregistre chaque geste sans rien lancer.
type recordingSystem struct {
	mu          sync.Mutex
	dockerGroup bool
	members     map[string]bool
	dropIns     map[string]string
	proxmox     bool
	server      bool
	done        []string
}

func newRecordingSystem() *recordingSystem {
	return &recordingSystem{dockerGroup: true, members: map[string]bool{}, dropIns: map[string]string{}}
}

func (s *recordingSystem) GroupExists(group string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return group == machine.DockerGroup && s.dockerGroup, nil
}

func (s *recordingSystem) InGroup(account, group string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return group == machine.DockerGroup && s.members[account], nil
}

func (s *recordingSystem) Run(name string, args ...string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.done = append(s.done, strings.Join(append([]string{name}, args...), " "))
	switch {
	case name == "usermod":
		s.members[args[len(args)-1]] = true
	case name == "gpasswd":
		delete(s.members, args[1])
	}
	return nil
}

func (s *recordingSystem) MakeFolder(path string, mode fs.FileMode, owner fsx.Owner) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.done = append(s.done, fmt.Sprintf("folder %s %04o %d:%d", path, mode, owner.UID, owner.GID))
	return nil
}

func (s *recordingSystem) DropIns() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Sorted(maps.Keys(s.dropIns)), nil
}

func (s *recordingSystem) ReadDropIn(name string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	content, ok := s.dropIns[name]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return []byte(content), nil
}

func (s *recordingSystem) WriteDropIn(name string, content []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dropIns[name] = string(content)
	s.done = append(s.done, "write "+name+" "+strings.ReplaceAll(string(content), "\n", "|"))
	return nil
}

func (s *recordingSystem) RemoveDropIn(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.dropIns, name)
	s.done = append(s.done, "remove "+name)
	return nil
}

func (s *recordingSystem) Proxmox() bool       { return s.proxmox }
func (s *recordingSystem) ServerMachine() bool { return s.server }

// take rend les gestes enregistrés depuis le dernier appel.
func (s *recordingSystem) take() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	done := s.done
	s.done = nil
	return done
}

// testAccount rend le compte du test, celui qui possède l'état du banc.
func testAccount(t *testing.T) (string, string) {
	t.Helper()
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	return current.Username, current.Uid + ":" + current.Gid
}

func (b *policyBench) grantSet(t *testing.T, set agentpolicy.Set) PolicyChange {
	t.Helper()
	change, err := GrantSet(b.opts, set, accept)
	if err != nil {
		t.Fatal(err)
	}
	return change
}

// R-A3-8 : grant --set manage pose, dans l'ordre, le groupe docker, la racine
// des services au compte de l'agent, le drop-in ReadWritePaths, puis
// daemon-reload et la relance de l'agent ; le plan est dit avant la question.
// Jamais NoNewPrivileges=false, ni sudoers ni produce.conf, même en root sur
// un hôte Proxmox : la porte root arrive à l'étape 14, et grant le dit.
func TestR_A3_8_GrantLaysTheSystemPrerequisites(t *testing.T) {
	account, owner := testAccount(t)
	b := newPolicyBench(t)
	var shown []Prerequisite
	change, err := GrantSet(b.opts, agentpolicy.SetManage, func(change PolicyChange) error {
		shown = change.Prerequisites
		if done := b.system.take(); len(done) != 0 {
			t.Errorf("laid before the answer: %v", done)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"usermod -aG docker " + account,
		"folder /srv/workspace 0755 " + owner,
		"write droits.conf [Service]|ReadWritePaths=-/srv/workspace|",
		"systemctl daemon-reload",
		"systemctl try-restart opencloud-agent.service",
	}
	if done := b.system.take(); !slices.Equal(done, want) {
		t.Fatalf("laid %q\nwant %q", done, want)
	}
	kinds := []PrerequisiteKind{PrerequisiteDockerJoin, PrerequisiteFolder, PrerequisiteDropIn, PrerequisiteRestart}
	if !slices.Equal(kindsOf(shown), kinds) || !slices.Equal(kindsOf(change.Laid), kinds) {
		t.Fatalf("shown %v, laid %v, want %v", kindsOf(shown), kindsOf(change.Laid), kinds)
	}
	if agentpolicy.FormatCapabilities(b.stored(t).Rights) != "observe,probe.lan,agent.update,docker.deploy,docker.update,files.write=/srv/workspace,restic.produce,restic.docker,restic.restore,terminal.container" {
		t.Fatalf("stored %s", agentpolicy.FormatCapabilities(b.stored(t).Rights))
	}

	// Gérer en root sur un hôte Proxmox : rien de plus sur le système que la
	// relance n'exige ; les droits de la porte sont dits, pas posés.
	b.system.proxmox = true
	change = b.grantSet(t, agentpolicy.SetRoot)
	if done := b.system.take(); len(done) != 0 {
		t.Fatalf("root laid %q", done)
	}
	var gate []string
	for _, step := range change.Prerequisites {
		if step.Kind == PrerequisiteRootGate {
			gate = append(gate, step.Detail)
		}
	}
	if !slices.Equal(gate, []string{"backup.produce", "terminal.host", "network.private"}) {
		t.Fatalf("root gate %v", gate)
	}
	for name, content := range b.system.dropIns {
		if strings.Contains(content, "NoNewPrivileges") || name != "droits.conf" {
			t.Fatalf("drop-in %s: %q", name, content)
		}
	}
	// Un dossier sous un dossier du compte se fait sous le compte, après lui.
	b.grant(t, "files.write=/srv/workspace/static:/opt/site,restic.target=/srv/restic")
	want = []string{
		"folder /opt/site 0755 " + owner,
		"folder /srv/restic 0700 " + owner,
		"runuser -u " + account + " -- install -d -m 0755 /srv/workspace/static",
		"write droits.conf [Service]|ReadWritePaths=-/srv/workspace -/opt/site -/srv/workspace/static -/srv/restic|",
		"systemctl daemon-reload",
		"systemctl try-restart opencloud-agent.service",
	}
	if done := b.system.take(); !slices.Equal(done, want) {
		t.Fatalf("laid %q\nwant %q", done, want)
	}
}

func kindsOf(steps []Prerequisite) []PrerequisiteKind {
	kinds := make([]PrerequisiteKind, 0, len(steps))
	for _, step := range steps {
		kinds = append(kinds, step.Kind)
	}
	return kinds
}

// R-A3-8 : sans Docker, grant pose ce qui se passe de lui et dit ce qu'il
// laisse ; un drop-in posé à la main sous un autre nom est dit, pas touché.
func TestR_A3_8_WithoutDockerTheRestIsLaidAndSaid(t *testing.T) {
	b := newPolicyBench(t)
	b.system.dockerGroup = false
	b.system.dropIns["produce.conf"] = "[Service]\nNoNewPrivileges=false\n"
	change := b.grantSet(t, agentpolicy.SetManage)
	kinds := map[PrerequisiteKind]string{}
	for _, step := range change.Prerequisites {
		kinds[step.Kind] = step.Detail
	}
	if kinds[PrerequisiteDockerMissing] != "docker" || kinds[PrerequisiteOtherDropIn] != machine.UnitDropInDir+"/produce.conf" {
		t.Fatalf("plan %+v", change.Prerequisites)
	}
	for _, done := range b.system.take() {
		if strings.HasPrefix(done, "usermod") || strings.Contains(done, "produce.conf") {
			t.Fatalf("laid %q", done)
		}
	}
	if b.system.dropIns["produce.conf"] != "[Service]\nNoNewPrivileges=false\n" || b.system.dropIns["droits.conf"] == "" {
		t.Fatalf("drop-ins %v", b.system.dropIns)
	}
}

// E03-10 : « Gérer » posé sans Docker, puis Docker installé : grant --set
// manage, les droits inchangés, refait le plan et y met le groupe docker ;
// il le dit avant la question, ne pose rien sur un refus, le pose après
// l'accord sans réécrire la politique, puis n'a plus rien à demander.
func TestE03_10_UnchangedRightsStillLayTheDockerGroup(t *testing.T) {
	account, _ := testAccount(t)
	b := newPolicyBench(t)
	b.system.dockerGroup = false
	b.grantSet(t, agentpolicy.SetManage)
	b.system.take()
	written := b.stored(t)

	// Sans Docker, la même commande n'a rien à poser : elle ne demande rien
	// et dit ce qui manque.
	change, err := GrantSet(b.opts, agentpolicy.SetManage, func(PolicyChange) error {
		t.Fatal("asked with nothing to lay")
		return nil
	})
	if err != nil || change.Changed() || change.LaysPrerequisites() || !slices.Contains(kindsOf(change.Prerequisites), PrerequisiteDockerMissing) {
		t.Fatalf("without docker: %+v %v", change.Prerequisites, err)
	}

	b.system.dockerGroup = true
	declined := errors.New("declined")
	var shown []Prerequisite
	if _, err := GrantSet(b.opts, agentpolicy.SetManage, func(change PolicyChange) error {
		shown = change.Prerequisites
		return declined
	}); !errors.Is(err, declined) {
		t.Fatalf("declined: %v", err)
	}
	if done := b.system.take(); len(done) != 0 {
		t.Fatalf("laid after a refusal: %q", done)
	}
	if !slices.Equal(kindsOf(shown), []PrerequisiteKind{PrerequisiteDockerJoin, PrerequisiteRestart}) {
		t.Fatalf("shown %v", kindsOf(shown))
	}

	change = b.grantSet(t, agentpolicy.SetManage)
	want := []string{"usermod -aG docker " + account, "systemctl daemon-reload", "systemctl try-restart opencloud-agent.service"}
	if done := b.system.take(); !slices.Equal(done, want) || change.Changed() {
		t.Fatalf("laid %q, changed %v\nwant %q", done, change.Changed(), want)
	}
	if !b.stored(t).Same(written) {
		t.Fatalf("policy rewritten: %+v", b.stored(t))
	}
	if _, err := GrantSet(b.opts, agentpolicy.SetManage, func(PolicyChange) error {
		t.Fatal("asked again once laid")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// R-A3-8 : revoke défait ce qui ne sert plus : le groupe docker quand plus
// aucun droit ne le demande, le drop-in quand plus rien ne s'écrit ailleurs,
// puis la relance ; les dossiers restent (ce sont des données). Un retrait
// qui laisse un droit docker ne touche pas au groupe.
func TestR_A3_8_RevokeUndoesWhatNoLongerServes(t *testing.T) {
	account, _ := testAccount(t)
	b := newPolicyBench(t)
	b.grantSet(t, agentpolicy.SetManage)
	b.system.take()
	if _, err := RevokeRights(b.opts, []string{agentpolicy.CapabilityDockerDeploy, agentpolicy.CapabilityTerminalContainer}, accept); err != nil {
		t.Fatal(err)
	}
	if done := b.system.take(); len(done) != 0 {
		t.Fatalf("docker.update still needs the group and the folder: %q", done)
	}
	if _, err := RevokeRights(b.opts, []string{agentpolicy.CapabilityDockerUpdate, agentpolicy.CapabilityResticDocker}, accept); err != nil {
		t.Fatal(err)
	}
	want := []string{"gpasswd -d " + account + " docker", "systemctl daemon-reload", "systemctl try-restart opencloud-agent.service"}
	if done := b.system.take(); !slices.Equal(done, want) {
		t.Fatalf("revoke undid %q\nwant %q", done, want)
	}
	// --set observe retire files.write : plus rien ne s'écrit ailleurs.
	b.grantSet(t, agentpolicy.SetObserve)
	want = []string{"remove droits.conf", "systemctl daemon-reload", "systemctl try-restart opencloud-agent.service"}
	if done := b.system.take(); !slices.Equal(done, want) {
		t.Fatalf("set observe undid %q\nwant %q", done, want)
	}
}

// La pose s'arrête au premier échec : la politique est écrite, ce qui est
// posé se dit, et l'agent n'est pas relancé sur un système à moitié prêt.
func TestR_A3_8_AFailedStepStopsTheRest(t *testing.T) {
	b := newPolicyBench(t)
	failing := &failingSystem{recordingSystem: b.system, failOn: "usermod"}
	b.opts.System = failing
	_, err := GrantSet(b.opts, agentpolicy.SetManage, accept)
	var partial *PrerequisiteError
	if !errors.As(err, &partial) || len(partial.Change.Laid) != 0 || !agentpolicy.HasCapability(b.stored(t).Rights, agentpolicy.CapabilityDockerDeploy) {
		t.Fatalf("err %v", err)
	}
	if done := b.system.take(); len(done) != 1 {
		t.Fatalf("went on after the failure: %q", done)
	}
}

type failingSystem struct {
	*recordingSystem
	failOn string
}

func (s *failingSystem) Run(name string, args ...string) error {
	_ = s.recordingSystem.Run(name, args...)
	if name == s.failOn {
		return errors.New("refused")
	}
	return nil
}

// Le compte de l'agent est celui qui possède l'état : root n'a pas de groupe
// à prendre ; un uid sans nom ne se passe pas à usermod.
func TestAgentAccountOf_IsTheStateOwner(t *testing.T) {
	b := newPolicyBench(t)
	account, err := agentAccountOf(b.opts.StateDir)
	name, _ := testAccount(t)
	if err != nil || account.name != name || strconv.Itoa(account.owner.UID) == "" {
		t.Fatalf("account %+v %v", account, err)
	}
	plan, err := planDockerGroup(b.system, hostAccount{owner: fsx.Owner{UID: 0}}, nil, []agentpolicy.Capability{{Name: agentpolicy.CapabilityDockerDeploy}})
	if err != nil || len(plan) != 0 {
		t.Fatalf("root plan %+v %v", plan, err)
	}
}
