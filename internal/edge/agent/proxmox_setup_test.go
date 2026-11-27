package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/fact/machine"
	"github.com/ldesfontaine/kagu/internal/kit/brand"
	"github.com/ldesfontaine/kagu/internal/kit/refusal"
)

// benchSecret est le secret que le faux pveum donne au jeton : aucune sortie
// ne doit le porter, hors du fichier du jeton.
const benchSecret = "5f0c2b1e-9d3a-4c7e-8b21-0a6f4e3d2c19"

const benchFingerprint = "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12"

// fakePveum tient les rôles, comptes, droits et jetons d'un Proxmox, tels
// que pveum les lit et les change. answer rend ce que pveum écrirait.
type fakePveum struct {
	roles       map[string]string
	users       map[string]bool
	acls        []proxmoxACL
	tokens      map[string]bool
	tokenOutput string
	fingerprint string
}

func newFakePveum() *fakePveum {
	return &fakePveum{
		roles: map[string]string{"PVEAdmin": "Sys.Audit"}, users: map[string]bool{"root@pam": true}, tokens: map[string]bool{},
		tokenOutput: `{"full-tokenid":"` + machine.ProxmoxTokenID + `","info":{"privsep":"0"},"value":"` + benchSecret + `"}`,
		fingerprint: benchFingerprint,
	}
}

func (p *fakePveum) answer(args []string) ([]byte, error) {
	if p == nil {
		return nil, errors.New("pveum: not found")
	}
	args = slices.DeleteFunc(slices.Clone(args), func(word string) bool { return word == "--output-format" || word == "json" })
	words := strings.Join(args, " ")
	switch {
	case words == "role list":
		var roles []map[string]string
		for _, id := range slices.Sorted(maps.Keys(p.roles)) {
			roles = append(roles, map[string]string{"roleid": id, "privs": p.roles[id]})
		}
		return json.Marshal(roles)
	case words == "user list":
		var users []map[string]string
		for _, id := range slices.Sorted(maps.Keys(p.users)) {
			users = append(users, map[string]string{"userid": id})
		}
		return json.Marshal(users)
	case words == "acl list":
		return json.Marshal(p.acls)
	case words == "user token list "+machine.ProxmoxUser:
		var tokens []map[string]string
		for _, id := range slices.Sorted(maps.Keys(p.tokens)) {
			tokens = append(tokens, map[string]string{"tokenid": id})
		}
		return json.Marshal(tokens)
	case len(args) == 5 && args[0] == "role" && (args[1] == "add" || args[1] == "modify") && args[3] == "--privs":
		p.roles[args[2]] = args[4]
	case len(args) == 3 && args[0] == "role" && args[1] == "delete":
		delete(p.roles, args[2])
		p.acls = slices.DeleteFunc(p.acls, func(acl proxmoxACL) bool { return acl.Role == args[2] })
	case len(args) == 3 && args[0] == "user" && args[1] == "add":
		p.users[args[2]] = true
	case len(args) == 3 && args[0] == "user" && args[1] == "delete":
		delete(p.users, args[2])
		clear(p.tokens)
		p.acls = slices.DeleteFunc(p.acls, func(acl proxmoxACL) bool { return acl.Who == args[2] })
	case len(args) == 7 && args[0] == "acl" && args[1] == "modify":
		p.acls = append(p.acls, proxmoxACL{Path: args[2], Who: args[4], Role: args[6]})
	case len(args) == 7 && args[0] == "acl" && args[1] == "delete":
		p.acls = slices.DeleteFunc(p.acls, func(acl proxmoxACL) bool { return acl == proxmoxACL{Path: args[2], Who: args[4], Role: args[6]} })
	case len(args) == 7 && strings.HasPrefix(words, "user token add "+machine.ProxmoxUser+" "):
		p.tokens[args[4]] = true
		return []byte(p.tokenOutput), nil
	case len(args) == 5 && strings.HasPrefix(words, "user token remove "+machine.ProxmoxUser+" "):
		delete(p.tokens, args[4])
	default:
		return nil, fmt.Errorf("pveum %s: not on the bench", words)
	}
	return nil, nil
}

// newProxmoxBench est un banc de politique sur un hôte Proxmox, avec ces
// droits posés par grant.
func newProxmoxBench(t *testing.T, rights ...string) *policyBench {
	t.Helper()
	b := newPolicyBench(t)
	b.system.proxmox, b.system.pve = true, newFakePveum()
	for _, right := range rights {
		b.grant(t, right)
	}
	b.system.take()
	return b
}

// layToken joue « agent proxmox-token » et accepte le plan.
func (b *policyBench) layToken(t *testing.T) ProxmoxTokenChange {
	t.Helper()
	change, err := LayProxmoxToken(b.opts, func([]Prerequisite) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	return change
}

// R-DROIT-8, R-A3-15 (#902) : « agent proxmox-token » dit ce qu'il va créer
// (rôle, compte, rôle sur /vms, jeton, fichier) avant la question, et rien
// n'est créé avant l'accord ; ensuite, l'agent lit le jeton et proxmox.power
// redevient exerçable.
func TestR_DROIT_8_T0409b_ProxmoxTokenSaysWhatItCreatesBeforeAsking(t *testing.T) {
	b := newProxmoxBench(t, "proxmox.power")
	var shown []Prerequisite
	change, err := LayProxmoxToken(b.opts, func(plan []Prerequisite) error {
		shown = plan
		for _, done := range b.system.take() {
			if !strings.Contains(done, " list") {
				t.Errorf("changed before the answer: %s", done)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []PrerequisiteKind{PrerequisiteProxmoxRole, PrerequisiteProxmoxUser, PrerequisiteProxmoxACL, PrerequisiteProxmoxToken, PrerequisiteProxmoxTokenFile, PrerequisiteRestart}
	if !slices.Equal(kindsOf(shown), want) || !slices.Equal(kindsOf(change.Laid), want) {
		t.Fatalf("shown %v, laid %v, want %v", kindsOf(shown), kindsOf(change.Laid), want)
	}
	wantDone := []string{
		"pveum role add " + machine.ProxmoxRole + " --privs VM.Audit,VM.PowerMgmt,VM.Snapshot",
		"pveum user add " + machine.ProxmoxUser,
		"pveum acl modify /vms --users " + machine.ProxmoxUser + " --roles " + machine.ProxmoxRole,
		"pveum user token add " + machine.ProxmoxUser + " agent --privsep 0 --output-format json",
		"systemctl daemon-reload",
		"systemctl try-restart " + brand.AgentUnit,
	}
	if done := b.system.take(); !slices.Equal(done, wantDone) {
		t.Fatalf("done %q\nwant %q", done, wantDone)
	}
	if shown[4].Detail != filepath.Join(b.opts.StatePath, "proxmox.json") {
		t.Fatalf("file detail %q", shown[4].Detail)
	}
	info, err := b.opts.StateDir.Stat(brand.AgentProxmoxFile)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("token file %v %v, want 0600", info, err)
	}
	token, reason := readProxmoxToken(b.opts.StateDir)
	if reason != "" || token.ID != machine.ProxmoxTokenID || token.Secret != benchSecret || token.Fingerprint != benchFingerprint {
		t.Fatalf("the agent reads %+v, reason %q", token, reason)
	}
	checks := hostChecks{proxmoxToken: func() string { _, reason := readProxmoxToken(b.opts.StateDir); return reason }}
	rights, _ := agentpolicy.ParseCapabilities("proxmox.power")
	if unavailable := judgeRights(t.Context(), rights, "", checks); len(unavailable) != 0 {
		t.Fatalf("proxmox.power still unavailable: %v", unavailable)
	}
}

// Le rôle n'a que VM.Audit, VM.PowerMgmt et VM.Snapshot, sur /vms : un
// privilège en trop ou en moins fait tomber ce test (décision de Lucas du
// 26/11/2026).
func TestR_A3_15_T0409b_TheRoleHoldsOnlyWhatPowerAndSnapshotNeed(t *testing.T) {
	want := []string{"VM.Audit", "VM.PowerMgmt", "VM.Snapshot"}
	if got := machine.ProxmoxRolePrivileges(); !slices.Equal(got, want) {
		t.Fatalf("privileges %v, want %v", got, want)
	}
	b := newProxmoxBench(t, "proxmox.snapshot")
	b.layToken(t)
	if got := b.system.pve.roles[machine.ProxmoxRole]; got != strings.Join(want, ",") {
		t.Fatalf("role %q holds %q", machine.ProxmoxRole, got)
	}
	wantACL := []proxmoxACL{{Path: "/vms", Who: machine.ProxmoxUser, Role: machine.ProxmoxRole}}
	if !slices.Equal(b.system.pve.acls, wantACL) {
		t.Fatalf("acls %+v, want %+v", b.system.pve.acls, wantACL)
	}
}

// Une pose d'avant la commande (le rôle sur « / », un autre privilège dans
// le rôle, un jeton dont le secret n'est plus lisible) est ramenée à la
// forme exacte : le rôle remis à ses privilèges, le rôle sur « / » retiré,
// le jeton remplacé.
func TestR_A3_15_T0409b_AnEarlierHandMadeTokenIsBroughtBackToShape(t *testing.T) {
	b := newProxmoxBench(t, "proxmox.power")
	pve := b.system.pve
	pve.roles[machine.ProxmoxRole] = "VM.Audit,VM.PowerMgmt,VM.Snapshot,Sys.Modify"
	pve.users[machine.ProxmoxUser] = true
	pve.acls = append(pve.acls, proxmoxACL{Path: "/", Who: machine.ProxmoxUser, Role: machine.ProxmoxRole})
	pve.tokens[machine.ProxmoxTokenName] = true
	change := b.layToken(t)
	want := []PrerequisiteKind{PrerequisiteProxmoxRole, PrerequisiteProxmoxACLRemoved, PrerequisiteProxmoxACL, PrerequisiteProxmoxTokenReplaced, PrerequisiteProxmoxTokenFile, PrerequisiteRestart}
	if !slices.Equal(kindsOf(change.Laid), want) {
		t.Fatalf("laid %v, want %v", kindsOf(change.Laid), want)
	}
	if pve.roles[machine.ProxmoxRole] != "VM.Audit,VM.PowerMgmt,VM.Snapshot" {
		t.Fatalf("role holds %q", pve.roles[machine.ProxmoxRole])
	}
	if len(pve.acls) != 1 || pve.acls[0].Path != "/vms" {
		t.Fatalf("acls %+v", pve.acls)
	}
	done := strings.Join(b.system.take(), "\n")
	if !strings.Contains(done, "pveum role modify ") || !strings.Contains(done, "pveum user token remove "+machine.ProxmoxUser+" agent") {
		t.Fatalf("done %s", done)
	}
}

// Le secret n'apparaît dans aucune commande lancée, dans aucun plan dit,
// dans aucune trace au journal : seulement dans le fichier du jeton.
func TestR_A3_15_T0409b_TheSecretIsInNoCommandNoPlanNoJournal(t *testing.T) {
	b := newProxmoxBench(t, "proxmox.power")
	var journal []string
	b.opts.Audit = func(message string) error {
		journal = append(journal, message)
		return nil
	}
	var said []string
	change, err := LayProxmoxToken(b.opts, func(plan []Prerequisite) error {
		for _, step := range plan {
			said = append(said, string(step.Kind)+" "+step.Detail)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range change.Laid {
		said = append(said, string(step.Kind)+" "+step.Detail)
	}
	if len(journal) != 1 || !strings.Contains(journal[0], machine.ProxmoxTokenID) {
		t.Fatalf("journal %q", journal)
	}
	for name, text := range map[string]string{"commands": strings.Join(b.system.take(), "\n"), "plan": strings.Join(said, "\n"), "journal": strings.Join(journal, "\n")} {
		if strings.Contains(text, benchSecret) {
			t.Errorf("the secret is in the %s:\n%s", name, text)
		}
	}
	content, err := b.opts.StateDir.ReadFile(brand.AgentProxmoxFile)
	if err != nil || !strings.Contains(string(content), benchSecret) {
		t.Fatalf("token file %q %v", content, err)
	}
}

// Une sortie de pveum qui ne se lit pas n'entre pas dans l'erreur : elle
// pourrait porter le secret. Rien n'est écrit.
func TestR_A3_15_T0409b_AnUnreadableTokenAnswerKeepsTheSecretOutOfTheError(t *testing.T) {
	b := newProxmoxBench(t, "proxmox.power")
	b.system.pve.tokenOutput = "value: " + benchSecret
	_, err := LayProxmoxToken(b.opts, func([]Prerequisite) error { return nil })
	if err == nil || strings.Contains(err.Error(), benchSecret) {
		t.Fatalf("err %v", err)
	}
	if _, statErr := b.opts.StateDir.Stat(brand.AgentProxmoxFile); statErr == nil {
		t.Fatal("a token file was written")
	}
}

// Refus : un compte sans privilège, une machine qui n'est pas un hôte
// Proxmox, une politique sans proxmox.power ni proxmox.snapshot (le prochain
// grant retirerait le jeton). Un « non » ne crée rien.
func TestR_DROIT_8_T0409b_ProxmoxTokenRefusesWithoutWritingAnything(t *testing.T) {
	declined := errors.New("declined")
	cases := map[string]struct {
		prepare func(*policyBench)
		rights  []string
		confirm func([]Prerequisite) error
		want    error
	}{
		"not root":      {prepare: func(b *policyBench) { b.opts.EUID = 1000 }, rights: []string{"proxmox.power"}, want: ErrTrustNotRoot},
		"not proxmox":   {prepare: func(b *policyBench) { b.system.proxmox = false }, rights: []string{"proxmox.power"}, want: ErrNotProxmoxHost},
		"no right":      {rights: []string{"docker.deploy"}, want: ErrProxmoxRightMissing},
		"answered no":   {rights: []string{"proxmox.power"}, confirm: func([]Prerequisite) error { return declined }, want: declined},
		"no tls on api": {prepare: func(b *policyBench) { b.system.pve.fingerprint = "" }, rights: []string{"proxmox.power"}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			b := newProxmoxBench(t, c.rights...)
			if c.prepare != nil {
				c.prepare(b)
			}
			confirm := c.confirm
			if confirm == nil {
				confirm = func([]Prerequisite) error { return nil }
			}
			_, err := LayProxmoxToken(b.opts, confirm)
			if err == nil || (c.want != nil && !errors.Is(err, c.want)) {
				t.Fatalf("err %v, want %v", err, c.want)
			}
			if key, ok := refusal.KeyOf(err); c.want == ErrNotProxmoxHost && (!ok || key != "agent.proxmox_token_not_proxmox") {
				t.Fatalf("key %q", key)
			}
			for _, done := range b.system.take() {
				if !strings.Contains(done, " list") {
					t.Errorf("changed: %s", done)
				}
			}
			if _, statErr := b.opts.StateDir.Stat(brand.AgentProxmoxFile); statErr == nil {
				t.Fatal("a token file was written")
			}
		})
	}
}

// R-A3-8 (#902) : revoke du dernier des deux droits proxmox.* retire le
// jeton, le compte, le rôle et le fichier ; avant, revoke du premier n'y
// touche pas. Le retrait se dit avant la question.
func TestR_A3_8_T0409b_RevokingTheLastProxmoxRightRemovesTheToken(t *testing.T) {
	b := newProxmoxBench(t, "proxmox.power", "proxmox.snapshot")
	b.layToken(t)
	b.system.take()

	change, err := RevokeRights(b.opts, []string{"proxmox.power"}, accept)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(kindsOf(change.Prerequisites), PrerequisiteProxmoxTokenRemoved) {
		t.Fatalf("removed while proxmox.snapshot holds: %v", kindsOf(change.Prerequisites))
	}
	b.system.take()

	var shown []Prerequisite
	change, err = RevokeRights(b.opts, []string{"proxmox.snapshot"}, func(change PolicyChange) error {
		shown = change.Prerequisites
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(kindsOf(shown), []PrerequisiteKind{PrerequisiteProxmoxTokenRemoved}) || !slices.Equal(kindsOf(change.Laid), kindsOf(shown)) {
		t.Fatalf("shown %v, laid %v", kindsOf(shown), kindsOf(change.Laid))
	}
	wantDetail := machine.ProxmoxTokenID + " " + machine.ProxmoxUser + " " + machine.ProxmoxRole + " " + filepath.Join(b.opts.StatePath, "proxmox.json")
	if shown[0].Detail != wantDetail {
		t.Fatalf("detail %q, want %q", shown[0].Detail, wantDetail)
	}
	pve := b.system.pve
	if pve.users[machine.ProxmoxUser] || len(pve.tokens) != 0 || pve.roles[machine.ProxmoxRole] != "" || len(pve.acls) != 0 {
		t.Fatalf("left in Proxmox: users %v tokens %v roles %v acls %v", pve.users, pve.tokens, pve.roles, pve.acls)
	}
	if _, err := b.opts.StateDir.Stat(brand.AgentProxmoxFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("token file still there: %v", err)
	}
	// Plus rien à retirer : le geste suivant ne le redit pas.
	change = b.grant(t, "docker.deploy")
	if slices.Contains(kindsOf(change.Prerequisites), PrerequisiteProxmoxTokenRemoved) {
		t.Fatalf("removed twice: %v", kindsOf(change.Prerequisites))
	}
}

// grant d'un droit proxmox.* sur un hôte sans fichier du jeton dit la
// commande qui le pose ; il ne la lance pas.
func TestR_A3_8_T0409b_GrantSaysTheTokenLineWhenTheFileIsMissing(t *testing.T) {
	b := newProxmoxBench(t)
	change := b.grant(t, "proxmox.power")
	index := slices.Index(kindsOf(change.Prerequisites), PrerequisiteProxmoxTokenMissing)
	if index < 0 || change.Prerequisites[index].Detail != "sudo kagu agent proxmox-token" {
		t.Fatalf("plan %+v", change.Prerequisites)
	}
	if done := strings.Join(b.system.take(), "\n"); strings.Contains(done, "pveum") {
		t.Fatalf("grant ran pveum:\n%s", done)
	}
}
