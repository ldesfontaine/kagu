package agentpolicy

import (
	"slices"
	"time"

	"github.com/ldesfontaine/kagu/internal/kit/refusal"
)

// Set est un jeu de droits (R-A3-7) : trois, et seulement trois. Un jeu est
// un raccourci, un droit se pose aussi seul.
type Set string

const (
	SetObserve Set = "observe"
	SetManage  Set = "manage"
	SetRoot    Set = "root"
)

// SetRight est un droit qu'un jeu pose, avec sa valeur. ServicesRoot : la
// valeur est la racine des services de la machine, connue à la pose.
type SetRight struct {
	Name         string
	Value        string
	ServicesRoot bool
}

// setRights est ce qu'un jeu pose partout, et ce qu'il pose en plus sur un
// hôte Proxmox.
type setRights struct {
	everywhere []SetRight
	onProxmox  []SetRight
}

// Gérer reprend Observer, Gérer en root reprend Gérer. Les droits hors jeu
// (observe.env, backup.receive, restic.target, restic.verify, restic.browse)
// se posent un par un.
var (
	observeRights = []SetRight{{Name: CapabilityObserve}, {Name: CapabilityProbeLAN}}
	manageRights  = slices.Concat(observeRights, []SetRight{
		{Name: CapabilityAgentUpdate}, {Name: CapabilityDockerDeploy}, {Name: CapabilityDockerUpdate},
		{Name: CapabilityResticProduce}, {Name: CapabilityResticDocker}, {Name: CapabilityResticRestore},
		{Name: CapabilityFilesWrite, ServicesRoot: true}, {Name: CapabilityTerminalContainer},
	})
	manageProxmoxRights = []SetRight{{Name: CapabilityProxmoxPower}, {Name: CapabilityProxmoxSnapshot}}
	rootRights          = slices.Concat(manageRights, []SetRight{
		{Name: CapabilityTerminalHost, Value: "root"}, {Name: CapabilityServiceFree}, {Name: CapabilityNetworkPrivate, Value: "1"},
	})
	rootProxmoxRights = slices.Concat(manageProxmoxRights, []SetRight{{Name: CapabilityBackupProduce, Value: ProducerProxmoxVzdump}})
)

// sets : les jeux, figés par TestR_A3_7_ThreeSetsAndOnlyThree ; grant --set
// les lit (GrantSet).
var sets = map[Set]setRights{
	SetObserve: {everywhere: observeRights},
	SetManage:  {everywhere: manageRights, onProxmox: manageProxmoxRights},
	SetRoot:    {everywhere: rootRights, onProxmox: rootProxmoxRights},
}

// ErrSetUnknown : un jeu est observe, manage ou root.
var ErrSetUnknown = refusal.Invalid("agent.policy_set_unknown", "a set is observe, manage or root")

// ParseSet lit le jeu de « grant --set ».
func ParseSet(text string) (Set, error) {
	set := Set(text)
	if _, ok := sets[set]; !ok {
		return "", ErrSetUnknown
	}
	return set, nil
}

// SetHost est ce que la pose d'un jeu lit de la machine : la racine de ses
// services, et si c'est un hôte Proxmox.
type SetHost struct {
	ServicesRoot string
	Proxmox      bool
}

// Rights rend les droits que le jeu pose sur cette machine.
func (s Set) Rights(host SetHost) []Capability {
	listed := sets[s].everywhere
	if host.Proxmox {
		listed = slices.Concat(listed, sets[s].onProxmox)
	}
	rights := make([]Capability, 0, len(listed))
	for _, right := range listed {
		capability := Capability{Name: right.Name}
		switch {
		case right.ServicesRoot:
			capability.Paths = []string{host.ServicesRoot}
		case right.Value != "":
			capability.Paths = []string{right.Value}
		}
		rights = append(rights, capability)
	}
	return rights
}

// inSomeSet dit si un jeu pose ce droit, où que ce soit : --set le remplace.
func inSomeSet(name string) bool {
	for _, listed := range sets {
		if slices.ContainsFunc(slices.Concat(listed.everywhere, listed.onProxmox), func(right SetRight) bool { return right.Name == name }) {
			return true
		}
	}
	return false
}

// GrantSet remplace les droits des jeux par ceux de set (R-A3-7) et garde
// le reste : les ancres, les clés du serveur, les droits hors jeu et leur
// échéance (backup.receive de la machine du serveur compris). Le jeu se pose
// sans échéance, « Gérer en root » compris (fiche A3, §3).
func (d Document) GrantSet(set Set, host SetHost) (Document, error) {
	if _, ok := sets[set]; !ok {
		return Document{}, ErrSetUnknown
	}
	kept := slices.DeleteFunc(slices.Clone(d.Rights), func(held Capability) bool { return inSomeSet(held.Name) })
	var replaced []string
	for _, held := range d.Rights {
		if inSomeSet(held.Name) {
			replaced = append(replaced, held.Name)
		}
	}
	d.Rights, d.Expiries = kept, expiriesWithout(d.Expiries, replaced)
	return d.Grant(set.Rights(host), Term{Permanent: true}, Clock{})
}

// CoversSet dit si des droits portent tout ce que le jeu pose partout : la
// machine est dans ce jeu, ou au-delà.
func CoversSet(rights []Capability, set Set) bool {
	for _, right := range sets[set].everywhere {
		if !HasCapability(rights, right.Name) {
			return false
		}
	}
	return true
}

// setsInOrder : les jeux, du plus étroit au plus large, dans l'ordre où
// l'onglet Droits donne leurs lignes.
var setsInOrder = []Set{SetObserve, SetManage, SetRoot}

// Sets rend les trois jeux, du plus étroit au plus large.
func Sets() []Set {
	return slices.Clone(setsInOrder)
}

// SetOf rend le jeu que ces droits posent, à l'identique : leurs droits de
// jeu sont ceux d'un jeu, partout ou sur un hôte Proxmox, quelles que soient
// leurs valeurs ; les droits hors jeu n'y changent rien (--set les garde),
// ni un droit à échéance (until) : un jeu se pose sans échéance, un droit
// ajouté pour un temps ne le change pas. Faux : personnalisé.
func SetOf(rights []Capability, until map[string]time.Time) (Set, bool) {
	var held []string
	for _, right := range rights {
		if _, lapses := until[right.Name]; inSomeSet(right.Name) && !lapses {
			held = append(held, right.Name)
		}
	}
	for _, set := range setsInOrder {
		listed := sets[set]
		if sameNames(held, listed.everywhere) || sameNames(held, slices.Concat(listed.everywhere, listed.onProxmox)) {
			return set, true
		}
	}
	return "", false
}

// sameNames dit si held porte exactement les droits listés.
func sameNames(held []string, listed []SetRight) bool {
	names := make([]string, 0, len(listed))
	for _, right := range listed {
		names = append(names, right.Name)
	}
	slices.Sort(names)
	sorted := slices.Sorted(slices.Values(held))
	return slices.Equal(slices.Compact(sorted), names)
}
