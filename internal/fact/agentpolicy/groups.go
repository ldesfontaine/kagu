package agentpolicy

import (
	"slices"
	"time"
)

// groups : les cinq groupes de l'onglet Droits, dans l'ordre où ils
// s'affichent (R-A3-13).
var groups = []Group{GroupSee, GroupDeploy, GroupBackup, GroupEnter, GroupNetwork}

// GroupFit est le verdict d'un groupe de l'onglet Droits : ce que l'écran
// affiche sans le recalculer.
type GroupFit struct {
	Group Group
	// ok : au moins un de ses droits s'exerce ; unavailable : il en porte,
	// aucun ne s'exerce ; missing : il n'en porte aucun ; unknown : l'agent
	// n'a pas encore rapporté ses droits.
	State FitState
	// Groupe permis : l'heure où son dernier droit tombe ; zéro quand l'un
	// d'eux est sans échéance.
	Until time.Time
	// Ses droits, dans l'ordre de knownRights : le détail replié.
	Rights []RightFit
	// Le droit que la ligne grant pose quand le groupe n'est pas permis.
	Opener string
	// Déployer, quand l'agent est dans le groupe docker : il vaut root
	// (R-A3-12, R-DROIT-7).
	WorthRoot bool
	// Entrer, quand terminal.host est posé : l'agent devient l'égal de root
	// au premier terminal ouvert (R-A3-12, N-M6).
	HostTerminal bool
}

// GroupFits rend le verdict des cinq groupes : celui de chacun de leurs
// droits (Fit), et until, l'échéance de chaque droit qui en a une.
func GroupFits(status AgentStatus, until map[string]time.Time) []GroupFit {
	fits := make([]GroupFit, 0, len(groups))
	for _, group := range groups {
		fit := GroupFit{Group: group}
		for _, known := range knownRights {
			if known.group != group {
				continue
			}
			fit.Rights = append(fit.Rights, Fit(status, known.name, ""))
			if known.opens {
				fit.Opener = known.name
			}
		}
		fit.State = groupState(fit.Rights)
		if fit.State == FitOK {
			fit.Until = groupUntil(fit.Rights, until)
		}
		fit.WorthRoot = group == GroupDeploy && NeedsDockerGroup(status.Rights)
		fit.HostTerminal = group == GroupEnter && HasCapability(status.Rights, CapabilityTerminalHost)
		fits = append(fits, fit)
	}
	return fits
}

// groupStates : l'état d'un groupe est le premier de cette liste qu'un de
// ses droits porte.
var groupStates = []FitState{FitOK, FitUnavailable, FitUnknown}

func groupState(rights []RightFit) FitState {
	for _, state := range groupStates {
		if slices.ContainsFunc(rights, func(right RightFit) bool { return right.State == state }) {
			return state
		}
	}
	return FitMissing
}

// groupUntil rend l'heure où le dernier droit exercé du groupe tombe ; zéro
// quand l'un d'eux est sans échéance.
func groupUntil(rights []RightFit, until map[string]time.Time) time.Time {
	var last time.Time
	for _, right := range rights {
		if right.State != FitOK {
			continue
		}
		at, ok := until[right.Right]
		if !ok {
			return time.Time{}
		}
		if at.After(last) {
			last = at
		}
	}
	return last
}

// HeldNames rend les droits que le groupe porte, exerçables ou non : ceux
// que sa ligne revoke retire.
func (g GroupFit) HeldNames() []string {
	var names []string
	for _, right := range g.Rights {
		if right.State == FitOK || right.State == FitUnavailable {
			names = append(names, right.Right)
		}
	}
	return names
}

// SetGroup est ce qu'un jeu pose dans un groupe de l'onglet Droits : le
// détail replié d'une carte de « Ajouter une machine ».
type SetGroup struct {
	Group  Group
	Rights []string
}

// Groups rend les droits que le jeu pose partout, groupés et rangés comme
// l'onglet Droits ; un groupe où il ne pose rien n'y est pas.
func (s Set) Groups() []SetGroup {
	var grouped []SetGroup
	for _, group := range groups {
		current := SetGroup{Group: group}
		for _, known := range knownRights {
			if known.group == group && slices.ContainsFunc(sets[s].everywhere, func(right SetRight) bool { return right.Name == known.name }) {
				current.Rights = append(current.Rights, known.name)
			}
		}
		if len(current.Rights) > 0 {
			grouped = append(grouped, current)
		}
	}
	return grouped
}
