package action

import (
	"cmp"
	"context"
	"slices"

	"github.com/ldesfontaine/kagu/internal/fact/machine"
	"github.com/ldesfontaine/kagu/internal/wire/agentwire"
)

// PlanEntry est ce que le plan de mise à jour dit d'une machine.
type PlanEntry struct {
	MachineID   string
	MachineName string
	Version     string
	Target      string
	// UpToDate, Behind et Missing : où en est l'agent (AgentStanding).
	UpToDate        bool
	Behind          bool
	Missing         []string
	RollbackCapable bool
	Online          bool
	UpdateLast      bool
	// Pourquoi rien ne peut partir pour cette machine (les raisons de la fiche) ;
	// vide quand l'ordre peut partir, ou que la machine est à jour.
	Blocked string
	// Le rang recommandé, de 1 ; 0 quand rien n'est à faire ou que rien ne peut
	// partir.
	Order int
}

// UpdatePlan lit les machines et dit, pour chacune, où en est son agent, et
// dans quel ordre les mettre à jour. Rien ne s'exécute : le serveur ne met
// jamais plusieurs agents à jour d'un coup, l'enchaînement est fait par
// l'opérateur ou par un agent IA, une machine à la fois, en s'arrêtant au
// premier échec.
func (s *Service) UpdatePlan(ctx context.Context) ([]PlanEntry, error) {
	machines, err := s.machines.List(ctx)
	if err != nil {
		return nil, err
	}
	cache := artifactCache{}
	entries := make([]PlanEntry, 0, len(machines))
	for _, target := range machines {
		offer, _, err := s.judgeMachine(target, cache)
		if err != nil {
			return nil, err
		}
		entries = append(entries, planEntryOf(target, offer, s.StandingOf(target.Agent)))
	}
	rankPlan(entries)
	return entries, nil
}

func planEntryOf(target machine.Status, offer UpdateOffer, standing AgentStanding) PlanEntry {
	entry := PlanEntry{
		MachineID: target.ID, MachineName: target.Name, Version: offer.Current, Target: offer.Target,
		RollbackCapable: target.Agent.CanRollBack(), Online: target.Online, UpdateLast: target.UpdateLast,
		UpToDate: standing.UpToDate, Behind: standing.Behind, Missing: standing.Missing,
	}
	if !entry.UpToDate && !offer.Available {
		entry.Blocked = offer.Reason
	}
	// Une offre disponible peut porter right_unavailable : l'agent refusera.
	if offer.Available && offer.Reason != "" {
		entry.Blocked = offer.Reason
	}
	return entry
}

// AgentStanding dit où en est l'agent d'une machine face au serveur (R-B2-9),
// quelle que soit la raison qui retient sa mise à jour : un agent plus ancien
// hors ligne, ou sans droit, reste en retard.
type AgentStanding struct {
	// La version du serveur, ou une plus récente.
	UpToDate bool
	// Plus ancien que le serveur, ou d'une version illisible.
	Behind bool
	// Les genres d'ordres du serveur que l'agent ne reçoit pas, par nom.
	Missing []string
}

// StandingOf juge l'agent : sans agent actif, rien ; sans bibliothèque des
// versions, ni à jour ni en retard, mais ce qui lui manque se lit quand même
// dans ses genres annoncés.
func (s *Service) StandingOf(agent machine.Agent) AgentStanding {
	if !agent.IsActive() {
		return AgentStanding{}
	}
	standing := AgentStanding{Missing: missingKinds(agent)}
	if s.releases == nil {
		return standing
	}
	switch s.versionReason(agent.Version) {
	case OfferSameVersion, OfferNewerAgent:
		standing.UpToDate = true
	default:
		standing.Behind = true
	}
	return standing
}

// missingKinds rend les genres du registre que le serveur refuserait
// d'envoyer à cet agent (envelopeFor), d'après ce qu'il a annoncé à sa
// dernière ouverture du flux.
func missingKinds(agent machine.Agent) []string {
	var missing []string
	for _, kind := range agentwire.OrderKinds() {
		spec, _ := agentwire.SpecOf(kind)
		if _, err := envelopeFor(agent.Protocol, agent.OrderKinds, spec); err != nil {
			missing = append(missing, string(kind))
		}
	}
	return missing
}

// rankPlan numérote ce qui peut partir (pas à jour, pas bloqué) : d'abord les
// machines ordinaires, puis celles à mettre à jour en dernier, chaque groupe
// par nom ; les autres suivent, par nom, sans rang.
func rankPlan(entries []PlanEntry) {
	slices.SortFunc(entries, func(first, second PlanEntry) int {
		firstReady, secondReady := first.isReady(), second.isReady()
		if firstReady != secondReady {
			if firstReady {
				return -1
			}
			return 1
		}
		if first.UpdateLast != second.UpdateLast && firstReady {
			if second.UpdateLast {
				return -1
			}
			return 1
		}
		return cmp.Compare(first.MachineName, second.MachineName)
	})
	rank := 0
	for index := range entries {
		if entries[index].isReady() {
			rank++
			entries[index].Order = rank
		}
	}
}

func (e PlanEntry) isReady() bool {
	return !e.UpToDate && (e.Blocked == "" || e.Blocked == OfferRightUnavailable)
}

// ImportedAhead rend la plus récente des versions importées au-dessus de
// celle du serveur : root l'a déposée sans l'installer. Vide sans
// bibliothèque, ou quand rien d'importé n'est plus récent.
func (s *Service) ImportedAhead() (string, error) {
	if s.releases == nil {
		return "", nil
	}
	versions, err := s.releases.Versions()
	if err != nil || len(versions) == 0 {
		return "", err
	}
	newest := versions[len(versions)-1]
	if newest.Compare(s.serverVersion) <= 0 {
		return "", nil
	}
	return newest.String(), nil
}

// TargetVersion est la version du serveur, celle que ses agents reçoivent ;
// vide quand la mise à jour des agents est coupée.
func (s *Service) TargetVersion() string {
	if s.releases == nil {
		return ""
	}
	return s.serverVersion.String()
}
