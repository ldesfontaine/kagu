package machine

import (
	"slices"
	"sync"

	"github.com/ldesfontaine/kagu/internal/kit/untrusted"
)

// Les champs qu'un agent dit à l'ouverture du flux, et qui peuvent être refusés.
const (
	ReportFieldSystem  = "system"
	ReportFieldVersion = "version"
)

// reportRefusals garde, par machine, les champs que son agent a dits et que le
// serveur a refusés. Rien n'est écrit en base : le refus vaut pour la session
// en cours, un redémarrage l'efface, le champ redit valable aussi.
type reportRefusals struct {
	mu      sync.Mutex
	byField map[string]map[string]bool
}

func (r *reportRefusals) note(machineID, field string, refused bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !refused {
		delete(r.byField[machineID], field)
		return
	}
	if r.byField == nil {
		r.byField = make(map[string]map[string]bool)
	}
	if r.byField[machineID] == nil {
		r.byField[machineID] = make(map[string]bool)
	}
	r.byField[machineID][field] = true
}

func (r *reportRefusals) forget(machineID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.byField, machineID)
}

// of rend les champs refusés d'une machine, dans l'ordre ; nil sans refus.
func (r *reportRefusals) of(machineID string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var fields []string
	for field := range r.byField[machineID] {
		fields = append(fields, field)
	}
	slices.Sort(fields)
	return fields
}

// isReportedText juge un texte que l'agent dit de lui : borné, sans caractère
// de contrôle. Vide, c'est un agent qui ne le dit pas.
func isReportedText(text string) bool {
	return len(text) <= MaxSystemLength && !untrusted.HasControl(text)
}
