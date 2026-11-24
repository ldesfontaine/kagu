package machine

import (
	"context"
	"fmt"

	"github.com/ldesfontaine/kagu/internal/kit/untrusted"
)

// Les champs qu'un agent dit de lui, et qui peuvent être refusés. Le nom
// d'hôte et l'architecture ne se disent qu'à l'enrôlement ; le système et la
// version aussi à l'ouverture du flux.
const (
	ReportFieldHostname = "hostname"
	ReportFieldSystem   = "system"
	ReportFieldArch     = "arch"
	ReportFieldVersion  = "version"
)

// Reported est ce que l'agent dit de lui à l'enrôlement, et ce que la base en
// garde.
type Reported struct {
	Hostname string
	System   string
	Arch     string
	Version  string
}

// RefusedFields rend, dans l'ordre, les champs que le jugement d'aujourd'hui
// refuse ; nil s'ils passent tous. Un champ vide est un agent qui ne le dit pas.
// C'est le juge de l'enrôlement, et celui qui rejuge une base d'avant (050).
func RefusedFields(reported Reported) []string {
	var refused []string
	if reported.Hostname != "" && !IsHostname(reported.Hostname) {
		refused = append(refused, ReportFieldHostname)
	}
	if !isReportedText(reported.System) {
		refused = append(refused, ReportFieldSystem)
	}
	if !isReportedText(reported.Arch) {
		refused = append(refused, ReportFieldArch)
	}
	if !isReportedText(reported.Version) {
		refused = append(refused, ReportFieldVersion)
	}
	return refused
}

// isReportedText juge un texte que l'agent dit de lui : borné, sans caractère
// de contrôle. Vide, c'est un agent qui ne le dit pas.
func isReportedText(text string) bool {
	return len(text) <= MaxSystemLength && !untrusted.HasControl(text)
}

// noteRefusal garde en base le refus d'un champ dit au flux, ou l'efface quand
// le champ est redit valable : la fiche le lit, un redémarrage ne l'efface pas.
func (s *Service) noteRefusal(ctx context.Context, machineID, field string, refused bool) error {
	if err := s.store.NoteReportRefusal(ctx, machineID, field, refused); err != nil {
		return fmt.Errorf("note %s refusal: %w", field, err)
	}
	return nil
}
