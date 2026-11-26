package agentpolicy

import "slices"

// FitState dit où en est un droit sur l'agent d'une machine : le seul type
// d'état de cette question, que l'API rend et que l'écran affiche sans le
// recalculer.
type FitState string

const (
	FitOK      FitState = "ok"
	FitMissing FitState = "missing"
	// L'agent porte le droit, mais son compte ne peut pas l'exercer : le
	// serveur l'affiche sans refuser le geste, l'agent refuse au moment de
	// l'ordre, avec la raison.
	FitUnavailable FitState = "unavailable"
	// L'agent n'a pas encore rapporté ses droits : c'est lui qui jugera.
	FitUnknown FitState = "unknown"
)

// AgentStatus est ce que Fit lit de l'agent d'une machine.
type AgentStatus struct {
	// Installé et pas révoqué.
	Active bool
	// Faux tant que l'agent n'a pas rapporté ses droits.
	Reported bool
	Rights   []Capability
	// Par nom de droit, pourquoi un droit porté ne peut pas s'exercer.
	Unavailable map[string]string
}

// RightFit est le verdict d'un droit : son état et, pour un droit porté mais
// inexerçable, la raison que l'agent a rapportée.
type RightFit struct {
	Right  string
	State  FitState
	Reason string
}

// Fit dit si l'agent peut exercer ce droit, avec cette valeur : un chemin
// pour un droit borné, un producteur pour backup.produce, rien pour les
// autres. Un agent révoqué ou absent n'a aucun droit ; un agent qui n'a pas
// encore parlé est inconnu, quoi que son jeton ait demandé.
func Fit(status AgentStatus, right, value string) RightFit {
	fit := RightFit{Right: right, State: FitMissing}
	switch {
	case !status.Active:
		return fit
	case !status.Reported:
		fit.State = FitUnknown
		return fit
	case !Covers(status.Rights, right, value):
		return fit
	}
	fit.State = FitOK
	if reason := status.Unavailable[right]; reason != "" {
		fit.State, fit.Reason = FitUnavailable, reason
	}
	return fit
}

// Covers dit si les droits portent celui-ci et, quand une valeur est dite,
// si sa portée la couvre.
func Covers(rights []Capability, right, value string) bool {
	switch {
	case value == "":
		return HasCapability(rights, right)
	case right == CapabilityBackupProduce:
		return CoversProducer(rights, value)
	}
	return CoversPath(rights, right, value)
}

// CheckRequested juge un droit que le serveur demande à l'agent par l'ordre
// right.request (R-DROIT-8, ARB-1) : un nom que la politique connaît, et une
// valeur seulement quand elle vient de la liste fermée des producteurs,
// pour backup.produce. Un chemin ne se demande jamais : root le choisit
// lui-même. L'agent note la même valeur d'un ordre refusé.
func CheckRequested(right, value string) error {
	switch {
	case !slices.Contains(Names(), right):
		return ErrCapabilityUnknown
	case value == "":
		return nil
	case right != CapabilityBackupProduce || !slices.Contains(Producers(), value):
		return ErrCapabilityProducer
	}
	return nil
}
