package server

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/ldesfontaine/kagu/internal/domain/proxmox"
	"github.com/ldesfontaine/kagu/internal/edge/server/httpx"
	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/fact/anchor"
	"github.com/ldesfontaine/kagu/internal/fact/machine"
	"github.com/ldesfontaine/kagu/internal/fact/role"
	"github.com/ldesfontaine/kagu/internal/kit/brand"
	"github.com/ldesfontaine/kagu/internal/kit/ident"
	"github.com/ldesfontaine/kagu/internal/kit/module"
	"github.com/ldesfontaine/kagu/internal/kit/step"
	"github.com/ldesfontaine/kagu/internal/kit/version"
	"github.com/ldesfontaine/kagu/internal/wire/agentwire"
)

// Une machine telle que le front la lit : des faits et des instants, pas
// de texte formaté ; « vu il y a » se calcule dans le navigateur.
type machineJSON struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Hostname string `json:"hostname"`
	Address  string `json:"address"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Online   bool   `json:"online"`
	// Les champs que l'agent a dits à l'ouverture du flux et que le serveur a
	// refusés (system, version) ; la valeur affichée est celle d'avant.
	ReportRejected []string `json:"report_rejected"`
	// À mettre à jour en dernier : la machine porte le chemin des ordres.
	UpdateLast bool       `json:"update_last"`
	LastSeenAt *time.Time `json:"last_seen_at"`
	// L'agent courant, null tant qu'aucun ne s'est enrôlé.
	Agent *agentJSON `json:"agent"`
	// Ce que la machine porte, ou est, pour Proxmox : voir api_proxmox.go.
	Proxmox proxmoxSummaryJSON `json:"proxmox"`
	// Ce que l'agent reconnaît sur la machine, par ses signes locaux ; vide
	// sans agent, ou quand rien n'est reconnu. Un rôle ne donne aucun droit.
	Roles []roleJSON `json:"roles"`
	// Le rôle que l'opérateur lui a donné, et les modules qu'elle porte : ceux
	// de son rôle et ceux que l'agent observe (internal/kit/module).
	Role    string   `json:"role"`
	Modules []string `json:"modules"`
	// Où elle tourne : le type retenu (la correction de l'opérateur, sinon ce
	// que l'hôte ou l'agent en disent), la correction seule (vide sans), et
	// l'hôte qui la porte, null s'il n'est pas connu.
	Kind         string           `json:"kind"`
	KindOverride string           `json:"kind_override"`
	Host         *machineHostJSON `json:"host"`
	// Le support du système, seulement quand l'opérateur a activé la fin
	// de support.
	Lifecycle *lifecycleJSON `json:"lifecycle,omitempty"`
}

// L'hôte d'une machine : celui que l'opérateur a désigné (override), sinon
// celui dont l'API rapproche la machine d'un de ses invités (guest).
type machineHostJSON struct {
	MachineID   string `json:"machine_id"`
	MachineName string `json:"machine_name"`
	// Le nœud de l'hôte qui l'héberge, quand l'API le dit ; vide sinon.
	Node   string `json:"node"`
	Source string `json:"source"`
}

type roleJSON struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// L'agent d'une machine : ce qu'il rapporte de son fichier, ce que son
// jeton demandait, et s'ils diffèrent. L'agent applique ceux de son fichier.
type agentJSON struct {
	ID           string                   `json:"id"`
	Version      string                   `json:"version"`
	EnrolledAt   time.Time                `json:"enrolled_at"`
	RevokedAt    *time.Time               `json:"revoked_at"`
	Capabilities []reportedCapabilityJSON `json:"capabilities"`
	ReportedAt   *time.Time               `json:"reported_at"`
	Requested    []capabilityJSON         `json:"requested"`
	// Le fichier de l'agent ne dit pas ce que le jeton demandait.
	CapabilitiesDiffer bool `json:"capabilities_differ"`
	// L'empreinte de la clé du serveur que l'agent dit avoir épinglée ; vide
	// tant qu'il n'a rien dit. Différente de GET /api/agents/server-key :
	// l'agent refuserait les ordres de ce serveur.
	ServerKeyFingerprint string `json:"server_key_fingerprint"`
	// L'empreinte de la clé de l'agent, celle que join affiche à la fin de
	// l'ajout, à comparer (R-B1-10).
	KeyFingerprint string `json:"key_fingerprint"`
	// Le compte sous lequel l'agent dit tourner ; null tant qu'il ne l'a pas
	// dit (un agent d'avant).
	RunAs *accountJSON `json:"run_as"`
	// L'agent revient seul à sa version d'avant si une mise à jour n'est pas
	// confirmée ; sans cela, le serveur ne lui en envoie aucune.
	RollbackCapable bool `json:"rollback_capable"`
	// Les ancres de confiance locales que l'agent dit tenir.
	Anchors anchorsJSON `json:"anchors"`
	// D'où l'agent tient ses droits : "policy", "identity", "refused" (la
	// politique ne se lit pas ou est mal gardée : observe seul), vide tant
	// qu'il n'a rien dit ; et l'empreinte SHA-256 du fichier de sa politique.
	PolicySource string `json:"policy_source"`
	PolicyDigest string `json:"policy_digest"`
	// Source refused : pourquoi, tel que l'agent le rapporte (essai E03-08) ;
	// null sinon, et chez un agent d'avant, qui ne le dit pas.
	PolicyRefusal *policyRefusalJSON `json:"policy_refusal"`
	// Source identity : les droits ne sont pas protégés, et la ligne qui les
	// recopie dans la politique (R-A3-16) ; vide sinon.
	MigrateLine string `json:"migrate_line"`
	// Par droit connu, le verdict d'agentpolicy.Fit : l'écran l'affiche sans
	// le recalculer.
	Fit map[string]fitJSON `json:"fit"`
	// Plus ancien que le serveur (R-B2-9), et les genres d'ordres du serveur
	// qu'il ne reçoit pas, lus dans ce qu'il a annoncé (action.StandingOf).
	Behind       bool     `json:"behind"`
	MissingKinds []string `json:"missing_kinds"`
	// L'onglet Droits ; null tant que l'agent n'a pas rapporté ses droits, et
	// pour un agent révoqué.
	Rights *rightsJSON `json:"rights"`
}

// Les droits d'un agent tels que l'onglet Droits les montre (R-A3-13) : le
// jeu, cinq groupes, jamais une liste à plat ; chaque verdict vient
// d'agentpolicy et chaque ligne de ses fonctions (R-DROIT-3).
type rightsJSON struct {
	// Le jeu que les droits posent ; vide : personnalisé ; "refused" : la
	// politique est refusée, aucun jeu ne tient (observe seul, R-A3-6).
	Set string `json:"set"`
	// Les lignes --set des autres jeux (des trois quand le jeu est
	// personnalisé).
	SetLines []setLineJSON `json:"set_lines"`
	// La machine du serveur en « Gérer en root » : qui entre dans
	// l'interface est root sur elle (R-DROIT-5).
	RootHere bool              `json:"root_here"`
	Groups   []rightsGroupJSON `json:"groups"`
	// La ligne qui refait les prérequis du système quand un droit posé ne
	// s'exerce pas faute du groupe docker (E03-10) : celle du jeu que les
	// droits posent, grant refaisant le plan même sans changement ; vide
	// sinon, et pour des droits personnalisés, que SetLines remplaceraient.
	PrepareLine string `json:"prepare_line"`
}

// La raison d'un refus de la politique : un mot de l'ensemble fermé
// (agentpolicy.RefusedReasons), que l'écran traduit ; son détail, texte
// venu de la machine, affiché brut ; la commande qui le corrige quand elle
// existe (agentpolicy.Refusal.FixLine), vide sinon.
type policyRefusalJSON struct {
	Reason  string `json:"reason"`
	Detail  string `json:"detail"`
	FixLine string `json:"fix_line"`
}

func policyRefusalToJSON(agent machine.Agent) *policyRefusalJSON {
	refused := agent.PolicyRefusal
	if agent.PolicySource != agentpolicy.SourceRefused || refused.Reason == "" {
		return nil
	}
	return &policyRefusalJSON{Reason: refused.Reason, Detail: refused.Detail, FixLine: refused.FixLine()}
}

type setLineJSON struct {
	Set  string `json:"set"`
	Line string `json:"line"`
}

// Un groupe : son verdict (agentpolicy.GroupFits), ses droits pour le
// détail replié, la ligne constante quand il n'est pas permis
// (agentpolicy.PendingLine) et le droit que « Demander ce droit à la
// machine » demande alors (celui qui ouvre le groupe, ARB-1), la ligne revoke
// qui retire ce qu'il porte.
type rightsGroupJSON struct {
	Name         string           `json:"name"`
	State        string           `json:"state"`
	Until        *time.Time       `json:"until"`
	WorthRoot    bool             `json:"worth_root"`
	HostTerminal bool             `json:"host_terminal"`
	Rights       []groupRightJSON `json:"rights"`
	GrantLine    string           `json:"grant_line"`
	RequestRight string           `json:"request_right"`
	RevokeLine   string           `json:"revoke_line"`
}

// Un droit du détail : son nom, sa valeur rapportée, son état et son
// échéance (null sans).
type groupRightJSON struct {
	Name  string     `json:"name"`
	Paths []string   `json:"paths"`
	State string     `json:"state"`
	Until *time.Time `json:"until"`
}

func rightsToJSON(agent machine.Agent) *rightsJSON {
	if !agent.IsActive() || agent.ReportedAt.IsZero() {
		return nil
	}
	set, ok := agentpolicy.SetOf(agent.Capabilities, agent.RightsUntil)
	setName := string(set)
	if agent.PolicySource == agentpolicy.SourceRefused {
		setName, ok = agentpolicy.SourceRefused, false
	}
	rights := &rightsJSON{
		Set:      setName,
		SetLines: []setLineJSON{},
		RootHere: agent.MachineID == machine.LocalID && agentpolicy.CoversSet(agent.Capabilities, agentpolicy.SetRoot),
	}
	for _, other := range agentpolicy.Sets() {
		if !ok || other != set {
			rights.SetLines = append(rights.SetLines, setLineJSON{Set: string(other), Line: agentpolicy.GrantSetLine(other)})
		}
	}
	for _, group := range agent.GroupFits() {
		rights.Groups = append(rights.Groups, groupToJSON(agent, group))
	}
	if ok && dockerDenied(agent) {
		rights.PrepareLine = agentpolicy.GrantSetLine(set)
	}
	return rights
}

// dockerDenied dit si un droit posé ne s'exerce pas parce que le compte de
// l'agent n'ouvre pas la socket de Docker, tel que l'agent le rapporte.
func dockerDenied(agent machine.Agent) bool {
	for _, reason := range agent.Unavailable {
		if reason == agentwire.ReasonDockerDenied {
			return true
		}
	}
	return false
}

func groupToJSON(agent machine.Agent, group agentpolicy.GroupFit) rightsGroupJSON {
	converted := rightsGroupJSON{
		Name: string(group.Group), State: string(group.State), Until: httpx.TimeOrNil(group.Until),
		WorthRoot: group.WorthRoot, HostTerminal: group.HostTerminal,
		RevokeLine: agentpolicy.RevokeLine(group.HeldNames()),
	}
	if group.State == agentpolicy.FitMissing {
		converted.GrantLine, converted.RequestRight = agentpolicy.PendingLine(), group.Opener
	}
	for _, right := range group.Rights {
		converted.Rights = append(converted.Rights, groupRightJSON{
			Name: right.Right, Paths: orEmpty(agentpolicy.PathsOf(agent.Capabilities, right.Right)), State: string(right.State),
			Until: httpx.TimeOrNil(agent.RightsUntil[right.Right]),
		})
	}
	return converted
}

// state : "ok", "missing", "unavailable" (reason dit pourquoi) ou "unknown"
// (l'agent n'a pas encore rapporté ses droits).
type fitJSON struct {
	State  string `json:"state"`
	Reason string `json:"reason"`
}

func fitsToJSON(agent machine.Agent) map[string]fitJSON {
	fits := make(map[string]fitJSON, len(agentpolicy.Names()))
	for _, right := range agentpolicy.Names() {
		fit := agent.Fit(right, "")
		fits[right] = fitJSON{State: string(fit.State), Reason: fit.Reason}
	}
	return fits
}

// Les ancres d'un agent : reported est faux chez un agent d'avant les ancres,
// qui ne les applique pas ; sinon chaque type du registre dit son état.
type anchorsJSON struct {
	Reported bool             `json:"reported"`
	Kinds    []anchorKindJSON `json:"kinds"`
}

// state : "set" (des valeurs), "none" (rien de posé : l'ordre est refusé) ou
// "unreadable" (le fichier de l'agent porte des valeurs qui ne se lisent pas).
type anchorKindJSON struct {
	Name   string   `json:"name"`
	Right  string   `json:"right"`
	Max    int      `json:"max"`
	State  string   `json:"state"`
	Values []string `json:"values"`
}

const (
	anchorStateSet        = "set"
	anchorStateNone       = "none"
	anchorStateUnreadable = "unreadable"
)

func anchorsToJSON(state anchor.State) anchorsJSON {
	kinds := make([]anchorKindJSON, 0, len(anchor.Kinds()))
	for _, kind := range anchor.Kinds() {
		entry := anchorKindJSON{Name: kind.Name, Right: kind.Right, Max: kind.Max, State: anchorStateNone, Values: orEmpty(state.Values[kind.Name])}
		switch {
		case state.Unreadable[kind.Name]:
			entry.State = anchorStateUnreadable
		case len(entry.Values) > 0:
			entry.State = anchorStateSet
		}
		kinds = append(kinds, entry)
	}
	return anchorsJSON{Reported: state.Reported, Kinds: kinds}
}

type capabilityJSON struct {
	Name  string   `json:"name"`
	Paths []string `json:"paths"`
}

// Un droit tel que l'agent le rapporte : unavailable dit pourquoi son compte
// ne peut pas l'exercer sur la machine, vide s'il le peut. Le droit demandé
// par un jeton n'a pas ce champ.
type reportedCapabilityJSON struct {
	Name        string   `json:"name"`
	Paths       []string `json:"paths"`
	Unavailable string   `json:"unavailable"`
	// L'échéance que l'agent rapporte pour ce droit ; null sans échéance.
	Until *time.Time `json:"until"`
}

type accountJSON struct {
	UID  int64  `json:"uid"`
	Name string `json:"name"`
}

type pendingTokenJSON struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Masked    string    `json:"masked"`
	ExpiresAt time.Time `json:"expires_at"`
	Reenroll  bool      `json:"reenroll"`
}

type machinesResponse struct {
	Machines []machineJSON      `json:"machines"`
	Pending  []pendingTokenJSON `json:"pending"`
	// Ce que l'écran « Ajouter une machine » montre ; un jeton d'API n'en a
	// pas l'usage.
	Join *joinOfferJSON `json:"join,omitempty"`
}

// L'offre d'ajout d'une machine : prête quand le serveur a une adresse
// publique en https (R-B1-13), sinon la commande qui lui donne un domaine ;
// et les trois jeux, chacun avec ses droits groupés pour « Voir le détail ».
type joinOfferJSON struct {
	Ready      bool          `json:"ready"`
	DomainLine string        `json:"domain_line"`
	Sets       []joinSetJSON `json:"sets"`
}

type joinSetJSON struct {
	Set    string          `json:"set"`
	Groups []joinGroupJSON `json:"groups"`
}

type joinGroupJSON struct {
	Name   string   `json:"name"`
	Rights []string `json:"rights"`
}

// Un ajout nomme la machine, son rôle (les modules affichés) et le jeu de
// droits que la ligne portera.
type tokenRequest struct {
	Name string `json:"name"`
	// Le rôle de la machine ; absent, générique.
	Role string `json:"role"`
	Set  string `json:"set"`
}

// Ré-enrôler, avec le jeu que la ligne portera.
type reenrollRequest struct {
	Set string `json:"set"`
}

// Le jeton en clair, une seule fois, à part de la ligne d'ajout, qui ne le
// porte jamais (R-B1-10) : l'écran copie la ligne puis le jeton.
type tokenResponse struct {
	// L'identifiant du jeton : la tuile en lit l'avancement.
	ID      string `json:"id"`
	Name    string `json:"name"`
	Token   string `json:"token"`
	Set     string `json:"set"`
	Command string `json:"command"`
	// Ré-enrôler : les deux commandes qui arrêtent l'agent en place et
	// retirent son identité, à jouer avant, l'une après l'autre ; vide pour
	// un ajout.
	ReenrollLines []string  `json:"reenroll_lines"`
	ExpiresAt     time.Time `json:"expires_at"`
}

func machineToJSON(machineStatus machine.Status) machineJSON {
	return machineJSON{
		ID:             machineStatus.ID,
		Name:           machineStatus.Name,
		Hostname:       machineStatus.Hostname,
		Address:        machineStatus.Address,
		OS:             machineStatus.OS,
		Arch:           machineStatus.Arch,
		Online:         machineStatus.Online,
		ReportRejected: orEmpty(machineStatus.ReportRejected),
		UpdateLast:     machineStatus.UpdateLast,
		Role:           string(machineStatus.Role),
		LastSeenAt:     httpx.TimeOrNil(machineStatus.LastSeenAt),
		Agent:          agentToJSON(machineStatus.Agent),
	}
}

func agentToJSON(agent machine.Agent) *agentJSON {
	if !agent.Exists() {
		return nil
	}
	return &agentJSON{
		ID:                 agent.ID,
		Version:            agent.Version,
		EnrolledAt:         agent.EnrolledAt.UTC(),
		RevokedAt:          httpx.TimeOrNil(agent.RevokedAt),
		Capabilities:       reportedCapabilitiesToJSON(agent),
		ReportedAt:         httpx.TimeOrNil(agent.ReportedAt),
		Requested:          httpx.ConvertAll(agent.Requested, capabilityToJSON),
		CapabilitiesDiffer: agent.CapabilitiesDiffer(),

		ServerKeyFingerprint: agent.ServerKeyFingerprint,
		KeyFingerprint:       ident.KeyFingerprint(agent.PublicKey),
		RunAs:                accountToJSON(agent.RunAs),
		RollbackCapable:      agent.CanRollBack(),
		Anchors:              anchorsToJSON(agent.Anchors),
		PolicySource:         agent.PolicySource,
		PolicyDigest:         agent.PolicyDigest,
		PolicyRefusal:        policyRefusalToJSON(agent),
		MigrateLine:          migrateLineFor(agent.PolicySource),
		Fit:                  fitsToJSON(agent),
		Rights:               rightsToJSON(agent),
	}
}

func migrateLineFor(source string) string {
	if source != agentpolicy.SourceIdentity {
		return ""
	}
	return agentpolicy.MigrateLine()
}

func accountToJSON(account *machine.Account) *accountJSON {
	if account == nil {
		return nil
	}
	return &accountJSON{UID: account.UID, Name: account.Name}
}

func reportedCapabilitiesToJSON(agent machine.Agent) []reportedCapabilityJSON {
	reported := make([]reportedCapabilityJSON, 0, len(agent.Capabilities))
	for _, capability := range agent.Capabilities {
		reported = append(reported, reportedCapabilityJSON{
			Name: capability.Name, Paths: orEmpty(capability.Paths), Unavailable: agent.UnavailableReason(capability.Name),
			Until: httpx.TimeOrNil(agent.RightsUntil[capability.Name]),
		})
	}
	return reported
}

func capabilityToJSON(capability agentpolicy.Capability) capabilityJSON {
	return capabilityJSON{Name: capability.Name, Paths: orEmpty(capability.Paths)}
}

func roleToJSON(detected role.Role) roleJSON {
	return roleJSON{Name: string(detected.Name), Version: detected.Version}
}

// machineFacts est ce que les machines portent hors de leur ligne : lu une
// fois pour la liste, une fois pour une fiche.
type machineFacts struct {
	summaries     map[string]proxmox.Summary
	roles         map[string][]role.Role
	modules       map[string][]module.ID
	names         map[string]string
	withLifecycle bool
}

func (s *Server) readMachineFacts(ctx context.Context) (machineFacts, error) {
	withLifecycle, err := s.lifecycleEnabled(ctx)
	if err != nil {
		return machineFacts{}, err
	}
	summaries, err := s.reader.ProxmoxSummaries(ctx)
	if err != nil {
		return machineFacts{}, err
	}
	roles, err := s.reader.MachineRoles(ctx)
	if err != nil {
		return machineFacts{}, err
	}
	modules, err := s.reader.MachineModules(ctx)
	if err != nil {
		return machineFacts{}, err
	}
	names, err := s.reader.MachineNames(ctx)
	if err != nil {
		return machineFacts{}, err
	}
	return machineFacts{summaries: summaries, roles: roles, modules: modules, names: names, withLifecycle: withLifecycle}, nil
}

// machineJSONOf ajoute aux faits de la machine ce qu'elle est pour Proxmox, ses
// rôles reconnus, ses modules et le support de son système, quand la fin de
// support est activée.
func (s *Server) machineJSONOf(machineStatus machine.Status, facts machineFacts) machineJSON {
	converted := machineToJSON(machineStatus)
	if converted.Agent != nil {
		standing := s.actions.StandingOf(machineStatus.Agent)
		converted.Agent.Behind, converted.Agent.MissingKinds = standing.Behind, orEmpty(standing.Missing)
	}
	converted.Proxmox = proxmoxSummaryToJSON(facts.summaries[machineStatus.ID])
	converted.Roles = httpx.ConvertAll(facts.roles[machineStatus.ID], roleToJSON)
	converted.Modules = httpx.ConvertAll(facts.modules[machineStatus.ID], func(id module.ID) string { return string(id) })
	converted.Host = hostingOf(machineStatus, facts)
	converted.KindOverride = string(machineStatus.KindOverride)
	converted.Kind = string(effectiveKind(machineStatus, facts.summaries[machineStatus.ID], converted.Host != nil))
	if facts.withLifecycle {
		converted.Lifecycle = lifecycleToJSON(s.lifecycle.OfSystem(machineStatus.OS))
	}
	return converted
}

func (s *Server) listMachines(w http.ResponseWriter, r *http.Request) {
	statuses, err := s.machines.List(r.Context())
	if s.failed(w, r, err, nil) {
		return
	}
	// Les jetons d'enrôlement en attente sont des autorités : un jeton d'API
	// n'en voit aucun.
	var pending []machine.Token
	if _, byToken := apiTokenFrom(r.Context()); !byToken {
		pending, err = s.machines.PendingTokens(r.Context())
		if s.failed(w, r, err, nil) {
			return
		}
	}
	facts, err := s.readMachineFacts(r.Context())
	if s.failed(w, r, err, nil) {
		return
	}
	response := machinesResponse{
		Machines: httpx.ConvertAll(statuses, func(machineStatus machine.Status) machineJSON {
			return s.machineJSONOf(machineStatus, facts)
		}),
		Pending: make([]pendingTokenJSON, 0, len(pending)),
	}
	if _, byToken := apiTokenFrom(r.Context()); !byToken {
		response.Join = s.joinOffer()
	}
	for _, token := range pending {
		response.Pending = append(response.Pending, pendingTokenJSON{
			ID:        token.ID,
			Name:      token.Name,
			Masked:    token.Masked(),
			ExpiresAt: token.ExpiresAt.UTC(),
			Reenroll:  token.MachineID != "",
		})
	}
	s.writeAPI(w, http.StatusOK, response)
}

func (s *Server) getMachine(w http.ResponseWriter, r *http.Request) {
	found, err := s.machines.Get(r.Context(), r.PathValue("id"))
	if s.failed(w, r, err, machine.ErrNotFound) {
		return
	}
	facts, err := s.readMachineFacts(r.Context())
	if s.failed(w, r, err, nil) {
		return
	}
	arrival, err := s.machines.ArrivalSteps(r.Context(), found.Agent.ID)
	if s.failed(w, r, err, nil) {
		return
	}
	s.writeAPI(w, http.StatusOK, machineSheetJSON{machineJSON: s.machineJSONOf(found, facts), Arrival: arrival})
}

// machineSheetJSON est la fiche : la machine, et la frise de son arrivée,
// lue par le jeton que son agent a consommé (R-B1-11) ; vide si ce jeton est
// purgé.
type machineSheetJSON struct {
	machineJSON
	Arrival []step.Step `json:"arrival"`
}

// arrivalJSON est l'avancement d'une machine qui arrive, lu sur son jeton :
// la tuile « en cours d'arrivée » le dessine (StepTrail) sans le recalculer.
type arrivalJSON struct {
	State     machine.ArrivalState `json:"state"`
	ExpiresAt time.Time            `json:"expires_at"`
	Steps     []step.Step          `json:"steps"`
}

// getTokenProgress rend l'avancement d'un jeton, servi ou non (niveau 0) :
// ses étapes, sans le jeton.
func (s *Server) getTokenProgress(w http.ResponseWriter, r *http.Request) {
	arrival, err := s.machines.ArrivalOf(r.Context(), r.PathValue("id"))
	if s.failed(w, r, err, machine.ErrTokenNotFound) {
		return
	}
	s.writeAPI(w, http.StatusOK, arrivalJSON{State: arrival.State, ExpiresAt: arrival.ExpiresAt.UTC(), Steps: arrival.Steps})
}

// La migration d'un agent installé avant le retour arrière automatique : les
// lignes à coller sur la machine, avec le téléchargement vérifié du binaire.
// commands : pour un compte non root qui a sudo ; root_commands : pour root
// (su -), sans sudo, comme sur un hôte Proxmox. Les mêmes pour toutes les
// machines ; la version est celle de ce serveur. L'écran propose root_commands
// d'office quand la machine est un hôte Proxmox ou que son agent dit que sudo
// manque.
type agentMigrationJSON struct {
	Version      string `json:"version"`
	Commands     string `json:"commands"`
	RootCommands string `json:"root_commands"`
}

func (s *Server) getAgentMigration(w http.ResponseWriter, _ *http.Request) {
	number := version.Number()
	s.writeAPI(w, http.StatusOK, agentMigrationJSON{
		Version:      number,
		Commands:     machine.GuardMigrationText(s.releasesURL, number, false),
		RootCommands: machine.GuardMigrationText(s.releasesURL, number, true),
	})
}

type updateLastRequest struct {
	UpdateLast bool `json:"update_last"`
}

// setUpdateLast pose ou retire « à mettre à jour en dernier ». Réservé à
// l'opérateur : la route n'est ni un verbe ni une lecture de jeton.
func (s *Server) setUpdateLast(w http.ResponseWriter, r *http.Request) {
	var request updateLastRequest
	if !s.readAPI(w, r, &request) {
		return
	}
	updated, err := s.machines.SetUpdateLast(r.Context(), r.PathValue("id"), request.UpdateLast)
	if s.failed(w, r, err, machine.ErrNotFound) {
		return
	}
	found, err := s.machines.Get(r.Context(), updated.ID)
	if s.failed(w, r, err, machine.ErrNotFound) {
		return
	}
	facts, err := s.readMachineFacts(r.Context())
	if s.failed(w, r, err, nil) {
		return
	}
	s.writeAPI(w, http.StatusOK, s.machineJSONOf(found, facts))
}

type roleRequest struct {
	Role string `json:"role"`
}

// setRole change le rôle de la machine, donc les modules qu'elle porte. Il ne
// change pas les droits de son agent : les ré-enrôler les donne. Réservé à
// l'opérateur : la route n'est ni un verbe ni une lecture de jeton.
func (s *Server) setRole(w http.ResponseWriter, r *http.Request) {
	var request roleRequest
	if !s.readAPI(w, r, &request) {
		return
	}
	role, err := machine.ParseRole(request.Role)
	if s.failed(w, r, err, nil) {
		return
	}
	updated, err := s.machines.SetRole(r.Context(), r.PathValue("id"), role)
	if s.failed(w, r, err, machine.ErrNotFound) {
		return
	}
	found, err := s.machines.Get(r.Context(), updated.ID)
	if s.failed(w, r, err, machine.ErrNotFound) {
		return
	}
	facts, err := s.readMachineFacts(r.Context())
	if s.failed(w, r, err, nil) {
		return
	}
	s.writeAPI(w, http.StatusOK, s.machineJSONOf(found, facts))
}

// L'opérateur nomme la machine et choisit le jeu ; le jeton naît et se
// montre une seule fois. Sans adresse publique en https, aucun jeton ne
// naît : il n'y aurait pas de ligne pour lui.
func (s *Server) createMachineToken(w http.ResponseWriter, r *http.Request) {
	var request tokenRequest
	if !s.readAPI(w, r, &request) {
		return
	}
	role, err := machine.ParseRole(request.Role)
	if s.failed(w, r, err, nil) {
		return
	}
	set, err := agentpolicy.ParseSet(request.Set)
	if s.failed(w, r, err, nil) {
		return
	}
	if s.failed(w, r, s.joinReady(), nil) {
		return
	}
	cleartext, token, err := s.machines.CreateToken(r.Context(), request.Name, role, setRightsShown(set))
	if s.failed(w, r, err, nil) {
		return
	}
	s.writeToken(w, r, token, cleartext, set, []string{})
}

// setRightsShown : ce que le jeton garde du jeu, pour l'écran seulement ;
// aucun droit ne se pose depuis le jeton (R-DROIT-6), le jeu vient de la
// ligne.
func setRightsShown(set agentpolicy.Set) []agentpolicy.Capability {
	return set.Rights(agentpolicy.SetHost{ServicesRoot: brand.WorkspaceRoot})
}

// joinReady refuse l'ajout d'une machine tant que le serveur n'a pas
// d'adresse publique en https.
func (s *Server) joinReady() error {
	if !machine.JoinReady(s.publicURL) {
		return machine.ErrJoinNeedsDomain
	}
	return nil
}

func (s *Server) writeToken(w http.ResponseWriter, r *http.Request, token machine.Token, cleartext string, set agentpolicy.Set, reenrollLines []string) {
	_, fingerprint, err := s.actions.ServerKey()
	if s.failed(w, r, err, nil) {
		return
	}
	command, err := machine.JoinLine(s.releasesURL, version.Number(), strings.TrimRight(s.publicURL, "/"), fingerprint, set)
	if s.failed(w, r, err, nil) {
		return
	}
	s.writeAPI(w, http.StatusCreated, tokenResponse{
		ID:            token.ID,
		Name:          token.Name,
		Token:         cleartext,
		Set:           string(set),
		Command:       command,
		ReenrollLines: reenrollLines,
		ExpiresAt:     token.ExpiresAt.UTC(),
	})
}

// joinOffer : ce que l'écran « Ajouter une machine » montre.
func (s *Server) joinOffer() *joinOfferJSON {
	offer := &joinOfferJSON{Ready: s.joinReady() == nil, DomainLine: machine.DomainLine()}
	for _, set := range agentpolicy.Sets() {
		shown := joinSetJSON{Set: string(set), Groups: []joinGroupJSON{}}
		for _, grouped := range set.Groups() {
			shown.Groups = append(shown.Groups, joinGroupJSON{Name: string(grouped.Group), Rights: grouped.Rights})
		}
		offer.Sets = append(offer.Sets, shown)
	}
	return offer
}

// Un jeton déjà parti est un jeton annulé : 204 dans les deux cas.
func (s *Server) cancelMachineToken(w http.ResponseWriter, r *http.Request) {
	err := s.machines.CancelToken(r.Context(), r.PathValue("id"))
	if err != nil && !errors.Is(err, machine.ErrTokenNotFound) {
		s.apiInternalError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// removeMachineRequest : garder l'historique archive la machine au lieu de
// l'effacer. Absent (ou sans corps), la machine est retirée.
type removeMachineRequest struct {
	KeepHistory bool `json:"keep_history"`
}

// Supprimer la machine, le geste unique du retrait : effacée avec son
// historique, ou, avec keep_history, archivée (agent coupé, rien d'effacé).
// C'est aussi la route du verbe machine.delete, que l'opérateur confirme.
func (s *Server) removeMachine(w http.ResponseWriter, r *http.Request) {
	var request removeMachineRequest
	if r.ContentLength != 0 && !s.readAPI(w, r, &request) {
		return
	}
	err := s.machines.Remove(r.Context(), r.PathValue("id"), machine.RemoveOptions{KeepHistory: request.KeepHistory})
	s.finishAPIAction(w, r, err, machine.ErrNotFound)
}

// Ré-enrôler : un nouveau jeton pour la même machine, qui garde son id, et
// la ligne d'ajout avec le jeu choisi ; l'agent en place s'arrête d'abord.
// La machine Kagu ne se ré-enrôle que par setup.
func (s *Server) reenrollMachine(w http.ResponseWriter, r *http.Request) {
	var request reenrollRequest
	if !s.readAPI(w, r, &request) {
		return
	}
	set, err := agentpolicy.ParseSet(request.Set)
	if s.failed(w, r, err, nil) {
		return
	}
	if s.failed(w, r, s.joinReady(), nil) {
		return
	}
	cleartext, token, err := s.machines.CreateReenrollToken(r.Context(), r.PathValue("id"), setRightsShown(set))
	if s.failed(w, r, err, machine.ErrNotFound) {
		return
	}
	s.writeToken(w, r, token, cleartext, set, machine.ReenrollLines())
}

// hostingOf dit quel hôte porte la machine : celui que l'opérateur a désigné
// l'emporte sur celui que l'API de l'hyperviseur rapproche d'un invité.
func hostingOf(machineStatus machine.Status, facts machineFacts) *machineHostJSON {
	hosted := facts.summaries[machineStatus.ID].Hosted
	if machineStatus.HostOverride != "" {
		host := &machineHostJSON{MachineID: machineStatus.HostOverride, MachineName: facts.names[machineStatus.HostOverride], Source: "override"}
		if hosted != nil && hosted.HostMachineID == host.MachineID {
			host.Node = hosted.Node
		}
		return host
	}
	if hosted == nil {
		return nil
	}
	return &machineHostJSON{MachineID: hosted.HostMachineID, MachineName: hosted.HostName, Node: hosted.Node, Source: "guest"}
}

// effectiveKind applique la règle du type (machine.EffectiveKind) aux faits que
// la machine et l'hôte rapportent.
func effectiveKind(machineStatus machine.Status, summary proxmox.Summary, hasHost bool) machine.Kind {
	placement := machine.Placement{Reported: machineStatus.Kind, Override: machineStatus.KindOverride, HasHost: hasHost, Address: machineStatus.Address}
	if summary.Hosted != nil {
		placement.GuestKind = machine.KindOfGuest(summary.Hosted.Kind)
	}
	return machine.EffectiveKind(placement)
}
