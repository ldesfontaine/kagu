package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/kit/fsx"
	"github.com/ldesfontaine/kagu/internal/wire/agentwire"
)

// Les droits en attente (R-DROIT-8, R-A3-15, essai E03-07) : l'agent note
// chaque droit qu'il a refusé à un ordre jugé, dans son état ;
// « agent grant --pending », en root, les montre et les pose. La ligne que
// l'interface donne à coller est constante (agentpolicy.PendingLine) : le
// serveur, qui sert l'écran, n'écrit rien de ce que root lance. Seul un ordre
// dont la signature est vérifiée arrive au jugement du droit : un ordre forgé
// n'écrit rien ici.

const (
	pendingRightsFile = "pending-rights.json"
	pendingRightsMode = 0o600
	// maxPendingRights : le registre compte une vingtaine de droits, chacun
	// noté une fois ; 32 les tient tous et borne le fichier qu'un flot de
	// refus ferait grandir. Au-delà, le plus ancien refus tombe.
	maxPendingRights = 32
	// pendingRightLife : une entrée vaut 24 h après le dernier refus de son
	// droit ; un refus ancien ne se pose plus.
	pendingRightLife = 24 * time.Hour
	// maxPendingRightsBytes : ce que root lit au plus du fichier.
	maxPendingRightsBytes = 16 << 10
)

// PendingRight est un droit que l'agent a refusé : son nom, sa valeur quand
// l'agent la connaît (le producteur de backup.produce), l'heure du dernier
// refus.
type PendingRight struct {
	Name      string    `json:"name"`
	Value     string    `json:"value,omitempty"`
	RefusedAt time.Time `json:"refused_at"`
}

type pendingRightsDocument struct {
	Rights []PendingRight `json:"rights"`
}

// Text écrit le droit comme grant le lit : « nom » ou « nom=valeur ».
func (p PendingRight) Text() string {
	if p.Value == "" {
		return p.Name
	}
	return p.Name + agentpolicy.ScopeSeparator + p.Value
}

// Until rend l'heure où l'entrée ne vaut plus.
func (p PendingRight) Until() time.Time {
	return p.RefusedAt.Add(pendingRightLife)
}

// live dit si l'entrée vaut à now : refusée dans les dernières 24 h, jamais
// dans le futur (une horloge revenue en arrière ne la prolonge pas).
func (p PendingRight) live(now time.Time) bool {
	return !p.RefusedAt.After(now) && now.Before(p.Until())
}

func (p PendingRight) sameRight(other PendingRight) bool {
	return p.Name == other.Name && p.Value == other.Value
}

// notePendingRight note le droit d'un refus right_missing que l'agent vient
// de juger ; toute autre raison ne note rien. Appelé sous le verrou de
// l'agent. Un échec d'écriture se dit au journal : le refus reste rapporté.
func (r *orderRunner) notePendingRight(order judgedOrder, reason string) {
	name, ok := agentwire.RightOfReason(reason)
	if !ok || r.stateDir == nil {
		return
	}
	entry := PendingRight{Name: name, Value: missingValueOf(order, name), RefusedAt: r.now()}
	if agentpolicy.Covers(r.rights(), entry.Name, entry.Value) {
		return
	}
	if err := r.updatePendingRights(func(rights []PendingRight) []PendingRight {
		rights = slices.DeleteFunc(rights, entry.sameRight)
		return append(rights, entry)
	}); err != nil {
		r.logger.Warn("note pending right", "right", entry.Text(), "error", err)
	}
}

// noteRefusedRight note un droit que l'agent a refusé hors d'un ordre : une
// sonde du réseau local sans probe.lan. Pris sous le verrou de l'agent.
func (r *orderRunner) noteRefusedRight(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.notePendingRight(judgedOrder{}, agentwire.RightMissing(name))
}

// missingValueOf rend la valeur du droit refusé quand elle se lit sans le
// serveur : un producteur de la liste fermée (agentpolicy.Producers). Un
// chemin ne s'y note jamais : root le choisit lui-même.
func missingValueOf(order judgedOrder, name string) string {
	if name != agentpolicy.CapabilityBackupProduce {
		return ""
	}
	producer := ""
	switch params := order.Params.(type) {
	case agentwire.BackupProduceParams:
		producer = params.Producer
	case agentwire.ResticBackupParams:
		producer = agentpolicy.ProducerProxmoxVzdump
	case agentwire.RightRequestParams:
		producer = params.Value
	}
	if producer == "" || agentpolicy.CheckRequested(name, producer) != nil {
		return ""
	}
	return producer
}

// requestRight joue right.request (ARB-1) : rien à exécuter. Le juge a
// refusé l'ordre si la politique ne porte pas le droit ; porté sans la
// valeur demandée (un autre producteur), il est refusé ici, avec la même
// raison. Dans les deux cas receive le note, par notePendingRight : le seul
// chemin d'écriture de la liste. Tenu, l'ordre réussit à vide.
func (r *orderRunner) requestRight(order judgedOrder) agentwire.ActionResult {
	params, _ := order.Params.(agentwire.RightRequestParams)
	if !agentpolicy.Covers(r.rights(), params.Right, params.Value) {
		reason := agentwire.RightMissing(params.Right)
		r.journal.notAccepted(order, reason)
		return agentwire.ActionResult{RunID: order.RunID, State: agentwire.ActionRefused, Reason: reason}
	}
	r.journal.executed(order)
	return agentwire.ActionResult{RunID: order.RunID, State: agentwire.ActionSucceeded}
}

// forgetHeldPendingRights retire les droits que la politique porte
// désormais : un droit posé sort de la liste. Appelé sous le verrou.
func (r *orderRunner) forgetHeldPendingRights() {
	if r.stateDir == nil {
		return
	}
	if err := r.updatePendingRights(func(pending []PendingRight) []PendingRight { return pending }); err != nil {
		r.logger.Warn("forget held pending rights", "error", err)
	}
}

// updatePendingRights relit la liste, y applique change, retire ce qui est
// échu ou déjà posé, garde les maxPendingRights refus les plus récents et
// l'écrit d'un coup (temporaire puis renommage). Rien ne change : rien ne
// s'écrit.
func (r *orderRunner) updatePendingRights(change func([]PendingRight) []PendingRight) error {
	before, err := readPendingRights(r.stateDir)
	if err != nil {
		// Un fichier illisible repart de zéro : il ne tient que des refus.
		r.logger.Warn("pending rights unreadable, starting again", "error", err)
		before = nil
	}
	now, held := r.now(), r.rights()
	after := slices.DeleteFunc(change(slices.Clone(before)), func(entry PendingRight) bool {
		return !entry.live(now) || agentpolicy.Covers(held, entry.Name, entry.Value)
	})
	slices.SortStableFunc(after, func(a, b PendingRight) int { return a.RefusedAt.Compare(b.RefusedAt) })
	if len(after) > maxPendingRights {
		after = after[len(after)-maxPendingRights:]
	}
	if slices.Equal(before, after) {
		return nil
	}
	content, err := json.Marshal(pendingRightsDocument{Rights: after})
	if err != nil {
		return fmt.Errorf("encode pending rights: %w", err)
	}
	return fsx.WriteAtomic(r.stateDir, pendingRightsFile, content, pendingRightsMode)
}

// readPendingRights lit la liste telle qu'elle est écrite ; absente : vide.
func readPendingRights(stateDir *os.Root) ([]PendingRight, error) {
	content, err := fsx.ReadPrivate(stateDir, pendingRightsFile, maxPendingRightsBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var document pendingRightsDocument
	if err := agentwire.StrictDecode(content, &document); err != nil {
		return nil, fmt.Errorf("parse pending rights: %w", err)
	}
	return document.Rights, nil
}

// PendingRights est ce que « grant --pending » trouve : les droits qu'il peut
// poser, et ceux dont root doit choisir la valeur (un chemin).
type PendingRights struct {
	Grantable  []PendingRight
	NeedsValue []PendingRight
}

// ReadPendingRightsAsRoot lit la liste pour root, état jugé d'abord (par
// ReadPolicyAsRoot). Une entrée échue, déjà posée, d'un droit inconnu ou d'une
// valeur mal formée est ignorée : le fichier est écrit par le compte de
// l'agent, pas par root, et l'agent ne le relit qu'à son prochain refus ou à
// la relecture de la politique.
func ReadPendingRightsAsRoot(opts PolicyOptions) (PendingRights, error) {
	report, err := ReadPolicyAsRoot(opts)
	if err != nil {
		return PendingRights{}, err
	}
	entries, err := readPendingRights(opts.StateDir)
	if err != nil {
		return PendingRights{}, err
	}
	now, held := opts.clock().Now, report.Applied.Rights
	var found PendingRights
	for _, entry := range entries {
		if !entry.live(now) || !slices.Contains(agentpolicy.CapabilityNames(), entry.Name) || agentpolicy.Covers(held, entry.Name, entry.Value) {
			continue
		}
		_, err := agentpolicy.ParsePolicyRights(entry.Text())
		switch {
		case err == nil:
			found.Grantable = append(found.Grantable, entry)
		case entry.Value == "":
			found.NeedsValue = append(found.NeedsValue, entry)
		}
	}
	return found, nil
}

// GrantPending pose les droits en attente par le chemin de grant
// (GrantRights), au terme que grant leur donne sans --for.
func GrantPending(opts PolicyOptions, pending []PendingRight, confirm func(PolicyChange) error) (PolicyChange, error) {
	texts := make([]string, 0, len(pending))
	for _, entry := range pending {
		texts = append(texts, entry.Text())
	}
	granted, err := agentpolicy.ParsePolicyRights(strings.Join(texts, agentpolicy.RightSeparator))
	if err != nil {
		return PolicyChange{}, err
	}
	return GrantRights(opts, granted, agentpolicy.Term{}, confirm)
}
