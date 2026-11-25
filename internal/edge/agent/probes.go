package agent

import (
	"sync"

	"github.com/ldesfontaine/kagu/internal/fact/probe"
)

// Une heure d'essais pour un jeu plein de sondes à la cadence la plus
// serrée : ce qu'une coupure peut retenir. Pas de spool sur disque, un
// redémarrage de l'agent perd au plus ce tampon.
const maxBufferedResults = probe.MaxResultsPerReport

// results garde ce que les sondes ont donné entre deux signaux, dans
// l'ordre ; plein, il oublie le plus ancien. refused note le droit qu'un
// essai n'a pas eu (probe.lan) parmi les droits en attente : la ligne
// constante « grant --pending » le pose (R-DROIT-8, essai E03-09).
type results struct {
	mu      sync.Mutex
	pending []probe.Result
	refused func(right string)
}

// Deliver fait de results un probe.Sink. Chaque essai refusé faute de droit
// se note : l'entrée vaut 24 h après le dernier refus, et la sonde suspendue
// continue d'essayer.
func (r *results) Deliver(report probe.Report) {
	r.mu.Lock()
	r.pending = appendBounded(r.pending, report.Results, maxBufferedResults)
	r.mu.Unlock()
	if r.refused == nil {
		return
	}
	for _, result := range report.Results {
		if right, missing := result.Reason.MissingRight(); missing {
			r.refused(right)
		}
	}
}

// take vide le tampon ; nil s'il n'y a rien à dire.
func (r *results) take() *probe.Report {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.pending) == 0 {
		return nil
	}
	taken := probe.Report{Results: r.pending}
	r.pending = nil
	return &taken
}

// restore remet devant ce qu'un signal n'a pas pu livrer ; ce qui a été
// sondé entre-temps passe derrière.
func (r *results) restore(report *probe.Report) {
	if report == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pending = appendBounded(report.Results, r.pending, maxBufferedResults)
}

// markReplayed marque ce qui a attendu une reconnexion : le serveur
// l'écrit dans l'histoire sans y voir du neuf.
func (r *results) markReplayed() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.pending {
		r.pending[i].Replayed = true
	}
}
