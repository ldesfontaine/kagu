package auth

import (
	"context"
	"sync"
	"time"
)

// Un flux ouvert par une session (R-A2-12) attend sa fin sur un canal, comme
// les flux des agents (machine.Session.Done) : la mort de la session le ferme
// tout de suite, sans attendre le ping du flux. Toute mort passe par là :
// déconnexion, fermeture depuis la liste, mot de passe changé, autre identité
// en forward, cookie sans la preuve du mandataire, retour au mode none ; et
// l'échéance, qu'un minuteur guette.
//
// Le registre est en mémoire : une session effacée par un autre processus
// (`auth disable`) n'est vue qu'au ping, par SessionAlive.

// sessionWatch est la fin d'une session que des flux attendent.
type sessionWatch struct {
	ended    chan struct{}
	watchers int
	// Le minuteur qui relit la session à son échéance.
	deadline *time.Timer
}

type sessionWatches struct {
	mu   sync.Mutex
	byID map[string]*sessionWatch
}

// WatchSession rend un canal qui se ferme quand la session id meurt, et stop,
// que le flux appelle en partant. Une session déjà morte rend un canal fermé.
func (s *Service) WatchSession(ctx context.Context, id string) (<-chan struct{}, func(), error) {
	watch := s.watches.join(id)
	stop := func() { s.watches.leave(id, watch) }
	// Inscrit d'abord, relu ensuite : une fin écrite entre la reprise de la
	// session et l'inscription se voit à cette lecture.
	if err := s.awaitSessionEnd(ctx, id); err != nil {
		stop()
		return nil, nil, err
	}
	return watch.ended, stop, nil
}

// awaitSessionEnd relit la session : morte, ses flux se ferment ; vivante,
// le minuteur est posé à son échéance. Une requête venue entre-temps l'a
// peut-être repoussée : le minuteur relit avant de fermer.
func (s *Service) awaitSessionEnd(ctx context.Context, id string) error {
	session, alive, err := s.liveSession(ctx, id)
	if err != nil {
		return err
	}
	if !alive {
		s.watches.end(id)
		return nil
	}
	s.watches.arm(id, session.endsAt().Sub(s.now()), func() {
		if err := s.awaitSessionEnd(context.Background(), id); err != nil {
			s.logger.Warn("operator session end not checked, its streams close", "session", id, "error", err)
			s.watches.end(id)
		}
	})
	return nil
}

// join inscrit un flux de plus sur la session id.
func (w *sessionWatches) join(id string) *sessionWatch {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.byID == nil {
		w.byID = make(map[string]*sessionWatch)
	}
	watch, found := w.byID[id]
	if !found {
		watch = &sessionWatch{ended: make(chan struct{})}
		w.byID[id] = watch
	}
	watch.watchers++
	return watch
}

// leave retire un flux parti ; le dernier emporte le minuteur.
func (w *sessionWatches) leave(id string, watch *sessionWatch) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.byID[id] != watch {
		return
	}
	watch.watchers--
	if watch.watchers == 0 {
		w.forget(id, watch)
	}
}

// arm pose le minuteur de la session id, si des flux l'attendent encore.
func (w *sessionWatches) arm(id string, after time.Duration, check func()) {
	w.mu.Lock()
	defer w.mu.Unlock()
	watch, found := w.byID[id]
	if !found {
		return
	}
	if watch.deadline != nil {
		watch.deadline.Stop()
	}
	watch.deadline = time.AfterFunc(after, check)
}

// end ferme les flux de la session id.
func (w *sessionWatches) end(id string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if watch, found := w.byID[id]; found {
		w.forget(id, watch)
		close(watch.ended)
	}
}

// endAllBut ferme les flux de toutes les sessions sauf keepID.
func (w *sessionWatches) endAllBut(keepID string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for id, watch := range w.byID {
		if id != keepID {
			w.forget(id, watch)
			close(watch.ended)
		}
	}
}

func (w *sessionWatches) forget(id string, watch *sessionWatch) {
	if watch.deadline != nil {
		watch.deadline.Stop()
	}
	delete(w.byID, id)
}
