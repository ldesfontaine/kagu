package alert

import (
	"context"
	"time"

	"github.com/ldesfontaine/kagu/internal/kit/brand"
)

const (
	// ClockUnsyncedDelay : au démarrage de la machine, systemd-timesyncd ou
	// chrony se synchronisent en une à deux minutes ; quinze laissent passer
	// un démarrage lent sans alerte. Une horloge libre dérive de quelques
	// secondes par jour au pire : en quinze minutes elle n'approche pas le pas
	// de marge du code à six chiffres (30 s).
	ClockUnsyncedDelay = 15 * time.Minute
	// clockCheckPeriod : la lecture ne coûte qu'un appel au noyau.
	clockCheckPeriod = time.Minute
)

// clockObject est la machine Kagu : une seule horloge, une seule alerte.
var clockObject = Object{Kind: ObjectServer, ID: "clock", Name: brand.ProductName}

// ClockWatch suit la synchronisation de l'horloge de la machine Kagu. Elle
// n'est pas synchronisée depuis plus de ClockUnsyncedDelay : l'alerte
// s'ouvre ; synchronisée de nouveau, elle se résout. Elle ne mesure aucun
// écart : rien ne part vers un serveur de temps.
type ClockWatch struct {
	alerts *Engine
	// synced lit l'état de l'horloge : clocksync.Synced en production.
	synced func() (bool, error)
	// unsyncedSince est la première lecture non synchronisée d'affilée ;
	// zéro tant que l'horloge l'est. En mémoire : un redémarrage relance le
	// délai, une alerte ouverte reste ouverte jusqu'au retour.
	unsyncedSince time.Time
	readFailed    bool
}

func NewClockWatch(alerts *Engine, synced func() (bool, error)) *ClockWatch {
	return &ClockWatch{alerts: alerts, synced: synced}
}

// Check lit l'horloge une fois et ouvre ou résout l'alerte. Une lecture
// impossible ne change rien : elle se journalise une fois.
func (w *ClockWatch) Check(ctx context.Context) {
	synced, err := w.synced()
	if err != nil {
		if !w.readFailed {
			w.alerts.logger.Warn("read clock synchronization", "error", err)
		}
		w.readFailed = true
		return
	}
	w.readFailed = false
	if synced {
		w.unsyncedSince = time.Time{}
		w.alerts.Resolve(ctx, KindClockUnsynced, clockObject)
		return
	}
	now := w.alerts.now()
	if w.unsyncedSince.IsZero() {
		w.unsyncedSince = now
	}
	if now.Sub(w.unsyncedSince) >= ClockUnsyncedDelay {
		w.alerts.Open(ctx, Fact{Kind: KindClockUnsynced, Severity: SeverityAttention, Object: clockObject, Details: Details{Since: w.unsyncedSince}})
	}
}

// Watch lit l'horloge au départ, puis chaque minute.
func (w *ClockWatch) Watch(ctx context.Context) {
	w.Check(ctx)
	ticker := time.NewTicker(clockCheckPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.Check(ctx)
		}
	}
}
