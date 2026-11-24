package clocksync

import (
	"fmt"
	"syscall"
)

// maxErrorLimit est l'erreur maximale, en microsecondes, au-delà de laquelle
// le noyau tient l'horloge pour libre (NTP_PHASE_LIMIT, 16 s). systemd juge
// au même seuil : « System clock synchronized » de timedatectl dit la même
// chose que Synced.
const maxErrorLimit = 16_000_000

// Synced lit l'état du noyau. adjtimex sans mode ne change rien et ne
// demande aucun droit. Le démon de synchronisation (systemd-timesyncd,
// chrony) baisse l'erreur maximale à chaque correction ; sans lui, elle
// monte de 500 µs par seconde jusqu'au seuil.
func Synced() (bool, error) {
	var state syscall.Timex
	if _, err := syscall.Adjtimex(&state); err != nil {
		return false, fmt.Errorf("read kernel clock state: %w", err)
	}
	return state.Maxerror < maxErrorLimit, nil
}
