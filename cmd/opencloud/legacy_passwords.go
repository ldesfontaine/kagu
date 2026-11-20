package main

import (
	"context"
	"log/slog"
)

type passwordRemover interface {
	RemoveTargetPasswords(ctx context.Context) (int, error)
}

type databaseCompactor interface {
	Compact(ctx context.Context) error
}

// removeLegacyProbePasswords retire les mots de passe de cible d'avant, puis
// compacte la base si au moins un l'a été : sans cela l'ancienne valeur reste
// dans une page libre ou dans le -wal. Les démarrages suivants n'en trouvent
// plus et ne compactent pas. Un échec se journalise, le démarrage continue :
// la sonde est en pause et le mot de passe hors de sa ligne.
func removeLegacyProbePasswords(ctx context.Context, probes passwordRemover, db databaseCompactor, logger *slog.Logger) {
	removed, err := probes.RemoveTargetPasswords(ctx)
	if err != nil {
		logger.Warn("remove probe target passwords", "error", err)
	}
	if removed == 0 {
		return
	}
	if err := db.Compact(ctx); err != nil {
		logger.Error("compact database after removing probe passwords", "removed", removed, "error", err)
	}
}
