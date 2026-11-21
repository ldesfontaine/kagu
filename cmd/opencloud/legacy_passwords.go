package main

import (
	"context"
	"log/slog"
)

type passwordRemover interface {
	RemoveTargetPasswords(ctx context.Context) (int, error)
}

type targetRedactor interface {
	RedactProbeTargets(ctx context.Context) (int, error)
}

type databaseCompactor interface {
	Compact(ctx context.Context) error
}

// removeLegacyProbePasswords retire les mots de passe de cible d'avant, dans
// les sondes et dans les alertes qui citaient la cible, puis compacte la base
// si au moins un l'a été : sans cela l'ancienne valeur reste dans une page
// libre ou dans le -wal. Les démarrages suivants n'en trouvent plus et ne
// compactent pas. Un échec se journalise, le démarrage continue :
// la sonde est en pause et le mot de passe hors de sa ligne.
func removeLegacyProbePasswords(ctx context.Context, probes passwordRemover, alerts targetRedactor, db databaseCompactor, logger *slog.Logger) {
	removed, err := probes.RemoveTargetPasswords(ctx)
	if err != nil {
		logger.Warn("remove probe target passwords", "error", err)
	}
	redacted, err := alerts.RedactProbeTargets(ctx)
	if err != nil {
		logger.Warn("redact alert targets", "error", err)
	}
	if removed+redacted == 0 {
		return
	}
	if err := db.Compact(ctx); err != nil {
		logger.Error("compact database after removing probe passwords", "removed", removed, "redacted", redacted, "error", err)
	}
}
