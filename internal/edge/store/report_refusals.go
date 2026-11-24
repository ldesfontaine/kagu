package store

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/ldesfontaine/kagu/internal/fact/machine"
)

// NoteReportRefusal garde le refus d'un champ que l'agent a dit, ou l'efface
// quand refused est faux.
func (db *DB) NoteReportRefusal(ctx context.Context, machineID, field string, refused bool) error {
	return noteReportRefusal(ctx, db.sql, machineID, field, refused)
}

func noteReportRefusal(ctx context.Context, q execer, machineID, field string, refused bool) error {
	query := `DELETE FROM machine_report_refusals WHERE machine_id = ? AND field = ?`
	if refused {
		query = `INSERT OR IGNORE INTO machine_report_refusals (machine_id, field) VALUES (?, ?)`
	}
	if _, err := q.ExecContext(ctx, query, machineID, field); err != nil {
		return fmt.Errorf("note report refusal: %w", err)
	}
	return nil
}

// attachReportRefusals pose sur chaque machine les champs refusés de son agent,
// par nom.
func attachReportRefusals(ctx context.Context, q querier, machines []machine.Machine) error {
	return attachToMachines(ctx, q, machines, "report refusals",
		`SELECT machine_id, field FROM machine_report_refusals ORDER BY machine_id, field`,
		func(m *machine.Machine, field string) { m.ReportRejected = append(m.ReportRejected, field) })
}

// rejudgeReportedFields est l'étape Go de la 050 : une base d'avant garde ce
// que ses agents ont dit sans l'avoir jamais jugé. Chaque valeur passe le juge
// de l'enrôlement (machine.RefusedFields) ; une valeur refusée est effacée,
// comme une valeur refusée au flux n'est jamais écrite, et son refus est noté.
// La migration ne repasse pas : le refus, lui, reste en base.
func rejudgeReportedFields(ctx context.Context, tx *sql.Tx) error {
	machines, err := readStoredReports(ctx, tx, `SELECT id, id, hostname, os, arch, '' FROM machines`)
	if err != nil {
		return err
	}
	agents, err := readStoredReports(ctx, tx, `SELECT machine_id, id, '', '', '', version FROM agents`)
	if err != nil {
		return err
	}
	for _, entry := range append(machines, agents...) {
		for _, field := range machine.RefusedFields(entry.reported) {
			if _, err := tx.ExecContext(ctx, eraseRefused[field], entry.rowID); err != nil {
				return fmt.Errorf("erase refused %s: %w", field, err)
			}
			if err := noteReportRefusal(ctx, tx, entry.machineID, field, true); err != nil {
				return err
			}
		}
	}
	return nil
}

// eraseRefused efface la valeur gardée d'un champ refusé, sur la ligne qui la
// porte : la machine, ou l'agent pour la version.
var eraseRefused = map[string]string{
	machine.ReportFieldHostname: `UPDATE machines SET hostname = '' WHERE id = ?`,
	machine.ReportFieldSystem:   `UPDATE machines SET os = '' WHERE id = ?`,
	machine.ReportFieldArch:     `UPDATE machines SET arch = '' WHERE id = ?`,
	machine.ReportFieldVersion:  `UPDATE agents SET version = '' WHERE id = ?`,
}

// storedReport est une ligne qui garde ce qu'un agent a dit : la machine
// qu'elle concerne, la ligne elle-même, les valeurs.
type storedReport struct {
	machineID string
	rowID     string
	reported  machine.Reported
}

func readStoredReports(ctx context.Context, tx *sql.Tx, query string) ([]storedReport, error) {
	rows, err := tx.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("read stored reports: %w", err)
	}
	return collect(rows, func(row scanner) (storedReport, error) {
		var entry storedReport
		said := &entry.reported
		err := row.Scan(&entry.machineID, &entry.rowID, &said.Hostname, &said.System, &said.Arch, &said.Version)
		return entry, err
	})
}
