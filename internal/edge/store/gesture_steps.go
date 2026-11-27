package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/ldesfontaine/kagu/internal/kit/step"
)

// runSubjectPrefix : les étapes d'un run vivent sous « run:<id> » dans
// gesture_steps.
const runSubjectPrefix = "run:"

func runSubject(runID string) string {
	return runSubjectPrefix + runID
}

// replaceSteps écrit le parcours d'un sujet à la place du précédent : chaque
// rapport le rend entier, sa position est son rang. Un parcours vide ne
// touche à rien. source_addr reste nul : un run arrive par le flux de son
// agent, pas d'une adresse à garder.
func replaceSteps(ctx context.Context, tx execer, subject string, steps []step.Step) error {
	if len(steps) == 0 {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM gesture_steps WHERE subject = ?`, subject); err != nil {
		return fmt.Errorf("clear gesture steps: %w", err)
	}
	for position, reported := range steps {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO gesture_steps (subject, position, key, state, detail, at, source_addr)
			VALUES (?, ?, ?, ?, ?, ?, NULL)`,
			subject, position, string(reported.Key), string(reported.State), reported.Detail, reported.At.Unix())
		if err != nil {
			return fmt.Errorf("insert gesture step: %w", err)
		}
	}
	return nil
}

// readSteps rend le parcours d'un sujet dans l'ordre de position ; vide, jamais
// nil, s'il n'a rien rapporté.
func readSteps(ctx context.Context, q querier, subject string) ([]step.Step, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT key, state, detail, at FROM gesture_steps WHERE subject = ? ORDER BY position`, subject)
	if err != nil {
		return nil, fmt.Errorf("list gesture steps: %w", err)
	}
	return collect(rows, scanStep)
}

func scanStep(row scanner) (step.Step, error) {
	var reported step.Step
	var at int64
	if err := row.Scan(&reported.Key, &reported.State, &reported.Detail, &at); err != nil {
		return step.Step{}, err
	}
	reported.At = time.Unix(at, 0)
	return reported, nil
}

// enrollmentSubjectPrefix : l'arrivée d'une machine vit sous
// « enrollment:<id du jeton> » (B1 §5), avant qu'elle ait une fiche.
const enrollmentSubjectPrefix = "enrollment:"

func enrollmentSubject(tokenID string) string {
	return enrollmentSubjectPrefix + tokenID
}

// ReplaceEnrollmentSteps écrit le parcours que join rapporte pour un jeton, à
// la place du précédent.
func (db *DB) ReplaceEnrollmentSteps(ctx context.Context, tokenID string, steps []step.Step) error {
	return db.inTx(ctx, "enrollment steps", func(tx *sql.Tx) error {
		return replaceSteps(ctx, tx, enrollmentSubject(tokenID), steps)
	})
}

// AppendEnrollmentStep ajoute une étape à la fin du parcours d'un jeton,
// sans toucher aux autres : un enrôlement refusé s'écrit à la suite de ce
// que la machine servie a coché.
func (db *DB) AppendEnrollmentStep(ctx context.Context, tokenID string, reported step.Step) error {
	_, err := db.sql.ExecContext(ctx, `
		INSERT INTO gesture_steps (subject, position, key, state, detail, at, source_addr)
		SELECT ?, COALESCE(MAX(position) + 1, 0), ?, ?, ?, ?, NULL FROM gesture_steps WHERE subject = ?`,
		enrollmentSubject(tokenID), string(reported.Key), string(reported.State), reported.Detail, reported.At.Unix(),
		enrollmentSubject(tokenID))
	if err != nil {
		return fmt.Errorf("append enrollment step: %w", err)
	}
	return nil
}

// EnrollmentSteps rend le parcours d'un jeton ; vide s'il n'a rien rapporté.
func (db *DB) EnrollmentSteps(ctx context.Context, tokenID string) ([]step.Step, error) {
	return readSteps(ctx, db.sql, enrollmentSubject(tokenID))
}
