package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/fact/machine"
)

const tokenColumns = `id, token_hash, token_prefix, name, machine_id, role, requested_capabilities, created_at, expires_at, consumed_at, agent_id` // #nosec G101 -- des noms de colonnes.

func (db *DB) InsertToken(ctx context.Context, t machine.Token) error {
	_, err := db.sql.ExecContext(ctx, `
		INSERT INTO enrollment_tokens (id, token_hash, token_prefix, name, machine_id, role, requested_capabilities, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		t.ID, t.Hash, t.Prefix, t.Name, nullableString(t.MachineID), string(t.Role), agentpolicy.FormatCapabilities(t.Capabilities),
		t.CreatedAt.Unix(), t.ExpiresAt.Unix())
	if err != nil {
		return fmt.Errorf("insert token: %w", err)
	}
	return nil
}

// ListPendingTokens rend les jetons encore valables et non consommés, les
// plus récents d'abord.
func (db *DB) ListPendingTokens(ctx context.Context, now time.Time) ([]machine.Token, error) {
	rows, err := db.sql.QueryContext(ctx, `
		SELECT `+tokenColumns+` FROM enrollment_tokens
		WHERE consumed_at IS NULL AND expires_at > ?
		ORDER BY created_at DESC`, now.Unix())
	if err != nil {
		return nil, fmt.Errorf("list pending tokens: %w", err)
	}
	return collect(rows, scanToken)
}

// DeleteToken annule un jeton non consommé ; un jeton déjà servi reste, pour
// l'historique.
func (db *DB) DeleteToken(ctx context.Context, id string) error {
	result, err := db.sql.ExecContext(ctx,
		`DELETE FROM enrollment_tokens WHERE id = ? AND consumed_at IS NULL`, id)
	if err != nil {
		return fmt.Errorf("delete token: %w", err)
	}
	return notFoundIfNoRow(result, machine.ErrTokenNotFound)
}

// PurgeTokens efface les jetons périmés jamais consommés, et les consommés
// avant consumedBefore : passé ce délai, l'historique ne sert plus. Le jeton
// d'un agent actif reste : il dit les droits demandés, contre lesquels se lit
// ce que l'agent rapporte. Les étapes d'arrivée d'un jeton qui n'est plus
// partent avec lui : gesture_steps n'a pas de clé étrangère (T04-03), et un
// jeton annulé ou remplacé n'en laisse pas non plus.
func (db *DB) PurgeTokens(ctx context.Context, now, consumedBefore time.Time) error {
	return db.inTx(ctx, "purge tokens", func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			DELETE FROM enrollment_tokens
			WHERE (consumed_at IS NULL AND expires_at <= ?)
				OR (consumed_at < ? AND (agent_id IS NULL
					OR agent_id NOT IN (SELECT id FROM agents WHERE revoked_at IS NULL)))`,
			now.Unix(), consumedBefore.Unix())
		if err != nil {
			return fmt.Errorf("purge tokens: %w", err)
		}
		_, err = tx.ExecContext(ctx, `
			DELETE FROM gesture_steps
			WHERE substr(subject, 1, ?) = ?
				AND substr(subject, ?) NOT IN (SELECT id FROM enrollment_tokens)`,
			len(enrollmentSubjectPrefix), enrollmentSubjectPrefix, len(enrollmentSubjectPrefix)+1)
		if err != nil {
			return fmt.Errorf("purge enrollment steps: %w", err)
		}
		return nil
	})
}

// TokenByHash lit un jeton par l'empreinte de son clair, sans le consommer :
// l'avancement de join le compare, seul l'enrôlement le sert.
func (db *DB) TokenByHash(ctx context.Context, hash string) (machine.Token, error) {
	return db.readToken(ctx, `token_hash = ?`, hash)
}

// TokenByID lit un jeton par son identifiant, consommé ou non.
func (db *DB) TokenByID(ctx context.Context, id string) (machine.Token, error) {
	return db.readToken(ctx, `id = ?`, id)
}

// TokenOfAgent lit le jeton qu'un agent a consommé : celui de son arrivée.
func (db *DB) TokenOfAgent(ctx context.Context, agentID string) (machine.Token, error) {
	return db.readToken(ctx, `agent_id = ?`, agentID)
}

// readToken lit le jeton qui répond à where ; machine.ErrTokenNotFound sinon.
func (db *DB) readToken(ctx context.Context, where, value string) (machine.Token, error) {
	token, err := scanToken(db.sql.QueryRowContext(ctx, `SELECT `+tokenColumns+` FROM enrollment_tokens WHERE `+where, value)) // #nosec G202 -- une condition fixe du code, la valeur est liée.
	if errors.Is(err, sql.ErrNoRows) {
		return machine.Token{}, machine.ErrTokenNotFound
	}
	if err != nil {
		return machine.Token{}, fmt.Errorf("read token: %w", err)
	}
	return token, nil
}

func scanToken(row scanner) (machine.Token, error) {
	var t machine.Token
	var machineID, agentID sql.NullString
	var role, requested string
	var createdAt, expiresAt int64
	var consumedAt sql.NullInt64
	err := row.Scan(&t.ID, &t.Hash, &t.Prefix, &t.Name, &machineID, &role, &requested, &createdAt, &expiresAt, &consumedAt, &agentID)
	if err != nil {
		return machine.Token{}, err
	}
	t.MachineID = machineID.String
	t.Role = machine.Role(role)
	t.AgentID = agentID.String
	if requested != "" {
		t.Capabilities, _ = agentpolicy.ParsePolicyRights(requested)
	}
	t.CreatedAt = time.Unix(createdAt, 0)
	t.ExpiresAt = time.Unix(expiresAt, 0)
	if consumedAt.Valid {
		t.ConsumedAt = time.Unix(consumedAt.Int64, 0)
	}
	return t, nil
}
