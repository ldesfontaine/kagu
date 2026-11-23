package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/ldesfontaine/kagu/internal/fact/auth"
)

var _ auth.SessionStore = (*DB)(nil)

const operatorSessionColumns = `id, identity, created_at, seen_at, expires_at, source, user_agent`

// CreateSession écrit la session et l'empreinte de son jeton. reauth_at reste
// nul : rien ne redemande encore le mot de passe (R-A2-7).
func (db *DB) CreateSession(ctx context.Context, session auth.Session, tokenHash string) error {
	_, err := db.sql.ExecContext(ctx, `
		INSERT INTO operator_sessions (id, token_hash, identity, created_at, seen_at, expires_at, reauth_at, source, user_agent)
		VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?)`,
		session.ID, tokenHash, session.Identity, session.CreatedAt.Unix(), session.SeenAt.Unix(), session.ExpiresAt.Unix(),
		session.Source, session.UserAgent)
	if err != nil {
		return fmt.Errorf("create operator session: %w", err)
	}
	return nil
}

func (db *DB) SessionByTokenHash(ctx context.Context, tokenHash string) (auth.Session, bool, error) {
	row := db.sql.QueryRowContext(ctx, `SELECT `+operatorSessionColumns+` FROM operator_sessions WHERE token_hash = ?`, tokenHash)
	return foundOperatorSession(row)
}

func (db *DB) SessionByID(ctx context.Context, id string) (auth.Session, bool, error) {
	row := db.sql.QueryRowContext(ctx, `SELECT `+operatorSessionColumns+` FROM operator_sessions WHERE id = ?`, id)
	return foundOperatorSession(row)
}

// foundOperatorSession lit la session d'une ligne, et dit si elle existe.
func foundOperatorSession(row scanner) (auth.Session, bool, error) {
	session, err := scanOperatorSession(row)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.Session{}, false, nil
	}
	if err != nil {
		return auth.Session{}, false, fmt.Errorf("get operator session: %w", err)
	}
	return session, true, nil
}

func (db *DB) TouchSession(ctx context.Context, id string, seenAt time.Time) error {
	if _, err := db.sql.ExecContext(ctx, `UPDATE operator_sessions SET seen_at = ? WHERE id = ?`, seenAt.Unix(), id); err != nil {
		return fmt.Errorf("touch operator session: %w", err)
	}
	return nil
}

func (db *DB) DeleteSession(ctx context.Context, id string) (bool, error) {
	result, err := db.sql.ExecContext(ctx, `DELETE FROM operator_sessions WHERE id = ?`, id)
	if err != nil {
		return false, fmt.Errorf("delete operator session: %w", err)
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("delete operator session: %w", err)
	}
	return deleted > 0, nil
}

func (db *DB) DeleteOtherSessions(ctx context.Context, keepID string) (int, error) {
	result, err := db.sql.ExecContext(ctx, `DELETE FROM operator_sessions WHERE id <> ?`, keepID)
	if err != nil {
		return 0, fmt.Errorf("delete other operator sessions: %w", err)
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("delete other operator sessions: %w", err)
	}
	return int(deleted), nil
}

func (db *DB) DeleteDeadSessions(ctx context.Context, idleSince, now time.Time) error {
	_, err := db.sql.ExecContext(ctx, `DELETE FROM operator_sessions WHERE seen_at <= ? OR expires_at <= ?`, idleSince.Unix(), now.Unix())
	if err != nil {
		return fmt.Errorf("delete dead operator sessions: %w", err)
	}
	return nil
}

// ListSessions rend les sessions, les plus récentes d'abord.
func (db *DB) ListSessions(ctx context.Context) ([]auth.Session, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT `+operatorSessionColumns+` FROM operator_sessions ORDER BY created_at DESC, id`)
	if err != nil {
		return nil, fmt.Errorf("list operator sessions: %w", err)
	}
	defer rows.Close()
	var sessions []auth.Session
	for rows.Next() {
		session, err := scanOperatorSession(rows)
		if err != nil {
			return nil, fmt.Errorf("list operator sessions: %w", err)
		}
		sessions = append(sessions, session)
	}
	return sessions, rows.Err()
}

func scanOperatorSession(row scanner) (auth.Session, error) {
	var session auth.Session
	var createdAt, seenAt, expiresAt int64
	err := row.Scan(&session.ID, &session.Identity, &createdAt, &seenAt, &expiresAt, &session.Source, &session.UserAgent)
	if err != nil {
		return auth.Session{}, err
	}
	session.CreatedAt = time.Unix(createdAt, 0)
	session.SeenAt = time.Unix(seenAt, 0)
	session.ExpiresAt = time.Unix(expiresAt, 0)
	return session, nil
}
