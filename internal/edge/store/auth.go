package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/ldesfontaine/opencloud/internal/fact/auth"
)

const authStateSelect = `SELECT mode, username, password_hash, forward_header, enabled_at FROM auth_settings WHERE id = 1`

// GetAuthState rend l'état de l'accès à l'interface ; sans ligne, le mode
// est « none » : une installation neuve n'a pas encore d'identifiants.
func (db *DB) GetAuthState(ctx context.Context) (auth.State, error) {
	return scanAuthState(db.sql.QueryRowContext(ctx, authStateSelect))
}

func scanAuthState(row scanner) (auth.State, error) {
	var state auth.State
	var mode string
	var enabledAt sql.NullInt64
	err := row.Scan(&mode, &state.Username, &state.PasswordHash, &state.Header, &enabledAt)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.State{Mode: auth.ModeNone}, nil
	}
	if err != nil {
		return auth.State{}, fmt.Errorf("get auth state: %w", err)
	}
	state.Mode = auth.Mode(mode)
	if enabledAt.Valid {
		state.EnabledAt = time.Unix(enabledAt.Int64, 0)
	}
	return state, nil
}

// SaveAuthStateIf remplace la ligne unique, créée au premier appel, seulement
// si elle vaut encore expected : la lecture et l'écriture tiennent dans une
// même transaction, qui prend le verrou d'écriture dès son début (_txlock,
// voir openHandle). Rend faux, sans rien écrire, quand l'état a changé
// entre-temps.
func (db *DB) SaveAuthStateIf(ctx context.Context, expected, next auth.State, at time.Time) (bool, error) {
	written := false
	err := db.inTx(ctx, "auth state update", func(tx *sql.Tx) error {
		current, err := scanAuthState(tx.QueryRowContext(ctx, authStateSelect))
		if err != nil {
			return err
		}
		if !expected.Same(current) {
			return nil
		}
		if err := writeAuthState(ctx, tx, next, at); err != nil {
			return err
		}
		written = true
		return nil
	})
	return written, err
}

// writeAuthState efface aussi le code de première configuration : tout
// changement d'état l'use, et un code ne survit pas à la désactivation.
func writeAuthState(ctx context.Context, to execer, state auth.State, at time.Time) error {
	_, err := to.ExecContext(ctx, `
		INSERT INTO auth_settings (id, mode, username, password_hash, forward_header, enabled_at, updated_at)
		VALUES (1, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET
			mode = excluded.mode,
			username = excluded.username,
			password_hash = excluded.password_hash,
			forward_header = excluded.forward_header,
			enabled_at = excluded.enabled_at,
			updated_at = excluded.updated_at,
			setup_code_hash = '',
			setup_code_expires = NULL,
			setup_code_failures = 0`,
		string(state.Mode), state.Username, state.PasswordHash, state.Header, nullableTime(state.EnabledAt), at.Unix())
	if err != nil {
		return fmt.Errorf("save auth state: %w", err)
	}
	return nil
}

// GetSetupCode rend le code gardé ; sans ligne, ou sans code, l'empreinte est
// vide.
func (db *DB) GetSetupCode(ctx context.Context) (auth.SetupCode, error) {
	var code auth.SetupCode
	var expires sql.NullInt64
	err := db.sql.QueryRowContext(ctx,
		`SELECT setup_code_hash, setup_code_expires, setup_code_failures FROM auth_settings WHERE id = 1`).
		Scan(&code.Hash, &expires, &code.Failures)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.SetupCode{}, nil
	}
	if err != nil {
		return auth.SetupCode{}, fmt.Errorf("get setup code: %w", err)
	}
	if expires.Valid {
		code.Expires = time.Unix(expires.Int64, 0)
	}
	return code, nil
}

// SaveSetupCodeIfNone écrit le code, et la ligne en mode none si l'installation
// est neuve ; une ligne qui n'est plus en mode none n'est pas touchée.
func (db *DB) SaveSetupCodeIfNone(ctx context.Context, code auth.SetupCode, at time.Time) (bool, error) {
	result, err := db.sql.ExecContext(ctx, `
		INSERT INTO auth_settings (id, mode, updated_at, setup_code_hash, setup_code_expires, setup_code_failures)
		VALUES (1, 'none', ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET
			setup_code_hash = excluded.setup_code_hash,
			setup_code_expires = excluded.setup_code_expires,
			setup_code_failures = excluded.setup_code_failures,
			updated_at = excluded.updated_at
		WHERE auth_settings.mode = 'none'`,
		at.Unix(), code.Hash, code.Expires.Unix(), code.Failures)
	if err != nil {
		return false, fmt.Errorf("save setup code: %w", err)
	}
	written, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("save setup code: %w", err)
	}
	return written > 0, nil
}

func (db *DB) RecordSetupCodeFailure(ctx context.Context) error {
	_, err := db.sql.ExecContext(ctx, `UPDATE auth_settings SET setup_code_failures = setup_code_failures + 1 WHERE id = 1`)
	if err != nil {
		return fmt.Errorf("record setup code failure: %w", err)
	}
	return nil
}
