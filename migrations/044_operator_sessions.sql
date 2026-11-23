-- Les sessions de l'opérateur (A2, R-A2-2) : le jeton du cookie n'est gardé
-- que par son empreinte (ident.HashToken). seen_at s'écrit au plus une fois par
-- minute ; expires_at est la fin absolue (12 h). reauth_at reste nul : la
-- redemande du mot de passe (R-A2-7) viendra le poser. source est l'adresse au
-- /64, user_agent le navigateur coupé à 200 caractères.
CREATE TABLE operator_sessions (
    id         TEXT    PRIMARY KEY,
    token_hash TEXT    NOT NULL UNIQUE,
    identity   TEXT    NOT NULL,
    created_at INTEGER NOT NULL,
    seen_at    INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    reauth_at  INTEGER,
    source     TEXT    NOT NULL DEFAULT '',
    user_agent TEXT    NOT NULL DEFAULT ''
);

-- HTTP Basic disparaît (R-A2-1) : « basic » devient « native », même nom, même
-- empreinte bcrypt. SQLite ne change pas un CHECK : la table est recopiée.
CREATE TABLE auth_settings_native (
    id                  INTEGER PRIMARY KEY CHECK (id = 1),
    mode                TEXT    NOT NULL CHECK (mode IN ('none', 'native', 'forward')),
    username            TEXT    NOT NULL DEFAULT '',
    password_hash       TEXT    NOT NULL DEFAULT '',
    forward_header      TEXT    NOT NULL DEFAULT '',
    enabled_at          INTEGER,
    updated_at          INTEGER NOT NULL,
    setup_code_hash     TEXT    NOT NULL DEFAULT '',
    setup_code_expires  INTEGER,
    setup_code_failures INTEGER NOT NULL DEFAULT 0
);

INSERT INTO auth_settings_native (id, mode, username, password_hash, forward_header, enabled_at, updated_at,
                                  setup_code_hash, setup_code_expires, setup_code_failures)
SELECT id, CASE mode WHEN 'basic' THEN 'native' ELSE mode END, username, password_hash, forward_header,
       enabled_at, updated_at, setup_code_hash, setup_code_expires, setup_code_failures
FROM auth_settings;

DROP TABLE auth_settings;
ALTER TABLE auth_settings_native RENAME TO auth_settings;
