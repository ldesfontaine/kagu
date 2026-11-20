-- Une demande de verbe dont le jeton ne tient plus au moment de la confirmer
-- (échu, portée rétrécie, verbe retiré du jeton) est close « lapsed » : rien
-- n'est rejoué. La liste fermée des états est un CHECK, que SQLite ne modifie
-- pas en place : la table est refaite avec la liste élargie, ses lignes
-- recopiées telles quelles, ses index remis.
CREATE TABLE verb_requests_next (
    id           TEXT PRIMARY KEY,
    verb         TEXT NOT NULL,
    object_name  TEXT NOT NULL,
    params       TEXT NOT NULL,
    body         TEXT NOT NULL,
    token_id     TEXT NOT NULL REFERENCES api_tokens (id) ON DELETE CASCADE,
    token_name   TEXT NOT NULL,
    on_behalf_of TEXT NOT NULL,
    state        TEXT NOT NULL CHECK (state IN ('awaiting_confirmation', 'confirmed', 'rejected', 'expired', 'lapsed')),
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL
);

INSERT INTO verb_requests_next (id, verb, object_name, params, body, token_id, token_name, on_behalf_of, state, created_at, expires_at)
SELECT id, verb, object_name, params, body, token_id, token_name, on_behalf_of, state, created_at, expires_at FROM verb_requests;

DROP TABLE verb_requests;
ALTER TABLE verb_requests_next RENAME TO verb_requests;

CREATE INDEX verb_requests_state ON verb_requests (state, expires_at);
CREATE INDEX verb_requests_token ON verb_requests (token_id);
