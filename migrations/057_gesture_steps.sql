-- Les étapes cochées d'un geste suivi (brique B-1, R-GESTE-4), pour tout le
-- produit : une table, un sujet préfixé, « run:<id> » pour un ordre d'agent,
-- « enrollment:<id du jeton> » pour une machine qui arrive. Aucune clé
-- étrangère : un run purgé ou un jeton expiré ne bloque rien, chaque purge
-- efface elle-même les lignes de son sujet. L'ordre d'affichage est position.
CREATE TABLE gesture_steps (
    subject     TEXT    NOT NULL,
    position    INTEGER NOT NULL,
    key         TEXT    NOT NULL,
    state       TEXT    NOT NULL CHECK (state IN ('running', 'done', 'failed', 'skipped')),
    detail      TEXT    NOT NULL DEFAULT '' CHECK (length(detail) <= 200),
    at          INTEGER NOT NULL,
    source_addr TEXT,
    PRIMARY KEY (subject, position)
) WITHOUT ROWID;
