-- Une sonde que l'agent n'a plus le droit de faire tourner (probe.lan retiré
-- par root) est « suspended » : ni panne ni alerte, elle reprend seule quand
-- le droit revient (essai E03-09). La liste fermée des états est un CHECK,
-- que SQLite ne modifie pas en place : la table est refaite avec la liste
-- élargie, ses lignes recopiées telles quelles, ses index remis. Les tables
-- qui la visent (essais, certificats, membres, incidents, alertes) gardent
-- leurs clés : la migration tourne clés étrangères coupées, puis les vérifie.
CREATE TABLE probes_next (
    id                    TEXT    PRIMARY KEY,
    name                  TEXT    NOT NULL,
    kind                  TEXT    NOT NULL CHECK (kind IN ('http', 'tcp')),
    -- L'URL d'une sonde HTTP, « hôte:port » d'une sonde TCP.
    target                TEXT    NOT NULL,
    machine_id            TEXT    NOT NULL REFERENCES machines (id) ON DELETE RESTRICT,
    service_id            TEXT    REFERENCES declared_services (id) ON DELETE RESTRICT,
    status                TEXT    NOT NULL CHECK (status IN ('new', 'up', 'degraded', 'down', 'paused', 'suspended')),
    interval_seconds      INTEGER NOT NULL,
    timeout_seconds       INTEGER NOT NULL,
    -- Les seuils amortissent la bascule d'état, jamais l'uptime.
    failure_threshold     INTEGER NOT NULL,
    recovery_threshold    INTEGER NOT NULL,
    -- Propres à HTTP ; vides pour une sonde TCP.
    method                TEXT    NOT NULL DEFAULT '',
    expected_status       TEXT    NOT NULL DEFAULT '',
    expected_body         TEXT    NOT NULL DEFAULT '',
    follow_redirects      INTEGER NOT NULL DEFAULT 0,
    -- Une sonde TCP qui fait une poignée de main : c'est ce qui donne son
    -- certificat à un port chiffré qui ne parle pas HTTP.
    tls                   INTEGER NOT NULL DEFAULT 0,
    consecutive_failures  INTEGER NOT NULL DEFAULT 0,
    consecutive_successes INTEGER NOT NULL DEFAULT 0,
    last_checked_at       INTEGER,
    last_duration_ms      INTEGER NOT NULL DEFAULT 0,
    last_code             INTEGER,
    -- Un mot d'une liste fermée, traduit par le front ; jamais une phrase.
    last_reason           TEXT    NOT NULL DEFAULT '',
    created_at            INTEGER NOT NULL,
    -- En millisecondes : un essai de l'ancien réglage pris dans la seconde de
    -- l'édition ne doit pas écraser l'état remis à zéro. NULL : jamais révisée.
    revised_at            INTEGER
);

INSERT INTO probes_next (id, name, kind, target, machine_id, service_id, status, interval_seconds, timeout_seconds,
    failure_threshold, recovery_threshold, method, expected_status, expected_body, follow_redirects, tls,
    consecutive_failures, consecutive_successes, last_checked_at, last_duration_ms, last_code, last_reason, created_at, revised_at)
SELECT id, name, kind, target, machine_id, service_id, status, interval_seconds, timeout_seconds,
    failure_threshold, recovery_threshold, method, expected_status, expected_body, follow_redirects, tls,
    consecutive_failures, consecutive_successes, last_checked_at, last_duration_ms, last_code, last_reason, created_at, revised_at
FROM probes;

DROP TABLE probes;
ALTER TABLE probes_next RENAME TO probes;

CREATE INDEX probes_machine ON probes (machine_id);
CREATE INDEX probes_service ON probes (service_id);
