-- Le nom lisible de qui a demandé un ordre ou posé un silence, recopié à
-- l'instant du geste (Actor.Label : le compte d'une session, le nom d'un
-- jeton d'API). requested_by et created_by gardent l'acteur enregistré, la
-- session pour un opérateur (A2 §5) ; l'écran montre ce nom (essai E00-01).
-- Pas relu dans operator_sessions : une session fermée y est effacée.
-- Vide pour les acteurs sans libellé.
ALTER TABLE action_runs ADD COLUMN requested_by_label TEXT NOT NULL DEFAULT '';
ALTER TABLE mutes ADD COLUMN created_by_label TEXT NOT NULL DEFAULT '';

-- Les lignes d'avant reprennent le libellé de leur ligne d'audit, quand
-- elle existe encore et nomme le même acteur ; sinon elles restent vides et
-- se lisent comme avant.
UPDATE action_runs SET requested_by_label = COALESCE((
    SELECT event.actor_label FROM audit_events event
    WHERE event.object_kind = 'action' AND event.object_id = action_runs.id
      AND event.action = 'action.order'
      AND event.actor_kind || ':' || event.actor_name = action_runs.requested_by
      AND event.actor_label IS NOT NULL
    ORDER BY event.id LIMIT 1), '');

UPDATE mutes SET created_by_label = COALESCE((
    SELECT event.actor_label FROM audit_events event
    WHERE event.object_kind = 'mute' AND event.object_id = CAST(mutes.id AS TEXT)
      AND event.action = 'mute.create'
      AND event.actor_kind || ':' || event.actor_name = mutes.created_by
      AND event.actor_label IS NOT NULL
    ORDER BY event.id DESC LIMIT 1), '');
