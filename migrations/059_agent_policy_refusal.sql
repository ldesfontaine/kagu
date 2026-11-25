-- Pourquoi l'agent refuse sa politique (essai E03-08) : un mot d'une liste
-- fermée (agentpolicy.RefusedReasons), traduit par le front, et son détail
-- (la clé inconnue, le chemin mal gardé), borné et nettoyé. Redits à chaque
-- ouverture du flux sous la source 'refused' seulement ; nuls sinon, et chez
-- un agent d'avant, dont la fiche garde sa phrase générale.
ALTER TABLE agents ADD COLUMN policy_refusal TEXT CHECK (policy_refusal IN ('mode', 'owner', 'unknown_key', 'missing', 'unreadable'));
ALTER TABLE agents ADD COLUMN policy_refusal_detail TEXT CHECK (length(policy_refusal_detail) <= 128);
