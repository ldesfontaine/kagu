-- D'où l'agent tient les droits qu'il applique (fiche A3) : 'policy' (le
-- fichier de root), 'identity' (identity.json, une machine sans politique) ou
-- 'refused' (une politique illisible ou mal gardée : observe seul). Avec
-- l'empreinte SHA-256 du fichier lu, en hexadécimal. Redites à chaque
-- ouverture du flux ; nulles tant que l'agent n'a rien dit (un agent d'avant).
ALTER TABLE agents ADD COLUMN policy_source TEXT CHECK (policy_source IN ('policy', 'identity', 'refused'));
ALTER TABLE agents ADD COLUMN policy_digest TEXT CHECK (length(policy_digest) = 64);
