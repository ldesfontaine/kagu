-- La moitié publique X25519 de l'agent (R-B1-18), envoyée à l'enrôlement :
-- le serveur s'en servira pour sceller le champ secret des ordres (D3).
-- Nulle chez un agent enrôlé avant elle, qui la recevra en se ré-enrôlant.
ALTER TABLE agents ADD COLUMN seal_public_key BLOB CHECK (seal_public_key IS NULL OR length(seal_public_key) = 32);
