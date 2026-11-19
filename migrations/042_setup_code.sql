-- Le code de première configuration (R-A2-5) : haché, avec son échéance et le
-- compte de ses essais faux. Vide tant qu'aucun code n'est tiré ; tout
-- changement d'état de l'accès l'efface.
ALTER TABLE auth_settings ADD COLUMN setup_code_hash     TEXT    NOT NULL DEFAULT '';
ALTER TABLE auth_settings ADD COLUMN setup_code_expires  INTEGER;
ALTER TABLE auth_settings ADD COLUMN setup_code_failures INTEGER NOT NULL DEFAULT 0;
