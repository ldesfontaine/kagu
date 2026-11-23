-- Le code à six chiffres (TOTP, A2 R-A2-6), proposé en native, jamais imposé.
-- totp_secret est scellé par secret.key comme les autres secrets de la base
-- (internal/edge/store/secrets.go) ; vide, aucun code n'est actif.
-- totp_last_step est le dernier pas de 30 s servi : un code d'un pas égal ou
-- antérieur est refusé, ce qui interdit de rejouer un code dans sa fenêtre.
ALTER TABLE auth_settings ADD COLUMN totp_secret    TEXT    NOT NULL DEFAULT '';
ALTER TABLE auth_settings ADD COLUMN totp_last_step INTEGER NOT NULL DEFAULT 0;
