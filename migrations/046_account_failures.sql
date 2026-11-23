-- Les échecs comptés par compte (A2 R-A2-16, W-M4), en plus du limiteur par
-- adresse : il n'y a qu'un compte, ses compteurs sont ceux de la ligne unique.
-- Ils s'écrivent dans la transaction de la tentative (store/auth.go).
-- totp_failures : codes faux d'affilée, remis à zéro à la suspension ; le
-- plafond 5 est le plus haut seuil que la configuration admet.
-- totp_locked_until : fin de la suspension du code (secondes Unix) ; nul,
-- le code n'est pas suspendu.
-- password_failures_hour : mots de passe faux de l'heure comptée, qui
-- commence à password_failures_window (secondes Unix).
ALTER TABLE auth_settings ADD COLUMN totp_failures INTEGER NOT NULL DEFAULT 0 CHECK (totp_failures BETWEEN 0 AND 5);
ALTER TABLE auth_settings ADD COLUMN totp_locked_until INTEGER;
ALTER TABLE auth_settings ADD COLUMN password_failures_hour INTEGER NOT NULL DEFAULT 0 CHECK (password_failures_hour >= 0);
ALTER TABLE auth_settings ADD COLUMN password_failures_window INTEGER;
