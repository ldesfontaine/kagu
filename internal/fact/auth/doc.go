// Package auth tient l'accès de l'opérateur à l'interface : le mode
// (aucun, un compte natif, un SSO en amont qui authentifie), l'identifiant,
// l'empreinte lente du mot de passe, le nom de l'en-tête d'identité et les
// sessions ouvertes par la connexion.
// Il ne sait rien de HTTP : le serveur lit le cookie, répond 401 et limite.
package auth
