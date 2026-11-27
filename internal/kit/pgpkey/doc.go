// Package pgpkey lit l'empreinte d'une clé publique OpenPGP en armure, pour
// la comparer à celle qu'un binaire porte (la clé du dépôt de Docker, R-B1-4).
// Il ne vérifie aucune signature : apt le fait avec la clé une fois posée.
package pgpkey
