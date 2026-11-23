// Package peercred juge le pair d'une socket Unix par son uid, que le noyau
// atteste (SO_PEERCRED). C'est le seul code du dépôt qui lit l'uid d'un pair
// (brique B-9) : la socket de contrôle s'en sert pour ses routes
// d'administration, réservées à root (R-A2-11).
package peercred
