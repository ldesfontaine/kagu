// Package verb tient le registre des gestes et leur niveau (A4). Un verbe
// nomme une route d'action de l'opérateur, son inverse ou sa confirmation,
// l'ordre qu'il envoie et son action d'audit ; il ne porte aucun code :
// l'admission du serveur s'en sert pour laisser passer la requête d'un jeton,
// la route fait le reste. Un geste de niveau 3 ou 4 y est inscrit fermé aux
// jetons.
package verb
