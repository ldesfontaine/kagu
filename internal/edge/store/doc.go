// Package store ouvre la base SQLite de Kagu, applique les migrations
// embarquées, et porte toutes les requêtes : aucune autre part du programme
// n'écrit de SQL. Une transaction par opération métier.
package store
