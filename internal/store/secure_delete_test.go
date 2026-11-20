package store

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Chaque connexion du pool efface pour de bon : le pragma est posé par le DSN.
func TestOpenHandle_EnablesSecureDeleteOnEveryConnection(t *testing.T) {
	db := openEmpty(t)
	ctx := context.Background()
	first, err := db.sql.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := db.sql.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()

	for _, name := range []string{"first", "second"} {
		conn := first
		if name == "second" {
			conn = second
		}
		var enabled int
		if err := conn.QueryRowContext(ctx, `PRAGMA secure_delete`).Scan(&enabled); err != nil {
			t.Fatal(err)
		}
		if enabled != 1 {
			t.Fatalf("connection %s: secure_delete = %d, want 1", name, enabled)
		}
	}
}

// Une ligne effacée ne reste pas lisible dans le fichier, une fois le journal
// reporté dans la base par la fermeture.
func TestOpenHandle_DeletedRowLeavesNoBytesInTheFile(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	handle, err := openHandle(root)
	if err != nil {
		t.Fatal(err)
	}
	marker := "marker-secret-7f3a9c"
	for _, query := range []string{
		`CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT NOT NULL)`,
		`INSERT INTO notes (body) VALUES ('keep'), ('` + marker + `')`,
		`DELETE FROM notes WHERE body = '` + marker + `'`,
	} {
		if _, err := handle.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	if err := handle.Close(); err != nil {
		t.Fatal(err)
	}

	content, err := os.ReadFile(filepath.Join(root.Name(), fileName))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(content, []byte(marker)) {
		t.Fatal("the deleted row is still readable in the database file")
	}
}
