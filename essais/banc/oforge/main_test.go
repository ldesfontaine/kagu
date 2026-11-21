package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ldesfontaine/opencloud/internal/action"
)

// Les paramètres partent octet pour octet : une clé répétée d'une autre
// casse survit dans le corps signé. Si -dry-run décodait puis ré-encodait
// les paramètres dans une map, une des deux clés disparaîtrait ici.
func TestDryRun_KeepsBothDifferentlyCasedKeys(t *testing.T) {
	stateDir := t.TempDir()
	root, err := os.OpenRoot(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := action.CreateKey(root, action.GenerateKey()); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), "config.toml")
	config := "state_dir = \"" + stateDir + "\"\nlisten = \"127.0.0.1:18080\"\n"
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}

	params := `{"target":"5012","Target":"9999"}`
	var stdout bytes.Buffer
	args := []string{"-config", configPath, "-machine", "m1", "-kind", "backup.produce", "-params", params, "-dry-run"}
	if err := run(context.Background(), args, &stdout); err != nil {
		t.Fatalf("run: %v", err)
	}

	var body struct {
		Params json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &body); err != nil {
		t.Fatalf("decode printed body: %v\n%s", err, stdout.String())
	}
	got := string(body.Params)
	if !bytes.Contains([]byte(got), []byte(`"target":"5012"`)) || !bytes.Contains([]byte(got), []byte(`"Target":"9999"`)) {
		t.Fatalf("les deux clés ne survivent pas dans le corps signé: %s", got)
	}
}
