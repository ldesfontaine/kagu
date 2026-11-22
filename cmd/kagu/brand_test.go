package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ldesfontaine/kagu/internal/kit/brand"
)

// Le nom du binaire n'est pas dérivé de l'identifiant ni de ce répertoire :
// c'est le Makefile qui le pose. Si l'un bouge sans l'autre, les commandes que
// le serveur montre à l'opérateur ne se lancent plus.
func TestCommand_FollowsTheMakefile(t *testing.T) {
	makefile, err := os.ReadFile(filepath.Join("..", "..", "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(makefile), " -o bin/"+brand.Command+" ./cmd/") {
		t.Errorf("the Makefile does not build bin/%s", brand.Command)
	}
}
