package agent

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/ldesfontaine/kagu/internal/kit/fsx"
)

// folderBench est un dossier du test et le système de la machine, jugé comme
// en production, sauf que le compte du test y tient la place de root : les
// dossiers à root (« / », /home) restent jugés par rootOnlyDir. hook voit
// chaque dossier jugé, après son ouverture.
type folderBench struct {
	base   string
	owner  fsx.Owner
	system HostSystem
	hook   func(path string)
}

func newFolderBench(t *testing.T) *folderBench {
	t.Helper()
	base := t.TempDir()
	b := &folderBench{base: base, owner: fsx.Owner{UID: os.Getuid(), GID: os.Getgid()}}
	b.system = HostSystem{judgeDir: func(path string, stat *syscall.Stat_t) error {
		if b.hook != nil {
			b.hook(path)
		}
		if stat.Uid == 0 {
			return rootOnlyDir(path, stat)
		}
		return judgeOwnedDir(path, stat, uint32(b.owner.UID)) // #nosec G115 -- un uid.
	}}
	return b
}

func (b *folderBench) path(names ...string) string {
	return filepath.Join(append([]string{b.base}, names...)...)
}

// target est un dossier hors de la route, avec un dossier « x » en 0700 : un
// Fchown ou un Fchmod qui le toucherait le passerait en 0755.
func (b *folderBench) target(t *testing.T) string {
	t.Helper()
	target := b.path("target")
	if err := os.MkdirAll(filepath.Join(target, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	return target
}

func untouched(t *testing.T, path string) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("%s was given away: %s", path, info.Mode())
	}
}

func absent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("%s was created: %v", path, err)
	}
}

// Le chemin normal : les parents qui manquent se créent, le dossier prend
// son mode.
func TestMakeFolder_CreatesUnderJudgedParents(t *testing.T) {
	b := newFolderBench(t)
	if err := b.system.MakeFolder(b.path("a", "b", "c"), 0o700, b.owner); err != nil {
		t.Fatal(err)
	}
	untouched(t, b.path("a", "b", "c"))
}

// Un parent qui est un lien n'est pas suivi : rien n'est créé ni donné au
// bout du lien.
func TestMakeFolder_RefusesALinkedParent(t *testing.T) {
	b := newFolderBench(t)
	target := b.target(t)
	if err := os.Symlink(target, b.path("link")); err != nil {
		t.Fatal(err)
	}
	err := b.system.MakeFolder(b.path("link", "x"), 0o755, b.owner)
	if err == nil || !strings.Contains(err.Error(), b.path("link")) {
		t.Fatalf("a linked parent: %v", err)
	}
	untouched(t, filepath.Join(target, "x"))
}

// Un parent qui n'est pas à root (ici, pas au compte qui en tient lieu) est
// refusé, et rien n'est créé dessous.
func TestMakeFolder_RefusesAParentNotOwnedByRoot(t *testing.T) {
	b := newFolderBench(t)
	b.owner.UID++
	err := b.system.MakeFolder(b.path("x"), 0o755, b.owner)
	if err == nil || !strings.Contains(err.Error(), "does not belong to root") {
		t.Fatalf("a parent of another account: %v", err)
	}
	absent(t, b.path("x"))
}

// Un parent à root mais ouvert en écriture au groupe ou à tous (/tmp, un
// 0775) est un nom que le compte de l'agent contrôle : refusé.
func TestMakeFolder_RefusesAParentWritableByOthers(t *testing.T) {
	for _, mode := range []fs.FileMode{0o777 | fs.ModeSticky, 0o775, 0o757} {
		b := newFolderBench(t)
		open := b.path("open")
		if err := os.Mkdir(open, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(open, mode); err != nil {
			t.Fatal(err)
		}
		err := b.system.MakeFolder(filepath.Join(open, "x"), 0o755, b.owner)
		if err == nil || !strings.Contains(err.Error(), "writable by its group or others") {
			t.Fatalf("mode %s: %v", mode, err)
		}
		absent(t, filepath.Join(open, "x"))
	}
}

// Un parent remplacé par un lien entre deux composants : avant son
// ouverture, il est refusé ; après, le descripteur tient le vrai dossier et
// le lien ne mène nulle part. Jamais rien n'est donné au bout du lien
// (files.write=/tmp/a/cron.d, /tmp/a -> /etc).
func TestMakeFolder_RefusesAParentSwappedForALink(t *testing.T) {
	for _, swapAt := range []string{"before", "after"} {
		b := newFolderBench(t)
		target := b.target(t)
		if err := os.Mkdir(b.path("a"), 0o700); err != nil {
			t.Fatal(err)
		}
		swapped := false
		b.hook = func(path string) {
			if swapped || (swapAt == "before" && path != b.base) || (swapAt == "after" && path != b.path("a")) {
				return
			}
			swapped = true
			if err := os.Rename(b.path("a"), b.path("a-old")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, b.path("a")); err != nil {
				t.Fatal(err)
			}
		}
		err := b.system.MakeFolder(b.path("a", "x"), 0o755, b.owner)
		switch swapAt {
		case "before":
			if err == nil || !strings.Contains(err.Error(), "is a link or not a directory") {
				t.Fatalf("swapped before its opening: %v", err)
			}
		case "after":
			if err != nil {
				t.Fatalf("swapped after its opening: %v", err)
			}
			if _, err := os.Stat(b.path("a-old", "x")); err != nil {
				t.Fatalf("not made in the folder that was opened: %v", err)
			}
		}
		if !swapped {
			t.Fatal("the swap did not happen")
		}
		untouched(t, filepath.Join(target, "x"))
	}
}

// En production, la garde est root seul : un dossier du test (à son compte)
// est refusé, sans que rien soit créé.
func TestHostSystem_TheDefaultGuardIsRootOnly(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("the test account is root")
	}
	base := t.TempDir()
	err := HostSystem{}.MakeFolder(filepath.Join(base, "x"), 0o755, fsx.Owner{UID: os.Getuid(), GID: os.Getgid()})
	if err == nil || !strings.Contains(err.Error(), "does not belong to root") {
		t.Fatalf("default guard: %v", err)
	}
	absent(t, filepath.Join(base, "x"))
}
