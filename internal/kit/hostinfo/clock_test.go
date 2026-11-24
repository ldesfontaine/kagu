package hostinfo

import (
	"path/filepath"
	"testing"
	"time"
)

// L'horloge monotone : le démarrage et le temps écoulé depuis, lus de /proc ;
// rien des deux si l'un manque ou ne se lit pas.
func TestReadMonotonicClock_ReadsTheBootAndItsUptime(t *testing.T) {
	dir := t.TempDir()
	boot := writeIdentifier(t, dir, "boot_id", "9a6c1d2e-0b7f-4e3a-8c5d-1f2e3a4b5c6d")
	uptime := writeIdentifier(t, dir, "uptime", "51234.56 98765.43")
	gotBoot, gotUptime := readMonotonicClock(boot, uptime)
	if gotBoot != "9a6c1d2e-0b7f-4e3a-8c5d-1f2e3a4b5c6d" || gotUptime != 51234560*time.Millisecond {
		t.Fatalf("boot %q uptime %v", gotBoot, gotUptime)
	}
	garbled := writeIdentifier(t, dir, "garbled", "soon")
	for _, paths := range [][2]string{{filepath.Join(dir, "absent"), uptime}, {boot, filepath.Join(dir, "absent")}, {boot, garbled}} {
		if gotBoot, gotUptime := readMonotonicClock(paths[0], paths[1]); gotBoot != "" || gotUptime != 0 {
			t.Fatalf("%v: boot %q uptime %v", paths, gotBoot, gotUptime)
		}
	}
	if gotBoot, gotUptime := MonotonicClock(); gotBoot == "" || gotUptime <= 0 {
		t.Fatalf("this machine: boot %q uptime %v", gotBoot, gotUptime)
	}
}
