package hostinfo

import (
	"errors"
	"testing"
)

// Un rapport vient d'un pair : un texte d'UTF-8 cassé, de contrôle ou de sens
// d'écriture inversé est refusé en bloc (R-A1-13).
func TestReportValidate_UntrustedTextIsRefused(t *testing.T) {
	cases := map[string]func(*Report){
		"modèle en UTF-8 invalide":  func(r *Report) { r.Disks[0].Model = "WD\xff\xfe" },
		"modèle coupé au milieu":    func(r *Report) { r.Disks[0].Model = "caf\xc3" },
		"modèle avec saut de ligne": func(r *Report) { r.Disks[0].Model = "WD\nBlue" },
		"modèle bidi":               func(r *Report) { r.Disks[0].Model = "WD\u202eBlue" },
		"niveau en UTF-8 invalide":  func(r *Report) { r.Pools[0].Level = "raid\xff" },
		"niveau bidi":               func(r *Report) { r.Pools[0].Level = "raid\u2066" },
	}
	for name, mutate := range cases {
		report := Detect(aMachine(), "kvm")
		if err := report.Validate(); err != nil {
			t.Fatalf("a real report must validate: %v", err)
		}
		mutate(&report)
		if err := report.Validate(); !errors.Is(err, ErrReportInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
