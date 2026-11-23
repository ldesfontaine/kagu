package verb

import "github.com/ldesfontaine/kagu/internal/kit/audit"

// Le geste qui retire une machine ne se défait pas : il est offert à un jeton
// au niveau 2. Le jeton dépose une demande, l'opérateur la confirme dans
// l'interface, et seulement alors la route d'opérateur s'exécute.
func init() {
	Default.MustRegister(Verb{
		ID: "machine.delete", Route: "DELETE /api/machines/{id}", Params: []string{"id"}, Body: []string{"keep_history"}, Target: TargetMachine,
		Label: "api_token.verb_machine_delete", Summary: "api_token.verb_machine_delete_text",
		Level: 2, Token: true, Audit: audit.MachineDelete,
	})
}
