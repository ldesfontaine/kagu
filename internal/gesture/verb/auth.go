package verb

import "github.com/ldesfontaine/kagu/internal/kit/audit"

// Les gestes de l'accès à l'interface (A2 §7) sont de niveau 3 : la personne
// connectée seule, aucun jeton. Ils ne visent ni machine ni sonde : pas de
// cible. Inscrits pour que leur niveau se lise ici, comme celui de tout geste.
func init() {
	const reason = "api_token.verb_auth_reason"
	Default.MustRegister(Verb{
		ID: "auth.password.change", Route: "PUT /api/auth/password", Params: []string{}, Body: []string{"current", "password"},
		Label: "api_token.verb_auth_password_change", Summary: "api_token.verb_auth_password_change_text",
		Level: 3, Reason: reason, Audit: audit.AuthChangePassword,
	})
	Default.MustRegister(Verb{
		ID: "auth.totp.enable", Route: "POST /api/auth/totp", Params: []string{}, Body: []string{"secret", "code"},
		Label: "api_token.verb_auth_totp_enable", Summary: "api_token.verb_auth_totp_enable_text",
		Level: 3, Reason: reason, Audit: audit.AuthTOTPEnable,
	})
	Default.MustRegister(Verb{
		ID: "auth.totp.disable", Route: "DELETE /api/auth/totp", Params: []string{}, Body: []string{"password"},
		Label: "api_token.verb_auth_totp_disable", Summary: "api_token.verb_auth_totp_disable_text",
		Level: 3, Reason: reason, Audit: audit.AuthTOTPDisable,
	})
	Default.MustRegister(Verb{
		ID: "auth.session.close", Route: "DELETE /api/auth/sessions/{id}", Params: []string{"id"}, Body: []string{},
		Label: "api_token.verb_auth_session_close", Summary: "api_token.verb_auth_session_close_text",
		Level: 3, Reason: reason, Audit: audit.AuthCloseSession,
	})
	Default.MustRegister(Verb{
		ID: "auth.session.close_others", Route: "POST /api/auth/sessions/actions/close-others", Params: []string{}, Body: []string{},
		Label: "api_token.verb_auth_session_close_others", Summary: "api_token.verb_auth_session_close_others_text",
		Level: 3, Reason: reason, Audit: audit.AuthCloseSession,
	})
}
