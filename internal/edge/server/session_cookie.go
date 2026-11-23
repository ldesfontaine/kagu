package server

import (
	"net/http"
	"net/netip"
	"strings"

	"github.com/ldesfontaine/kagu/internal/edge/server/httpx"
	"github.com/ldesfontaine/kagu/internal/fact/auth"
	"github.com/ldesfontaine/kagu/internal/kit/brand"
)

// Le cookie d'une session native (R-A2-3, R-A2-4). Sur HTTPS, __Host-, Secure,
// HttpOnly, SameSite=Strict, Path=/. Sur la boucle locale en HTTP (le tunnel
// SSH), le cookie local, sans Secure, lu seulement d'un client de boucle
// locale. Ailleurs, en HTTP clair, aucune session ne s'ouvre.

// codeHTTPSRequired est le refus d'ouvrir une session en HTTP clair hors de la
// boucle locale.
const codeHTTPSRequired = "auth.https_required"

// sessionCookieName rend le cookie que porterait une session ouverte par cette
// requête, ou faux si aucune ne doit s'ouvrir (R-A2-4).
func (s *Server) sessionCookieName(r *http.Request) (string, bool) {
	if strings.HasPrefix(s.pageAddress(r), "https://") {
		return brand.SessionCookie, true
	}
	if s.isLoopbackClient(r) {
		return brand.LocalSessionCookie, true
	}
	return "", false
}

// isLoopbackClient juge le pair et l'adresse cliente, et refuse un schéma
// transmis : derrière un mandataire de confiance sur 127.0.0.1, tout client a
// un pair de boucle locale, mais pas une adresse cliente de boucle locale.
func (s *Server) isLoopbackClient(r *http.Request) bool {
	if r.Header.Get("X-Forwarded-Proto") != "" {
		return false
	}
	return isLoopbackAddress(httpx.PeerHost(r)) && isLoopbackAddress(s.clientAddress(r))
}

func isLoopbackAddress(text string) bool {
	address, err := netip.ParseAddr(text)
	return err == nil && prefixesContain(loopbackRanges, address)
}

// presentedSessionToken rend le jeton que la requête présente. Le cookie
// __Host- vaut d'où qu'il vienne : le navigateur ne le pose et ne l'envoie
// qu'en HTTPS. Le cookie local ne vaut que d'un client de boucle locale.
func (s *Server) presentedSessionToken(r *http.Request) string {
	if cookie, err := r.Cookie(brand.SessionCookie); err == nil && cookie.Value != "" {
		return cookie.Value
	}
	if !s.isLoopbackClient(r) {
		return ""
	}
	if cookie, err := r.Cookie(brand.LocalSessionCookie); err == nil {
		return cookie.Value
	}
	return ""
}

// setSessionCookie pose le jeton d'une session neuve sous name, et efface
// l'autre cookie : un seul jeton reste au navigateur.
func setSessionCookie(w http.ResponseWriter, name, token string) {
	http.SetCookie(w, sessionCookie(name, token, int(auth.SessionLifetime.Seconds())))
	for _, other := range []string{brand.SessionCookie, brand.LocalSessionCookie} {
		if other != name {
			http.SetCookie(w, sessionCookie(other, "", -1))
		}
	}
}

// clearSessionCookies efface les deux cookies : à la déconnexion, le
// navigateur ne garde rien.
func clearSessionCookies(w http.ResponseWriter) {
	for _, name := range []string{brand.SessionCookie, brand.LocalSessionCookie} {
		http.SetCookie(w, sessionCookie(name, "", -1))
	}
}

// sessionCookie : maxAge négatif efface le cookie. Secure suit le nom :
// __Host- l'exige, le cookie local sert le HTTP de la boucle locale.
func sessionCookie(name, token string, maxAge int) *http.Cookie {
	return &http.Cookie{ // #nosec G124 -- le cookie local, sans Secure, ne sert que la boucle locale en HTTP (R-A2-3).
		Name:     name,
		Value:    token,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   name == brand.SessionCookie,
		SameSite: http.SameSiteStrictMode,
	}
}
