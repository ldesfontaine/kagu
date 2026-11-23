package server

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/ldesfontaine/kagu/internal/kit/audit"
	"github.com/ldesfontaine/kagu/internal/kit/peercred"
)

// controlPrefix : les routes du fichier de l'annuaire, que la socket sert
// comme le port.
const controlPrefix = "/api/manifest/"

// adminPrefix : les routes d'administration, que la socket est seule à
// servir (hors de routes(), donc jamais sur le port) et au seul pair d'uid 0
// (R-A2-11). Ni jeton ni session : l'uid que le noyau atteste suffit.
const adminPrefix = "/control/admin/"

// rootUID : le seul pair admis sur adminPrefix. Jamais un groupe : le compte
// du service est dans le groupe de l'agent local, pas root.
const rootUID = 0

// controlRoute est une route d'administration de la socket, avec sa méthode.
type controlRoute struct {
	pattern string
	handler http.HandlerFunc
}

// adminRoutes sont les gestes de root sur la machine Kagu : ils ne sont
// pas des gestes de l'interface (R-A2-10).
func (s *Server) adminRoutes() []controlRoute {
	return []controlRoute{
		{"POST " + adminPrefix + "setup-code", s.issueSetupCode},
		{"POST " + adminPrefix + "reset-password", s.resetPassword},
		{"POST " + adminPrefix + "auth-mode", s.setAuthMode},
		{"POST " + adminPrefix + "sessions/close-all", s.closeAllSessions},
		{"POST " + adminPrefix + "tokens/revoke-all", s.revokeAllAPITokens},
	}
}

// ControlHandler est ce que serve sert sur state_dir/control.sock. Qui
// atteint la socket peut déjà lire la base (0600 dans un dossier 0700), comme
// pour « auth » : pas de garde d'opérateur ni de garde même-origine, aucun
// navigateur n'y passe. Le fichier de l'annuaire y est servi au compte du
// service ; les routes d'administration, à root seul.
func (s *Server) ControlHandler() http.Handler {
	return s.controlHandler
}

// controlMux n'enregistre que les routes de controlPrefix et d'adminPrefix,
// chacune avec sa méthode : le motif sans méthode ouvrirait d'un coup toutes
// les méthodes sur une porte qui n'a ni garde d'opérateur ni garde
// même-origine. N'y ajoutez pas une route sans méthode, ni une route qui
// écrit sans y avoir réfléchi.
func (s *Server) controlMux() *http.ServeMux {
	mux := http.NewServeMux()
	for _, route := range s.routes() {
		if !strings.HasPrefix(route.pattern, controlPrefix) || route.method == anyMethod {
			continue
		}
		mux.HandleFunc(route.method+" "+route.pattern, markControlSocket(route.handler))
	}
	admin := http.NewServeMux()
	for _, route := range s.adminRoutes() {
		admin.HandleFunc(route.pattern, markControlSocket(route.handler))
	}
	admin.HandleFunc("/", s.apiUnknown)
	mux.Handle(adminPrefix, peercred.OnlyUID(admin, rootUID))
	mux.HandleFunc("/", s.apiUnknown)
	return mux
}

// markControlSocket dit au gestionnaire qu'il répond à la commande locale :
// l'acteur d'un apply en dépend, et seule cette porte peut le dire. Le
// journal d'audit y voit la commande, sous l'uid que le noyau a donné ;
// l'apply la nomme ensuite du compte qu'elle déclare.
func markControlSocket(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), controlSocketKey{}, struct{}{})
		next(w, r.WithContext(audit.WithActor(ctx, audit.CLI(peerName(ctx)))))
	}
}

// peerName nomme le pair de la socket par son uid ; vide s'il n'a pas été lu.
func peerName(ctx context.Context) string {
	uid, known := peercred.UID(ctx)
	if !known {
		return ""
	}
	return "uid:" + strconv.FormatUint(uint64(uid), 10)
}
