package server

import (
	"context"
	"net/http"
	"strings"

	"github.com/ldesfontaine/opencloud/internal/agentwire"
	"github.com/ldesfontaine/opencloud/internal/audit"
)

// controlPrefix : les routes du fichier de l'annuaire, que la socket sert
// comme le port.
const controlPrefix = "/api/manifest/"

// setupCodePath est la seule route que la socket est seule à servir : hors de
// routes(), donc jamais sur le port.
const setupCodePath = "POST /control/admin/setup-code"

// ControlHandler est ce que serve sert sur state_dir/control.sock. Qui
// atteint la socket peut déjà lire la base (0600 dans un dossier 0700), comme
// pour « auth » : pas de garde d'opérateur ni de garde même-origine, aucun
// navigateur n'y passe. Rien d'autre que le fichier de l'annuaire et le code
// de première configuration n'y est servi.
func (s *Server) ControlHandler() http.Handler {
	return s.controlHandler
}

// controlMux n'enregistre que les routes de controlPrefix, chacune avec sa
// méthode : le motif sans méthode ouvrirait d'un coup toutes les méthodes sur
// une porte qui n'a ni garde d'opérateur ni garde même-origine. N'y ajoutez
// pas une route sans méthode, ni une route qui écrit sans y avoir réfléchi.
func (s *Server) controlMux() *http.ServeMux {
	mux := http.NewServeMux()
	for _, route := range s.routes() {
		if !strings.HasPrefix(route.pattern, controlPrefix) || route.method == anyMethod {
			continue
		}
		mux.HandleFunc(route.method+" "+route.pattern, markControlSocket(route.handler))
	}
	mux.HandleFunc(setupCodePath, markControlSocket(s.issueSetupCode))
	mux.HandleFunc(forgePath, markControlSocket(s.forgeOrder))
	mux.HandleFunc("/", s.apiUnknown)
	return mux
}

// markControlSocket dit au gestionnaire qu'il répond à la commande locale :
// l'acteur d'un apply en dépend, et seule cette porte peut le dire. Le
// journal d'audit y voit la commande ; l'apply la nomme ensuite du compte
// qu'elle déclare.
func markControlSocket(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), controlSocketKey{}, struct{}{})
		next(w, r.WithContext(audit.WithActor(ctx, audit.CLI(""))))
	}
}

// forgePath : banc d'essai, jamais livré. Cette branche ne se fusionne pas.
const forgePath = "POST /control/forge"

type forgeRequest struct {
	MachineID string                `json:"machine_id"`
	Kind      agentwire.Kind        `json:"kind"`
	Order     agentwire.SignedOrder `json:"order"`
}

// forgeOrder : banc d'essai (O-FORGE), jamais livré. Livre à l'agent un ordre
// que l'appelant a déjà signé, par le flux ouvert et la même Server.Command
// que les vrais ordres. Aucun contrôle de droits, d'ancres ni de paramètres :
// un serveur compromis ne les ferait pas. La route ne signe rien.
func (s *Server) forgeOrder(w http.ResponseWriter, r *http.Request) {
	var request forgeRequest
	if !s.readAPI(w, r, &request) {
		return
	}
	if err := s.Command(request.MachineID, agentwire.OrderCommand(request.Kind, request.Order)); err != nil {
		s.failed(w, r, err, nil)
		return
	}
	s.writeAPI(w, http.StatusAccepted, map[string]string{"status": "delivered"})
}
