package server

import (
	"encoding/json"
	"net"
	"net/http"
	"time"

	"github.com/ldesfontaine/kagu/internal/kit/brand"
)

// Ce que Paramètres dit de mcp-maison : s'il répond, sa version, combien
// d'outils Kagu il sert. SuggestedURL est ce qu'il faut écrire dans
// mcp_url (config.toml) pour que Kagu le cherche.
type mcpCheckResponse struct {
	URL          string
	State        string
	Version      string
	ProductTools int
	CheckedAt    time.Time
	SuggestedURL string
}

// MarshalJSON écrit le compte des outils sous brand.ID + "_tools" : une
// balise de champ ne lit pas brand.
func (response mcpCheckResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"url": response.URL, "state": response.State, "version": response.Version,
		brand.ID + "_tools": response.ProductTools, "checked_at": response.CheckedAt,
		"suggested_url": response.SuggestedURL,
	})
}

// getMCPCheck lit le /health de mcp-maison à chaque appel : la carte de
// Paramètres le demande à son ouverture et au bouton « Vérifier », sans
// boucle de fond ni alerte.
func (s *Server) getMCPCheck(w http.ResponseWriter, r *http.Request) {
	health := s.mcpCheck.Check(r.Context())
	host, _ := mcpEnvOf(s.listen)
	s.writeAPI(w, http.StatusOK, mcpCheckResponse{
		URL: s.mcpURL, State: string(health.State), Version: health.Version,
		ProductTools: health.ProductTools, CheckedAt: health.CheckedAt.UTC(),
		SuggestedURL: "http://" + net.JoinHostPort(host, mcpDefaultPort),
	})
}
