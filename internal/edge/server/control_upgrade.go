package server

import (
	"net/http"

	"github.com/ldesfontaine/kagu/internal/kit/release"
)

// Les routes de root qui préparent une montée de serve (B2). Root appelle,
// serve agit sous son propre compte : root n'écrit jamais dans state_dir.

// healthResponse est la version que serve fait tourner : upgrade attend celle
// qu'il vient d'installer.
type healthResponse struct {
	Version string `json:"version"`
	Commit  string `json:"commit,omitempty"`
}

func (s *Server) controlHealth(w http.ResponseWriter, _ *http.Request) {
	s.writeAPI(w, http.StatusOK, healthResponse{Version: s.version, Commit: s.commit})
}

type upgradeCopyResponse struct {
	Path string `json:"path"`
}

// copyBeforeUpgrade copie la base sous state_dir/upgrade/, nommée par la
// version qui tourne : celle dont le binaire sait la relire (R-B2-2).
func (s *Server) copyBeforeUpgrade(w http.ResponseWriter, r *http.Request) {
	if !s.readEmptyBody(w, r) {
		return
	}
	running, err := release.ParseVersion(s.version)
	if s.failed(w, r, err, nil) {
		return
	}
	copied, err := s.upgradeCopies.CopyBeforeUpgrade(r.Context(), running)
	if s.failed(w, r, err, nil) {
		return
	}
	s.writeAPI(w, http.StatusCreated, upgradeCopyResponse{Path: copied})
}

// Le dossier d'une version téléchargée, en chemin absolu, lisible du compte
// du service et hors de /tmp : l'unité de serve a son propre /tmp.
type releaseImportRequest struct {
	Folder string `json:"folder"`
}

type releaseImportResponse struct {
	Version  string   `json:"version"`
	Binaries []string `json:"binaries"`
}

// importRelease vérifie la version avec les clés de ce binaire, jamais sur
// la foi de root, puis la copie dans la bibliothèque (R-B2-1).
func (s *Server) importRelease(w http.ResponseWriter, r *http.Request) {
	var request releaseImportRequest
	if !s.readAPI(w, r, &request) {
		return
	}
	if s.releases == nil {
		s.failed(w, r, release.ErrNoTrustedKey, nil)
		return
	}
	signed, err := s.releases.Import(request.Folder)
	if s.failed(w, r, err, nil) {
		return
	}
	s.writeAPI(w, http.StatusOK, releaseImportResponse{Version: signed.Version.String(), Binaries: signed.BinaryNames()})
}
