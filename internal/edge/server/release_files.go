package server

import (
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/ldesfontaine/kagu/internal/kit/release"
)

// releaseFilesPattern sert la bibliothèque des versions à une machine qui
// s'ajoute sans joindre l'adresse des versions (R-B1-12) : les sommes, leur
// signature et le binaire de son architecture, sans authentification ni
// jeton dans l'adresse. Ce n'est qu'une source de fichiers : install.sh les
// vérifie avec les clés écrites dans le script avant d'en poser un seul.
const releaseFilesPattern = "/releases/{version}/{name}"

func (s *Server) serveReleaseFile(w http.ResponseWriter, r *http.Request) {
	version, err := release.ParseVersion(r.PathValue("version"))
	if err != nil || s.releases == nil {
		http.NotFound(w, r)
		return
	}
	file, err := s.releases.OpenServed(version, r.PathValue("name"))
	if errors.Is(err, release.ErrNoRelease) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.logger.Error("serve release file", "path", r.URL.Path, "error", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		s.logger.Error("serve release file", "path", r.URL.Path, "error", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
	if _, err := io.Copy(w, file); err != nil {
		s.logger.Warn("serve release file", "path", r.URL.Path, "error", err)
	}
}
