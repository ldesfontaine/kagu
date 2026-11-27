package main

import (
	"bufio"
	"bytes"
	"compress/bzip2"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
	"github.com/ldesfontaine/kagu/internal/fact/machine"
	"github.com/ldesfontaine/kagu/internal/kit/brand"
	"github.com/ldesfontaine/kagu/internal/kit/fsx"
	"github.com/ldesfontaine/kagu/internal/kit/hostinfo"
	"github.com/ldesfontaine/kagu/internal/kit/pgpkey"
	"github.com/ldesfontaine/kagu/internal/kit/step"
)

// Docker et restic dans setup (R-B1-4, R-B1-5, R-B1-15) : posés après un oui,
// depuis leurs sources officielles, aux versions et sommes de brand. Docker
// passe avant le compte de l'agent : le compte n'entre dans le groupe docker
// que si le groupe existe. Le plafond des journaux de Docker s'écrit dans
// daemon.json s'il manque ; un daemon.json présent n'est jamais réécrit : la
// coche le dit.

const (
	// La place d'une clé et d'une archive de restic téléchargées, et celle de
	// restic une fois décompressé.
	maxKeyBytes        = 64 << 10
	maxResticArchive   = 64 << 20
	maxResticBinary    = 256 << 20
	downloadTimeout    = 5 * time.Minute
	systemFileMode     = 0o644
	systemDirMode      = 0o755
	dockerAnswerYes    = "yes"
	dockerAnswerNo     = "no"
	resticSystemBinary = "/usr/bin/restic"
)

// daemonLogLimit est le plafond des journaux des conteneurs (R-B1-15) : le
// pilote local, 10 Mio par fichier, trois fichiers.
var daemonLogLimit = map[string]any{
	"log-driver": "local",
	"log-opts":   map[string]string{"max-size": "10m", "max-file": "3"},
}

// toolsMissing dit ce qui manque sur la machine : Docker, restic.
func (r *setupRun) toolsMissing() (docker, restic bool) {
	docker = !r.system.Exists(machine.DockerBinary)
	restic = !r.system.Exists(r.paths.resticBinary) && !r.system.Exists(resticSystemBinary)
	return docker, restic
}

// chooseTools pose la question Docker (R-B1-1), seulement si Docker ou
// restic manque et que le jeu n'est pas Observer. Un oui vaut pour les deux ;
// --no-docker vaut non ; sans terminal, la réponse par défaut, oui. Une
// réponse d'un setup d'avant vaut. Docker refusé, un jeu qui le demande
// devient Observer : la ligne de l'agent le dira (lowered).
func (r *setupRun) chooseTools(noDocker bool) error {
	dockerMissing, resticMissing := r.toolsMissing()
	if r.rights == agentpolicy.SetObserve || (!dockerMissing && !resticMissing) {
		return nil
	}
	switch {
	case noDocker:
		r.state.Tools = dockerAnswerNo
	case r.state.Tools == "":
		r.state.Tools = r.askTools(dockerMissing, resticMissing)
	}
	if r.state.Tools == dockerAnswerNo && dockerMissing {
		r.requested, r.rights = r.rights, agentpolicy.SetObserve
		r.state.Rights = r.rights
	}
	return nil
}

// askTools demande sur le terminal ; Entrée vaut oui, comme l'absence de
// terminal.
func (r *setupRun) askTools(dockerMissing, resticMissing bool) string {
	terminal, err := r.openTerminal()
	if err != nil {
		return dockerAnswerYes
	}
	defer terminal.Close()
	question := r.text.Get("setup.restic_question")
	if dockerMissing {
		question = r.text.Get("setup.docker_question")
		if resticMissing {
			question = r.text.Get("setup.docker_restic_question")
		}
	}
	fmt.Fprint(r.out, question)
	answer, _ := bufio.NewReader(terminal).ReadString('\n')
	fmt.Fprintln(r.out)
	if strings.TrimSpace(answer) == "" || isYes(answer) {
		return dockerAnswerYes
	}
	return dockerAnswerNo
}

// toolsSkipped dit pourquoi Docker et restic ne se posent pas : Observer, ou
// le non de l'opérateur ; vide s'ils se posent.
func (r *setupRun) toolsSkipped() string {
	switch {
	case r.rights == agentpolicy.SetObserve && r.requested == "":
		return r.text.Get("setup.tools_observe")
	case r.state.Tools == dockerAnswerNo:
		return r.text.Get("setup.tools_declined")
	}
	return ""
}

// installDocker : Docker là, le plafond des journaux se juge ; Docker absent,
// le plafond s'écrit d'abord (le démon le lit à son premier démarrage), puis
// le dépôt de Docker et ses paquets.
func (r *setupRun) installDocker(context.Context) (step.State, string, error) {
	dockerMissing, _ := r.toolsMissing()
	if !dockerMissing {
		return r.checkDaemonConfig()
	}
	if skipped := r.toolsSkipped(); skipped != "" {
		return step.StateSkipped, skipped, nil
	}
	if _, err := r.writeDaemonConfig(); err != nil {
		return "", "", err
	}
	if err := r.addDockerRepository(); err != nil {
		return "", "", err
	}
	if err := r.system.InstallPackages(dockerPackages(r.system.Release())); err != nil {
		return "", "", &stepFailure{reason: r.text.Format("setup.docker_failed", err.Error()), todo: r.text.Get("setup.failed_todo")}
	}
	if !r.system.Exists(machine.DockerBinary) {
		return "", "", &stepFailure{reason: r.text.Format("setup.docker_failed", machine.DockerBinary), todo: r.text.Get("setup.failed_todo")}
	}
	return step.StateDone, dockerVersionShown(), nil
}

// checkDaemonConfig juge le plafond des journaux d'un Docker déjà là :
// daemon.json absent, il s'écrit ; présent, il ne se touche pas, et la coche
// jaune dit la ligne à ajouter s'il n'a pas de plafond.
func (r *setupRun) checkDaemonConfig() (step.State, string, error) {
	written, err := r.writeDaemonConfig()
	if err != nil {
		return "", "", err
	}
	if written {
		return step.StateDone, r.text.Get("setup.docker_log_limit_written"), nil
	}
	content, err := os.ReadFile(r.paths.dockerConfig)
	if err != nil {
		return "", "", err
	}
	if !limitsLogs(content) {
		return step.StateWarned, r.text.Format("setup.docker_log_limit_missing", r.paths.dockerConfig, daemonLogLimitLine()), nil
	}
	return step.StateDone, r.text.Get("setup.already_done"), nil
}

// writeDaemonConfig écrit daemon.json s'il n'existe pas, par O_EXCL : un
// fichier présent, même apparu entre-temps, n'est jamais réécrit (R-B1-15).
// Rend vrai s'il l'a écrit.
func (r *setupRun) writeDaemonConfig() (bool, error) {
	if err := os.MkdirAll(filepath.Dir(r.paths.dockerConfig), systemDirMode); err != nil {
		return false, err
	}
	file, err := os.OpenFile(r.paths.dockerConfig, os.O_WRONLY|os.O_CREATE|os.O_EXCL, systemFileMode) // #nosec G304 -- chemin de setup.
	if errors.Is(err, fs.ErrExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	content, err := json.MarshalIndent(daemonLogLimit, "", "  ")
	if err != nil {
		_ = file.Close()
		return false, err
	}
	_, writeErr := file.Write(append(content, '\n'))
	return true, errors.Join(writeErr, file.Sync(), file.Close())
}

// limitsLogs : le pilote local (plafonné de lui-même), ou un max-size posé.
func limitsLogs(content []byte) bool {
	var config struct {
		LogDriver string            `json:"log-driver"`
		LogOpts   map[string]string `json:"log-opts"`
	}
	if err := json.Unmarshal(content, &config); err != nil {
		return false
	}
	return config.LogDriver == "local" || config.LogOpts["max-size"] != ""
}

// daemonLogLimitLine est ce qu'il faut ajouter à un daemon.json sans plafond.
func daemonLogLimitLine() string {
	content, _ := json.Marshal(daemonLogLimit)
	return strings.Trim(string(content), "{}")
}

// addDockerRepository pose la clé du dépôt de Docker, téléchargée et
// comparée à l'empreinte de brand, puis la source APT qui la nomme.
func (r *setupRun) addDockerRepository() error {
	release := r.system.Release()
	key, err := r.system.Download(brand.DockerRepositoryURL+"/"+release.ID+"/gpg", maxKeyBytes)
	if err != nil {
		return &stepFailure{reason: r.text.Format("setup.download_failed", err.Error()), todo: r.text.Get("setup.failed_todo")}
	}
	fingerprints, err := pgpkey.PrimaryFingerprints(key)
	if err != nil || !slices.Equal(fingerprints, []string{brand.DockerKeyFingerprint}) {
		return &stepFailure{reason: r.text.Format("setup.docker_key_refused", brand.DockerKeyFingerprint), todo: r.text.Get("setup.failed_todo")}
	}
	if err := writeSystemFile(r.paths.dockerKeyring, key, systemFileMode); err != nil {
		return err
	}
	source := fmt.Sprintf("deb [arch=%s signed-by=%s] %s/%s %s stable\n",
		runtime.GOARCH, r.paths.dockerKeyring, brand.DockerRepositoryURL, release.ID, release.Codename)
	return writeSystemFile(r.paths.dockerSource, []byte(source), systemFileMode)
}

// dockerPackages : les paquets de Docker aux versions de brand, avec le
// suffixe que le dépôt donne à ce système (« ~debian.12~bookworm »).
func dockerPackages(release hostinfo.Release) []string {
	suffix := "~" + release.ID + "." + release.VersionID + "~" + release.Codename
	return []string{
		"docker-ce=" + brand.DockerVersion + suffix,
		"docker-ce-cli=" + brand.DockerVersion + suffix,
		"containerd.io=" + brand.ContainerdVersion + suffix,
		"docker-compose-plugin=" + brand.DockerComposeVersion + suffix,
	}
}

// dockerVersionShown : « 29.10.0 », sans l'époque ni la révision du paquet.
func dockerVersionShown() string {
	version := strings.TrimPrefix(brand.DockerVersion, "5:")
	version, _, _ = strings.Cut(version, "-")
	return version
}

// installRestic pose le binaire officiel de restic : l'archive téléchargée,
// sa somme comparée à celle de brand, décompressée, puis écrite d'un coup.
func (r *setupRun) installRestic(context.Context) (step.State, string, error) {
	if _, resticMissing := r.toolsMissing(); !resticMissing {
		return step.StateDone, r.text.Get("setup.already_done"), nil
	}
	if skipped := r.toolsSkipped(); skipped != "" {
		return step.StateSkipped, skipped, nil
	}
	sums := r.resticSums
	if sums == nil {
		sums = brand.ResticArchiveSums
	}
	sum, known := sums[runtime.GOARCH]
	if !known {
		return "", "", &stepFailure{reason: r.text.Format("setup.restic_no_build", runtime.GOARCH), todo: r.text.Get("setup.failed_todo")}
	}
	name := "restic_" + brand.ResticVersion + "_linux_" + runtime.GOARCH + ".bz2"
	archive, err := r.system.Download(brand.ResticReleaseURL+"/v"+brand.ResticVersion+"/"+name, maxResticArchive)
	if err != nil {
		return "", "", &stepFailure{reason: r.text.Format("setup.download_failed", err.Error()), todo: r.text.Get("setup.failed_todo")}
	}
	digest := sha256.Sum256(archive)
	if hex.EncodeToString(digest[:]) != sum {
		return "", "", &stepFailure{reason: r.text.Format("setup.restic_sum_refused", name), todo: r.text.Get("setup.failed_todo")}
	}
	binary, err := fsx.ReadLimited(bzip2.NewReader(bytes.NewReader(archive)), maxResticBinary)
	if err != nil {
		return "", "", &stepFailure{reason: r.text.Format("setup.restic_sum_refused", name), todo: r.text.Get("setup.failed_todo")}
	}
	if err := writeSystemFile(r.paths.resticBinary, binary, binaryMode); err != nil {
		return "", "", err
	}
	return step.StateDone, brand.ResticVersion, nil
}

// writeSystemFile écrit un fichier de root d'un coup, son dossier créé s'il
// manque.
func writeSystemFile(path string, content []byte, mode fs.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), systemDirMode); err != nil {
		return err
	}
	dir, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return fsx.WriteAtomic(dir, filepath.Base(path), content, mode)
}

func (hostSetupSystem) Release() hostinfo.Release {
	return hostinfo.OSRelease()
}

// Download lit une adresse HTTPS, au plus limit octets ; le magasin de
// certificats du système juge le serveur.
func (hostSetupSystem) Download(url string, limit int64) ([]byte, error) {
	client := http.Client{Timeout: downloadTimeout}
	response, err := client.Get(url) // #nosec G107 -- une adresse de brand.
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", url, response.Status)
	}
	return fsx.ReadLimited(response.Body, limit)
}

// InstallPackages relit les sources d'APT puis pose ces paquets, sans
// question ni recommandation.
func (hostSetupSystem) InstallPackages(packages []string) error {
	for _, args := range [][]string{
		{"update"},
		append([]string{"install", "-y", "--no-install-recommends"}, packages...),
	} {
		command := exec.Command("apt-get", args...) // #nosec G204 -- des paquets de brand, aux versions de brand.
		command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "DEBIAN_FRONTEND=noninteractive"}
		output, err := command.CombinedOutput()
		if err != nil {
			return fmt.Errorf("apt-get %s: %w: %s", args[0], err, lastLine(string(output)))
		}
	}
	return nil
}
