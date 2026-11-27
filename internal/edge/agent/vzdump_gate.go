package agent

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"os/user"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ldesfontaine/kagu/internal/fact/machine"
	"github.com/ldesfontaine/kagu/internal/kit/brand"
	"github.com/ldesfontaine/kagu/internal/kit/peercred"
	"github.com/ldesfontaine/kagu/internal/wire/agentwire"
)

// La porte vzdump (décision de Lucas du 26/11/2026) : une connexion, une
// demande « <invité> <compression> », jugée sur sa forme avant que rien ne se
// lance ; puis vzdump, aux options fixées par machine.VzdumpArguments. La
// réponse va par trames : un en-tête (« ok » ou « refused »), les données
// de vzdump, puis une fin qui porte son code de sortie, le type de l'invité
// et la fin de sa sortie d'erreur. Le serveur tourne en root, lancé par
// systemd (kagu-vzdump@.service) ; le client, sous le compte de l'agent.

// Les trames : une lettre, la longueur sur quatre octets, le contenu.
const (
	gateFrameHeader byte = 'h'
	gateFrameData   byte = 'd'
	gateFrameEnd    byte = 'e'
	gateHeaderLen        = 5
	gateAccepted         = "ok"
	gateRefused          = "refused"
	// Une demande tient sur une ligne courte ; une trame, en 64 Kio.
	maxGateRequestBytes = 64
	maxGateFrameBytes   = 64 << 10
	// La demande arrive aussitôt la connexion ouverte.
	gateRequestTimeout = 10 * time.Second
	// Le code d'un vzdump qui n'est pas sorti de lui-même (tué, pas lancé).
	gateNoExitCode = -1
)

var (
	// vzdumpGuest : un numéro d'invité, des chiffres seuls, jamais une option.
	vzdumpGuest = regexp.MustCompile(`^\d{1,9}$`)
	// La ligne où vzdump nomme le type de l'invité qu'il sauvegarde.
	vzdumpGuestLine = regexp.MustCompile(`Starting Backup of VM \d+ \((qemu|lxc)\)`)

	errGateRequest = errors.New("vzdump gate: malformed request")
	errGatePeer    = errors.New("vzdump gate: peer is neither root nor the agent account")
	errGateFrame   = errors.New("vzdump gate: malformed frame")
)

// gateEnd est la trame de fin : ce que vzdump a donné.
type gateEnd struct {
	Code   int                    `json:"code"`
	Guest  string                 `json:"guest"`
	Stderr []agentwire.OutputLine `json:"stderr"`
}

// gateRequest est une demande jugée.
type gateRequest struct {
	guest    string
	compress string
}

// parseGateRequest juge la ligne : deux mots, un numéro d'invité et une
// compression de la liste fermée. Tout le reste est refusé.
func parseGateRequest(line string) (gateRequest, error) {
	words := strings.Split(line, " ")
	if len(words) != 2 || !vzdumpGuest.MatchString(words[0]) || !slices.Contains(machine.VzdumpGateCompressions(), words[1]) {
		return gateRequest{}, errGateRequest
	}
	return gateRequest{guest: words[0], compress: words[1]}, nil
}

// vzdumpLaunch lance vzdump avec ces arguments et rend son code de sortie ;
// un test donne le sien.
type vzdumpLaunch func(ctx context.Context, args []string, stdout, stderr io.Writer) (int, error)

// ServeVzdumpGate sert la connexion que systemd passe à kagu-vzdump@.service :
// le pair doit être root ou le compte de l'agent (la socket est aussi ouverte
// au groupe, dont le serveur est membre sur la machine Kagu).
func ServeVzdumpGate(ctx context.Context, conn net.Conn) error {
	uid, err := peercred.Peer(conn)
	if err != nil {
		return err
	}
	return serveVzdumpGate(ctx, conn, isGatePeer(uid), runVzdumpAt(machine.VzdumpBinary))
}

// isGatePeer : root, ou le compte de l'agent.
func isGatePeer(uid uint32) bool {
	if uid == 0 {
		return true
	}
	account, err := user.Lookup(brand.AgentAccount)
	return err == nil && account.Uid == strconv.FormatUint(uint64(uid), 10)
}

func serveVzdumpGate(ctx context.Context, conn net.Conn, allowedPeer bool, launch vzdumpLaunch) error {
	_ = conn.SetReadDeadline(time.Now().Add(gateRequestTimeout))
	line, err := readGateRequest(conn)
	_ = conn.SetReadDeadline(time.Time{})
	if err == nil && !allowedPeer {
		err = errGatePeer
	}
	var request gateRequest
	if err == nil {
		request, err = parseGateRequest(line)
	}
	if err != nil {
		_ = writeGateFrame(conn, gateFrameHeader, []byte(gateRefused))
		return err
	}
	if err := writeGateFrame(conn, gateFrameHeader, []byte(gateAccepted)); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// L'agent n'écrit plus rien après la demande : une lecture qui finit dit
	// qu'il est parti (ordre arrêté), et vzdump s'arrête au lieu de tourner
	// pour personne. Une écriture qui échoue aussi.
	go func() {
		_, _ = io.Copy(io.Discard, conn)
		cancel()
	}()
	data := &gateDataWriter{conn: conn, failed: cancel}
	tail := newLineTail(producerTailLines)
	guest := &guestKindWriter{}
	code, runErr := launch(ctx, machine.VzdumpArguments(request.guest, request.compress), data, io.MultiWriter(tail.writer("stderr"), guest))
	tail.flush()
	if data.err != nil {
		return data.err
	}
	end := gateEnd{Code: code, Guest: guest.kind(), Stderr: tail.lines()}
	if runErr != nil {
		end.Stderr = append(end.Stderr, agentwire.OutputLine{Stream: "stderr", Line: cleanLine(runErr.Error())})
	}
	content, err := json.Marshal(end)
	if err != nil {
		return err
	}
	return writeGateFrame(conn, gateFrameEnd, content)
}

// readGateRequest lit la ligne de la demande, octet par octet : rien après
// elle ne se lit, et une ligne trop longue est refusée.
func readGateRequest(conn io.Reader) (string, error) {
	var line []byte
	one := make([]byte, 1)
	for len(line) <= maxGateRequestBytes {
		if _, err := io.ReadFull(conn, one); err != nil {
			return "", err
		}
		if one[0] == '\n' {
			return string(line), nil
		}
		line = append(line, one[0])
	}
	return "", errGateRequest
}

// runVzdumpAt lance vzdump (machine.VzdumpBinary ; un test donne le sien),
// un environnement remplacé ; l'arrêt demande poliment, puis tue.
func runVzdumpAt(binary string) vzdumpLaunch {
	return func(ctx context.Context, args []string, stdout, stderr io.Writer) (int, error) {
		command := exec.CommandContext(ctx, binary, args...) // #nosec G204 -- bounded: une constante, l'invité et la compression jugés par parseGateRequest.
		command.Env = producerEnvironment
		command.Stdout, command.Stderr = stdout, stderr
		command.Cancel = func() error { return command.Process.Signal(syscall.SIGTERM) }
		command.WaitDelay = producerStopDelay
		err := command.Run()
		var exited *exec.ExitError
		if errors.As(err, &exited) && exited.Exited() {
			return exited.ExitCode(), nil
		}
		if err != nil {
			return gateNoExitCode, err
		}
		return 0, nil
	}
}

// gateDataWriter met la sortie de vzdump en trames de données ; la première
// écriture qui échoue arrête vzdump (failed).
type gateDataWriter struct {
	conn   io.Writer
	failed func()
	err    error
}

func (w *gateDataWriter) Write(data []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	for written := 0; written < len(data); {
		chunk := data[written:min(len(data), written+maxGateFrameBytes)]
		if err := writeGateFrame(w.conn, gateFrameData, chunk); err != nil {
			w.err = err
			w.failed()
			return written, err
		}
		written += len(chunk)
	}
	return len(data), nil
}

func writeGateFrame(conn io.Writer, kind byte, payload []byte) error {
	header := make([]byte, gateHeaderLen)
	header[0] = kind
	binary.BigEndian.PutUint32(header[1:], uint32(len(payload))) // #nosec G115 -- une trame fait au plus maxGateFrameBytes.
	if _, err := conn.Write(append(header, payload...)); err != nil {
		return fmt.Errorf("vzdump gate: write: %w", err)
	}
	return nil
}

// readGateFrame lit une trame ; une longueur hors borne est refusée.
func readGateFrame(conn *bufio.Reader) (byte, []byte, error) {
	header := make([]byte, gateHeaderLen)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, nil, err
	}
	size := binary.BigEndian.Uint32(header[1:])
	if size > maxGateFrameBytes {
		return 0, nil, errGateFrame
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return 0, nil, err
	}
	return header[0], payload, nil
}

// vzdumpGateClient demande vzdump à la porte, sous le compte de l'agent.
type vzdumpGateClient struct {
	socket string
}

// dump écrit le flux de vzdump dans out et rend la trame de fin. Une porte
// absente se dit gate_missing, une porte qui refuse le compte ou la demande
// gate_denied ; rien n'a alors été lancé.
func (c vzdumpGateClient) dump(ctx context.Context, guest, compress string, out io.Writer) (gateEnd, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", c.socket)
	if err != nil {
		return gateEnd{}, refuseWith(gateDialReason(err), err)
	}
	defer conn.Close()
	// Un ordre arrêté ferme la connexion : la porte arrête vzdump.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if _, err := conn.Write([]byte(guest + " " + compress + "\n")); err != nil {
		return gateEnd{}, err
	}
	reader := bufio.NewReader(conn)
	kind, payload, err := readGateFrame(reader)
	if err != nil {
		return gateEnd{}, err
	}
	if kind != gateFrameHeader || string(payload) != gateAccepted {
		return gateEnd{}, refuseWith(agentwire.ReasonGateDenied, errors.New("the vzdump gate refused the request"))
	}
	return readGateStream(ctx, reader, out)
}

// StreamVzdump est « agent vzdump-stream <invité> », que restic lance pour
// un invité (--stdin-from-command) : le flux de vzdump sans compression sur
// out, la fin de sa sortie d'erreur sur errOut. Une erreur si vzdump ne sort
// pas en 0 : restic ne crée alors aucun instantané.
func StreamVzdump(ctx context.Context, guest string, out, errOut io.Writer) error {
	if !vzdumpGuest.MatchString(guest) {
		return errGateRequest
	}
	end, err := vzdumpGateClient{socket: brand.VzdumpGateSocket}.dump(ctx, guest, machine.VzdumpCompressNone, out)
	for _, line := range end.Stderr {
		fmt.Fprintln(errOut, line.Line)
	}
	if err != nil {
		return err
	}
	if end.Code != 0 {
		return fmt.Errorf("vzdump exited with code %d", end.Code)
	}
	return nil
}

// readGateStream recopie les données jusqu'à la trame de fin.
func readGateStream(ctx context.Context, reader *bufio.Reader, out io.Writer) (gateEnd, error) {
	for {
		kind, payload, err := readGateFrame(reader)
		if err != nil {
			if ctx.Err() != nil {
				return gateEnd{}, fmt.Errorf("vzdump: %w", ctx.Err())
			}
			return gateEnd{}, err
		}
		switch kind {
		case gateFrameData:
			if _, err := out.Write(payload); err != nil {
				return gateEnd{}, err
			}
		case gateFrameEnd:
			return decodeGateEnd(payload)
		default:
			return gateEnd{}, errGateFrame
		}
	}
}

// decodeGateEnd relit la fin : les lignes se nettoient encore ici, le type
// ne vaut que qemu ou lxc.
func decodeGateEnd(payload []byte) (gateEnd, error) {
	var end gateEnd
	if err := json.Unmarshal(payload, &end); err != nil {
		return gateEnd{}, errGateFrame
	}
	if end.Guest != guestLXC {
		end.Guest = guestQEMU
	}
	if len(end.Stderr) > producerTailLines {
		end.Stderr = end.Stderr[len(end.Stderr)-producerTailLines:]
	}
	for index := range end.Stderr {
		end.Stderr[index] = agentwire.OutputLine{Stream: "stderr", Line: cleanLine(end.Stderr[index].Line)}
	}
	return end, nil
}

// gateDialReason : une socket absente ou sans porte derrière manque, une
// socket que le compte n'ouvre pas refuse.
func gateDialReason(err error) string {
	if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
		return agentwire.ReasonGateDenied
	}
	return agentwire.ReasonGateMissing
}

// guestKindWriter lit la sortie d'erreur de vzdump ligne à ligne pour y trouver
// le type de l'invité. À défaut de la ligne qui le nomme, une machine
// virtuelle (qemu), sauf si une ligne parle de lxc : le type ne fait que
// nommer l'entrée du tar, le contenu ne change pas.
type guestKindWriter struct {
	line   []byte
	named  string
	sawLXC bool
}

func (g *guestKindWriter) Write(data []byte) (int, error) {
	for _, b := range data {
		if b == '\n' || b == '\r' {
			g.scan()
			continue
		}
		if len(g.line) < maxGuestLine {
			g.line = append(g.line, b)
		}
	}
	return len(data), nil
}

func (g *guestKindWriter) scan() {
	line := string(g.line)
	g.line = g.line[:0]
	if match := vzdumpGuestLine.FindStringSubmatch(line); match != nil && g.named == "" {
		g.named = match[1]
	}
	if strings.Contains(strings.ToLower(line), guestLXC) {
		g.sawLXC = true
	}
}

func (g *guestKindWriter) kind() string {
	g.scan()
	switch {
	case g.named != "":
		return g.named
	case g.sawLXC:
		return guestLXC
	}
	return guestQEMU
}
