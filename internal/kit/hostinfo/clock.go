package hostinfo

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Le temps écoulé depuis le démarrage, que l'horloge affichée ne déplace
// pas : NTP peut la reculer, pas lui.
const uptimePath = "/proc/uptime"

// MonotonicClock rend le démarrage en cours et le temps écoulé depuis : de
// quoi mesurer une durée qu'un recul de l'horloge ne prolonge pas. Vide et
// zéro si l'un des deux ne se lit pas.
func MonotonicClock() (boot string, uptime time.Duration) {
	return readMonotonicClock(bootIDPath, uptimePath)
}

func readMonotonicClock(bootPath, uptimePath string) (string, time.Duration) {
	boot := readFirstIdentifier([]string{bootPath})
	content, err := os.ReadFile(uptimePath) // #nosec G304 -- chemin constant.
	if boot == "" || err != nil {
		return "", 0
	}
	fields := strings.Fields(string(content))
	if len(fields) == 0 {
		return "", 0
	}
	seconds, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || seconds < 0 {
		return "", 0
	}
	return boot, time.Duration(seconds * float64(time.Second))
}
