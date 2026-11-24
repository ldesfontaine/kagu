package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ldesfontaine/kagu/internal/fact/auth"
)

func TestParse_EmptyFile_UsesDefaults(t *testing.T) {
	cfg, warnings, err := Parse(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != Default().Listen || cfg.StateDir != Default().StateDir || cfg.PublicURL != "" || len(cfg.TrustedProxies) != 0 {
		t.Fatalf("got %+v, want defaults", cfg)
	}
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings %v", warnings)
	}
}

func TestParse_KnownKeys_AreApplied(t *testing.T) {
	cfg, _, err := Parse([]byte("listen = \"0.0.0.0:9090\"\nstate_dir = \"/tmp/oc\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "0.0.0.0:9090" || cfg.StateDir != "/tmp/oc" {
		t.Fatalf("got %+v", cfg)
	}
}

func TestParse_UnknownKey_WarnsAndKeepsTheRest(t *testing.T) {
	cfg, warnings, err := Parse([]byte("listen = \"127.0.0.1:1\"\ncolour = \"blue\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "127.0.0.1:1" {
		t.Fatalf("known key lost: %+v", cfg)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "colour") {
		t.Fatalf("want one warning naming colour, got %v", warnings)
	}
}

func TestParse_BadListen_IsRejected(t *testing.T) {
	if _, _, err := Parse([]byte("listen = \"not an address\"\n")); err == nil {
		t.Fatal("want a validation error")
	}
}

func TestParse_BadToml_IsRejected(t *testing.T) {
	if _, _, err := Parse([]byte("listen = \n")); err == nil {
		t.Fatal("want a syntax error")
	}
}

func TestLoad_ReadsTheFileAtThePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte("listen = \"127.0.0.1:7\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "127.0.0.1:7" {
		t.Fatalf("got %+v", cfg)
	}
	if _, _, err := Load(filepath.Join(t.TempDir(), "absent.toml")); err == nil {
		t.Fatal("want an error for a missing file")
	}
}

func TestParse_PublicURLAndProxies_AreValidated(t *testing.T) {
	cfg, _, err := Parse([]byte("public_url = \"https://oc.example.fr\"\ntrusted_proxies = [\"127.0.0.1/32\", \"10.0.0.0/8\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PublicURL != "https://oc.example.fr" || len(cfg.TrustedPrefixes()) != 2 {
		t.Fatalf("got %+v", cfg)
	}
	if _, _, err := Parse([]byte("public_url = \"oc.example.fr\"\n")); err == nil {
		t.Error("public_url without scheme accepted")
	}
	if _, _, err := Parse([]byte("trusted_proxies = [\"not-a-cidr\"]\n")); err == nil {
		t.Error("bad cidr accepted")
	}
}

// mcp_url est l'adresse de mcp-maison : vide, openCloud ne le cherche pas ;
// sinon une adresse http(s), sans quoi le démarrage la refuse.
func TestParse_MCPURL_IsEmptyByDefaultAndMustBeAnHTTPAddress(t *testing.T) {
	cfg, _, err := Parse([]byte(""))
	if err != nil || cfg.MCPURL != "" {
		t.Fatalf("default: %q %v", cfg.MCPURL, err)
	}
	cfg, _, err = Parse([]byte("mcp_url = \"http://127.0.0.1:3000\"\n"))
	if err != nil || cfg.MCPURL != "http://127.0.0.1:3000" {
		t.Fatalf("set: %q %v", cfg.MCPURL, err)
	}
	for _, bad := range []string{"127.0.0.1:3000", "ftp://127.0.0.1:3000", "mcp-maison"} {
		if _, _, err := Parse([]byte("mcp_url = \"" + bad + "\"\n")); err == nil {
			t.Errorf("mcp_url %q accepted", bad)
		}
	}
}

// Un mandataire déclaré par un sous-réseau est cru pour chacun de ses pairs :
// le démarrage le dit, sans refuser la configuration.
func TestParse_WideTrustedProxy_Warns(t *testing.T) {
	_, warnings, err := Parse([]byte("trusted_proxies = [\"127.0.0.1/32\", \"::1/128\", \"172.18.0.0/16\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "172.18.0.0/16") {
		t.Fatalf("want one warning naming 172.18.0.0/16, got %v", warnings)
	}
}

func TestParse_ForwardSecretFile_IsAPathNotTheSecret(t *testing.T) {
	cfg, warnings, err := Parse([]byte("forward_secret_file = \"/etc/opencloud/forward.secret\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ForwardSecretFile != "/etc/opencloud/forward.secret" || len(warnings) != 0 {
		t.Fatalf("got %+v, warnings %v", cfg, warnings)
	}
	if Default().ForwardSecretFile != "" {
		t.Fatal("no secret by default")
	}
}

func TestParse_ForwardUsers_AbsentOrEmptyMeansEveryone(t *testing.T) {
	for _, content := range []string{"", "forward_users = []\n"} {
		cfg, _, err := Parse([]byte(content))
		if err != nil {
			t.Fatalf("%q: %v", content, err)
		}
		if len(cfg.ForwardUsers) != 0 {
			t.Fatalf("%q: got %v", content, cfg.ForwardUsers)
		}
	}
}

func TestParse_ForwardUsers_KeepsTheEntriesAsWritten(t *testing.T) {
	// Deux entrées qui ne diffèrent que par la casse sont deux identités.
	cfg, _, err := Parse([]byte("forward_users = [\"lucas\", \"Lucas\", \"léa@example.org\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(cfg.ForwardUsers, "|"); got != "lucas|Lucas|léa@example.org" {
		t.Fatalf("got %q", got)
	}
}

func TestParse_ForwardUsers_AFalseListStopsTheStart(t *testing.T) {
	cases := []struct{ name, entries string }{
		{"empty entry", `""`},
		{"empty entry next to a good one", `"lucas", ""`},
		{"leading space", `" lucas"`},
		{"trailing space", `"lucas "`},
		{"only spaces", `"   "`},
		{"trailing tab", `"lucas\t"`},
		{"no-break space at the edge", `"lucas\u00a0"`},
		{"newline inside", `"lu\ncas"`},
		{"NUL inside", `"lu\u0000cas"`},
		{"escape inside", `"lu\u001bcas"`},
		{"twice", `"lucas", "lucas"`},
		{"twice, apart", `"lucas", "lea", "lucas"`},
		{"too long", `"` + strings.Repeat("a", 65) + `"`},
		{"too long in characters, not bytes", `"` + strings.Repeat("é", 65) + `"`},
	}
	for _, tc := range cases {
		if _, _, err := Parse([]byte("forward_users = [" + tc.entries + "]\n")); err == nil {
			t.Errorf("%s: the list must be refused", tc.name)
		}
	}
}

func TestParse_ForwardUsers_TheLimitsAreInclusive(t *testing.T) {
	longest := strings.Repeat("é", 64)
	if _, _, err := Parse([]byte("forward_users = [\"" + longest + "\"]\n")); err != nil {
		t.Fatalf("64 characters: %v", err)
	}
	entries := func(count int) string {
		quoted := make([]string, count)
		for index := range quoted {
			quoted[index] = fmt.Sprintf("%q", fmt.Sprintf("user-%02d", index))
		}
		return "forward_users = [" + strings.Join(quoted, ", ") + "]\n"
	}
	if _, _, err := Parse([]byte(entries(64))); err != nil {
		t.Fatalf("64 entries: %v", err)
	}
	if _, _, err := Parse([]byte(entries(65))); err == nil {
		t.Fatal("65 entries must be refused")
	}
}

// Le message nomme l'entrée fautive, sans laisser un caractère de contrôle
// y passer tel quel.
func TestParse_ForwardUsers_TheErrorNamesTheEntryWithoutControlCharacters(t *testing.T) {
	_, _, err := Parse([]byte("forward_users = [\"lu\\ncas\"]\n"))
	if err == nil {
		t.Fatal("must be refused")
	}
	if strings.ContainsRune(err.Error(), '\n') || !strings.Contains(err.Error(), "forward_users") {
		t.Fatalf("got %q", err)
	}
}

func TestParse_ConnectionLimits_DefaultAndCustom(t *testing.T) {
	cfg, _, err := Parse(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MaxConnections != 1024 || cfg.MaxConnectionsPerSource != 64 || cfg.WriteTimeout() != 30*time.Second {
		t.Fatalf("got %+v, want 1024, 64 and 30s", cfg)
	}
	cfg, _, err = Parse([]byte("max_connections = 10\nmax_connections_per_source = 2\nwrite_timeout_seconds = 5\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MaxConnections != 10 || cfg.MaxConnectionsPerSource != 2 || cfg.WriteTimeout() != 5*time.Second {
		t.Fatalf("got %+v", cfg)
	}
}

func TestParse_ConnectionLimits_ABadValueStopsTheStart(t *testing.T) {
	for _, line := range []string{
		"max_connections = 0", "max_connections = -1",
		"max_connections_per_source = 0",
		"write_timeout_seconds = 0", "write_timeout_seconds = -30", "write_timeout_seconds = 86400",
	} {
		if _, _, err := Parse([]byte(line + "\n")); err == nil {
			t.Errorf("%q was accepted", line)
		}
	}
}

func TestParse_AccountLimits_DefaultAndCustom(t *testing.T) {
	cfg, _, err := Parse(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := cfg.AccountLimits(), auth.DefaultAccountLimits(); got != want {
		t.Fatalf("got %+v, want the defaults %+v", got, want)
	}
	custom := "totp_max_failures = 3\ntotp_lock_minutes = 60\npassword_failures_per_hour = 8\npassword_pace_seconds = 90\n"
	cfg, _, err = Parse([]byte(custom))
	if err != nil {
		t.Fatal(err)
	}
	want := auth.AccountLimits{TOTPFailures: 3, TOTPLock: time.Hour, PasswordFailuresPerHour: 8, PasswordPace: 90 * time.Second}
	if got := cfg.AccountLimits(); got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

// Le seuil des codes faux ne dépasse pas ce que la colonne totp_failures tient.
func TestParse_AccountLimits_ABadValueStopsTheStart(t *testing.T) {
	if _, _, err := Parse([]byte(fmt.Sprintf("totp_max_failures = %d\n", auth.MaxTOTPFailures))); err != nil {
		t.Fatalf("the column's own ceiling must be accepted: %v", err)
	}
	for _, line := range []string{
		fmt.Sprintf("totp_max_failures = %d", auth.MaxTOTPFailures+1), "totp_max_failures = 0",
		"totp_lock_minutes = 0", "totp_lock_minutes = 1441",
		"password_failures_per_hour = 0", "password_pace_seconds = 0", "password_pace_seconds = 3601",
	} {
		if _, _, err := Parse([]byte(line + "\n")); err == nil {
			t.Errorf("%q was accepted", line)
		}
	}
}

// R-CNX-5 : sans mandataire HTTPS déclaré, serve n'écoute que sur la boucle
// locale. setup --domain (listen sur docker0) et une installation derrière
// son mandataire démarrent ; public_url en http:// ne déclare pas d'HTTPS.
func TestR_CNX_5_ServeListensOnLoopbackWithoutAnHTTPSProxy(t *testing.T) {
	const proxied = "public_url = \"https://kagu.example.org\"\ntrusted_proxies = [\"172.30.0.2/32\"]\n"
	cases := []struct {
		name    string
		content string
		starts  bool
	}{
		{"every IPv4 address", "listen = \"0.0.0.0:8080\"\n", false},
		{"a public address", "listen = \"192.0.2.1:8080\"\n", false},
		{"every IPv6 address", "listen = \"[::]:8080\"\n", false},
		{"every address, no host", "listen = \":8080\"\n", false},
		{"a host name", "listen = \"kagu.example.org:8080\"\n", false},
		{"docker0 without a proxy", "listen = \"172.17.0.1:8080\"\n", false},
		{"https but no proxy", "listen = \"0.0.0.0:8080\"\npublic_url = \"https://kagu.example.org\"\n", false},
		{"a proxy over http", "listen = \"172.17.0.1:8080\"\npublic_url = \"http://kagu.example.org\"\ntrusted_proxies = [\"172.30.0.2/32\"]\n", false},
		{"the default", "", true},
		{"IPv4 loopback", "listen = \"127.0.0.1:8080\"\n", true},
		{"IPv6 loopback", "listen = \"[::1]:8080\"\n", true},
		{"docker0 behind its HTTPS proxy", "listen = \"172.17.0.1:8080\"\n" + proxied, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg, _, err := Parse([]byte(c.content))
			if err != nil {
				t.Fatal(err)
			}
			if refused := cfg.ServesClearHTTPBeyondLoopback(); refused == c.starts {
				t.Fatalf("listen %q refused: %v, want %v", cfg.Listen, refused, !c.starts)
			}
		})
	}
}

// listen admet une IPv6 entre crochets ; un port faux ou absent reste refusé.
func TestParse_ListenTakesABracketedIPv6(t *testing.T) {
	for _, listen := range []string{"[::1]:8080", "[::]:8080", "127.0.0.1:8080", "kagu.example.org:8080"} {
		if _, _, err := Parse([]byte("listen = \"" + listen + "\"\n")); err != nil {
			t.Errorf("%s refused: %v", listen, err)
		}
	}
	for _, listen := range []string{"8080", "[::1]", "[::1]:99999", "[::1]:port", "127.0.0.1:0x50", "::1:8080"} {
		if _, _, err := Parse([]byte("listen = \"" + listen + "\"\n")); err == nil {
			t.Errorf("%s accepted", listen)
		}
	}
}
