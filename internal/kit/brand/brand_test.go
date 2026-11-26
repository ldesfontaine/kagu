package brand

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

// Chaque valeur est écrite en littéral : renommer le produit doit casser ce
// test, pour que l'auteur voie ce qui bouge avec lui (chemins, protocole).
func TestValues_AreFrozen(t *testing.T) {
	for name, pair := range map[string][2]string{
		"ProductName":                {ProductName, "Kagu"},
		"ID":                         {ID, "kagu"},
		"ConfigDir":                  {ConfigDir, "/etc/kagu"},
		"ConfigPath":                 {ConfigPath, "/etc/kagu/config.toml"},
		"StateDir":                   {StateDir, "/var/lib/kagu"},
		"SetupStateFile":             {SetupStateFile, "/etc/kagu/setup.json"},
		"SetupLockPath":              {SetupLockPath, "/run/kagu-setup.lock"},
		"ServerAccount":              {ServerAccount, "kagu"},
		"InstalledBinary":            {InstalledBinary, "/usr/local/bin/kagu"},
		"AgentDatabaseBackupsDir":    {AgentDatabaseBackupsDir, "/var/lib/kagu-agent/database-backups"},
		"AgentStateDir":              {AgentStateDir, "/var/lib/kagu-agent"},
		"AgentCurrentPath":           {AgentCurrentPath, "/var/lib/kagu-agent/bin/current"},
		"AgentProduceDir":            {AgentProduceDir, "produce"},
		"VzdumpWrapperPath":          {VzdumpWrapperPath, "/usr/local/sbin/kagu-vzdump"},
		"AgentAccount":               {AgentAccount, "kagu-agent"},
		"RuntimeDir":                 {RuntimeDir, "/run/kagu"},
		"AgentSocketPath":            {AgentSocketPath, "/run/kagu/agent.sock"},
		"DatabaseFile":               {DatabaseFile, "kagu.db"},
		"SecretKeyFile":              {SecretKeyFile, "secret.key"},
		"ServerKeyFile":              {ServerKeyFile, "server.key"},
		"SecretKeyIDDomain":          {SecretKeyIDDomain, "kagu-key-id\x00"},
		"LocalMachineName":           {LocalMachineName, "kagu"},
		"MatrixTransactionPrefix":    {MatrixTransactionPrefix, "kagu-"},
		"OutgoingDir":                {OutgoingDir, "outgoing"},
		"BackupKeyFilePrefix":        {BackupKeyFilePrefix, "kagu-key-"},
		"LabelPrefix":                {LabelPrefix, "kagu."},
		"WorkspaceMarker":            {WorkspaceMarker, ".kagu"},
		"ServerUnit":                 {ServerUnit, "kagu.service"},
		"AgentUnit":                  {AgentUnit, "kagu-agent.service"},
		"InstallDocURL":              {InstallDocURL, "https://github.com/ldesfontaine/kagu/blob/dev/docs/installation.md"},
		"ReleaseBaseURL":             {ReleaseBaseURL, "https://github.com/ldesfontaine/kagu/releases/download"},
		"SetupReleaseDir":            {SetupReleaseDir, "/var/lib/kagu-setup/release"},
		"AgentIdentityFile":          {AgentIdentityFile, "identity.json"},
		"Command":                    {Command, "kagu"},
		"UserAgent":                  {UserAgent, "Kagu"},
		"RegistryUserAgent":          {RegistryUserAgent, "Kagu-agent"},
		"LifecycleUserAgent":         {LifecycleUserAgent, "kagu"},
		"HeaderPrefix":               {HeaderPrefix, "Kagu-"},
		"WebhookEventHeader":         {WebhookEventHeader, "Kagu-Event"},
		"WebhookSignatureHeader":     {WebhookSignatureHeader, "Kagu-Signature"},
		"ProxySecretHeader":          {ProxySecretHeader, "X-Kagu-Proxy-Secret"},
		"OrderSignatureDomain":       {OrderSignatureDomain, "kagu-order/v2\x00"},
		"LegacyOrderSignatureDomain": {LegacyOrderSignatureDomain, "kagu-order/v1\x00"},
		"AgentProofDomain":           {AgentProofDomain, "kagu-agent-proof/v2\x00"},
		"TokenPrefix":                {TokenPrefix, "kg"},
		"EnrollmentTokenScheme":      {EnrollmentTokenScheme, "kg_"},
		"APITokenScheme":             {APITokenScheme, "kgk_"},
		"HostFingerprintPrefix":      {HostFingerprintPrefix, "kagu-host:"},
		"SnapshotPrefix":             {SnapshotPrefix, "kg-"},
		"AgentGuardDir":              {AgentGuardDir, "/usr/local/lib/kagu-agent"},
		"AgentGuardPath":             {AgentGuardPath, "/usr/local/lib/kagu-agent/kagu-guard"},
		"AgentGuardEnv":              {AgentGuardEnv, "KAGU_AGENT_GUARD"},
		"AgentPolicyDir":             {AgentPolicyDir, "/etc/kagu-agent"},
		"AgentBinaryPrefix":          {AgentBinaryPrefix, "kagu-"},
		"ReleaseBinaryPrefix":        {ReleaseBinaryPrefix, "kagu-linux-"},
		"ReleaseSignatureComment":    {ReleaseSignatureComment, "signature from kagu release key"},
		"SessionCookie":              {SessionCookie, "__Host-kagu_session"},
		"LocalSessionCookie":         {LocalSessionCookie, "kagu_session_local"},
	} {
		if pair[0] != pair[1] {
			t.Errorf("%s = %q, want %q", name, pair[0], pair[1])
		}
		// Ces valeurs entrent dans des formats et des gabarits : un « % » ou
		// une accolade y serait lu comme un verbe ou un marqueur.
		if strings.ContainsAny(pair[0], "%{}") {
			t.Errorf("%s = %q contains %%, { or }", name, pair[0])
		}
	}
}

// Les racines du nom, seules écrites en littéral : toute autre valeur de ce
// paquet qui porte le nom le tire d'elles, pour qu'un changement de nom se
// fasse en une ligne.
var nameRoots = map[string]bool{"ProductName": true, "ID": true, "TokenPrefix": true}

func TestBrand_EveryNameDerivesFromID(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "brand.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	for _, declaration := range file.Decls {
		general, ok := declaration.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range general.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for index, name := range value.Names {
				if nameRoots[name.Name] || index >= len(value.Values) {
					continue
				}
				checkDerived(t, name.Name, value.Values[index])
			}
		}
	}
}

func checkDerived(t *testing.T, name string, expression ast.Expr) {
	t.Helper()
	ast.Inspect(expression, func(node ast.Node) bool {
		literal, ok := node.(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			return true
		}
		value, err := strconv.Unquote(literal.Value)
		if err != nil {
			t.Errorf("%s: %s: %v", name, literal.Value, err)
			return true
		}
		if carriesTheName(value) {
			t.Errorf("%s: literal %q names the product: build it from ID, ProductName or TokenPrefix", name, value)
		}
		return true
	})
}

// carriesTheName juge un littéral : le nom, l'ancien compris, ou le préfixe des
// jetons écrit à la main.
func carriesTheName(value string) bool {
	lower := strings.ToLower(value)
	return strings.Contains(lower, strings.ToLower(ID)) || strings.Contains(lower, strings.ToLower(ProductName)) ||
		strings.Contains(lower, "opencloud") || strings.HasPrefix(value, TokenPrefix)
}

func TestCarriesTheName_SeesTheNameTheOldNameAndTheTokenPrefix(t *testing.T) {
	for _, value := range []string{"/etc/" + ID, "X-" + ProductName + "-Proxy-Secret", "OpenCloud-", TokenPrefix + "_"} {
		if !carriesTheName(value) {
			t.Errorf("%q is not seen", value)
		}
	}
	for _, value := range []string{"/srv/workspace", "secret.key", "SHA256SUMS"} {
		if carriesTheName(value) {
			t.Errorf("%q is seen", value)
		}
	}
}
