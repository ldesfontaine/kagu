package shell

import "testing"

// Un mot simple reste tel quel ; tout autre texte devient une seule valeur
// entre apostrophes, que le shell ne lit pas.
func TestQuote_LeavesAWordAndQuotesTheRest(t *testing.T) {
	for value, want := range map[string]string{
		"https://github.com/x/releases/download": "https://github.com/x/releases/download",
		"/srv/mon appli":                         "'/srv/mon appli'",
		"":                                       "''",
		"$(reboot)":                              "'$(reboot)'",
		"it's":                                   `'it'\''s'`,
	} {
		if got := Quote(value); got != want {
			t.Errorf("Quote(%q) = %s, want %s", value, got, want)
		}
	}
}
