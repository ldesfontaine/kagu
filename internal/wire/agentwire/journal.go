package agentwire

import (
	"encoding/json"
	"strconv"
	"unicode"
	"unicode/utf8"
)

// Une valeur journalisée tient en une ligne courte : au-delà, ce n'est plus un
// identifiant mais un contenu.
const maxJournalValueRunes = 200

// JournalValues rend, des paramètres décodés de l'ordre, les seuls champs de
// la liste blanche de son genre (Spec.Journal), en texte : nombres, booléens et
// chaînes imprimables et courtes. Tout autre champ, et tout autre type de
// valeur, est laissé. Les valeurs sont celles de l'objet que le juge a lu,
// écrites par json.Marshal ; les octets reçus ne sont pas relus (R-A1-5).
func (o Order) JournalValues() map[string]string {
	if len(o.spec.Journal) == 0 || o.Params == nil {
		return nil
	}
	encoded, err := json.Marshal(o.Params)
	var all map[string]json.RawMessage
	if err != nil || json.Unmarshal(encoded, &all) != nil {
		return nil
	}
	kept := map[string]string{}
	for _, field := range o.spec.Journal {
		if text, ok := journalText(all[field]); ok {
			kept[field] = text
		}
	}
	return kept
}

func journalText(raw json.RawMessage) (string, bool) {
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return text, isJournalText(text)
	}
	var number json.Number
	if json.Unmarshal(raw, &number) == nil && number != "" {
		return number.String(), true
	}
	var flag bool
	if json.Unmarshal(raw, &flag) == nil {
		return strconv.FormatBool(flag), true
	}
	return "", false
}

func isJournalText(text string) bool {
	if utf8.RuneCountInString(text) > maxJournalValueRunes {
		return false
	}
	for _, r := range text {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}
