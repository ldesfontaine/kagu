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

// JournalFields rend les champs que le journal local retient pour ce genre
// (Spec.Journal) ; ok est faux pour un genre hors du registre, dont rien ne se
// journalise.
func JournalFields(kind Kind) ([]string, bool) {
	spec, ok := SpecOf(kind)
	return spec.Journal, ok
}

// JournalParams rend, des paramètres d'un ordre, les seuls champs de la liste
// blanche de son genre, en texte : nombres, booléens et chaînes imprimables et
// courtes. Tout autre champ, et tout autre type de valeur, est laissé.
func JournalParams(kind Kind, params json.RawMessage) map[string]string {
	fields, _ := JournalFields(kind)
	var all map[string]json.RawMessage
	if len(fields) == 0 || json.Unmarshal(params, &all) != nil {
		return nil
	}
	kept := map[string]string{}
	for _, field := range fields {
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
