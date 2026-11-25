package refusal

import "errors"

// Error est un refus. Il se déclare en sentinelle, une fois par cause :
// errors.Is le reconnaît par son adresse, comme une erreur ordinaire.
type Error struct {
	key        string
	message    string
	isConflict bool
	// fix : ce qui lève un refus de droit (Missing) ; nil pour les autres.
	fix *Fix
	// declared : la sentinelle dont ce refus de droit est l'instance.
	declared *Error
}

// Fix dit ce qui lève un refus de droit : le droit qui manque et la machine
// dont l'agent doit le tenir. La ligne à coller, le serveur la joint : la
// ligne constante (agentpolicy.PendingLine) ; ce paquet ne connaît pas les
// droits.
type Fix struct {
	Right   string
	Machine string
}

// Invalid déclare un refus de la demande elle-même : un champ faux, une
// limite dépassée.
func Invalid(key, message string) *Error {
	return &Error{key: key, message: message}
}

// Conflict déclare un refus dû à l'état présent : la même demande passerait
// ailleurs ou plus tard.
func Conflict(key, message string) *Error {
	return &Error{key: key, message: message, isConflict: true}
}

// Missing rend le refus déclaré par la sentinelle (un « *_right_missing »),
// pour cette machine et ce droit : errors.Is reconnaît toujours la sentinelle,
// et la réponse porte de quoi lever le refus.
func Missing(declared *Error, right, machineID string) *Error {
	return &Error{
		key: declared.key, message: declared.message, isConflict: declared.isConflict,
		fix: &Fix{Right: right, Machine: machineID}, declared: declared,
	}
}

// Unwrap rend la sentinelle d'un refus de droit ; nil pour une sentinelle.
func (e *Error) Unwrap() error {
	if e.declared == nil {
		return nil
	}
	return e.declared
}

// Error rend le texte du journal ; l'opérateur, lui, lit la clé.
func (e *Error) Error() string {
	return e.message
}

// KeyOf rend la clé du premier refus de la chaîne. ok est faux pour une
// erreur qui n'est pas un refus : elle n'a pas de clé, et son texte ne doit
// pas remonter à l'opérateur.
func KeyOf(err error) (key string, ok bool) {
	var refused *Error
	if !errors.As(err, &refused) {
		return "", false
	}
	return refused.key, true
}

// IsConflict dit si le premier refus de la chaîne vient de l'état présent.
func IsConflict(err error) bool {
	var refused *Error
	return errors.As(err, &refused) && refused.isConflict
}

// FixOf rend ce qui lève le premier refus de la chaîne ; ok est faux quand ce
// n'est pas un refus de droit.
func FixOf(err error) (fix Fix, ok bool) {
	var refused *Error
	if !errors.As(err, &refused) || refused.fix == nil {
		return Fix{}, false
	}
	return *refused.fix, true
}
