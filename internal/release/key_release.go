//go:build release

package release

// Une version ne se construit pas sans clé de secours : sans elle, une clé
// courante prise ne se retire plus. len(BackupPublicKey) - 1 ne tient dans un
// uint que si la clé est posée ; vide, le compilateur s'arrête sur cette ligne
// (« constant -1 overflows uint »). La poser : docs/projet/12-methode.md.
const _ = uint(len(BackupPublicKey) - 1)
