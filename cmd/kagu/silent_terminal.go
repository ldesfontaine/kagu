package main

import (
	"errors"
	"io"
	"os"
	"syscall"
	"unsafe"
)

// silentTerminal est le terminal de l'opérateur, écho coupé : un mot de passe
// saisi ne s'affiche pas. Close remet le terminal comme il était.
type silentTerminal struct {
	*os.File
	saved syscall.Termios
}

// openSilentTerminal ouvre le terminal sans écho. Sans terminal, ou si l'écho
// ne se coupe pas, rien n'est lu : un mot de passe ne s'affiche jamais.
func openSilentTerminal() (io.ReadCloser, error) {
	terminal, err := openControllingTerminal()
	if err != nil {
		return nil, err
	}
	file, ok := terminal.(*os.File)
	if !ok {
		_ = terminal.Close()
		return nil, errors.New("the controlling terminal is not a file")
	}
	var saved syscall.Termios
	if err := termios(file, syscall.TCGETS, &saved); err != nil {
		_ = file.Close()
		return nil, err
	}
	// Comme golang.org/x/term : sans écho, mais ligne par ligne et Ctrl-C
	// toujours actif.
	silent := saved
	silent.Lflag &^= syscall.ECHO
	silent.Lflag |= syscall.ICANON | syscall.ISIG
	silent.Iflag |= syscall.ICRNL
	if err := termios(file, syscall.TCSETS, &silent); err != nil {
		_ = file.Close()
		return nil, err
	}
	return &silentTerminal{File: file, saved: saved}, nil
}

func (t *silentTerminal) Close() error {
	restoreErr := termios(t.File, syscall.TCSETS, &t.saved)
	closeErr := t.File.Close()
	return errors.Join(restoreErr, closeErr)
}

// termios lit (TCGETS) ou pose (TCSETS) les réglages du terminal. La
// bibliothèque standard n'a pas d'appel nommé : l'ioctl se fait à la main,
// plutôt qu'ajouter golang.org/x/term pour ces quelques lignes.
func termios(file *os.File, request uintptr, settings *syscall.Termios) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), request, uintptr(unsafe.Pointer(settings))) // #nosec G103 -- l'ioctl des réglages du terminal prend l'adresse de la structure ; elle vit jusqu'au retour de l'appel.
	if errno != 0 {
		return errno
	}
	return nil
}
