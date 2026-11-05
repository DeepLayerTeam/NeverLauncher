//go:build !linux

package main

import "errors"

func hostServiceHandle02811(_ []string) error {
	return errors.New("Установка служб systemd поддерживается только в Linux")
}
