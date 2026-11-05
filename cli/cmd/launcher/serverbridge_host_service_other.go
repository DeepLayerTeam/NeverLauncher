//go:build !linux

package main

import "errors"

func hostServiceHandle02811(_ []string) error {
	return errors.New("Установщик службы systemd поддерживается только в Linux")
}
