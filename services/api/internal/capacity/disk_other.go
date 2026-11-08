//go:build !linux && !darwin && !freebsd

package capacity

import "errors"

func measureDisk(name, path string) (Disk, error) {
	return Disk{Name: name}, errors.New("На этой ОС не поддерживается проверка свободного места на диске; подтверждать сертификацию запрещено")
}
