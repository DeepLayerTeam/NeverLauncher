//go:build !linux && !darwin && !freebsd

package capacity

import "errors"

func measureDisk(name, path string) (Disk, error) {
	return Disk{Name: name}, errors.New("disk capacity probe unsupported on this OS; cannot certify")
}
