//go:build !linux || !amd64

package installer

import "errors"

func noReplace(from, to string) error { return errors.New("atomic install requires Linux renameat2") }
