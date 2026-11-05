//go:build !linux || !amd64

package installer

import "errors"

func noReplace(from, to string) error { return errors.New("Для атомарной установки требуется Linux renameat2") }
