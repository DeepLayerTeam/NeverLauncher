//go:build !linux

package sqlitepg

import "errors"

func publishNewDirectory0377(_, _ string) error {
	return errors.New("Для «minimal offline bundle transfer» требуется «Linux atomic no-replace rename»")
}
