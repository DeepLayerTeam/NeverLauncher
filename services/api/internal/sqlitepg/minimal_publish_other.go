//go:build !linux

package sqlitepg

import "errors"

func publishNewDirectory0377(_, _ string) error {
	return errors.New("minimal offline bundle transfer requires Linux atomic no-replace rename")
}
