//go:build !linux

package devtools

import (
	"errors"
	"os"
)

func sandboxNoNetworkFilter() (*os.File, error) {
	return nil, errors.New("seccomp requires Linux")
}
