//go:build !windows

package installer

import "errors"

func writeWindowsShortcut(path, target, config, root string) error {
	return errors.New("Windows shortcut unsupported on this OS")
}
func removeWindowsShortcut(path, managedRoot string) error {
	return errors.New("Windows shortcut unsupported on this OS")
}
