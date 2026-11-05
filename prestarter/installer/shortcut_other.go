//go:build !windows

package installer

import "errors"

func writeWindowsShortcut(path, target, config, root, icon string) error {
	return errors.New("Ярлыки Windows не поддерживаются в этой ОС")
}
func removeWindowsShortcut(path, managedRoot string) error {
	return errors.New("Ярлыки Windows не поддерживаются в этой ОС")
}
