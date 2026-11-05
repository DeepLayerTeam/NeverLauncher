package model

import "fmt"

// ValidateProfileLaunch0382 сверяет реальные входные данные сборки с неизменяемым
// снимком. Устаревшие профили без стартовых значений по умолчанию сохраняют
// совместимость. checkJava=false применим только к package-create без входного Java
// Runtime.
func ValidateProfileLaunch0382(spec ProfileSpec, game MinecraftInfo, javaMajor int, checkJava bool) error {
	if spec.MinecraftVersion == "" {
		return nil
	}
	if game.Version != spec.MinecraftVersion {
		return fmt.Errorf("Несовпадение параметров запуска профиля: требуется Minecraft %q, получено %q", spec.MinecraftVersion, game.Version)
	}
	if game.Loader != spec.Loader {
		return fmt.Errorf("Несовпадение параметров запуска профиля: требуется загрузчик %q, получен %q", spec.Loader, game.Loader)
	}
	if game.LoaderVersion != "" && game.LoaderVersion != spec.LoaderVersion {
		return fmt.Errorf("Несовпадение параметров запуска профиля: требуется loaderVersion %q, получено %q", spec.LoaderVersion, game.LoaderVersion)
	}
	if checkJava && javaMajor != spec.JavaMajor {
		return fmt.Errorf("Несовпадение параметров запуска профиля: требуется Java %d, получено %d", spec.JavaMajor, javaMajor)
	}
	return nil
}
