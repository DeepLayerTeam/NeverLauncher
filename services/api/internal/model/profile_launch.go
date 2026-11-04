package model

import "fmt"

// ValidateProfileLaunch0382 checks actual build inputs against the immutable
// snapshot. Legacy profiles without launch defaults remain compatible.
// checkJava=false is only for package-create, which has no runtime Java input.
func ValidateProfileLaunch0382(spec ProfileSpec, game MinecraftInfo, javaMajor int, checkJava bool) error {
	if spec.MinecraftVersion == "" {
		return nil
	}
	if game.Version != spec.MinecraftVersion {
		return fmt.Errorf("profile launch mismatch: Minecraft %q required, received %q", spec.MinecraftVersion, game.Version)
	}
	if game.Loader != spec.Loader {
		return fmt.Errorf("profile launch mismatch: loader %q required, received %q", spec.Loader, game.Loader)
	}
	if game.LoaderVersion != "" && game.LoaderVersion != spec.LoaderVersion {
		return fmt.Errorf("profile launch mismatch: loaderVersion %q required, received %q", spec.LoaderVersion, game.LoaderVersion)
	}
	if checkJava && javaMajor != spec.JavaMajor {
		return fmt.Errorf("profile launch mismatch: Java %d required, received %d", spec.JavaMajor, javaMajor)
	}
	return nil
}
