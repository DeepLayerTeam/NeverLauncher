package main

import "testing"

func TestExtension0430RealPackagesRequiredInRelease(t *testing.T) {
	mandatory := []string{
		"launcher-example-java-host.nlext",
		"launcher-example-gravit-port.nlext",
		"EXTENSION_PUBLISHER_PUBLIC_KEY_0430.pem",
		"EXTENSION_RELEASE_CERTIFICATION_0430.json",
		"EXTENSION_ACCEPTANCE_EVIDENCE_0430.zip",
	}
	for _, version := range []string{"0.43.0", "0.43.1", "1.0.0"} {
		set := make(map[string]bool)
		for _, name := range releaseArtifacts(version) {
			set[name] = true
		}
		for _, name := range mandatory {
			if !set[name] {
				t.Fatalf("%s can ship without mandatory extension artifact %s", version, name)
			}
		}
	}
	for _, name := range releaseArtifacts("0.42.12") {
		for _, future := range mandatory {
			if name == future {
				t.Fatalf("historical release unexpectedly changed: %s", name)
			}
		}
	}
}
