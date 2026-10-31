package main

import "testing"

func TestNoExtensionsSafeModeFlag02012(t *testing.T) {
	if !hasCommandArg02012([]string{"--listen", ":8080", "--no-extensions"}, "--no-extensions") {
		t.Fatal("--no-extensions was not detected")
	}
	if hasCommandArg02012([]string{"--no-extensions=false"}, "--no-extensions") {
		t.Fatal("safe mode must require the exact --no-extensions switch")
	}
}
