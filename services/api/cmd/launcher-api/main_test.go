package main

import "testing"

func TestNoExtensionsSafeModeFlag02012(t *testing.T) {
	if !hasCommandArg02012([]string{"--listen", ":8080", "--no-extensions"}, "--no-extensions") {
		t.Fatal("Параметр --no-extensions не обнаружен")
	}
	if hasCommandArg02012([]string{"--no-extensions=false"}, "--no-extensions") {
		t.Fatal("Безопасный режим должен требовать именно параметр --no-extensions")
	}
}
