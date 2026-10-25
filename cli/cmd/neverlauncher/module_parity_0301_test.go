package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestModuleParityCLI0301Audit(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "report.json")
	if err := handleModuleParity0301([]string{"audit", "--root", root, "--report", output}); err != nil {
		t.Fatal(err)
	}
	var report struct {
		FullyCertified bool `json:"fullyCertified"`
		Results        []struct {
			ModuleID string `json:"moduleId"`
		} `json:"results"`
	}
	bytes, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(bytes, &report); err != nil {
		t.Fatal(err)
	}
	if report.FullyCertified || len(report.Results) != 19 {
		t.Fatalf("incorrect results: %#v", report)
	}
	if err := handleModuleParity0301([]string{"audit", "--root", root, "--report", output, "--require-full-parity"}); err == nil {
		t.Fatal("full parity wrongly certified")
	}
}
func TestModuleParityCLI0301Flags(t *testing.T) {
	if !paritySwitch0301([]string{"--run-tests", "--timeout", "10s"}, "--run-tests") {
		t.Fatal("standalone boolean lost")
	}
	if paritySwitch0301([]string{"--run-tests=false"}, "--run-tests") {
		t.Fatal("false treated as true")
	}
	if !paritySwitch0301([]string{"--run-tests=true"}, "--run-tests") {
		t.Fatal("true treated as false")
	}
	if err := handleModuleParity0301([]string{"audit", "--root", ".", "--module", "M20"}); err == nil {
		t.Fatal("invalid module accepted")
	}
}
