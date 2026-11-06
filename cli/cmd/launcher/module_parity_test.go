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
		t.Fatalf("Неверные результаты: %#v", report)
	}
	if err := handleModuleParity0301([]string{"audit", "--root", root, "--report", output, "--require-full-parity"}); err == nil {
		t.Fatal("Полное соответствие ошибочно сертифицировано")
	}
}
func TestModuleParityCLI0301Flags(t *testing.T) {
	if !paritySwitch0301([]string{"--run-tests", "--timeout", "10s"}, "--run-tests") {
		t.Fatal("Потеряно отдельное логическое значение")
	}
	if paritySwitch0301([]string{"--run-tests=false"}, "--run-tests") {
		t.Fatal("Значение false интерпретировано как true")
	}
	if !paritySwitch0301([]string{"--run-tests=true"}, "--run-tests") {
		t.Fatal("Значение true интерпретировано как false")
	}
	if err := handleModuleParity0301([]string{"audit", "--root", ".", "--module", "M20"}); err == nil {
		t.Fatal("Принят недопустимый модуль")
	}
}

func TestModuleParityCLI03011HistoricalSelection(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, baseline := range []string{"0.30.1", "0.30.11"} {
		out := filepath.Join(t.TempDir(), "report.json")
		if err = handleModuleParity0301([]string{"audit", "--root", root, "--baseline", baseline, "--report", out}); err != nil {
			t.Fatalf("%s: %v", baseline, err)
		}
		data, e := os.ReadFile(out)
		if e != nil {
			t.Fatal(e)
		}
		var report struct {
			Results []struct {
				Status string `json:"status"`
			} `json:"results"`
		}
		if e = json.Unmarshal(data, &report); e != nil {
			t.Fatal(e)
		}
		if len(report.Results) != 19 {
			t.Fatalf("%s: %d records", baseline, len(report.Results))
		}
		if baseline == "0.30.1" && report.Results[1].Status != "planned" {
			t.Fatal("Перезаписан исторический реестр")
		}
		if baseline == "0.30.11" && report.Results[1].Status != "partial" {
			t.Fatal("Отсутствует актуальное свидетельство Discord")
		}
	}
	if err = handleModuleParity0301([]string{"audit", "--root", root, "--baseline", "future"}); err == nil {
		t.Fatal("Принята неподдерживаемая базовая конфигурация")
	}
}
