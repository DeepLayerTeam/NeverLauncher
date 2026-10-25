package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/cli/internal/moduleparity"
)

func moduleParityRepo0301() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, moduleparity.MatrixPath)); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", errors.New("module parity registry not found; use --root <repository checkout>")
}

func paritySwitch0301(args []string, name string) bool {
	for i, arg := range args {
		if arg == name {
			if i+1 < len(args) && (args[i+1] == "false" || args[i+1] == "0") {
				return false
			}
			return true
		}
		if arg == name+"=true" || arg == name+"=1" {
			return true
		}
	}
	return false
}

func handleModuleParity0301(args []string) error {
	if len(args) == 0 || args[0] != "audit" {
		return errors.New("usage: nl module-parity audit [--root PATH] [--baseline 0.30.1|0.30.11|0.30.12|0.31.0] [--run-tests] [--module M01,M03] [--timeout 180s] [--report PATH|-] [--require-tests] [--require-full-parity]")
	}
	args = args[1:]
	root := flagValue(args, "--root", "")
	if root == "" {
		var err error
		root, err = moduleParityRepo0301()
		if err != nil {
			return err
		}
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	selected := map[string]bool{}
	for _, part := range strings.Split(flagValue(args, "--module", ""), ",") {
		if part == "" {
			continue
		}
		if len(part) != 3 || part[0] != 'M' || part[1] < '0' || part[1] > '1' || part[2] < '0' || part[2] > '9' || part == "M00" {
			return fmt.Errorf("invalid --module %q", part)
		}
		selected[part] = true
	}
	timeout, err := time.ParseDuration(flagValue(args, "--timeout", "180s"))
	if err != nil || timeout <= 0 {
		return errors.New("--timeout requires a positive duration")
	}
	baseline := flagValue(args, "--baseline", "0.31.0")
	var report moduleparity.Report
	var registry moduleparity.Matrix
	switch baseline {
	case "0.30.1":
		report, err = moduleparity.Inspect(root)
		if err != nil {
			return err
		}
		registry, err = moduleparity.LoadMatrix(root)
	case "0.30.11":
		report, err = moduleparity.InspectPrevious03011(root)
		if err != nil {
			return err
		}
		registry, err = moduleparity.LoadPreviousMatrix03011(root)
	case "0.30.12":
		report, err = moduleparity.InspectPrevious03012(root)
		if err != nil {
			return err
		}
		registry, err = moduleparity.LoadPreviousMatrix03012(root)
	case "0.31.0":
		report, err = moduleparity.InspectCurrent(root)
		if err != nil {
			return err
		}
		registry, err = moduleparity.LoadCurrentMatrix(root)
	default:
		return fmt.Errorf("unsupported module parity baseline %q", baseline)
	}
	if err != nil {
		return err
	}
	for name := range selected {
		found := false
		for _, row := range registry.Modules {
			if row.ID == name {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("unknown module %s", name)
		}
	}
	execute := paritySwitch0301(args, "--run-tests")
	if paritySwitch0301(args, "--require-tests") && !execute {
		return errors.New("--require-tests requires --run-tests")
	}
	if execute {
		err = moduleparity.RunTests(context.Background(), root, &report, registry, moduleparity.Options{RunTests: true, Timeout: timeout, Selected: selected})
		if err != nil {
			return err
		}
		report.AuditStatus = "tests-executed-not-certified"
	}
	output := flagValue(args, "--report", "-")
	if err = moduleparity.WriteReport(output, report); err != nil {
		return err
	}
	if paritySwitch0301(args, "--require-full-parity") {
		return errors.New("full M01-M19 parity is not certified; registry contains partial/planned/blocked outcomes")
	}
	if paritySwitch0301(args, "--require-tests") {
		for _, r := range report.Results {
			if len(selected) > 0 && !selected[r.ModuleID] {
				continue
			}
			if r.Test.Status != "passed" {
				return fmt.Errorf("%s: regression tests not passed (%s)", r.ModuleID, r.Test.Status)
			}
		}
	}
	return nil
}
