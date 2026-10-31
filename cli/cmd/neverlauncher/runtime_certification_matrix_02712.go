package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type factoryMatrixTarget02712 struct {
	ID          string `json:"id"`
	Loader      string `json:"loader"`
	Minecraft   string `json:"minecraft"`
	OS          string `json:"os"`
	Arch        string `json:"arch"`
	ClientDir   string `json:"clientDir"`
	Certificate string `json:"certificate"`
}
type factoryMatrix02712 struct {
	Schema  string                     `json:"schema"`
	Targets []factoryMatrixTarget02712 `json:"targets"`
}
type factoryMatrixResult02712 struct {
	ID         string `json:"id"`
	Status     string `json:"status"`
	Reason     string `json:"reason,omitempty"`
	PlanSHA256 string `json:"planSha256,omitempty"`
}
type factoryMatrixReport02712 struct {
	Schema  string                     `json:"schema"`
	Status  string                     `json:"status"`
	Total   int                        `json:"total"`
	Passed  int                        `json:"passed"`
	Failed  int                        `json:"failed"`
	Results []factoryMatrixResult02712 `json:"results"`
}

func certifyMatrix02712(manifestPath, pubPath, out string, allLoaders bool) (factoryMatrixReport02712, error) {
	var report factoryMatrixReport02712
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return report, err
	}
	if len(raw) > 2<<20 {
		return report, errors.New("certification matrix too large")
	}
	var m factoryMatrix02712
	if err = json.Unmarshal(raw, &m); err != nil {
		return report, err
	}
	if m.Schema != "launcher.factory.certification-matrix.v1" || len(m.Targets) == 0 || len(m.Targets) > 100 {
		return report, errors.New("invalid certification matrix")
	}
	report = factoryMatrixReport02712{Schema: "launcher.factory.certification-report.v1", Total: len(m.Targets), Status: "failed", Results: make([]factoryMatrixResult02712, 0, len(m.Targets))}
	seen := map[string]bool{}
	families := map[string]bool{}
	for _, t := range m.Targets {
		if strings.TrimSpace(t.ID) == "" || strings.ContainsAny(t.ID, "/\\\n\t ") || seen[t.ID] {
			return report, fmt.Errorf("duplicate/invalid target ID %q", t.ID)
		}
		seen[t.ID] = true
		if t.ClientDir == "" || t.Certificate == "" || t.Loader == "" || t.Minecraft == "" || t.OS == "" || t.Arch == "" {
			return report, fmt.Errorf("incomplete certification target %s", t.ID)
		}
		families[t.Loader] = true
		dir := t.ClientDir
		if !filepath.IsAbs(dir) {
			dir = filepath.Join(filepath.Dir(manifestPath), dir)
		}
		certPath := t.Certificate
		if !filepath.IsAbs(certPath) {
			certPath = filepath.Join(filepath.Dir(manifestPath), certPath)
		}
		record := factoryMatrixResult02712{ID: t.ID, Status: "failed"}
		cert, verifyErr := certVerify02712(dir, certPath, pubPath)
		if verifyErr == nil && (cert.Loader != t.Loader || cert.MinecraftVersion != t.Minecraft || cert.Target.OS != t.OS || cert.Target.Arch != t.Arch) {
			verifyErr = errors.New("certificate identity does not match required matrix target")
		}
		if verifyErr != nil {
			record.Reason = verifyErr.Error()
			report.Failed++
		} else {
			record.Status = "passed"
			record.PlanSHA256 = cert.PlanSHA256
			report.Passed++
		}
		report.Results = append(report.Results, record)
	}
	if allLoaders {
		for _, loader := range []string{"vanilla", "fabric", "quilt", "forge", "neoforge"} {
			if !families[loader] {
				report.Results = append(report.Results, factoryMatrixResult02712{ID: "missing-" + loader, Status: "failed", Reason: "required loader family absent from matrix"})
				report.Total++
				report.Failed++
			}
		}
	}
	sort.Slice(report.Results, func(i, j int) bool { return report.Results[i].ID < report.Results[j].ID })
	if report.Failed == 0 {
		report.Status = "passed"
	}
	if out != "" && out != "-" {
		if err = writeOrPrintJSON(out, report); err != nil {
			return report, err
		}
	}
	if report.Failed != 0 {
		return report, fmt.Errorf("certification incomplete: %d/%d targets failed", report.Failed, report.Total)
	}
	return report, nil
}
