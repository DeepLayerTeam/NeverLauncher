package main

import (
	"errors"
	"sort"
	"strings"
)

type factoryAdapterReport02711 struct {
	Schema      string                   `json:"schema"`
	Loader      string                   `json:"loader,omitempty"`
	Minecraft   string                   `json:"minecraft,omitempty"`
	Targets     []vanillaTarget          `json:"targets,omitempty"`
	Locked      []factoryAdapterPin02711 `json:"locked,omitempty"`
	Available   []factoryAdapterPin02711 `json:"available"`
	Current     bool                     `json:"current"`
	Status      string                   `json:"status"`
	BuildSHA256 string                   `json:"buildSha256,omitempty"`
}

func handleRuntimeFactoryAdapters02711(args []string) error {
	dir := strings.TrimSpace(flagValue(args[1:], "--client-dir", ""))
	out := flagValue(args[1:], "--output", "")
	if dir != "" {
		if err := rejectFactoryOutputPath0271(dir, out); err != nil {
			return err
		}
	}
	if dir == "" {
		if args[0] == "adapter-verify" {
			return errors.New("adapter-verify requires --client-dir")
		}
		keys := make([]string, 0, len(factoryAdapterDefinitions02711))
		for id := range factoryAdapterDefinitions02711 {
			keys = append(keys, id)
		}
		sort.Strings(keys)
		pins := make([]factoryAdapterPin02711, 0, len(keys))
		for _, id := range keys {
			pin, err := factoryAdapterPinByID02711(id)
			if err != nil {
				return err
			}
			pins = append(pins, pin)
		}
		return writeOrPrintJSON(out, factoryAdapterReport02711{Schema: "neverlauncher.factory.adapters.v1", Available: pins, Current: true, Status: "registry"})
	}
	p, err := readFactoryPlan0271(dir)
	if err != nil {
		return err
	}
	currentErr := requireCurrentFactoryAdapters02711(p)
	report := factoryAdapterReport02711{Schema: "neverlauncher.factory.adapters.v1", Loader: p.Loader, Minecraft: p.MinecraftVersion, Targets: p.Targets, Locked: p.AdapterPins, Available: currentFactoryAdapterPins02711(p.Loader), Current: currentErr == nil, BuildSHA256: p.ReproducibilitySHA256}
	if currentErr != nil {
		report.Status = "adapter-upgrade-required"
	} else {
		report.Status = "current"
	}
	if args[0] == "adapter-inspect" {
		return writeOrPrintJSON(out, report)
	}
	if currentErr != nil {
		return currentErr
	}
	if err := factoryAdapterTargetCheck02711(p); err != nil {
		return err
	}
	if err := verifyFactoryPlan0271(dir, p); err != nil {
		return err
	}
	report.Status = "verified"
	if out != "" && out != "-" {
		if err := rejectFactoryOutputPath0271(dir, out); err != nil {
			return err
		}
	}
	return writeOrPrintJSON(out, report)
}
