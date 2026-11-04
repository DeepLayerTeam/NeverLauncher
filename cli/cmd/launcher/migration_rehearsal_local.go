package main

// A second rehearsal after a signed client update cannot overwrite the
// PostgreSQL MIG10 receipt: its evidence is intentionally immutable. Run the
// existing real Minecraft/RCON/probe pipeline and save a separate local-only
// witness instead. It does NOT certify cutover or mutate Backend state.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

func handleMigrationRehearsalLocal04910(args []string) error {
	run := strings.TrimSpace(flagValue(args, "--run", ""))
	stage := flagValue(args, "--stage", "")
	inventory := flagValue(args, "--inventory-sha256", "")
	output := flagValue(args, "--output", "")
	if output == "" || output == "-" {
		return errors.New("rehearse-local requires a new private --output file (no stdout evidence)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	report, err := migrationRehearsalRun03310(ctx, stage, run, inventory)
	if err != nil {
		return fmt.Errorf("local post-update Minecraft rehearsal failed: %w", err)
	}
	if report.Ready || report.CutoverAllowed || report.LiveSession == nil || len(report.Probes) != len(rehearsalRequired03310) {
		return errors.New("invalid local rehearsal: not a separate uncertified live witness")
	}
	for i, name := range rehearsalRequired03310 {
		if report.Probes[i].Name != name || !report.Probes[i].Passed || report.Probes[i].EvidenceSHA256 == "" {
			return fmt.Errorf("local rehearsal check %s failed", name)
		}
	}
	return writePrivateIdentityReport0334(output, report)
}
