package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

func markdownSafe(s string) string {
	s = strings.Map(func(c rune) rune {
		if c == '\n' || c == '\r' || c == 0 {
			return ' '
		}
		return c
	}, s)
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "`", "'")
	return strings.TrimSpace(s)
}

// Export all outstanding manual operations from the immutable report itself;
// this is a worklist for operators, NOT a claim that the actions were done.
func renderManualWorklist(p Plan, r Report) ([]byte, error) {
	if err := reportVerified(r); err != nil {
		return nil, err
	}
	if p.RunID != r.RunID || p.ProjectID != r.ProjectID {
		return nil, errors.New("worklist belongs to another project")
	}
	items := append([]Item(nil), r.Items...)
	sort.Slice(items, func(i, j int) bool { return items[i].Kind+items[i].Source < items[j].Kind+items[j].Source })
	var b strings.Builder
	fmt.Fprintf(&b, "# Gravit → Never: manual migration and rollback worklist\n\n")
	fmt.Fprintf(&b, "- Run: `%s`\n- Project: `%s`\n- Source SHA-256: `%s`\n- Report SHA-256: `%s`\n- Target release SHA-256: `%s`\n", markdownSafe(r.RunID), markdownSafe(r.ProjectID), r.SourceSHA256, r.ReportSHA256, p.TargetReleaseSHA256)
	fmt.Fprintf(&b, "\n## Manual source actions (%d)\n\n", r.Counts["manual"])
	n := 0
	for _, item := range items {
		if item.Status == "manual" {
			n++
			fmt.Fprintf(&b, "- [ ] **%s** — `%s`", markdownSafe(item.Kind), markdownSafe(item.Source))
			if item.Target != "" {
				fmt.Fprintf(&b, " → `%s`", markdownSafe(item.Target))
			}
			if item.Reason != "" {
				fmt.Fprintf(&b, "; %s", markdownSafe(item.Reason))
			}
			b.WriteByte('\n')
		}
	}
	if n == 0 {
		b.WriteString("No manual inventory items in this report. Operator checks below still apply.\n")
	}
	b.WriteString(`
## Mandatory operator verification before switching

- [ ] Record exactly which Minecraft worlds, external SQL stores, proxy routes, DNS records and custom extensions are outside the automated migration scope.
- [ ] Confirm ownership and password-reset workflow for any player unable to authenticate; do not reuse Gravit tokens, old keys or permissions.
- [ ] Quiesce or fence **every** Gravit and Never writer; systemd unit masking alone is not proof other writers stopped.
- [ ] Take independently restorable backups of worlds, inventory/economy data, databases, plugins, configuration and secrets.
- [ ] Capture *two distinct* source/target snapshot directories with world/, plugins/, player-uuids.txt; use audit-state before the cutover and after the rollback drill.
- [ ] Perform real Java/Minecraft login and server join with the migrated UUID for each configured reference class.
- [ ] Recheck every manual item above; record responsible operator, completion timestamp and private evidence location in the migration change ticket.

## Rollback limits and point of no return

- [ ] Set a bounded cutover window, record original proxy/DNS/route and signed release revisions.
- [ ] Verify the Never writer is fenced before returning traffic to Gravit.
- [ ] If players changed worlds, inventory, economy, privileges or plugin SQL state after cutover, **do not** restore a stale Gravit copy. Reconcile the changed data and independently verify it first.
- [ ] Recheck fresh snapshots, the exact rollback authorization digest and the routing revision before committing rollback.
- [ ] Verify player UUID/login, world and plugin data, and connectivity *after* the rollback. Record any unavailable or manually replaced modules.

This checklist is generated from an authoritative report, not proof of completed actions. Migration GA requires signed private E2E evidence and an independent live verification of the complete three-reference cohort.
`)
	return []byte(b.String()), nil
}

func exportManualWorklist(ctx context.Context, p Plan, token, output string) error {
	if strings.TrimSpace(token) == "" {
		return errors.New("missing GA backend token")
	}
	if err := checkBackendURL(p.Backend); err != nil {
		return err
	}
	client := &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	endpoint := strings.TrimRight(p.Backend, "/") + "/api/v1/admin/migration-runs/" + url.PathEscape(p.RunID) + "/report"
	var report Report
	if err := getJSON(ctx, client, endpoint, token, &report); err != nil {
		return err
	}
	raw, err := renderManualWorklist(p, report)
	if err != nil {
		return err
	}
	return writePrivate(output, raw)
}
