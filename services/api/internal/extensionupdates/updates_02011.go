package extensionupdates

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/extensionhost"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/extensionlifecycle"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

type Config struct{ HealthTimeout, LeaseTTL time.Duration }
type Lifecycle interface {
	Install(context.Context, model.ExtensionRegistryVersion, extensionlifecycle.Scope) (model.ExtensionInstall, error)
	Enable(context.Context, string, extensionlifecycle.Scope) (model.ExtensionInstall, error)
	Update(context.Context, model.ExtensionRegistryVersion, extensionlifecycle.Scope) (model.ExtensionInstall, error)
	Uninstall(context.Context, string, extensionlifecycle.Scope) (model.ExtensionInstall, error)
	Rollback(context.Context, string, extensionlifecycle.Scope) (model.ExtensionInstall, error)
}

type Host interface {
	Stop(context.Context, extensionhost.Key) error
	StartInstallation(context.Context, model.ExtensionInstall) error
	Get(extensionhost.Key) (extensionhost.Status, error)
}

type Security interface {
	PermissionDiff(context.Context, string, string, string, string, string) (model.ExtensionPermissionDiff, error)
}

type Manager struct {
	Repo      repository.Repository
	Lifecycle Lifecycle
	Host      Host
	Security  Security
	Config    Config
}

type appliedItem struct {
	Item         model.ExtensionUpdatePlanItem
	Before       model.ExtensionInstall
	InstalledNew bool
}

func (m *Manager) normalized() Config {
	c := m.Config
	if c.HealthTimeout <= 0 {
		c.HealthTimeout = 20 * time.Second
	}
	if c.LeaseTTL <= 0 {
		c.LeaseTTL = 30 * time.Minute
	}
	return c
}
func token02011() (string, error) {
	b := make([]byte, 24)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	return hex.EncodeToString(b), nil
}
func scope02011(plan model.ExtensionUpdatePlan) extensionlifecycle.Scope {
	return extensionlifecycle.Scope{Scope: plan.Scope, ScopeID: plan.ScopeID}
}
func hostKey02011(x model.ExtensionInstall) extensionhost.Key {
	return extensionhost.Key{ExtensionID: x.ExtensionID, Scope: x.Scope, ScopeID: x.ScopeID}
}

func (m *Manager) Apply(ctx context.Context, plan model.ExtensionUpdatePlan) (model.ExtensionUpdateTransaction, error) {
	if m == nil || m.Repo == nil || m.Lifecycle == nil {
		return model.ExtensionUpdateTransaction{}, errors.New("extension update manager is not configured")
	}
	cfg := m.normalized()
	owner, err := token02011()
	if err != nil {
		return model.ExtensionUpdateTransaction{}, err
	}
	idToken, err := token02011()
	if err != nil {
		return model.ExtensionUpdateTransaction{}, err
	}
	txid := "extupd-" + idToken[:24]
	got, err := m.Repo.AcquireExtensionUpdateLease(ctx, plan.Scope, plan.ScopeID, owner, cfg.LeaseTTL)
	if err != nil {
		return model.ExtensionUpdateTransaction{}, err
	}
	if !got {
		return model.ExtensionUpdateTransaction{}, fmt.Errorf("%w: another extension update transaction owns this scope", repository.ErrConflict)
	}
	defer m.Repo.ReleaseExtensionUpdateLease(context.Background(), plan.Scope, plan.ScopeID, owner)
	if err := m.recoverInterrupted02011(ctx, plan.Scope, plan.ScopeID, cfg.HealthTimeout); err != nil {
		return model.ExtensionUpdateTransaction{}, fmt.Errorf("recover interrupted extension update: %w", err)
	}
	tx := model.ExtensionUpdateTransaction{ID: txid, Scope: plan.Scope, ScopeID: plan.ScopeID, Status: "running", Plan: plan, StartedAt: time.Now().UTC(), LeaseOwner: owner}
	if _, err = m.Repo.SaveExtensionUpdateTransaction(ctx, tx); err != nil {
		return tx, err
	}
	snapshots := map[string]model.ExtensionInstall{}
	pins, e := m.Repo.ListExtensionUpdatePins(ctx, plan.Scope, plan.ScopeID)
	if e != nil {
		return m.fail(tx, e)
	}
	pinMap := map[string]string{}
	for _, p := range pins {
		pinMap[p.ExtensionID] = p.Version
	}
	requiresHost := false
	for _, item := range plan.Items {
		cur, e := m.Repo.GetExtensionInstallState(ctx, item.ExtensionID, plan.Scope, plan.ScopeID)
		if errors.Is(e, repository.ErrNotFound) {
			cur = model.ExtensionInstall{ExtensionID: item.ExtensionID, Scope: plan.Scope, ScopeID: plan.ScopeID, CurrentState: model.ExtensionInstallStateAbsent, DesiredState: model.ExtensionInstallStateAbsent}
		} else if e != nil {
			return m.fail(tx, e)
		}
		snapshots[item.ExtensionID] = cur
		if item.Operation == "update" && cur.CurrentVersion != item.FromVersion {
			return m.fail(tx, fmt.Errorf("%w: stale update plan for %s: planned from %s, current is %s", repository.ErrConflict, item.ExtensionID, item.FromVersion, cur.CurrentVersion))
		}
		if item.Operation == "install" && cur.CurrentState != model.ExtensionInstallStateAbsent {
			return m.fail(tx, fmt.Errorf("%w: stale update plan for %s: extension is already installed", repository.ErrConflict, item.ExtensionID))
		}
		if pinned := pinMap[item.ExtensionID]; pinned != "" && pinned != item.ToVersion {
			return m.fail(tx, fmt.Errorf("%w: %s is pinned to %s, plan targets %s", repository.ErrConflict, item.ExtensionID, pinned, item.ToVersion))
		}
		reg, e := m.Repo.GetExtensionRegistryVersion(ctx, item.ExtensionID, item.ToVersion)
		if e != nil {
			return m.fail(tx, e)
		}
		if reg.YankedAt != nil || reg.Artifact.PackageIdentity != item.PackageIdentity {
			return m.fail(tx, errors.New("resolved registry artifact changed or was yanked after planning"))
		}
		if item.Operation == "update" || item.Operation == "install" {
			if m.Security == nil {
				if len(reg.Manifest.Permissions) > 0 {
					return m.fail(tx, fmt.Errorf("capability policy unavailable for %s", item.ExtensionID))
				}
			} else {
				fromVersion := ""
				if item.Operation == "update" {
					fromVersion = cur.CurrentVersion
				}
				d, e := m.Security.PermissionDiff(ctx, item.ExtensionID, fromVersion, item.ToVersion, plan.Scope, plan.ScopeID)
				if e != nil {
					return m.fail(tx, e)
				}
				if len(d.AddedNotGranted) > 0 {
					return m.fail(tx, fmt.Errorf("%w: %s %s needs grants: %s", repository.ErrConflict, item.ExtensionID, item.Operation, strings.Join(d.AddedNotGranted, ",")))
				}
			}
		}
		for _, target := range reg.Manifest.Targets {
			if target.Kind == "backend" {
				requiresHost = true
				break
			}
		}
	}
	if requiresHost && m.Host == nil {
		return m.fail(tx, errors.New("extension host is required for backend extension health verification"))
	}
	// Stop all enabled selected hosts before touching any payload so dependants never run against a half-updated graph.
	if m.Host != nil {
		for _, item := range plan.Items {
			cur := snapshots[item.ExtensionID]
			if cur.CurrentState == model.ExtensionInstallStateEnabled && cur.Enabled {
				if e := m.Host.Stop(ctx, hostKey02011(cur)); e != nil && !errors.Is(e, repository.ErrNotFound) && !errors.Is(e, extensionhost.ErrHostNotRunning) {
					m.restartSnapshots02011(snapshots, plan.Items)
					return m.fail(tx, fmt.Errorf("stop %s: %w", item.ExtensionID, e))
				}
			}
		}
	}
	applied := []appliedItem{}
	for _, item := range plan.Items {
		if item.Operation == "unchanged" {
			continue
		}
		reg, e := m.Repo.GetExtensionRegistryVersion(ctx, item.ExtensionID, item.ToVersion)
		if e != nil {
			return m.rollback(tx, applied, snapshots, e)
		}
		before := snapshots[item.ExtensionID]
		tx.InFlight = item.ExtensionID
		if _, e = m.Repo.SaveExtensionUpdateTransaction(context.Background(), tx); e != nil {
			return m.rollback(tx, applied, snapshots, fmt.Errorf("journal in-flight %s: %w", item.ExtensionID, e))
		}
		var after model.ExtensionInstall
		switch item.Operation {
		case "install":
			after, e = m.Lifecycle.Install(ctx, reg, scope02011(plan))
			if e == nil {
				after, e = m.Lifecycle.Enable(ctx, item.ExtensionID, scope02011(plan))
			}
		case "update":
			after, e = m.Lifecycle.Update(ctx, reg, scope02011(plan))
		default:
			e = fmt.Errorf("unsupported update operation %q", item.Operation)
		}
		if e != nil {
			tx.InFlight = ""
			_, _ = m.Repo.SaveExtensionUpdateTransaction(context.Background(), tx)
			return m.rollback(tx, applied, snapshots, fmt.Errorf("%s %s: %w", item.Operation, item.ExtensionID, e))
		}
		applied = append(applied, appliedItem{Item: item, Before: before, InstalledNew: item.Operation == "install"})
		tx.Applied = append(tx.Applied, item.ExtensionID)
		tx.InFlight = ""
		if _, e = m.Repo.SaveExtensionUpdateTransaction(context.Background(), tx); e != nil {
			return m.rollback(tx, applied, snapshots, fmt.Errorf("journal applied %s: %w", item.ExtensionID, e))
		}
		_ = after
	}
	// Start all enabled final installs dependency-first and require a healthy Host handshake/heartbeat for backend targets.
	if m.Host != nil {
		for _, item := range plan.Items {
			cur, e := m.Repo.GetExtensionInstallState(ctx, item.ExtensionID, plan.Scope, plan.ScopeID)
			if e != nil {
				return m.rollback(tx, applied, snapshots, e)
			}
			if cur.CurrentState != model.ExtensionInstallStateEnabled || !cur.Enabled {
				continue
			}
			e = m.Host.StartInstallation(ctx, cur)
			if errors.Is(e, extensionhost.ErrNoBackendTarget) {
				continue
			}
			if e != nil {
				return m.rollback(tx, applied, snapshots, fmt.Errorf("host start %s: %w", item.ExtensionID, e))
			}
			if e = m.waitHealthy(ctx, cur, cfg.HealthTimeout); e != nil {
				return m.rollback(tx, applied, snapshots, e)
			}
		}
	}
	now := time.Now().UTC()
	tx.Status = "succeeded"
	tx.FinishedAt = &now
	_, err = m.Repo.SaveExtensionUpdateTransaction(context.Background(), tx)
	return tx, err
}

func (m *Manager) waitHealthy(ctx context.Context, install model.ExtensionInstall, timeout time.Duration) error {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		st, e := m.Host.Get(hostKey02011(install))
		if e == nil && st.Healthy {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("extension %s failed health check within %s", install.ExtensionID, timeout)
		case <-tick.C:
		}
	}
}

func (m *Manager) restartSnapshots02011(snapshots map[string]model.ExtensionInstall, items []model.ExtensionUpdatePlanItem) {
	if m.Host == nil {
		return
	}
	for _, item := range items {
		old := snapshots[item.ExtensionID]
		if old.CurrentState == model.ExtensionInstallStateEnabled && old.Enabled {
			_ = m.Host.StartInstallation(context.Background(), old)
		}
	}
}

func contains02011(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}

func planItem02011(plan model.ExtensionUpdatePlan, id string) (model.ExtensionUpdatePlanItem, bool) {
	for _, item := range plan.Items {
		if item.ExtensionID == id {
			return item, true
		}
	}
	return model.ExtensionUpdatePlanItem{}, false
}

// recoverInterrupted02011 is invoked only after this replica owns the scope
// lease. A previous running transaction therefore cannot still be active on a
// healthy replica. The durable in-flight marker closes the crash window between
// filesystem/lifecycle mutation and the applied journal write.
func (m *Manager) recoverInterrupted02011(ctx context.Context, scope, scopeID string, healthTimeout time.Duration) error {
	txs, err := m.Repo.ListExtensionUpdateTransactions(ctx, scope, scopeID, "running")
	if err != nil {
		return err
	}
	for _, tx := range txs {
		if err := m.recoverTransaction02011(ctx, tx, healthTimeout); err != nil {
			return fmt.Errorf("transaction %s: %w", tx.ID, err)
		}
	}
	return nil
}

func (m *Manager) recoverTransaction02011(ctx context.Context, tx model.ExtensionUpdateTransaction, healthTimeout time.Duration) error {
	if tx.InFlight != "" && !contains02011(tx.Applied, tx.InFlight) && !contains02011(tx.RolledBack, tx.InFlight) {
		item, ok := planItem02011(tx.Plan, tx.InFlight)
		if !ok {
			return errors.New("in-flight extension is missing from durable update plan")
		}
		cur, err := m.Repo.GetExtensionInstallState(ctx, item.ExtensionID, tx.Scope, tx.ScopeID)
		if errors.Is(err, repository.ErrNotFound) {
			cur = model.ExtensionInstall{CurrentState: model.ExtensionInstallStateAbsent}
		} else if err != nil {
			return err
		}
		mutated := false
		switch item.Operation {
		case "install":
			if cur.CurrentState != model.ExtensionInstallStateAbsent {
				if cur.CurrentVersion != item.ToVersion {
					return fmt.Errorf("in-flight install %s has unexpected current version %s", item.ExtensionID, cur.CurrentVersion)
				}
				mutated = true
			}
		case "update":
			switch cur.CurrentVersion {
			case item.ToVersion:
				mutated = true
			case item.FromVersion:
				mutated = false
			default:
				return fmt.Errorf("in-flight update %s has unexpected current version %s", item.ExtensionID, cur.CurrentVersion)
			}
		default:
			return fmt.Errorf("unsupported in-flight operation %q", item.Operation)
		}
		if mutated {
			tx.Applied = append(tx.Applied, item.ExtensionID)
		}
		tx.InFlight = ""
		if _, err := m.Repo.SaveExtensionUpdateTransaction(context.Background(), tx); err != nil {
			return err
		}
	}

	rolled := map[string]struct{}{}
	for _, id := range tx.RolledBack {
		rolled[id] = struct{}{}
	}
	var rbErrs []string
	for i := len(tx.Applied) - 1; i >= 0; i-- {
		id := tx.Applied[i]
		if _, done := rolled[id]; done {
			continue
		}
		item, ok := planItem02011(tx.Plan, id)
		if !ok {
			rbErrs = append(rbErrs, id+": missing plan item")
			continue
		}
		if m.Host != nil {
			_ = m.Host.Stop(context.Background(), extensionhost.Key{ExtensionID: id, Scope: tx.Scope, ScopeID: tx.ScopeID})
		}
		cur, getErr := m.Repo.GetExtensionInstallState(context.Background(), id, tx.Scope, tx.ScopeID)
		alreadyRestored := false
		if errors.Is(getErr, repository.ErrNotFound) {
			alreadyRestored = item.Operation == "install"
		} else if getErr != nil {
			rbErrs = append(rbErrs, id+": "+getErr.Error())
			continue
		} else if item.Operation == "install" {
			alreadyRestored = cur.CurrentState == model.ExtensionInstallStateAbsent
		} else if item.Operation == "update" {
			alreadyRestored = cur.CurrentVersion == item.FromVersion
		}
		var opErr error
		if !alreadyRestored {
			switch item.Operation {
			case "install":
				_, opErr = m.Lifecycle.Uninstall(context.Background(), id, scope02011(tx.Plan))
			case "update":
				if cur.CurrentVersion != item.ToVersion {
					opErr = fmt.Errorf("cannot safely recover from current version %s; expected %s or %s", cur.CurrentVersion, item.ToVersion, item.FromVersion)
				} else {
					_, opErr = m.Lifecycle.Rollback(context.Background(), id, scope02011(tx.Plan))
				}
			default:
				opErr = fmt.Errorf("unsupported operation %q", item.Operation)
			}
		}
		if opErr != nil {
			rbErrs = append(rbErrs, id+": "+opErr.Error())
			continue
		}
		tx.RolledBack = append(tx.RolledBack, id)
		rolled[id] = struct{}{}
		if _, err := m.Repo.SaveExtensionUpdateTransaction(context.Background(), tx); err != nil {
			rbErrs = append(rbErrs, id+": journal rollback: "+err.Error())
		}
	}

	if len(rbErrs) == 0 && m.Host != nil {
		for _, item := range tx.Plan.Items {
			cur, err := m.Repo.GetExtensionInstallState(context.Background(), item.ExtensionID, tx.Scope, tx.ScopeID)
			if errors.Is(err, repository.ErrNotFound) || cur.CurrentState != model.ExtensionInstallStateEnabled || !cur.Enabled {
				continue
			}
			if err != nil {
				rbErrs = append(rbErrs, item.ExtensionID+": "+err.Error())
				continue
			}
			if err := m.Host.StartInstallation(context.Background(), cur); errors.Is(err, extensionhost.ErrNoBackendTarget) {
				continue
			} else if err != nil {
				rbErrs = append(rbErrs, "restart "+item.ExtensionID+": "+err.Error())
				continue
			}
			if err := m.waitHealthy(context.Background(), cur, healthTimeout); err != nil {
				rbErrs = append(rbErrs, "health "+item.ExtensionID+": "+err.Error())
			}
		}
	}
	now := time.Now().UTC()
	tx.InFlight = ""
	tx.FinishedAt = &now
	if len(rbErrs) > 0 {
		tx.Status = "rollback_failed"
		tx.Failure = "automatic recovery failed: " + strings.Join(rbErrs, "; ")
		_, _ = m.Repo.SaveExtensionUpdateTransaction(context.Background(), tx)
		return errors.New(tx.Failure)
	}
	tx.Status = "rolled_back"
	if tx.Failure == "" {
		tx.Failure = "automatically rolled back after interrupted update transaction"
	} else {
		tx.Failure += "; automatically rolled back after interrupted update transaction"
	}
	_, err := m.Repo.SaveExtensionUpdateTransaction(context.Background(), tx)
	return err
}

func (m *Manager) fail(tx model.ExtensionUpdateTransaction, e error) (model.ExtensionUpdateTransaction, error) {
	now := time.Now().UTC()
	tx.Status = "failed"
	tx.Failure = e.Error()
	tx.FinishedAt = &now
	_, _ = m.Repo.SaveExtensionUpdateTransaction(context.Background(), tx)
	return tx, e
}
func (m *Manager) rollback(tx model.ExtensionUpdateTransaction, applied []appliedItem, snapshots map[string]model.ExtensionInstall, cause error) (model.ExtensionUpdateTransaction, error) {
	if m.Host != nil {
		for _, item := range tx.Plan.Items {
			_ = m.Host.Stop(context.Background(), extensionhost.Key{ExtensionID: item.ExtensionID, Scope: tx.Scope, ScopeID: tx.ScopeID})
		}
	}
	var rbErrs []string
	for i := len(applied) - 1; i >= 0; i-- {
		a := applied[i]
		var e error
		if a.InstalledNew {
			_, e = m.Lifecycle.Uninstall(context.Background(), a.Item.ExtensionID, scope02011(tx.Plan))
		} else {
			_, e = m.Lifecycle.Rollback(context.Background(), a.Item.ExtensionID, scope02011(tx.Plan))
		}
		if e != nil {
			rbErrs = append(rbErrs, a.Item.ExtensionID+": "+e.Error())
		} else {
			tx.RolledBack = append(tx.RolledBack, a.Item.ExtensionID)
			tx.InFlight = ""
			_, _ = m.Repo.SaveExtensionUpdateTransaction(context.Background(), tx)
		}
	}
	if m.Host != nil {
		for _, item := range tx.Plan.Items {
			old := snapshots[item.ExtensionID]
			if old.CurrentState == model.ExtensionInstallStateEnabled && old.Enabled {
				if e := m.Host.StartInstallation(context.Background(), old); e != nil && !errors.Is(e, extensionhost.ErrNoBackendTarget) {
					rbErrs = append(rbErrs, "restart "+item.ExtensionID+": "+e.Error())
				}
			}
		}
	}
	now := time.Now().UTC()
	tx.Failure = cause.Error()
	tx.FinishedAt = &now
	if len(rbErrs) > 0 {
		tx.Status = "rollback_failed"
		tx.Failure += "; rollback: " + strings.Join(rbErrs, "; ")
	} else {
		tx.Status = "rolled_back"
	}
	_, _ = m.Repo.SaveExtensionUpdateTransaction(context.Background(), tx)
	return tx, fmt.Errorf("multi-extension update %s: %w", tx.Status, cause)
}
