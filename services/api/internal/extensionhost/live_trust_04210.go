package extensionhost

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"gitflic.ru/skif4er/launcher/services/api/internal/extensiontrust"
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
)

// enforceLiveTrust04210 reads durable policy for each privileged broker action
// and each monitor pass. Cached hello capabilities are never a grant: a token
// issued before an emergency disable, quarantine, update or publisher-key
// revocation must not keep authorizing commands on a running process.
func (s *Supervisor) enforceLiveTrust04210(ctx context.Context, st *processState) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	key, install := st.key.normalized(), st.install
	if _, err := s.repo.GetExtensionEmergencyDisable(ctx, key.ExtensionID, key.Scope, key.ScopeID); err == nil {
		return errors.New("extension emergency-disabled")
	} else if !errors.Is(err, repository.ErrNotFound) {
		return fmt.Errorf("extension emergency policy unavailable: %w", err)
	}
	if install.CurrentPackageIdentity != "" {
		quarantined, err := s.repo.IsExtensionPackageQuarantined(ctx, install.CurrentPackageIdentity)
		if err != nil {
			return fmt.Errorf("extension quarantine policy unavailable: %w", err)
		}
		if quarantined {
			return errors.New("extension package quarantined")
		}
	}
	current, err := s.repo.GetExtensionInstallState(ctx, key.ExtensionID, key.Scope, key.ScopeID)
	signed := strings.HasPrefix(install.Source, "registry:") || (strings.HasPrefix(install.Source, "rollback:") && install.CurrentPackageIdentity != "")
	if signed && install.CurrentPackageIdentity == "" {
		return errors.New("signed extension has no package identity")
	}
	if err == nil {
		if !current.Enabled || current.CurrentState != model.ExtensionInstallStateEnabled ||
			current.Generation != install.Generation || current.CurrentVersion != install.CurrentVersion ||
			current.CurrentPackageIdentity != install.CurrentPackageIdentity {
			return errors.New("extension installation disabled, changed or replaced")
		}
	} else if !errors.Is(err, repository.ErrNotFound) {
		return fmt.Errorf("extension state unavailable: %w", err)
	} else if signed {
		return errors.New("signed extension installation no longer exists")
	}
	if signed {
		publication, err := s.repo.GetExtensionRegistryVersion(ctx, key.ExtensionID, install.CurrentVersion)
		if err != nil {
			return fmt.Errorf("extension publication unavailable: %w", err)
		}
		if publication.Artifact.PackageIdentity != install.CurrentPackageIdentity {
			return errors.New("extension publication identity changed")
		}
		if _, err := extensiontrust.EvaluatePublication(ctx, s.repo, publication); err != nil {
			return fmt.Errorf("extension publisher trust revoked: %w", err)
		}
	}
	return nil
}

// denyRevokedHost04210 prevents restart of a process whose durable authority
// has been withdrawn. The actual durable ban/transition belongs to the owner
// operation; this supervisor enforces it even when that operation races RPC.
func (s *Supervisor) denyRevokedHost04210(st *processState, err error) {
	if err == nil {
		return
	}
	s.failProcess(st, "extension-live-trust-denied: "+err.Error(), true)
}
