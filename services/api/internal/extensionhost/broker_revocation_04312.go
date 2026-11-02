package extensionhost

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// revalidateCapability04312 closes the authorization-to-response gap for
// secret and data reads. Side effects remain subject to checks in their
// individual brokers; this additional gate prevents revoked instances from
// receiving results computed before the revoke committed.
func (s *Supervisor) revalidateCapability04312(ctx context.Context, st *processState, name string, req capabilityRequest) error {
	if err := s.enforceLiveTrust04210(ctx, st); err != nil {
		s.denyRevokedHost04210(st, err)
		return err
	}
	var permission string
	switch name {
	case "host.health", "extension.self":
		return nil
	case "project.get", "project.list", "profile.list", "profile.get", "job.get":
		permission = "project:read"
	case "release.list", "release.get", "release.page", "channel.list", "channel.get":
		permission = "release:read"
	case "storage.read", "runtime.config.get", "runtime.storage.get", "fs.read":
		permission = "storage:read"
	case "runtime.config.put", "runtime.config.delete", "runtime.storage.put", "runtime.storage.delete", "fs.write":
		permission = "storage:write"
	case "secret.get":
		permission = "secrets:read"
	case "telemetry.emit":
		permission = "telemetry:write"
	case "http.fetch":
		permission = "http:outbound"
	default:
		return fmt.Errorf("unknown capability %q", name)
	}
	project := strings.TrimSpace(req.ProjectID)
	allowed, err := s.permissionAllowed0207(ctx, st, permission, project)
	if err != nil {
		return err
	}
	if !allowed {
		return fmt.Errorf("%s revoked", permission)
	}
	if name == "http.fetch" && req.SecretName != "" {
		secretAllowed, err := s.permissionAllowed0207(ctx, st, "secrets:read", st.key.ScopeID)
		if err != nil {
			return err
		}
		if !secretAllowed {
			return errors.New("secret permission revoked")
		}
	}
	return nil
}
