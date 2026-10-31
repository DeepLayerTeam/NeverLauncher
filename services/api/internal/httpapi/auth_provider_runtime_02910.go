package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/authrequest"
	"gitflic.ru/skif4er/launcher/services/api/internal/federation"
	"gitflic.ru/skif4er/launcher/services/api/internal/httpconnector"
	"gitflic.ru/skif4er/launcher/services/api/internal/microsoftconnector"
	"gitflic.ru/skif4er/launcher/services/api/internal/oidcconnector"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
	"gitflic.ru/skif4er/launcher/services/api/internal/sqlconnector"
	"gitflic.ru/skif4er/launcher/services/api/pkg/authconnector"
	"gitflic.ru/skif4er/launcher/services/api/pkg/authconnector/conformance"
)

type managedProbe02910 struct {
	Connector authconnector.Connector     `json:"-"`
	Policy    federation.ProviderPolicy   `json:"-"`
	Metadata  authconnector.Metadata      `json:"metadata"`
	Mapping   []sqlconnector.MappedColumn `json:"mapping,omitempty"`
	Status    string                      `json:"status"`
}

func strictProviderConfig02910(raw json.RawMessage, dest any) error {
	return authrequest.Decode(bytes.NewReader(raw), dest)
}

// Prevent secret material reaching the DB, API responses, audit or browser.
// All credentials must be injected in the API process via explicitly named env
// variables; paths to secret files and inline DB connection strings are rejected.
func validateManagedSecrets02910(v repository.ManagedProviderRevision02910) error {
	if err := repository.ValidateManagedProviderDraft02910(v); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := strictProviderConfig02910(v.Config, &fields); err != nil {
		return err
	}
	var banned func(map[string]json.RawMessage) error
	banned = func(m map[string]json.RawMessage) error {
		for key, raw := range m {
			low := strings.ToLower(key)
			switch low {
			case "dsn", "password", "secret", "clientsecret", "clientsecretfile", "secretfile", "keyfile", "certfile", "cafile", "privatekey", "accesstoken", "refreshtoken", "token", "hmacsecret", "connectionstring":
				return fmt.Errorf("inline secrets or secret file paths are forbidden: %s", key)
			}
			if strings.Contains(low, "secret") && !strings.HasSuffix(low, "secretenv") {
				return fmt.Errorf("secret field forbidden: %s", key)
			}
			var nested map[string]json.RawMessage
			if len(raw) > 0 && raw[0] == '{' && json.Unmarshal(raw, &nested) == nil {
				if err := banned(nested); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := banned(fields); err != nil {
		return err
	}
	// Require an exact ID match, to prevent a staged configuration replacing an
	// unrelated issuer/provider during activation.
	var identity struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(v.Config, &identity); err != nil {
		return err
	}
	if identity.ID != v.ID {
		return errors.New("provider id and config id must match")
	}
	// Enforce the actual connector's strict schema before any JSON is stored;
	// otherwise arbitrary unknown fields can smuggle raw credentials into history.
	switch v.Kind {
	case "sql":
		var cfg sqlconnector.Config
		if err := strictProviderConfig02910(v.Config, &cfg); err != nil {
			return err
		}
		if cfg.DSNEnv == "" || cfg.DSN != "" {
			return errors.New("SQL requires dsnEnv only")
		}
	case "http":
		var cfg httpconnector.Config
		if err := strictProviderConfig02910(v.Config, &cfg); err != nil {
			return err
		}
		if cfg.HMAC.SecretEnv == "" || cfg.HMAC.SecretFile != "" {
			return errors.New("HTTP requires hmac.secretEnv only")
		}
	case "oidc":
		var cfg oidcconnector.Config
		if err := strictProviderConfig02910(v.Config, &cfg); err != nil {
			return err
		}
		if cfg.ClientSecretFile != "" {
			return errors.New("OIDC secret files are unsupported")
		}
	case "microsoft":
		var cfg microsoftconnector.Config
		if err := strictProviderConfig02910(v.Config, &cfg); err != nil {
			return err
		}
		if cfg.ClientSecretFile != "" {
			return errors.New("Microsoft secret files are unsupported")
		}
	}
	return nil
}
func createManagedProvider02910(ctx context.Context, v repository.ManagedProviderRevision02910) (managedProbe02910, error) {
	var out managedProbe02910
	if err := validateManagedSecrets02910(v); err != nil {
		return out, err
	}
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	var conn authconnector.Connector
	var policy federation.ProviderPolicy
	switch v.Kind {
	case "sql":
		var cfg sqlconnector.Config
		if err := strictProviderConfig02910(v.Config, &cfg); err != nil {
			return out, err
		}
		if cfg.DSNEnv == "" {
			return out, errors.New("SQL provider must use dsnEnv")
		}
		normalized, err := sqlconnector.Normalize(cfg)
		if err != nil {
			return out, err
		}
		c, err := sqlconnector.New(ctx, cfg)
		if err != nil {
			return out, err
		}
		conn = c
		policy = federation.ProviderPolicy{AutoProvision: normalized.Provisioning.Mode == "jit", DefaultRole: normalized.Provisioning.DefaultRole}
		mapping, err := c.MappingPreview(ctx)
		if err != nil {
			c.Close()
			return out, err
		}
		out.Mapping = mapping
	case "http":
		var cfg httpconnector.Config
		if err := strictProviderConfig02910(v.Config, &cfg); err != nil {
			return out, err
		}
		if cfg.HMAC.SecretEnv == "" {
			return out, errors.New("HTTP provider must use hmac.secretEnv")
		}
		c, err := httpconnector.New(ctx, cfg)
		if err != nil {
			return out, err
		}
		conn = c
		policy = federation.ProviderPolicy{AutoProvision: c.ProvisioningMode() == "jit", DefaultRole: c.DefaultRole()}
	case "oidc":
		var cfg oidcconnector.Config
		if err := strictProviderConfig02910(v.Config, &cfg); err != nil {
			return out, err
		}
		c, err := oidcconnector.New(ctx, cfg)
		if err != nil {
			return out, err
		}
		conn = c
		policy = federation.ProviderPolicy{AutoProvision: c.ProvisioningMode() == "jit", DefaultRole: c.DefaultRole(), RoleMappings: cfg.RoleMappings}
	case "microsoft":
		var cfg microsoftconnector.Config
		if err := strictProviderConfig02910(v.Config, &cfg); err != nil {
			return out, err
		}
		c, err := microsoftconnector.New(ctx, cfg)
		if err != nil {
			return out, err
		}
		conn = c
		policy = federation.ProviderPolicy{AutoProvision: c.ProvisioningMode() == "jit", DefaultRole: c.DefaultRole(), RoleMappings: c.RoleMappings()}
	default:
		return out, errors.New("unsupported provider kind")
	}
	report := conformance.Run(ctx, conn)
	if !report.Passed {
		_ = closeManaged02910(conn)
		return out, errors.New("live connector failed SDK conformance")
	}
	out.Connector = conn
	out.Policy = policy
	out.Metadata = authconnector.NormalizedMetadata(conn.Metadata())
	out.Status = "healthy"
	return out, nil
}
func closeManaged02910(c authconnector.Connector) error {
	if closer, ok := c.(interface{ Close() error }); ok {
		return closer.Close()
	}
	return nil
}

// Active revisions are reconciled before auth requests on every API replica.
// A DB error fails closed; no stale provider is used as a fallback.
func (s Server) syncManagedProviders02910(ctx context.Context) error {
	store, ok := s.Repo.(repository.ManagedProviderStore02910)
	if !ok {
		return nil
	}
	if s.Federation == nil {
		return errors.New("federation unavailable")
	}
	return s.Federation.WithManagedSync(func() error {
		reader, ok := store.(repository.ActiveManagedProviderReader02910)
		if !ok {
			return errors.New("active provider reader unavailable")
		}
		active, err := reader.ListActiveManagedProviders02910(ctx)
		if err != nil {
			return err
		}
		seen := make(map[string]bool, len(active))
		for _, candidate := range active {
			seen[candidate.ID] = true
			if s.Federation.ManagedRevision(candidate.ID) == candidate.Revision {
				continue
			}
			probe, err := createManagedProvider02910(ctx, candidate)
			if err != nil {
				return err
			}
			if err = s.Federation.SwapManaged(probe.Connector, probe.Policy, candidate.Revision); err != nil {
				_ = closeManaged02910(probe.Connector)
				return err
			}
		}
		for _, id := range s.Federation.ManagedIDs() {
			if !seen[id] {
				if err := s.Federation.DisableManaged(id); err != nil {
					return err
				}
			}
		}
		return nil
	})
}
func (s Server) withManagedProviders02910(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		// Admin recovery remains available when an active configuration is broken.
		if strings.HasPrefix(path, "/api/v1/admin/auth/provider-wizard") || !(strings.HasPrefix(path, "/api/v1/auth/") || strings.HasPrefix(path, "/api/v1/admin/login") || strings.HasPrefix(path, "/authserver/") || strings.HasPrefix(path, "/api/v1/minecraft/") || strings.HasPrefix(path, "/api/v1/server-bridge/")) {
			next.ServeHTTP(w, r)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		if err := s.syncManagedProviders02910(ctx); err != nil {
			writeError(w, http.StatusServiceUnavailable, "auth provider runtime cannot be synchronized")
			return
		}
		next.ServeHTTP(w, r)
	})
}
