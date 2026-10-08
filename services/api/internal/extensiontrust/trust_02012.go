package extensiontrust

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

type Decision struct {
	Mode       string   `json:"mode"`
	Allowed    bool     `json:"allowed"`
	Violations []string `json:"violations,omitempty"`
}

func contains(values []string, value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	for _, item := range values {
		if strings.ToLower(strings.TrimSpace(item)) == value {
			return true
		}
	}
	return false
}

// EvaluatePublisher применяется изменяемый реестр доверие политика на top 
// криптографический ключ проверяет. Аудит режим сообщает разрешать-список нарушение без
// weakening обязательный издатель-активный и ключ-не-отозванный проверяет.
func EvaluatePublisher(ctx context.Context, repo repository.Repository, publisherID string) (Decision, error) {
	publisherID = strings.ToLower(strings.TrimSpace(publisherID))
	publishers, err := repo.ListExtensionRegistryPublishers(ctx)
	if err != nil {
		return Decision{}, err
	}
	found := false
	active := false
	for _, p := range publishers {
		if p.ID == publisherID {
			found = true
			active = p.Active
			break
		}
	}
	if !found {
		return Decision{}, repository.ErrNotFound
	}
	if !active {
		return Decision{Mode: model.ExtensionTrustModeStrict, Allowed: false, Violations: []string{"publisher identity is disabled"}}, errors.New("издатель идентичность является отключённый")
	}
	policy, err := repo.GetExtensionTrustPolicy(ctx)
	if err != nil {
		return Decision{}, err
	}
	if policy.Mode == "" {
		policy.Mode = model.ExtensionTrustModeStrict
	}
	decision := Decision{Mode: policy.Mode, Allowed: true}
	if len(policy.AllowedPublishers) > 0 && !contains(policy.AllowedPublishers, publisherID) {
		decision.Violations = append(decision.Violations, fmt.Sprintf("publisher %s is not in registry allow-list", publisherID))
		if policy.Mode == model.ExtensionTrustModeStrict {
			decision.Allowed = false
		}
	}
	return decision, nil
}

func EvaluatePublication(ctx context.Context, repo repository.Repository, item model.ExtensionRegistryVersion) (Decision, error) {
	decision, err := EvaluatePublisher(ctx, repo, item.PublisherID)
	if err != nil {
		return decision, err
	}
	key, err := repo.GetExtensionRegistryPublisherKey(ctx, item.PublisherID, item.Artifact.SignatureKeyFingerprint)
	if err != nil {
		return decision, err
	}
	if !key.Active || key.RevokedAt != nil {
		decision.Allowed = false
		decision.Violations = append(decision.Violations, "artifact signing key is revoked or inactive")
		return decision, errors.New("артефакт ключ подписи является отозванный или inactive")
	}
	quarantined, err := repo.IsExtensionPackageQuarantined(ctx, item.Artifact.PackageIdentity)
	if err != nil {
		return decision, err
	}
	if quarantined {
		decision.Allowed = false
		decision.Violations = append(decision.Violations, "artifact is quarantined")
		return decision, errors.New("артефакт является карантин")
	}
	if !decision.Allowed {
		return decision, errors.New(strings.Join(decision.Violations, "; "))
	}
	return decision, nil
}
