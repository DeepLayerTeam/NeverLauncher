package repository

import "gitflic.ru/skif4er/neverlauncher/services/api/internal/model"

// ProviderCredentialRepository is intentionally separate from Repository so
// connectors/embedders that do not persist external refresh credentials remain
// source-compatible. Production PostgreSQL and the in-memory test repository
// implement it in 0.11.6.
type ProviderCredentialRepository interface {
	GetProviderCredential(userID, provider string) (model.ProviderCredential, error)
	SaveProviderCredential(credential model.ProviderCredential) (model.ProviderCredential, error)
	DeleteProviderCredential(userID, provider string) error
}
