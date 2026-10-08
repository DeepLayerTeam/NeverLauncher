package repository

import "gitflic.ru/skif4er/neverlauncher/services/api/internal/model"

// ProviderCredentialRepository является намеренно отдельный из Репозиторий так
// connectors/embedders тот делать не сохранять внешний обновление учётные данные оставаться
// исходник-compatible. Рабочий PostgreSQL и в памяти процесса тест репозиторий
// implement это в 0.11.6.
type ProviderCredentialRepository interface {
	GetProviderCredential(userID, provider string) (model.ProviderCredential, error)
	SaveProviderCredential(credential model.ProviderCredential) (model.ProviderCredential, error)
	DeleteProviderCredential(userID, provider string) error
}
