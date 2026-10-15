package repository

import "gitflic.ru/skif4er/neverlauncher/services/api/internal/model"

// ProviderCredentialRepository намеренно отделён от Repository, чтобы
// коннекторы и встроенные интеграции без постоянного хранения внешних
// refresh-токенов оставались совместимыми на уровне исходного кода.
// Реализован для PostgreSQL и тестового репозитория в памяти начиная с 0.11.6.
type ProviderCredentialRepository interface {
	GetProviderCredential(userID, provider string) (model.ProviderCredential, error)
	SaveProviderCredential(credential model.ProviderCredential) (model.ProviderCredential, error)
	DeleteProviderCredential(userID, provider string) error
}
