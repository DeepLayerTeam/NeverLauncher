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

// enforceLiveTrust04210 читает устойчивую политику перед каждым привилегированным
// действием брокера и каждым проходом монитора. Кэшированные возможности hello
// никогда не являются грантом: токен, выданный до экстренного отключения,
// карантина, обновления или отзыва ключа издателя, не должен разрешать команды
// работающего процесса.
func (s *Supervisor) enforceLiveTrust04210(ctx context.Context, st *processState) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	key, install := st.key.normalized(), st.install
	if _, err := s.repo.GetExtensionEmergencyDisable(ctx, key.ExtensionID, key.Scope, key.ScopeID); err == nil {
		return errors.New("Расширение аварийно отключено")
	} else if !errors.Is(err, repository.ErrNotFound) {
		return fmt.Errorf("Политика аварийного отключения расширения недоступна: %w", err)
	}
	if install.CurrentPackageIdentity != "" {
		quarantined, err := s.repo.IsExtensionPackageQuarantined(ctx, install.CurrentPackageIdentity)
		if err != nil {
			return fmt.Errorf("Политика карантина расширения недоступна: %w", err)
		}
		if quarantined {
			return errors.New("Пакет расширения помещён в карантин")
		}
	}
	current, err := s.repo.GetExtensionInstallState(ctx, key.ExtensionID, key.Scope, key.ScopeID)
	signed := strings.HasPrefix(install.Source, "registry:") || (strings.HasPrefix(install.Source, "rollback:") && install.CurrentPackageIdentity != "")
	if signed && install.CurrentPackageIdentity == "" {
		return errors.New("У подписанного расширения отсутствует идентификатор пакета")
	}
	if err == nil {
		if !current.Enabled || current.CurrentState != model.ExtensionInstallStateEnabled ||
			current.Generation != install.Generation || current.CurrentVersion != install.CurrentVersion ||
			current.CurrentPackageIdentity != install.CurrentPackageIdentity {
			return errors.New("Установка расширения отключена, изменена или заменена")
		}
	} else if !errors.Is(err, repository.ErrNotFound) {
		return fmt.Errorf("Состояние расширения недоступно: %w", err)
	} else if signed {
		return errors.New("Подписанная установка расширения больше не существует")
	}
	if signed {
		publication, err := s.repo.GetExtensionRegistryVersion(ctx, key.ExtensionID, install.CurrentVersion)
		if err != nil {
			return fmt.Errorf("Публикация расширения недоступна: %w", err)
		}
		if publication.Artifact.PackageIdentity != install.CurrentPackageIdentity {
			return errors.New("Идентификатор публикации расширения изменился")
		}
		if _, err := extensiontrust.EvaluatePublication(ctx, s.repo, publication); err != nil {
			return fmt.Errorf("Доверие к издателю расширения отозвано: %w", err)
		}
	}
	return nil
}

// denyRevokedHost04210 предотвращает перезапуск процесса с отозванными
// устойчивыми полномочиями. Само устойчивое запрещение/переход выполняет операция
// владельца; супервизор обеспечивает запрет даже при гонке этой операции с RPC.
func (s *Supervisor) denyRevokedHost04210(st *processState, err error) {
	if err == nil {
		return
	}
	s.failProcess(st, "extension-live-trust-denied: "+err.Error(), true)
}
