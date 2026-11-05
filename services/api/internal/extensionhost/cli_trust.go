package extensionhost

import (
	"context"
	"errors"
	"fmt"
)

// enforceCLITrust04312 проверяет ТЕКУЩУЮ установку, издателя и грант
// возможностей, а не права в момент запуска команды. Его используют и RunCLI, и
// монитор процесса. Ошибка чтения репозитория означает отказ, никогда не неявное
// разрешение.
func (s *Supervisor) enforceCLITrust04312(ctx context.Context, st *processState) error {
	if err := s.enforceLiveTrust04210(ctx, st); err != nil {
		return err
	}
	security := s.securityValue0207()
	if security == nil {
		return errors.New("Система защиты разрешений CLI недоступна")
	}
	projectID := ""
	if st.key.Scope == "project" {
		projectID = st.key.ScopeID
	}
	ok, err := security.Allowed(ctx, st.key.ExtensionID, st.install.CurrentVersion,
		st.key.Scope, st.key.ScopeID, "cli:contribute", projectID)
	if err != nil {
		return fmt.Errorf("Политика разрешений CLI недоступна: %w", err)
	}
	if !ok {
		return errors.New("Разрешение cli:contribute отозвано")
	}
	return nil
}
