package extensionhost

import (
	"context"
	"errors"
	"fmt"
)

// enforceCLITrust04312 checks the *current* installation, publisher and
// capability grant, not the permissions captured when the command started.
// Both RunCLI and the process monitor use it. A failed repository read is a
// denial, never an implicit grant.
func (s *Supervisor) enforceCLITrust04312(ctx context.Context, st *processState) error {
	if err := s.enforceLiveTrust04210(ctx, st); err != nil {
		return err
	}
	security := s.securityValue0207()
	if security == nil {
		return errors.New("CLI capability security unavailable")
	}
	projectID := ""
	if st.key.Scope == "project" {
		projectID = st.key.ScopeID
	}
	ok, err := security.Allowed(ctx, st.key.ExtensionID, st.install.CurrentVersion,
		st.key.Scope, st.key.ScopeID, "cli:contribute", projectID)
	if err != nil {
		return fmt.Errorf("CLI permission policy unavailable: %w", err)
	}
	if !ok {
		return errors.New("cli:contribute permission revoked")
	}
	return nil
}
