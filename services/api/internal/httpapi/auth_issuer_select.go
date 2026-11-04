package httpapi

import (
	"strings"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
)

// A provider-only credential operation is ambiguous if the user linked more
// than one issuer. Callers must explicitly select the exact stored issuer.
func selectedAuthIdentity0291(repo repository.Repository, userID, providerID, requestedIssuer string) (model.AuthIdentity, error) {
	providerID = strings.ToLower(strings.TrimSpace(providerID))
	requestedIssuer = strings.TrimSpace(requestedIssuer)
	var found model.AuthIdentity
	for _, item := range repo.ListAuthIdentities(userID) {
		if item.Provider != providerID {
			continue
		}
		if requestedIssuer != "" && item.Issuer != requestedIssuer {
			continue
		}
		if found.ID != "" {
			return model.AuthIdentity{}, repository.ErrConflict
		}
		found = item
	}
	if found.ID == "" {
		return model.AuthIdentity{}, repository.ErrNotFound
	}
	return found, nil
}
