package httpapi

import (
	"errors"
	"net/http"

	"gitflic.ru/skif4er/launcher/services/api/internal/authrequest"
)

// decodeSensitiveRequest0300 refuses ambiguous/oversized JSON before credential
// verification, identity linking or any irreversible session/policy mutation.
func decodeSensitiveRequest0300(w http.ResponseWriter, r *http.Request, destination any) bool {
	if err := authrequest.Decode(r.Body, destination); err != nil {
		if errors.Is(err, authrequest.ErrTooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "authentication/protection request exceeds 16 KiB")
		} else {
			writeError(w, http.StatusBadRequest, "некорректный JSON")
		}
		return false
	}
	return true
}
