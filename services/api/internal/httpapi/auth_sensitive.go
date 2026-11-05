package httpapi

import (
	"errors"
	"net/http"

	"gitflic.ru/skif4er/launcher/services/api/internal/authrequest"
)

// decodeSensitiveRequest0300 отклоняет неоднозначный или чрезмерный JSON до проверки
// учётных данных, привязки идентичности и любого необратимого изменения сессии или
// политики.
func decodeSensitiveRequest0300(w http.ResponseWriter, r *http.Request, destination any) bool {
	if err := authrequest.Decode(r.Body, destination); err != nil {
		if errors.Is(err, authrequest.ErrTooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "Запрос авторизации или защиты превышает 16 КиБ")
		} else {
			writeError(w, http.StatusBadRequest, "некорректный JSON")
		}
		return false
	}
	return true
}
