package model

import "time"

// ValidationAttempt03412 содержит только непрозрачные ID, хеши и ограниченные коды
// причин. Он не может сертифицировать запуск и никогда не содержит текст журнала
// пользователя.
type ValidationAttempt03412 struct {
	ID            int64     `json:"id"`
	PackageID     string    `json:"packageId"`
	RunID         string    `json:"runId,omitempty"`
	Kind          string    `json:"kind"`
	Outcome       string    `json:"outcome"`
	ReasonCode    string    `json:"reasonCode"`
	PayloadSHA256 string    `json:"payloadSha256"`
	CreatedAt     time.Time `json:"createdAt"`
}
