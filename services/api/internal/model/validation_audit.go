package model

import "time"

// ValidationAttempt03412 contains only opaque IDs, digests and bounded reason
// codes. It cannot certify a run and never contains user-supplied log text.
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
