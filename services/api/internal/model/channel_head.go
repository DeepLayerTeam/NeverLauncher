package model

import "time"

// ChannelHead определяет единственный видимый релиз для сочетания проект/профиль/канал.
// Нулевая ревизия означает, что в канал ещё ничего не публиковали.
type ChannelHead struct {
	ProjectID      string    `json:"projectId"`
	ProfileID      string    `json:"profileId"`
	Channel        string    `json:"channel"`
	Revision       int64     `json:"revision"`
	ReleaseID      string    `json:"releaseId,omitempty"`
	Version        string    `json:"version,omitempty"`
	ManifestDigest string    `json:"manifestDigest,omitempty"`
	UpdatedAt      time.Time `json:"updatedAt,omitempty"`
}
