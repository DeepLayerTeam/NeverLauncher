package model

import "time"

// ChannelHead identifies the only visible release of a (project, profile, channel).
// Revision zero means no release has ever been published to this channel.
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
