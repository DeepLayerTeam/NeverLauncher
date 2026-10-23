package model

import "time"

// TextureAssignment0251 is a revisioned selection, not the underlying PNG blob.
// UUID belongs to MinecraftProfile; project and launcher-profile identifiers are distinct.
type TextureAssignment0251 struct {
	ID                int64     `json:"id"`
	Realm             string    `json:"realm"`
	ProfileUUID       string    `json:"profileUuid"`
	UserID            string    `json:"userId"`
	ProjectID         string    `json:"projectId"`
	LauncherProfileID string    `json:"launcherProfileId"`
	Kind              string    `json:"kind"`
	BlobDigest        string    `json:"blobDigest,omitempty"`
	ExternalURL       string    `json:"externalUrl,omitempty"`
	Source            string    `json:"source"`
	Model             string    `json:"model"`
	Visibility        string    `json:"visibility"`
	Revision          int64     `json:"revision"`
	Active            bool      `json:"active"`
	UpdatedAt         time.Time `json:"updatedAt"`
}

type TextureRevision0251 struct {
	AssignmentID int64     `json:"assignmentId"`
	Revision     int64     `json:"revision"`
	Snapshot     []byte    `json:"-"`
	ActorUserID  string    `json:"actorUserId"`
	Reason       string    `json:"reason"`
	Event        string    `json:"event"`
	CreatedAt    time.Time `json:"createdAt"`
}
