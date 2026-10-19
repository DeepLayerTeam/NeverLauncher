package repository

import (
	"context"
	"database/sql"
	"errors"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

// ChannelHeadReader makes CAS revisions observable without exposing draft releases.
type ChannelHeadReader interface {
	GetChannelHead(ctx context.Context, projectID, profileID, channel string) (model.ChannelHead, error)
}

func emptyHead0228(projectID, profileID, channel string) model.ChannelHead {
	return model.ChannelHead{ProjectID: projectID, ProfileID: profileID, Channel: channel}
}

func (r *SQLRepository) GetChannelHead(ctx context.Context, projectID, profileID, channel string) (model.ChannelHead, error) {
	h := emptyHead0228(projectID, profileID, channel)
	if err := r.check(); err != nil {
		return h, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	err := r.db.QueryRowContext(ctx, `SELECT revision,release_id,version,manifest_digest,updated_at FROM channel_heads WHERE project_id=$1 AND profile_id=$2 AND channel=$3`, projectID, profileID, channel).Scan(&h.Revision, &h.ReleaseID, &h.Version, &h.ManifestDigest, &h.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return h, nil
	}
	return h, err
}

func (r *MemoryRepository) GetChannelHead(_ context.Context, projectID, profileID, channel string) (model.ChannelHead, error) {
	r.durableMu.Lock()
	defer r.durableMu.Unlock()
	if h, ok := r.channelHeads[headKey0228(projectID, profileID, channel)]; ok {
		return h, nil
	}
	return emptyHead0228(projectID, profileID, channel), nil
}
func headKey0228(projectID, profileID, channel string) string {
	return projectID + "\x00" + profileID + "\x00" + channel
}
