package model

import (
	"encoding/json"
	"time"
)

const (
	DurableJobStatusPending   = "pending"
	DurableJobStatusRunning   = "running"
	DurableJobStatusSucceeded = "succeeded"
	DurableJobStatusFailed    = "failed"
	DurableJobStatusRevoked   = "revoked"
	DurableJobStatusDead      = "dead"

	OutboxStatusPending   = "pending"
	OutboxStatusRunning   = "running"
	OutboxStatusDelivered = "delivered"
	OutboxStatusDead      = "dead"
)

// DurableJob — сохраняемая единица работы для действий, безопасность или
// корректность которых должна пережить рестарт процесса. Кортеж
// actor/action/resource хранится специально, чтобы авторизацию можно было
// повторно проверить при исполнении, а не наследовать от создающего запрос.
type DurableJob struct {
	ID             string          `json:"id"`
	Kind           string          `json:"kind"`
	ActorType      string          `json:"actorType"`
	ActorID        string          `json:"actorId"`
	Action         string          `json:"action"`
	ProjectID      string          `json:"projectId,omitempty"`
	ResourceType   string          `json:"resourceType"`
	ResourceID     string          `json:"resourceId"`
	IdempotencyKey string          `json:"idempotencyKey"`
	Payload        json.RawMessage `json:"payload"`
	PayloadDigest  string          `json:"payloadDigest"`
	Status         string          `json:"status"`
	LeaseOwner     string          `json:"leaseOwner,omitempty"`
	LeaseToken     string          `json:"leaseToken,omitempty"`
	LeaseFence     int64           `json:"leaseFence"`
	LeaseExpiresAt time.Time       `json:"leaseExpiresAt,omitempty"`
	AttemptCount   int             `json:"attemptCount"`
	MaxAttempts    int             `json:"maxAttempts"`
	AvailableAt    time.Time       `json:"availableAt"`
	LastError      string          `json:"lastError,omitempty"`
	Result         json.RawMessage `json:"result,omitempty"`
	CreatedAt      time.Time       `json:"createdAt"`
	UpdatedAt      time.Time       `json:"updatedAt"`
	CompletedAt    time.Time       `json:"completedAt,omitempty"`
}

type DurableJobAttempt struct {
	ID         int64     `json:"id"`
	JobID      string    `json:"jobId"`
	Attempt    int       `json:"attempt"`
	WorkerID   string    `json:"workerId"`
	LeaseFence int64     `json:"leaseFence"`
	StartedAt  time.Time `json:"startedAt"`
	FinishedAt time.Time `json:"finishedAt,omitempty"`
	Status     string    `json:"status"`
	Error      string    `json:"error,omitempty"`
}

// DurableScopeLease — распределённая аренда в БД. FencingToken
// монотонно увеличивается при каждом успешном получении и
// проверяется перед фиксацией необратимых операций.
type DurableScopeLease struct {
	ScopeKey     string    `json:"scopeKey"`
	Owner        string    `json:"owner"`
	LeaseToken   string    `json:"leaseToken"`
	FencingToken int64     `json:"fencingToken"`
	ExpiresAt    time.Time `json:"expiresAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

// DurableOutboxEvent записывается одной транзакцией с описываемым
// изменением состояния. Доставка повторяется независимо и идемпотентно.
type DurableOutboxEvent struct {
	ID             string          `json:"id"`
	EventType      string          `json:"eventType"`
	ProjectID      string          `json:"projectId,omitempty"`
	AggregateType  string          `json:"aggregateType"`
	AggregateID    string          `json:"aggregateId"`
	ActorID        string          `json:"actorId,omitempty"`
	IdempotencyKey string          `json:"idempotencyKey"`
	Payload        json.RawMessage `json:"payload"`
	Status         string          `json:"status"`
	LeaseOwner     string          `json:"leaseOwner,omitempty"`
	LeaseToken     string          `json:"leaseToken,omitempty"`
	LeaseFence     int64           `json:"leaseFence"`
	LeaseExpiresAt time.Time       `json:"leaseExpiresAt,omitempty"`
	AttemptCount   int             `json:"attemptCount"`
	MaxAttempts    int             `json:"maxAttempts"`
	AvailableAt    time.Time       `json:"availableAt"`
	LastError      string          `json:"lastError,omitempty"`
	CreatedAt      time.Time       `json:"createdAt"`
	UpdatedAt      time.Time       `json:"updatedAt"`
	DeliveredAt    time.Time       `json:"deliveredAt,omitempty"`
}

type DurablePublishPayload struct {
	PackageID              string `json:"packageId"`
	ExpectedManifestDigest string `json:"expectedManifestDigest"`
	ExpectedArtifactDigest string `json:"expectedArtifactDigest"`
	ExpectedStatus         string `json:"expectedStatus"`
}

type DurablePublishCommit struct {
	JobID                  string
	JobLeaseToken          string
	ScopeKey               string
	ScopeLeaseToken        string
	ScopeFencingToken      int64
	ExpectedManifestDigest string
	ExpectedArtifactDigest string
	ExpectedStatus         string
	ActorID                string
}
