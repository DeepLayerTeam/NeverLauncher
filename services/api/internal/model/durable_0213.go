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

// DurableJob является сохранённый модульный работа используется для эксплуатация чей безопасность
// или корректность должен переживать процесс перезапуск. actor/action/resource tuple
// является намеренно сохранённый так авторизация может быть re-оцениваются в выполнение
// время вместо чем inherited из запрос тот создан задача.
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

// DurableScopeLease является база данных-основанный распределённый аренда. FencingToken является
// монотонно increased для каждый успешный acquisition и является проверен через
// необратимый эксплуатация до фиксация.
type DurableScopeLease struct {
	ScopeKey     string    `json:"scopeKey"`
	Owner        string    `json:"owner"`
	LeaseToken   string    `json:"leaseToken"`
	FencingToken int64     `json:"fencingToken"`
	ExpiresAt    time.Time `json:"expiresAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

// DurableOutboxEvent является записан в одинаковый транзакция как состояние изменять это
// описывает. Доставка является retried независимо и является идемпотентный.
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
