package model

import (
	"encoding/json"
	"time"
)

const (
	ExtensionEventModeAsync = "async"
	ExtensionEventModeSync  = "sync"
)

type ExtensionEvent struct {
	Sequence       int64           `json:"sequence"`
	ID             string          `json:"id"`
	Type           string          `json:"type"`
	SchemaVersion  int             `json:"schemaVersion"`
	ProjectID      string          `json:"projectId,omitempty"`
	AggregateType  string          `json:"aggregateType"`
	AggregateID    string          `json:"aggregateId"`
	OrderingKey    string          `json:"orderingKey"`
	IdempotencyKey string          `json:"idempotencyKey"`
	Source         string          `json:"source"`
	Payload        json.RawMessage `json:"payload"`
	PayloadSHA256  string          `json:"payloadSha256"`
	OccurredAt     time.Time       `json:"occurredAt"`
	CreatedAt      time.Time       `json:"createdAt"`
}

type ExtensionEventSubscription struct {
	ID          int64     `json:"id"`
	ExtensionID string    `json:"extensionId"`
	Scope       string    `json:"scope"`
	ScopeID     string    `json:"scopeId,omitempty"`
	EventType   string    `json:"eventType"`
	Mode        string    `json:"mode"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

type ExtensionEventDelivery struct {
	ID             int64      `json:"id"`
	EventSequence  int64      `json:"eventSequence"`
	SubscriptionID int64      `json:"subscriptionId"`
	Status         string     `json:"status"`
	AttemptCount   int        `json:"attemptCount"`
	NextAttemptAt  time.Time  `json:"nextAttemptAt"`
	LeaseUntil     *time.Time `json:"leaseUntil,omitempty"`
	LeaseToken     string     `json:"-"`
	LastError      string     `json:"lastError,omitempty"`
	DeliveredAt    *time.Time `json:"deliveredAt,omitempty"`
	CreatedAt      time.Time  `json:"createdAt"`
	UpdatedAt      time.Time  `json:"updatedAt"`
}

type ExtensionEventDeliveryEnvelope struct {
	Delivery     ExtensionEventDelivery     `json:"delivery"`
	Event        ExtensionEvent             `json:"event"`
	Subscription ExtensionEventSubscription `json:"subscription"`
}

type ExtensionEventDeadLetter struct {
	ID             int64          `json:"id"`
	DeliveryID     int64          `json:"deliveryId"`
	EventSequence  int64          `json:"eventSequence"`
	SubscriptionID int64          `json:"subscriptionId"`
	ExtensionID    string         `json:"extensionId"`
	EventType      string         `json:"eventType"`
	Attempts       int            `json:"attempts"`
	LastError      string         `json:"lastError"`
	Event          ExtensionEvent `json:"event"`
	DeadAt         time.Time      `json:"deadAt"`
}

type ExtensionHookResult struct {
	OK      bool   `json:"ok"`
	Message string `json:"message,omitempty"`
}
