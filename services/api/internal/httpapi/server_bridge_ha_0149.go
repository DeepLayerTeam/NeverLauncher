package httpapi

import (
	"context"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

const (
	serverBridgeMaintenanceInterval0149 = 30 * time.Second
	serverBridgeMaintenanceTimeout01410 = 5 * time.Second
	serverBridgeRequestTimeout0149      = 8 * time.Second
)

// maybeMaintain0149 является opportunistic через design: любой работоспособный API реплика может
// trigger обслуживание после сигнал состояния, пока PostgreSQL pg_try_рекомендательный_xact_блокировка
// guarantees только один реплика выполняет очистка в given успешно.
func (b *serverBridgeStore) maybeMaintain0149() {
	if b == nil {
		return
	}
	backend := b.backendV2()
	if backend == nil {
		return
	}
	now := time.Now().UTC()
	b.mu.Lock()
	if b.nextMaintenanceAt.After(now) {
		b.mu.Unlock()
		return
	}
	b.nextMaintenanceAt = now.Add(serverBridgeMaintenanceInterval0149)
	b.mu.Unlock()

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), serverBridgeMaintenanceTimeout01410)
		defer cancel()
		result, err := backend.MaintainServerBridge(ctx, now)
		b.mu.Lock()
		b.lastMaintenance = result
		if err != nil {
			b.lastMaintenanceErr = err.Error()
		} else {
			b.lastMaintenanceErr = ""
		}
		b.mu.Unlock()
	}()
}

func (b *serverBridgeStore) haStatus0149() (model.ServerBridgeHAStatus, error) {
	backend := b.backendV2()
	if backend == nil {
		return model.ServerBridgeHAStatus{}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()
	return backend.ServerBridgeHAStatus(ctx, time.Now().UTC())
}

func (b *serverBridgeStore) maintenanceSnapshot0149() (model.ServerBridgeMaintenanceResult, string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.lastMaintenance, b.lastMaintenanceErr
}
