package httpapi

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
)

var fallbackPackageMutation sync.Mutex

// lockPackageMutation — граница распределённых изменений в 0.21.3.
// SQL-развёртывания берут постоянную аренду с fencing, чтобы два API-процесса
// не меняли файлы и метаданные одного пакета одновременно. Mutex остаётся
// только для совместимости со старыми репозиториями без DurableControlPlane.
func (s Server) lockPackageMutation(ctx context.Context, scope string) (func(), error) {
	scope = strings.TrimSpace(scope)
	if scope == "" {
		return nil, errors.New("package mutation scope required")
	}
	if cp, ok := s.Repo.(repository.DurableControlPlane); ok {
		owner := randomWorkerID0213("mutation")
		const leaseTTL = 15 * time.Minute
		lease, err := cp.AcquireDurableScopeLease(ctx, scope, owner, leaseTTL)
		if err != nil {
			return nil, err
		}
		keepaliveCtx, cancelKeepalive := context.WithCancel(context.Background())
		keepaliveDone := make(chan struct{})
		go func() {
			defer close(keepaliveDone)
			ticker := time.NewTicker(leaseTTL / 3)
			defer ticker.Stop()
			for {
				select {
				case <-keepaliveCtx.Done():
					return
				case <-ticker.C:
					renewCtx, cancel := context.WithTimeout(keepaliveCtx, 10*time.Second)
					_, _ = cp.RenewDurableScopeLease(renewCtx, scope, lease.LeaseToken, leaseTTL)
					cancel()
				}
			}
		}()
		return func() {
			cancelKeepalive()
			<-keepaliveDone
			_ = cp.ReleaseDurableScopeLease(context.Background(), scope, lease.LeaseToken)
		}, nil
	}
	mu := &fallbackPackageMutation
	if s.State != nil && s.State.PackageMutation != nil {
		mu = s.State.PackageMutation
	}
	mu.Lock()
	return mu.Unlock, nil
}

// lockPackageLookupMutation разрешает псевдонимы, например строку
// версии, в канонический release ID до получения распределённой
// аренды, затем заново загружает пакет под ней. Так ID и строка
// версии не создают разные области блокировки одного выпуска.
func (s Server) lockPackageLookupMutation(ctx context.Context, packageID string) (packageLookup, func(), error) {
	lookup, err := s.lookupPackage(packageID)
	if err != nil {
		return packageLookup{}, nil, err
	}
	unlock, err := s.lockPackageMutation(ctx, "package:"+lookup.Release.ID)
	if err != nil {
		return packageLookup{}, nil, err
	}
	fresh, err := s.lookupPackage(lookup.Release.ID)
	if err != nil {
		unlock()
		return packageLookup{}, nil, err
	}
	return fresh, unlock, nil
}
