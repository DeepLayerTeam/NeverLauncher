package httpapi

import "sync"

var fallbackPackageMutation sync.Mutex

// lockPackageMutation serializes package storage+metadata mutations in the canonical
// single-API production process. PostgreSQL repository methods additionally use row
// locks/conditional writes, so metadata immutability remains enforced below HTTP.
func (s Server) lockPackageMutation() func() {
	mu := &fallbackPackageMutation
	if s.State != nil && s.State.PackageMutation != nil {
		mu = s.State.PackageMutation
	}
	mu.Lock()
	return mu.Unlock
}
