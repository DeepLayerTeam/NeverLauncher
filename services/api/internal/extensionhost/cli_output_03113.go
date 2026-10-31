package extensionhost

import (
	"io"
	"sync"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

// Both CLI stdout and stderr share one instance-wide signed output budget.
// The underlying boundedBuffer0209 still caps retained memory. A child that
// exceeds the aggregate quota is terminated, not merely allowed to flood a
// bounded in-memory buffer indefinitely.
type cliOutputWriter03113 struct {
	st     *processState
	target io.Writer
	policy *model.ExtensionSandboxPolicy
	abort  func()
	once   *sync.Once
}

func (w *cliOutputWriter03113) Write(p []byte) (int, error) {
	n := len(p)
	w.st.mu.Lock()
	allowed := w.st.budget.chargeLocked03113(int64(n), w.policy)
	w.st.mu.Unlock()
	if !allowed {
		w.once.Do(func() { go w.abort() })
		return n, nil // drain pipe until kernel terminates the process
	}
	_, err := w.target.Write(p)
	if err != nil {
		return 0, err
	}
	return n, nil
}
