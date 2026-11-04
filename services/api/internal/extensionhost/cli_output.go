package extensionhost

import (
	"io"
	"sync"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

// stdout и stderr CLI разделяют один подписанный лимит вывода на экземпляр.
// Базовый boundedBuffer0209 по-прежнему ограничивает память. Дочерний процесс,
// превышающий совокупную квоту, завершается, а не продолжает бесконечно
// заполнять ограниченный буфер.
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
		return n, nil // читать канал до завершения процесса ядром ОС
	}
	_, err := w.target.Write(p)
	if err != nil {
		return 0, err
	}
	return n, nil
}
