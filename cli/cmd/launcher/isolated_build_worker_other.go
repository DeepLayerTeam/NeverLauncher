//go:build !linux && !darwin && !windows

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
)

// На платформах не-Linux рабочий процесс всё ещё имеет отдельный PID, ограниченную
// кучу, дедлайн, очищенное окружение и ограниченные журналы. Лимиты ядра и
// завершение группы процессов требуют обработчиков ОС и не заявлены здесь.
func limitWorkerResources0273(seconds int) error { return nil }
func prepareWorkerProcess0273(cmd *exec.Cmd)     {}
func terminateWorkerTree0273(p *os.Process) {
	if p != nil {
		_ = p.Kill()
	}
}

func strictSandboxJavaCommand0273(_ context.Context, _ processorWorkerRequest0273, _ []string) (*exec.Cmd, error) {
	return nil, errors.New("Для строгой изоляции процесса в Linux необходим bubblewrap")
}
