//go:build !(linux || darwin || freebsd || netbsd || openbsd || windows)

package main

import "errors"

func remoteKernelFence04112(string) (func(), error) {
	return nil, errors.New("Защита от параллельного запуска RemoteControl на уровне ядра недоступна в этой ОС; небезопасные команды узла отклонены")
}
