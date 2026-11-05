//go:build !(linux || darwin || freebsd || netbsd || openbsd || windows)

package main

import "errors"

func remoteKernelFence04112(string) (func(), error) {
	return nil, errors.New("Блокировка единственного экземпляра RemoteControl на уровне ядра не реализована в этой ОС; небезопасные команды хоста отклонены")
}
