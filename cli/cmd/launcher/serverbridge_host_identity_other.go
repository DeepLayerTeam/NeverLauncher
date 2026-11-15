//go:build !linux && !windows && !darwin

package main

import "errors"

// На платформах без подтверждённой ядром метки рождения процесса выполняется отказ: одного PID
// недостаточно для доказательства идентичности и разрешения stop/restart.
func hostProcessIdentity0282(pid int) (string, error) {
	return "", errors.New("Проверка идентификатора процесса недоступна на этой платформе")
}
