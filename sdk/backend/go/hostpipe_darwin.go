//go:build darwin

package extensions

import (
	"context"
	"errors"
	"net"
	"os"
	"strconv"
	"sync"
)

// Единственный путь к хосту внутри App Sandbox — одна наследуемая пара
// Unix-сокетов. HTTP-транспорт обязан переиспользовать это соединение; при
// закрытии он отклоняет запрос, а не открывает TCP на loopback.
func hostPipeDialer() func(context.Context, string, string) (net.Conn, error) {
	fd, err := strconv.Atoi(os.Getenv("LAUNCHER_EXTENSION_HOST_FD"))
	if err != nil || fd != 4 {
		return nil
	}
	var once sync.Once
	var conn net.Conn
	var initErr error
	return func(_ context.Context, _, _ string) (net.Conn, error) {
		first := false
		once.Do(func() {
			first = true
			f := os.NewFile(uintptr(fd), "sandbox-host-ipc")
			conn, initErr = net.FileConn(f)
			_ = f.Close()
		})
		if !first {
			return nil, errors.New("sandbox-host-socket-already-consumed")
		}
		return conn, initErr
	}
}
