//go:build !(linux || darwin || freebsd || netbsd || openbsd || windows)

package main

import "errors"

func remoteKernelFence04112(string) (func(), error) {
	return nil, errors.New("RemoteControl kernel singleton fencing is not implemented on this OS; refusing unsafe host commands")
}
