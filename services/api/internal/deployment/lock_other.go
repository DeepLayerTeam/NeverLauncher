//go:build !linux

package deployment

import "errors"

type InstanceLock struct{}

func Acquire(p Plan) (*InstanceLock, error) {
	if p.SingleInstance {
		return nil, errors.New("Блокировка экземпляра в промышленной среде реализована только для Linux")
	}
	return &InstanceLock{}, nil
}
func (l *InstanceLock) Close() error { return nil }
