package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

func parseNetworkCapacity0288(data []byte) (*int, error) {
	if len(data) == 0 {
		return nil, errors.New("Требуется: capacityLimit")
	}
	if string(data) == "null" {
		return nil, nil
	}
	var n int
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&n); err != nil {
		return nil, err
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		return nil, errors.New("Лишние данные после JSON с параметрами пропускной способности")
	}
	if n < 0 || n > 1000000 {
		return nil, errors.New("capacityLimit: требуется «0..1000000»")
	}
	return &n, nil
}
