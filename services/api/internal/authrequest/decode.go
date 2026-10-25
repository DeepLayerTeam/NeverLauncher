// Package authrequest parses security-sensitive authentication requests.
// An authentication endpoint must not interpret ambiguous JSON, accept
// unbounded passwords, or accidentally ignore a second JSON document.
package authrequest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

const MaxBytes = 16 * 1024

var ErrTooLarge = errors.New("authentication request exceeds 16 KiB")

// Decode accepts exactly one JSON object, rejects duplicate keys (including
// case variants and nested objects), unknown properties and trailing data.
// The byte limit is applied before any JSON allocation or upstream call.
func Decode(src io.Reader, destination any) error {
	if src == nil {
		return errors.New("authentication request body is missing")
	}
	raw, err := io.ReadAll(io.LimitReader(src, MaxBytes+1))
	if err != nil {
		return fmt.Errorf("read authentication request: %w", err)
	}
	if len(raw) > MaxBytes {
		return ErrTooLarge
	}
	if !json.Valid(raw) {
		return errors.New("invalid authentication JSON")
	}
	check := json.NewDecoder(bytes.NewReader(raw))
	if err := uniqueObject(check); err != nil {
		return err
	}
	if _, err := check.Token(); !errors.Is(err, io.EOF) {
		return errors.New("authentication JSON must contain one object")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(destination); err != nil {
		return fmt.Errorf("decode authentication JSON: %w", err)
	}
	return nil
}

func uniqueObject(dec *json.Decoder) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}
	if token != json.Delim('{') {
		return errors.New("authentication JSON must be an object")
	}
	return consumeObject(dec)
}

func consumeObject(dec *json.Decoder) error {
	seen := make(map[string]struct{})
	for dec.More() {
		keyToken, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := keyToken.(string)
		if !ok {
			return errors.New("invalid authentication JSON key")
		}
		// encoding/json resolves struct fields without case sensitivity. Apply
		// the same equivalence so a request cannot set one field twice.
		key = strings.ToLower(key)
		if _, duplicate := seen[key]; duplicate {
			return errors.New("duplicate authentication JSON key")
		}
		seen[key] = struct{}{}
		if err := consumeValue(dec); err != nil {
			return err
		}
	}
	_, err := dec.Token() // closing brace
	return err
}

func consumeValue(dec *json.Decoder) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		return consumeObject(dec)
	case '[':
		for dec.More() {
			if err := consumeValue(dec); err != nil {
				return err
			}
		}
		_, err := dec.Token()
		return err
	default:
		return errors.New("unexpected authentication JSON delimiter")
	}
}
