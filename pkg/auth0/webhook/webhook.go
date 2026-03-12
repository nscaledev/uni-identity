/*
Copyright 2026 Nscale.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/unikorn-cloud/identity/pkg/auth0"
)

const DefaultTolerance = 5 * time.Minute

var (
	ErrNotSigned        = errors.New("webhook has no X-Auth0-Signature header")
	ErrInvalidHeader    = errors.New("webhook has invalid X-Auth0-Signature header")
	ErrNoValidSignature = errors.New("webhook had no valid signature")
	ErrTooOld           = errors.New("timestamp wasn't within tolerance")
)

//nolint:staticcheck,nlreturn,wsl
func ComputeSignature(t time.Time, payload []byte, secret string) []byte {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(fmt.Sprintf("%d", t.Unix())))
	h.Write([]byte("."))
	h.Write(payload)
	return h.Sum(nil)
}

type signedHeader struct {
	timestamp  time.Time
	signatures [][]byte
}

func parseSignedHeader(header string) (*signedHeader, error) {
	if header == "" {
		return nil, ErrNotSigned
	}

	var sh signedHeader

	// The header is a comma-separated list of key=value pairs, e.g.:
	// "t=1495999758,v1=ABC,v1=DEF,v0=GHI"
	// where t is a Unix timestamp and v1 entries are hex-encoded HMAC-SHA256
	// signatures. Multiple v1 entries are used during signing key rotation.
	parts := strings.Split(header, ",")
	for _, part := range parts {
		pair := strings.Split(part, "=")
		if len(pair) != 2 {
			return nil, ErrInvalidHeader
		}

		switch pair[0] {
		case "t":
			timestamp, err := strconv.ParseInt(pair[1], 10, 64)
			if err != nil {
				return nil, ErrInvalidHeader
			}

			sh.timestamp = time.Unix(timestamp, 0)
		case "v1":
			signature, err := hex.DecodeString(pair[1])
			if err != nil {
				continue // skip malformed signatures rather than rejecting the whole header
			}

			sh.signatures = append(sh.signatures, signature)
		default:
			continue // skip unrecognised schemes (e.g. legacy v0 signatures)
		}
	}

	if len(sh.signatures) == 0 {
		return nil, ErrNoValidSignature
	}

	return &sh, nil
}

func ValidatePayload(payload []byte, header string, secret string) error {
	return ValidatePayloadWithTolerance(payload, header, secret, DefaultTolerance)
}

func ValidatePayloadIgnoringTolerance(payload []byte, header string, secret string) error {
	return validatePayload(payload, header, secret, 0*time.Second, false)
}

func ValidatePayloadWithTolerance(payload []byte, header string, secret string, tolerance time.Duration) error {
	return validatePayload(payload, header, secret, tolerance, true)
}

func validatePayload(payload []byte, header string, secret string, tolerance time.Duration, enforceTolerance bool) error {
	sh, err := parseSignedHeader(header)
	if err != nil {
		return err
	}

	isExpired := time.Since(sh.timestamp) > tolerance
	if enforceTolerance && isExpired {
		return ErrTooOld
	}

	expectedSignature := ComputeSignature(sh.timestamp, payload, secret)

	for _, signature := range sh.signatures {
		if hmac.Equal(expectedSignature, signature) {
			return nil
		}
	}

	return ErrNoValidSignature
}

func ConstructEvent(payload []byte, header string, secret string) (*auth0.Event, error) {
	return ConstructEventWithTolerance(payload, header, secret, DefaultTolerance)
}

func ConstructEventIgnoringTolerance(payload []byte, header string, secret string) (*auth0.Event, error) {
	return constructEvent(payload, header, secret, 0*time.Second, false)
}

func ConstructEventWithTolerance(payload []byte, header string, secret string, tolerance time.Duration) (*auth0.Event, error) {
	return constructEvent(payload, header, secret, tolerance, true)
}

func constructEvent(payload []byte, header string, secret string, tolerance time.Duration, enforceTolerance bool) (*auth0.Event, error) {
	if err := validatePayload(payload, header, secret, tolerance, enforceTolerance); err != nil {
		return nil, err
	}

	var e auth0.Event
	if err := json.Unmarshal(payload, &e); err != nil {
		return nil, fmt.Errorf("failed to parse webhook body json: %w", err)
	}

	return &e, nil
}
