// Licensed to SolID under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. SolID licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package v4

import (
	"bytes"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"

	"zntr.io/paseto/internal/common"
)

// Sign a message (m) with the private key (sk).
// PASETO v4 public signature primitive.
// https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md#sign
func Sign(m []byte, sk ed25519.PrivateKey, f, i []byte) (string, error) {
	// Compute protected content
	m2 := common.PreAuthenticationEncoding([]byte(PublicPrefix), m, f, i)

	// Sign protected content
	sig := ed25519.Sign(sk, m2)

	// Prepare content
	body := make([]byte, 0, len(m)+ed25519.SignatureSize)
	body = append(body, m...)
	body = append(body, sig...)

	// Encode body as RawURLBase64
	tokenLen := base64.RawURLEncoding.EncodedLen(len(body))
	footerLen := base64.RawURLEncoding.EncodedLen(len(f)) + 1
	if len(f) > 0 {
		tokenLen += base64.RawURLEncoding.EncodedLen(len(f)) + 1
	}

	final := make([]byte, tokenLen+len(PublicPrefix))
	copy(final, []byte(PublicPrefix))
	base64.RawURLEncoding.Encode(final[10:], body)

	// Assemble final token
	if len(f) > 0 {
		final[10+tokenLen-footerLen] = '.'
		// Encode footer as RawURLBase64
		base64.RawURLEncoding.Encode(final[10+tokenLen-footerLen+1:], []byte(f))
	}

	// No error
	return string(final), nil
}

// PASETO v4 signature verification primitive.
// https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md#verify
func Verify(t string, pk ed25519.PublicKey, f, i []byte) ([]byte, error) {
	rawToken := []byte(t)

	// Check token header
	if !bytes.HasPrefix(rawToken, []byte(PublicPrefix)) {
		return nil, errors.New("paseto: invalid token")
	}

	// Trim prefix
	rawToken = rawToken[len(PublicPrefix):]

	// Check footer usage
	if len(f) > 0 {
		// Split the footer and the body
		footerIdx := bytes.Index(rawToken, []byte("."))
		if footerIdx == 0 {
			return nil, errors.New("paseto: invalid token, footer is missing but expected")
		}

		// Decode footer
		footer := make([]byte, base64.RawURLEncoding.DecodedLen(len(rawToken[footerIdx+1:])))
		if _, err := base64.RawURLEncoding.Decode(footer, rawToken[footerIdx+1:]); err != nil {
			return nil, fmt.Errorf("paseto: invalid token, footer has invalid encoding: %w", err)
		}

		// Compare footer
		if subtle.ConstantTimeCompare(f, footer) == 0 {
			return nil, errors.New("paseto: invalid token, footer mismatch")
		}

		// Continue without footer
		rawToken = rawToken[:footerIdx]
	}

	// Decode token
	raw := make([]byte, base64.RawURLEncoding.DecodedLen(len(rawToken)))
	if _, err := base64.RawURLEncoding.Decode(raw, rawToken); err != nil {
		return nil, fmt.Errorf("paseto: invalid token body: %w", err)
	}

	// Extract components
	m := raw[:len(raw)-ed25519.SignatureSize]
	s := raw[len(raw)-ed25519.SignatureSize:]

	// Compute protected content
	m2 := common.PreAuthenticationEncoding([]byte(PublicPrefix), m, f, i)

	// Check signature
	if !ed25519.Verify(pk, m2, s) {
		return nil, errors.New("paseto: invalid token signature")
	}

	// No error
	return m, nil
}
