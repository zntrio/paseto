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
	"encoding/base64"
	"errors"
	"fmt"
)

// Sign a message (m) with the private key (sk).
// PASETO v4 public signature primitive.
// https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md#sign
func Sign(m []byte, sk ed25519.PrivateKey, f, i string) ([]byte, error) {
	// Compute protected content
	m2, err := pae([]byte(v4PublicPrefix), m, []byte(f), []byte(i))
	if err != nil {
		return nil, fmt.Errorf("unable to prepare protected content: %w", err)
	}

	// Sign protected content
	sig := ed25519.Sign(sk, m2)

	// Prepare content
	body := append([]byte{}, m...)
	body = append(body, sig...)

	// Encode body as RawURLBase64
	encodedBody := make([]byte, base64.RawURLEncoding.EncodedLen(len(body)))
	base64.RawURLEncoding.Encode(encodedBody, body)

	// Assemble final token
	final := append([]byte(v4PublicPrefix), encodedBody...)
	if f != "" {
		// Encode footer as RawURLBase64
		encodedFooter := make([]byte, base64.RawURLEncoding.EncodedLen(len(f)))
		base64.RawURLEncoding.Encode(encodedFooter, []byte(f))

		// Assemble body and footer
		final = append(final, append([]byte("."), encodedFooter...)...)
	}

	// No error
	return final, nil
}

// PASETO v4 signature verification primitive.
// https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md#verify
func Verify(sm []byte, pk ed25519.PublicKey, f, i string) ([]byte, error) {
	// Check token header
	if !bytes.HasPrefix(sm, []byte(v4PublicPrefix)) {
		return nil, errors.New("paseto: invalid token")
	}

	// Trim prefix
	sm = sm[len(v4PublicPrefix):]

	// Check footer usage
	if f != "" {
		// Split the footer and the body
		parts := bytes.SplitN(sm, []byte("."), 2)
		if len(parts) != 2 {
			return nil, errors.New("paseto: invalid token, footer is missing but expected")
		}

		// Decode footer
		footer := make([]byte, base64.RawURLEncoding.DecodedLen(len(parts[1])))
		if _, err := base64.RawURLEncoding.Decode(footer, parts[1]); err != nil {
			return nil, fmt.Errorf("paseto: invalid token, footer has invalid encoding: %w", err)
		}

		// Compare footer
		if !secureCompare([]byte(f), footer) {
			return nil, errors.New("paseto: invalid token, footer mismatch")
		}

		// Continue without footer
		sm = parts[0]
	}

	// Decode token
	raw := make([]byte, base64.RawURLEncoding.DecodedLen(len(sm)))
	if _, err := base64.RawURLEncoding.Decode(raw, sm); err != nil {
		return nil, fmt.Errorf("paseto: invalid token body: %w", err)
	}

	// Extract components
	m := raw[:len(raw)-ed25519.SignatureSize]
	s := raw[len(raw)-ed25519.SignatureSize:]

	// Compute protected content
	m2, err := pae([]byte(v4PublicPrefix), m, []byte(f), []byte(i))
	if err != nil {
		return nil, fmt.Errorf("unable to prepare protected content: %w", err)
	}

	// Check signature
	if !ed25519.Verify(pk, m2, s) {
		return nil, errors.New("paseto: invalid token signature")
	}

	// No error
	return m, nil
}
