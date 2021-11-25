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
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20"
)

// GenerateKey generates a key for local encryption.
func GenerateKey(r io.Reader) ([]byte, error) {
	var key [KeyLength]byte
	if _, err := io.ReadFull(r, key[:]); err != nil {
		return nil, fmt.Errorf("paseto: unable to generate a random key: %w", err)
	}

	// No error
	return key[:], nil
}

// PASETO v4 symmetric encryption primitive.
// https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md#encrypt
func Encrypt(r io.Reader, key, m []byte, f, i string) ([]byte, error) {
	// Check arguments
	if len(key) != KeyLength {
		return nil, fmt.Errorf("paseto: invalid key length, it must be %d bytes long", KeyLength)
	}

	// Create random seed
	var n [nonceLength]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return nil, fmt.Errorf("paseto: unable to generate random seed: %w", err)
	}

	// Derive keys from seed and secret key
	ek, n2, ak, err := kdf(key, n[:])
	if err != nil {
		return nil, fmt.Errorf("paseto: unable to derive keys from seed: %w", err)
	}

	// Prepare XChaCha20 stream cipher (nonce > 24bytes => XChacha)
	ciph, err := chacha20.NewUnauthenticatedCipher(ek, n2)
	if err != nil {
		return nil, fmt.Errorf("paseto: unable to initialize XChaCha20 cipher: %w", err)
	}

	// Encrypt the payload
	c := make([]byte, len(m))
	ciph.XORKeyStream(c, m)

	// Compute MAC
	t, err := mac(ak, v4LocalPrefix, n[:], c, f, i)
	if err != nil {
		return nil, fmt.Errorf("paseto: unable to compute MAC: %w", err)
	}

	// Serialize final token
	// h || base64url(n || c || t)
	body := append([]byte{}, n[:]...)
	body = append(body, c...)
	body = append(body, t...)

	// Encode body as RawURLBase64
	encodedBody := make([]byte, base64.RawURLEncoding.EncodedLen(len(body)))
	base64.RawURLEncoding.Encode(encodedBody, body)

	// Assemble final token
	final := append([]byte(v4LocalPrefix), encodedBody...)
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

// PASETO v4 symmetric decryption primitive
// https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md#decrypt
func Decrypt(key, input []byte, f, i string) ([]byte, error) {
	// Check arguments
	if key == nil {
		return nil, errors.New("paseto: key is nil")
	}
	if len(key) != KeyLength {
		return nil, fmt.Errorf("paseto: invalid key length, it must be %d bytes long", KeyLength)
	}
	if input == nil {
		return nil, errors.New("paseto: input is nil")
	}

	// Check token header
	if !bytes.HasPrefix(input, []byte(v4LocalPrefix)) {
		return nil, errors.New("paseto: invalid token")
	}

	// Trim prefix
	input = input[len(v4LocalPrefix):]

	// Check footer usage
	if f != "" {
		// Split the footer and the body
		parts := bytes.SplitN(input, []byte("."), 2)
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
		input = parts[0]
	}

	// Decode token
	raw := make([]byte, base64.RawURLEncoding.DecodedLen(len(input)))
	if _, err := base64.RawURLEncoding.Decode(raw, input); err != nil {
		return nil, fmt.Errorf("paseto: invalid token body: %w", err)
	}

	// Extract components
	n := raw[:nonceLength]
	t := raw[len(raw)-macLength:]
	c := raw[macLength : len(raw)-macLength]

	// Derive keys from seed and secret key
	ek, n2, ak, err := kdf(key, n)
	if err != nil {
		return nil, fmt.Errorf("paseto: unable to derive keys from seed: %w", err)
	}

	// Compute MAC
	t2, err := mac(ak, v4LocalPrefix, n, c, f, i)
	if err != nil {
		return nil, fmt.Errorf("paseto: unable to compute MAC: %w", err)
	}

	// Time-constant compare MAC
	if !secureCompare(t, t2) {
		return nil, errors.New("paseto: invalid pre-authentication header")
	}

	// Prepare XChaCha20 stream cipher
	ciph, err := chacha20.NewUnauthenticatedCipher(ek, n2)
	if err != nil {
		return nil, fmt.Errorf("paseto: unable to initialize XChaCha20 cipher: %w", err)
	}

	// Encrypt the payload
	m := make([]byte, len(c))
	ciph.XORKeyStream(m, c)

	// No error
	return m, nil
}
