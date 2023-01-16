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

package v3

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// GenerateLocalKey generates a key for local encryption.
func GenerateLocalKey(r io.Reader) (*LocalKey, error) {
	var key LocalKey
	if _, err := io.ReadFull(r, key[:]); err != nil {
		return nil, fmt.Errorf("paseto: unable to generate a random key: %w", err)
	}

	// No error
	return &key, nil
}

// LocalKeyFromSeed creates a local key from given input data.
func LocalKeyFromSeed(seed []byte) (*LocalKey, error) {
	// Check minimum seed size.
	if len(seed) < KeyLength {
		return nil, fmt.Errorf("paseto: invalid seed length, it must be %d bytes long at least", KeyLength)
	}

	// Copy data from seed.
	var key LocalKey
	copy(key[:], seed[:KeyLength])

	// No error
	return &key, nil
}

// PASETO v3 symmetric encryption primitive.
// https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version3.md#encrypt
func Encrypt(r io.Reader, key *LocalKey, m, f, i []byte) (string, error) {
	// Check arguments
	if key == nil {
		return "", errors.New("paseto: key is nil")
	}
	if len(key) != KeyLength {
		return "", fmt.Errorf("paseto: invalid key length, it must be %d bytes long", KeyLength)
	}

	// Pre-allocate body
	body := make([]byte, nonceLength+len(m), nonceLength+len(m)+macLength)

	// Create random seed
	if _, err := io.ReadFull(r, body[:nonceLength]); err != nil {
		return "", fmt.Errorf("paseto: unable to generate random seed: %w", err)
	}

	// Derive keys from seed and secret key
	ek, n2, ak, err := kdf(key, body[:nonceLength])
	if err != nil {
		return "", fmt.Errorf("paseto: unable to derive keys from seed: %w", err)
	}

	// Prepare an AES-256-CTR stream cipher
	block, err := aes.NewCipher(ek)
	if err != nil {
		return "", fmt.Errorf("paseto: unable to prepare block cipher: %w", err)
	}
	ciph := cipher.NewCTR(block, n2)

	// Encrypt the payload
	ciph.XORKeyStream(body[nonceLength:], m)

	// Compute MAC
	t, err := mac(ak, []byte(LocalPrefix), body[:nonceLength], body[nonceLength:], f, i)
	if err != nil {
		return "", fmt.Errorf("paseto: unable to compute MAC: %w", err)
	}

	// Serialize final token
	// h || base64url(n || c || t)
	body = append(body, t...)

	// Encode body as RawURLBase64
	tokenLen := base64.RawURLEncoding.EncodedLen(len(body))
	footerLen := base64.RawURLEncoding.EncodedLen(len(f)) + 1
	if len(f) > 0 {
		tokenLen += base64.RawURLEncoding.EncodedLen(len(f)) + 1
	}

	final := make([]byte, 9+tokenLen)
	copy(final, []byte(LocalPrefix))
	base64.RawURLEncoding.Encode(final[9:], body)

	// Assemble final token
	if len(f) > 0 {
		final[9+tokenLen-footerLen] = '.'
		// Encode footer as RawURLBase64
		base64.RawURLEncoding.Encode(final[9+tokenLen-footerLen+1:], []byte(f))
	}

	// No error
	return string(final), nil
}

// PASETO v3 symmetric decryption primitive
// https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version3.md#decrypt
func Decrypt(key *LocalKey, token string, f, i []byte) ([]byte, error) {
	// Check arguments
	if key == nil {
		return nil, errors.New("paseto: key is nil")
	}
	if len(key) != KeyLength {
		return nil, fmt.Errorf("paseto: invalid key length, it must be %d bytes long", KeyLength)
	}
	if token == "" {
		return nil, errors.New("paseto: token is blank")
	}

	rawToken := []byte(token)

	// Check token header
	if !bytes.HasPrefix(rawToken, []byte(LocalPrefix)) {
		return nil, errors.New("paseto: invalid token")
	}

	// Trim prefix
	rawToken = rawToken[len(LocalPrefix):]

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
	n := raw[:nonceLength]
	t := raw[len(raw)-macLength:]
	c := raw[nonceLength : len(raw)-macLength]

	// Derive keys from seed and secret key
	ek, n2, ak, err := kdf(key, n)
	if err != nil {
		return nil, fmt.Errorf("paseto: unable to derive keys from seed: %w", err)
	}

	// Compute MAC
	t2, err := mac(ak, []byte(LocalPrefix), n, c, f, i)
	if err != nil {
		return nil, fmt.Errorf("paseto: unable to compute MAC: %w", err)
	}

	// Time-constant compare MAC
	if subtle.ConstantTimeCompare(t, t2) == 0 {
		return nil, errors.New("paseto: invalid pre-authentication header")
	}

	// Prepare an AES-256-CTR stream cipher
	block, err := aes.NewCipher(ek)
	if err != nil {
		return nil, fmt.Errorf("paseto: unable to prepare block cipher: %w", err)
	}
	ciph := cipher.NewCTR(block, n2)

	// Decrypt the payload
	ciph.XORKeyStream(c, c)

	// No error
	return c, nil
}
