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
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"zntr.io/paseto/internal/common"
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
func Encrypt(r io.Reader, key *LocalKey, m, f, i []byte) ([]byte, error) {
	// Check arguments
	if key == nil {
		return nil, errors.New("paseto: key is nil")
	}
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

	// Prepare an AES-256-CTR stream cipher
	block, err := aes.NewCipher(ek)
	if err != nil {
		return nil, fmt.Errorf("paseto: unable to prepare block cipher: %w", err)
	}
	ciph := cipher.NewCTR(block, n2)

	// Encrypt the payload
	c := make([]byte, len(m))
	ciph.XORKeyStream(c, m)

	// Compute MAC
	t, err := mac(ak, []byte(LocalPrefix), n[:], c, f, i)
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
	final := append([]byte(LocalPrefix), encodedBody...)
	if len(f) > 0 {
		// Encode footer as RawURLBase64
		encodedFooter := make([]byte, base64.RawURLEncoding.EncodedLen(len(f)))
		base64.RawURLEncoding.Encode(encodedFooter, []byte(f))

		// Assemble body and footer
		final = append(final, append([]byte("."), encodedFooter...)...)
	}

	// No error
	return final, nil
}

// PASETO v3 symmetric decryption primitive
// https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version3.md#decrypt
func Decrypt(key *LocalKey, input, f, i []byte) ([]byte, error) {
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
	if !bytes.HasPrefix(input, []byte(LocalPrefix)) {
		return nil, errors.New("paseto: invalid token")
	}

	// Trim prefix
	input = input[len(LocalPrefix):]

	// Check footer usage
	if len(f) > 0 {
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
		if !common.SecureCompare(f, footer) {
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
	if !common.SecureCompare(t, t2) {
		return nil, errors.New("paseto: invalid pre-authentication header")
	}

	// Prepare an AES-256-CTR stream cipher
	block, err := aes.NewCipher(ek)
	if err != nil {
		return nil, fmt.Errorf("paseto: unable to prepare block cipher: %w", err)
	}
	ciph := cipher.NewCTR(block, n2)

	// Decrypt the payload
	m := make([]byte, len(c))
	ciph.XORKeyStream(m, c)

	// No error
	return m, nil
}
