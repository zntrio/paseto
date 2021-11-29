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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"

	"zntr.io/paseto/internal/common"
	"zntr.io/paseto/v3/internal/rfc6979"
)

// Sign a message (m) with the private key (sk).
// PASETO v3 public signature primitive.
// https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version3.md#sign
func Sign(m []byte, sk *ecdsa.PrivateKey, f, i string) ([]byte, error) {
	// Check arguments
	if sk == nil {
		return nil, errors.New("paseto: unable to sign with a nil private key")
	}

	// Compress public key point
	pk := elliptic.MarshalCompressed(elliptic.P384(), sk.X, sk.Y)

	// Compute protected content
	m2, err := common.PreAuthenticationEncoding([]byte(pk), []byte(PublicPrefix), m, []byte(f), []byte(i))
	if err != nil {
		return nil, fmt.Errorf("paseto: unable to prepare protected content: %w", err)
	}

	// Compute SHA-384 digest
	digest := sha512.Sum384(m2)

	// Sign using a determistic ECDSA scheme
	r, s := rfc6979.SignECDSA(sk, digest[:], sha512.New384)

	// Assemble signature
	sig := append(r.Bytes(), s.Bytes()...)

	// Prepare content
	body := append([]byte{}, m...)
	body = append(body, sig...)

	// Encode body as RawURLBase64
	encodedBody := make([]byte, base64.RawURLEncoding.EncodedLen(len(body)))
	base64.RawURLEncoding.Encode(encodedBody, body)

	// Assemble final token
	final := append([]byte(PublicPrefix), encodedBody...)
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

// PASETO v3 signature verification primitive.
// https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version3.md#verify
func Verify(sm []byte, pub *ecdsa.PublicKey, f, i string) ([]byte, error) {
	// Check arguments
	if pub == nil {
		return nil, errors.New("paseto: public key is nil")
	}

	// Check token header
	if !bytes.HasPrefix(sm, []byte(PublicPrefix)) {
		return nil, errors.New("paseto: invalid token")
	}

	// Trim prefix
	sm = sm[len(PublicPrefix):]

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
		if !common.SecureCompare([]byte(f), footer) {
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
	m := raw[:len(raw)-signatureSize]
	sig := raw[len(raw)-signatureSize:]

	// Compress public key point
	pk := elliptic.MarshalCompressed(elliptic.P384(), pub.X, pub.Y)

	// Compute protected content
	m2, err := common.PreAuthenticationEncoding([]byte(pk), []byte(PublicPrefix), m, []byte(f), []byte(i))
	if err != nil {
		return nil, fmt.Errorf("unable to prepare protected content: %w", err)
	}

	// Compute SHA-384 digest
	digest := sha512.Sum384(m2)

	// Split signature
	r := big.NewInt(0).SetBytes(sig[:kdfOutputLength])
	s := big.NewInt(0).SetBytes(sig[kdfOutputLength:])

	// Check signature
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return nil, errors.New("paseto: invalid token signature")
	}

	// No error
	return m, nil
}
