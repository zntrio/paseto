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
	"crypto/subtle"
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
func Sign(m []byte, sk *ecdsa.PrivateKey, f, i []byte) (string, error) {
	// Check arguments
	if sk == nil {
		return "", errors.New("paseto: unable to sign with a nil private key")
	}

	// Compress public key point
	pk := elliptic.MarshalCompressed(elliptic.P384(), sk.X, sk.Y)

	// Compute protected content
	m2 := common.PreAuthenticationEncoding(pk, []byte(PublicPrefix), m, f, i)

	// Compute SHA-384 digest
	digest := sha512.Sum384(m2)

	// Sign using a determistic ECDSA scheme
	r, s := rfc6979.SignECDSA(sk, digest[:], sha512.New384)

	// Prepare content
	body := make([]byte, 0, len(m)+r.BitLen()/8+s.BitLen()/8)
	body = append(body, m...)
	body = append(body, r.Bytes()...)
	body = append(body, s.Bytes()...)

	// Encode body as RawURLBase64
	tokenLen := base64.RawURLEncoding.EncodedLen(len(body))
	footerLen := base64.RawURLEncoding.EncodedLen(len(f)) + 1
	if len(f) > 0 {
		tokenLen += base64.RawURLEncoding.EncodedLen(len(f)) + 1
	}

	final := make([]byte, 10+tokenLen)
	copy(final, PublicPrefix)
	base64.RawURLEncoding.Encode(final[10:], body)

	// Assemble final token
	if len(f) > 0 {
		final[10+tokenLen-footerLen] = '.'
		// Encode footer as RawURLBase64
		base64.RawURLEncoding.Encode(final[10+tokenLen-footerLen+1:], f)
	}

	// No error
	return string(final), nil
}

// Verify PASETO v3 signature.
// https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version3.md#verify
func Verify(t string, pub *ecdsa.PublicKey, f, i []byte) ([]byte, error) {
	// Check arguments
	if pub == nil {
		return nil, errors.New("paseto: public key is nil")
	}

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
	m := raw[:len(raw)-signatureSize]
	sig := raw[len(raw)-signatureSize:]

	// Compress public key point
	pk := elliptic.MarshalCompressed(elliptic.P384(), pub.X, pub.Y)

	// Compute protected content
	m2 := common.PreAuthenticationEncoding(pk, []byte(PublicPrefix), m, f, i)

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
