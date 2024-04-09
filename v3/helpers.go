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
	"crypto/hmac"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"

	"zntr.io/paseto/internal/common"
)

func kdf(key *LocalKey, n []byte) (ek, n2, ak []byte, err error) {
	// Check arguments
	if key == nil {
		return nil, nil, nil, errors.New("unable to derive keys from a nil seed")
	}

	// Prepare HKDF-HMAC-SHA384
	encKDF := hkdf.New(sha512.New384, key[:], nil, append([]byte("paseto-encryption-key"), n...))

	// Derive encryption key
	tmp := make([]byte, kdfOutputLength)
	if _, err := io.ReadFull(encKDF, tmp); err != nil {
		return nil, nil, nil, fmt.Errorf("unable to generate encryption key from seed: %w", err)
	}

	// Split encryption key (Ek) and nonce (n2)
	ek = tmp[:KeyLength]
	n2 = tmp[KeyLength:]

	// Derive authentication key
	authKDF := hkdf.New(sha512.New384, key[:], nil, append([]byte("paseto-auth-key-for-aead"), n...))

	// Derive authentication key
	ak = make([]byte, kdfOutputLength)
	if _, err := io.ReadFull(authKDF, ak); err != nil {
		return nil, nil, nil, fmt.Errorf("unable to generate authentication key from seed: %w", err)
	}

	// No error
	return ek, n2, ak, nil
}

func mac(ak, h, n, c, f, i []byte) []byte {
	// Compute pre-authentication message
	preAuth := common.PreAuthenticationEncoding(h, n, c, f, i)

	// Compute MAC
	mac := hmac.New(sha512.New384, ak)

	// Hash pre-authentication content
	mac.Write(preAuth)

	// No error
	return mac.Sum(nil)
}
