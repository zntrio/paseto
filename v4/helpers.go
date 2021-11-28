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
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/blake2b"
)

func kdf(key *LocalKey, n []byte) (ek, n2, ak []byte, err error) {
	// Check arguments
	if key == nil {
		return nil, nil, nil, errors.New("unable to derive keys from a nil seed")
	}

	// Derive encryption key
	encKDF, err := blake2b.New(encryptionKDFLength, key[:])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("unable to initialize encryption kdf: %w", err)
	}

	// Domain separation (we use the same seed for 2 different purposes)
	encKDF.Write([]byte("paseto-encryption-key"))
	encKDF.Write(n)
	tmp := encKDF.Sum(nil)

	// Split encryption key (Ek) and nonce (n2)
	ek = tmp[:KeyLength]
	n2 = tmp[KeyLength:]

	// Derive authentication key
	authKDF, err := blake2b.New(authenticationKeyLength, key[:])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("unable to initialize authentication kdf: %w", err)
	}

	// Domain separation (we use the same seed for 2 different purposes)
	authKDF.Write([]byte("paseto-auth-key-for-aead"))
	authKDF.Write(n)
	ak = authKDF.Sum(nil)

	// No error
	return ek, n2, ak, nil
}

func mac(ak []byte, h string, n, c []byte, f, i string) ([]byte, error) {
	// Compute pre-authentication message
	preAuth, err := pae([]byte(h), n, c, []byte(f), []byte(i))
	if err != nil {
		return nil, fmt.Errorf("unable to compute pre-authentication content: %w", err)
	}

	// Compute MAC
	mac, err := blake2b.New(macLength, ak)
	if err != nil {
		return nil, fmt.Errorf("unable to in initialize MAC kdf: %w", err)
	}

	// Hash pre-authentication content
	mac.Write(preAuth)

	// No error
	return mac.Sum(nil), nil
}

// https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Common.md#authentication-padding
func pae(pieces ...[]byte) ([]byte, error) {
	output := &bytes.Buffer{}

	// Encode piece count
	count := len(pieces)
	if err := binary.Write(output, binary.LittleEndian, uint64(count)); err != nil {
		return nil, err
	}

	// For each element
	for i := range pieces {
		// Encode size
		if err := binary.Write(output, binary.LittleEndian, uint64(len(pieces[i]))); err != nil {
			return nil, err
		}

		// Encode data
		if _, err := output.Write(pieces[i]); err != nil {
			return nil, err
		}
	}

	// No error
	return output.Bytes(), nil
}

// secureCompare use constant time function to compare the two given array.
func secureCompare(given, actual []byte) bool {
	if subtle.ConstantTimeEq(int32(len(given)), int32(len(actual))) == 1 {
		return subtle.ConstantTimeCompare(given, actual) == 1
	}
	// Securely compare actual to itself to keep constant time, but always return false
	if subtle.ConstantTimeCompare(actual, actual) == 1 {
		return false
	}

	return false
}
