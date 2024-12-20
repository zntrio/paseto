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

package v4x

import (
	"errors"

	"lukechampine.com/blake3"

	"zntr.io/paseto/internal/common"
)

func kdf(key *LocalKey, n []byte) (ek, n2 []byte, err error) {
	// Check arguments
	if key == nil {
		return nil, nil, errors.New("unable to derive keys from a nil seed")
	}

	// Derive encryption key
	encKDF := blake3.New(encryptionKDFLength, key[:])

	// Domain separation (we use the same seed for 2 different purposes)
	encKDF.Write([]byte("paseto-encryption-key"))
	encKDF.Write(n)
	tmp := encKDF.Sum(nil)

	// No error
	return tmp[:KeyLength], tmp[KeyLength:], nil
}

func mac(ak, h, n, c, f, i []byte) ([]byte, error) {
	// Compute pre-authentication message
	preAuth := common.PreAuthenticationEncoding(h, n, c, f, i)

	// Compute MAC
	mac := blake3.New(macLength, ak)

	// Hash pre-authentication content
	mac.Write(preAuth)

	// No error
	return mac.Sum(nil), nil
}
