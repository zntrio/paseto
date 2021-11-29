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

package common

import (
	"bytes"
	"crypto/subtle"
	"encoding/binary"
)

// https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Common.md#authentication-padding
func PreAuthenticationEncoding(pieces ...[]byte) ([]byte, error) {
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

// SecureCompare use constant time function to compare the two given array.
func SecureCompare(given, actual []byte) bool {
	if subtle.ConstantTimeEq(int32(len(given)), int32(len(actual))) == 1 {
		return subtle.ConstantTimeCompare(given, actual) == 1
	}
	// Securely compare actual to itself to keep constant time, but always return false
	if subtle.ConstantTimeCompare(actual, actual) == 1 {
		return false
	}

	return false
}
