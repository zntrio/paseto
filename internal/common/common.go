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
	"encoding/binary"
)

// https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Common.md#authentication-padding
func PreAuthenticationEncoding(pieces ...[]byte) []byte {
	// Precompute length to allocate the buffer
	// PieceCount (8B) || ( PieceLen (8B) || Piece (*B) )*
	bufLen := 8
	for i := range pieces {
		bufLen += 8 + len(pieces[i])
	}

	// Pre-allocate the buffer
	output := make([]byte, bufLen)

	// Encode piece count
	binary.LittleEndian.PutUint64(output, uint64(len(pieces)))

	offset := 8
	// For each element
	for i := range pieces {
		// Encode size
		binary.LittleEndian.PutUint64(output[offset:], uint64(len(pieces[i])))
		offset += 8

		// Encode data
		copy(output[offset:], pieces[i])
		offset += len(pieces[i])
	}

	// No error
	return output
}
