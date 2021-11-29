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

const (
	// KeyLength is the requested encryption key size.
	KeyLength = 32
)

const (
	nonceLength     = 32
	macLength       = 48
	kdfOutputLength = 48
	signatureSize   = 96
	LocalPrefix     = "v3.local."
	PublicPrefix    = "v3.public."
)

// LocalKey represents a key for symetric encryption (local).
type LocalKey [32]byte
