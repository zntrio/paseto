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

package paseto_test

import (
	"bytes"
	"crypto/ed25519"
	"fmt"

	pasetov4 "zntr.io/paseto/v4"
)

func ExamplePasetoV4LocalWithoutFooter() {
	// Use this a random source, it must be replaced by rand.Reader for production use.
	deterministicSeedForTest := bytes.NewReader([]byte("deterministic-random-source-for-tests-1234567890123456789012345678901234567890"))

	// Generate an encryption key.
	localKey, err := pasetov4.GenerateLocalKey(deterministicSeedForTest)
	if err != nil {
		panic(err)
	}

	// Prepare the message
	m := []byte("my super secret message")

	// Encrypt the token
	token, err := pasetov4.Encrypt(deterministicSeedForTest, localKey, m, nil, nil)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%s", token)
	// Output: v4.local.dGVzdHMtMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTZ-qF7cj1LApZxpU5R2qdaX9Ox9NaKxnXOFQ0MyihHkhiIIv3VicidcEd6u0WjXiG1TouukHAG-
}

func ExamplePasetoV4LocalWithFooter() {
	// Use this a random source, it must be replaced by rand.Reader for production use.
	deterministicSeedForTest := bytes.NewReader([]byte("deterministic-random-source-for-tests-1234567890123456789012345678901234567890"))

	// Generate an encryption key.
	localKey, err := pasetov4.GenerateLocalKey(deterministicSeedForTest)
	if err != nil {
		panic(err)
	}

	// Prepare the message
	m := []byte("my super secret message")

	// The footer is public and not encrypted but protected by integrity check.
	// You can use it to transport information about the token context.
	footer := []byte(`{"kid":"1234567890"}`)

	// Encrypt the token
	token, err := pasetov4.Encrypt(deterministicSeedForTest, localKey, m, footer, nil)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%s", token)
	// Output: v4.local.dGVzdHMtMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTZ-qF7cj1LApZxpU5R2qdaX9Ox9NaKxnXjceRO_8DgJ7yODdxRd6Z0X2rG_InQPO_h6drwJoRKL.eyJraWQiOiIxMjM0NTY3ODkwIn0
}

func ExamplePasetoV4LocalWithFooterAndImplicitAssertions() {
	// Use this a random source, it must be replaced by rand.Reader for production use.
	deterministicSeedForTest := bytes.NewReader([]byte("deterministic-random-source-for-tests-1234567890123456789012345678901234567890"))

	// Generate an encryption key.
	localKey, err := pasetov4.GenerateLocalKey(deterministicSeedForTest)
	if err != nil {
		panic(err)
	}

	// Prepare the message
	m := []byte("my super secret message")
	footer := []byte(`{"kid":"1234567890"}`)

	// Assertions are informations not published in the token but kept by the producer
	// and used during the token integrity check.
	assertions := []byte(`{"user_id":"1234567890"}`)

	// Encrypt the token
	token, err := pasetov4.Encrypt(deterministicSeedForTest, localKey, m, footer, assertions)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%s", token)
	// Output: v4.local.dGVzdHMtMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTZ-qF7cj1LApZxpU5R2qdaX9Ox9NaKxnci6ObPVawSbAlqcRdmSDrklvbUqNGk61-tuOKJ0vkFQ.eyJraWQiOiIxMjM0NTY3ODkwIn0
}

func ExamplePasetoV4LocalDecrypt() {
	// Use this a random source, it must be replaced by rand.Reader for production use.
	deterministicSeedForTest := bytes.NewReader([]byte("deterministic-random-source-for-tests-1234567890123456789012345678901234567890"))

	// Generate an encryption key.
	localKey, err := pasetov4.GenerateLocalKey(deterministicSeedForTest)
	if err != nil {
		panic(err)
	}

	// Encrypted token.
	input := []byte("v4.local.dGVzdHMtMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTZ-qF7cj1LApZxpU5R2qdaX9Ox9NaKxnci6ObPVawSbAlqcRdmSDrklvbUqNGk61-tuOKJ0vkFQ.eyJraWQiOiIxMjM0NTY3ODkwIn0")

	// Expected footer value.
	footer := []byte(`{"kid":"1234567890"}`)

	// Assertions are informations not published in the token but kept by the producer
	// and used during the token integrity check.
	assertions := []byte(`{"user_id":"1234567890"}`)

	m, err := pasetov4.Decrypt(localKey, input, footer, assertions)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%s", m)
	// Output: my super secret message
}

// -----------------------------------------------------------------------------
func ExamplePasetoV4PublicSign() {
	// Use this a random source, it must be replaced by rand.Reader for production use.
	deterministicSeedForTest := bytes.NewReader([]byte("deterministic-random-source-for-tests-1234567890123456789012345678901234567890"))

	// Generate an ed25519 key pair.
	_, sk, err := ed25519.GenerateKey(deterministicSeedForTest)
	if err != nil {
		panic(err)
	}

	// Prepare the message
	m := []byte("my super secret message")
	footer := []byte(`{"kid":"1234567890"}`)
	assertions := []byte(`{"user_id":"1234567890"}`)

	// Sign the token
	token, err := pasetov4.Sign(m, sk, footer, assertions)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%s", token)
	// Output: v4.public.bXkgc3VwZXIgc2VjcmV0IG1lc3NhZ2UbOO-zu6XQbbhmDj0IUEjrmLS_TK1vM69D3pmdbUJmSa7A4c0qjEi9q-DQiMD6UUtbGEMXA1z9zdRskpGfStQH.eyJraWQiOiIxMjM0NTY3ODkwIn0
}

func ExamplePasetoV4PublicVerify() {
	// Use this a random source, it must be replaced by rand.Reader for production use.
	deterministicSeedForTest := bytes.NewReader([]byte("deterministic-random-source-for-tests-1234567890123456789012345678901234567890"))

	// Generate an ed25519 key pair.
	pk, _, err := ed25519.GenerateKey(deterministicSeedForTest)
	if err != nil {
		panic(err)
	}

	// Prepare the message
	input := []byte("v4.public.bXkgc3VwZXIgc2VjcmV0IG1lc3NhZ2UbOO-zu6XQbbhmDj0IUEjrmLS_TK1vM69D3pmdbUJmSa7A4c0qjEi9q-DQiMD6UUtbGEMXA1z9zdRskpGfStQH.eyJraWQiOiIxMjM0NTY3ODkwIn0")
	footer := []byte(`{"kid":"1234567890"}`)
	assertions := []byte(`{"user_id":"1234567890"}`)

	// Sign the token
	m, err := pasetov4.Verify(input, pk, footer, assertions)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%s", m)
	// Output: my super secret message
}
