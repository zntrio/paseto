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
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

// https://github.com/paseto-standard/test-vectors/blob/master/v4.json
func Test_Paseto_PublicVector(t *testing.T) {
	testCases := []struct {
		name              string
		expectFail        bool
		publicKey         string
		secretKey         string
		secretKeySeed     string
		secretKeyPem      string
		publicKeyPem      string
		token             string
		payload           []byte
		footer            string
		implicitAssertion string
	}{
		{
			name:              "4-S-1",
			expectFail:        false,
			publicKey:         "1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2",
			secretKey:         "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2",
			secretKeySeed:     "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a3774",
			secretKeyPem:      "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----",
			publicKeyPem:      "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\n-----END PUBLIC KEY-----",
			token:             "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9bg_XBBzds8lTZShVlwwKSgeKpLT3yukTw6JUz3W4h_ExsQV-P0V54zemZDcAxFaSeef1QlXEFtkqxT1ciiQEDA",
			payload:           []byte("{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}"),
			footer:            "",
			implicitAssertion: "",
		},
		{
			name:              "4-S-2",
			expectFail:        false,
			publicKey:         "1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2",
			secretKey:         "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2",
			secretKeySeed:     "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a3774",
			secretKeyPem:      "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----",
			publicKeyPem:      "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\n-----END PUBLIC KEY-----",
			token:             "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9v3Jt8mx_TdM2ceTGoqwrh4yDFn0XsHvvV_D0DtwQxVrJEBMl0F2caAdgnpKlt4p7xBnx1HcO-SPo8FPp214HDw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
			payload:           []byte("{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}"),
			footer:            "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}",
			implicitAssertion: "",
		},
		{
			name:              "4-S-3",
			expectFail:        false,
			publicKey:         "1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2",
			secretKey:         "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2",
			secretKeySeed:     "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a3774",
			secretKeyPem:      "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----",
			publicKeyPem:      "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\n-----END PUBLIC KEY-----",
			token:             "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9NPWciuD3d0o5eXJXG5pJy-DiVEoyPYWs1YSTwWHNJq6DZD3je5gf-0M4JR9ipdUSJbIovzmBECeaWmaqcaP0DQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
			payload:           []byte("{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}"),
			footer:            "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}",
			implicitAssertion: "{\"test-vector\":\"4-S-3\"}",
		},
	}

	// For each testcase
	for _, tc := range testCases {
		testCase := tc
		t.Run(testCase.name, func(t *testing.T) {
			// Decode input
			publicKey, err := hex.DecodeString(testCase.publicKey)
			assert.NoError(t, err)
			secretKey, err := hex.DecodeString(testCase.secretKey)
			assert.NoError(t, err)
			secretKeySeed, err := hex.DecodeString(testCase.secretKeySeed)
			assert.NoError(t, err)

			// Generate ed25519 key pair
			sk := ed25519.NewKeyFromSeed(secretKeySeed)
			assert.Equal(t, secretKey, []byte(sk))
			pk := sk.Public().(ed25519.PublicKey)
			assert.Equal(t, publicKey, []byte(pk))

			// Sign
			token, err := Sign(testCase.payload, sk, []byte(testCase.footer), []byte(testCase.implicitAssertion))
			if (err != nil) != testCase.expectFail {
				t.Errorf("error during the sign call, error = %v, wantErr %v", err, testCase.expectFail)
				return
			}
			assert.Equal(t, testCase.token, string(token))

			// Verify
			message, err := Verify([]byte(testCase.token), pk, []byte(testCase.footer), []byte(testCase.implicitAssertion))
			if (err != nil) != testCase.expectFail {
				t.Errorf("error during the verify call, error = %v, wantErr %v", err, testCase.expectFail)
				return
			}
			assert.Equal(t, testCase.payload, message)
		})
	}
}

// -----------------------------------------------------------------------------

func benchmarkSign(m []byte, sk ed25519.PrivateKey, f, i []byte, b *testing.B) {
	for n := 0; n < b.N; n++ {
		_, err := Sign(m, sk, f, i)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func Benchmark_Paseto_Sign(b *testing.B) {
	sk, err := hex.DecodeString("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")
	assert.NoError(b, err)

	m := []byte("{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}")
	f := []byte("{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}")
	i := []byte("{\"test-vector\":\"4-S-3\"}")

	b.ReportAllocs()
	b.ResetTimer()

	benchmarkSign(m, sk, f, i, b)
}

func benchmarkVerify(m []byte, pk ed25519.PublicKey, f, i []byte, b *testing.B) {
	for n := 0; n < b.N; n++ {
		_, err := Verify(m, pk, f, i)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func Benchmark_Paseto_Verify(b *testing.B) {
	pk, err := hex.DecodeString("1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")
	assert.NoError(b, err)

	token := []byte("v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9NPWciuD3d0o5eXJXG5pJy-DiVEoyPYWs1YSTwWHNJq6DZD3je5gf-0M4JR9ipdUSJbIovzmBECeaWmaqcaP0DQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9")
	f := []byte("{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}")
	i := []byte("{\"test-vector\":\"4-S-3\"}")

	b.ReportAllocs()
	b.ResetTimer()

	benchmarkVerify(token, pk, f, i, b)
}
