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
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

// https://github.com/paseto-standard/test-vectors/blob/master/v3.json
func Test_Paseto_PublicVector(t *testing.T) {
	testCases := []struct {
		name              string
		expectFail        bool
		publicKey         string
		secretKey         string
		secretKeyPem      string
		publicKeyPem      string
		token             string
		payload           string
		footer            string
		implicitAssertion string
	}{
		{
			name:              "3-S-1",
			expectFail:        false,
			publicKey:         "02fbcb7c69ee1c60579be7a334134878d9c5c5bf35d552dab63c0140397ed14cef637d7720925c44699ea30e72874c72fb",
			secretKey:         "20347609607477aca8fbfbc5e6218455f3199669792ef8b466faa87bdc67798144c848dd03661eed5ac62461340cea96",
			secretKeyPem:      "-----BEGIN EC PRIVATE KEY-----\nMIGkAgEBBDAgNHYJYHR3rKj7+8XmIYRV8xmWaXku+LRm+qh73Gd5gUTISN0DZh7t\nWsYkYTQM6pagBwYFK4EEACKhZANiAAT7y3xp7hxgV5vnozQTSHjZxcW/NdVS2rY8\nAUA5ftFM72N9dyCSXERpnqMOcodMcvt8kgcrB8KcKee0HU23E79/s4CvEs8hBfnj\nSUd/gcAm08EjSIz06iWjrNy4NakxR3I=\n-----END EC PRIVATE KEY-----",
			publicKeyPem:      "-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE+8t8ae4cYFeb56M0E0h42cXFvzXVUtq2\nPAFAOX7RTO9jfXcgklxEaZ6jDnKHTHL7fJIHKwfCnCnntB1NtxO/f7OArxLPIQX5\n40lHf4HAJtPBI0iM9Oolo6zcuDWpMUdy\n-----END PUBLIC KEY-----",
			token:             "v3.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9qqEwwrKHKi5lJ7b9MBKc0G4MGZy0ptUiMv3lAUAaz-JY_zjoqBSIxMxhfAoeNYiSyvfUErj76KOPWm1OeNnBPkTSespeSXDGaDfxeIrl3bRrPEIy7tLwLAIsRzsXkfph",
			payload:           "{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}",
			footer:            "",
			implicitAssertion: "",
		},
		{
			name:              "3-S-2",
			expectFail:        false,
			publicKey:         "02fbcb7c69ee1c60579be7a334134878d9c5c5bf35d552dab63c0140397ed14cef637d7720925c44699ea30e72874c72fb",
			secretKey:         "20347609607477aca8fbfbc5e6218455f3199669792ef8b466faa87bdc67798144c848dd03661eed5ac62461340cea96",
			secretKeyPem:      "-----BEGIN EC PRIVATE KEY-----\nMIGkAgEBBDAgNHYJYHR3rKj7+8XmIYRV8xmWaXku+LRm+qh73Gd5gUTISN0DZh7t\nWsYkYTQM6pagBwYFK4EEACKhZANiAAT7y3xp7hxgV5vnozQTSHjZxcW/NdVS2rY8\nAUA5ftFM72N9dyCSXERpnqMOcodMcvt8kgcrB8KcKee0HU23E79/s4CvEs8hBfnj\nSUd/gcAm08EjSIz06iWjrNy4NakxR3I=\n-----END EC PRIVATE KEY-----",
			publicKeyPem:      "-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE+8t8ae4cYFeb56M0E0h42cXFvzXVUtq2\nPAFAOX7RTO9jfXcgklxEaZ6jDnKHTHL7fJIHKwfCnCnntB1NtxO/f7OArxLPIQX5\n40lHf4HAJtPBI0iM9Oolo6zcuDWpMUdy\n-----END PUBLIC KEY-----",
			token:             "v3.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9ZWrbGZ6L0MDK72skosUaS0Dz7wJ_2bMcM6tOxFuCasO9GhwHrvvchqgXQNLQQyWzGC2wkr-VKII71AvkLpC8tJOrzJV1cap9NRwoFzbcXjzMZyxQ0wkshxZxx8ImmNWP.eyJraWQiOiJkWWtJU3lseFFlZWNFY0hFTGZ6Rjg4VVpyd2JMb2xOaUNkcHpVSEd3OVVxbiJ9",
			payload:           "{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}",
			footer:            "{\"kid\":\"dYkISylxQeecEcHELfzF88UZrwbLolNiCdpzUHGw9Uqn\"}",
			implicitAssertion: "",
		},
		{
			name:              "3-S-3",
			expectFail:        false,
			publicKey:         "02fbcb7c69ee1c60579be7a334134878d9c5c5bf35d552dab63c0140397ed14cef637d7720925c44699ea30e72874c72fb",
			secretKey:         "20347609607477aca8fbfbc5e6218455f3199669792ef8b466faa87bdc67798144c848dd03661eed5ac62461340cea96",
			secretKeyPem:      "-----BEGIN EC PRIVATE KEY-----\nMIGkAgEBBDAgNHYJYHR3rKj7+8XmIYRV8xmWaXku+LRm+qh73Gd5gUTISN0DZh7t\nWsYkYTQM6pagBwYFK4EEACKhZANiAAT7y3xp7hxgV5vnozQTSHjZxcW/NdVS2rY8\nAUA5ftFM72N9dyCSXERpnqMOcodMcvt8kgcrB8KcKee0HU23E79/s4CvEs8hBfnj\nSUd/gcAm08EjSIz06iWjrNy4NakxR3I=\n-----END EC PRIVATE KEY-----",
			publicKeyPem:      "-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE+8t8ae4cYFeb56M0E0h42cXFvzXVUtq2\nPAFAOX7RTO9jfXcgklxEaZ6jDnKHTHL7fJIHKwfCnCnntB1NtxO/f7OArxLPIQX5\n40lHf4HAJtPBI0iM9Oolo6zcuDWpMUdy\n-----END PUBLIC KEY-----",
			token:             "v3.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ94SjWIbjmS7715GjLSnHnpJrC9Z-cnwK45dmvnVvCRQDCCKAXaKEopTajX0DKYx1Xqr6gcTdfqscLCAbiB4eOW9jlt-oNqdG8TjsYEi6aloBfTzF1DXff_45tFlnBukEX.eyJraWQiOiJkWWtJU3lseFFlZWNFY0hFTGZ6Rjg4VVpyd2JMb2xOaUNkcHpVSEd3OVVxbiJ9",
			payload:           "{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}",
			footer:            "{\"kid\":\"dYkISylxQeecEcHELfzF88UZrwbLolNiCdpzUHGw9Uqn\"}",
			implicitAssertion: "{\"test-vector\":\"3-S-3\"}",
		},
	}

	// For each testcase
	for _, tc := range testCases {
		testCase := tc
		t.Run(testCase.name, func(t *testing.T) {
			// Decode input
			var sk ecdsa.PrivateKey
			sk.D, _ = new(big.Int).SetString(testCase.secretKey, 16)
			sk.PublicKey.Curve = elliptic.P384()
			pubRaw, _ := new(big.Int).SetString(testCase.publicKey, 16)
			sk.X, sk.Y = elliptic.UnmarshalCompressed(sk.PublicKey.Curve, pubRaw.Bytes())

			// Sign
			token, err := Sign([]byte(testCase.payload), &sk, []byte(testCase.footer), []byte(testCase.implicitAssertion))
			if (err != nil) != testCase.expectFail {
				t.Errorf("error during the sign call, error = %v, wantErr %v", err, testCase.expectFail)
				return
			}
			assert.Equal(t, testCase.token, string(token))

			// Verify
			message, err := Verify(testCase.token, &sk.PublicKey, []byte(testCase.footer), []byte(testCase.implicitAssertion))
			if (err != nil) != testCase.expectFail {
				t.Errorf("error during the verify call, error = %v, wantErr %v", err, testCase.expectFail)
				return
			}
			assert.Equal(t, testCase.payload, string(message))
		})
	}
}

// -----------------------------------------------------------------------------

func benchmarkSign(m []byte, sk *ecdsa.PrivateKey, f, i []byte, b *testing.B) {
	for n := 0; n < b.N; n++ {
		_, err := Sign(m, sk, f, i)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func Benchmark_Paseto_Sign(b *testing.B) {
	var sk ecdsa.PrivateKey
	sk.D, _ = new(big.Int).SetString("20347609607477aca8fbfbc5e6218455f3199669792ef8b466faa87bdc67798144c848dd03661eed5ac62461340cea96", 16)
	sk.Curve = elliptic.P384()
	pubRaw, _ := new(big.Int).SetString("02fbcb7c69ee1c60579be7a334134878d9c5c5bf35d552dab63c0140397ed14cef637d7720925c44699ea30e72874c72fb", 16)
	sk.X, sk.Y = elliptic.UnmarshalCompressed(sk.PublicKey.Curve, pubRaw.Bytes())

	m := []byte("{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}")
	f := []byte("{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}")
	i := []byte("{\"test-vector\":\"4-S-3\"}")

	b.ReportAllocs()
	b.ResetTimer()

	benchmarkSign(m, &sk, f, i, b)
}

func benchmarkVerify(t string, pk *ecdsa.PublicKey, f, i []byte, b *testing.B) {
	for n := 0; n < b.N; n++ {
		_, err := Verify(t, pk, f, i)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func Benchmark_Paseto_Verify(b *testing.B) {
	var sk ecdsa.PrivateKey
	sk.D, _ = new(big.Int).SetString("20347609607477aca8fbfbc5e6218455f3199669792ef8b466faa87bdc67798144c848dd03661eed5ac62461340cea96", 16)
	pubRaw, _ := new(big.Int).SetString("02fbcb7c69ee1c60579be7a334134878d9c5c5bf35d552dab63c0140397ed14cef637d7720925c44699ea30e72874c72fb", 16)
	sk.PublicKey.Curve = elliptic.P384()
	sk.PublicKey.X, sk.PublicKey.Y = elliptic.UnmarshalCompressed(sk.PublicKey.Curve, pubRaw.Bytes())

	token := "v3.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ94SjWIbjmS7715GjLSnHnpJrC9Z-cnwK45dmvnVvCRQDCCKAXaKEopTajX0DKYx1Xqr6gcTdfqscLCAbiB4eOW9jlt-oNqdG8TjsYEi6aloBfTzF1DXff_45tFlnBukEX.eyJraWQiOiJkWWtJU3lseFFlZWNFY0hFTGZ6Rjg4VVpyd2JMb2xOaUNkcHpVSEd3OVVxbiJ9"
	f := []byte("{\"kid\":\"dYkISylxQeecEcHELfzF88UZrwbLolNiCdpzUHGw9Uqn\"}")
	i := []byte("{\"test-vector\":\"3-S-3\"}")

	b.ReportAllocs()
	b.ResetTimer()

	benchmarkVerify(token, &sk.PublicKey, f, i, b)
}
