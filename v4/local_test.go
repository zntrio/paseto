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
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

// https://github.com/paseto-standard/test-vectors/blob/master/v4.json
func Test_Paseto_LocalVector(t *testing.T) {
	testCases := []struct {
		name              string
		expectFail        bool
		key               string
		nonce             string
		token             string
		payload           []byte
		footer            []byte
		implicitAssertion []byte
	}{
		{
			name:              "4-E-1",
			expectFail:        false,
			key:               "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
			nonce:             "0000000000000000000000000000000000000000000000000000000000000000",
			token:             "v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAr68PS4AXe7If_ZgesdkUMvSwscFlAl1pk5HC0e8kApeaqMfGo_7OpBnwJOAbY9V7WU6abu74MmcUE8YWAiaArVI8XJ5hOb_4v9RmDkneN0S92dx0OW4pgy7omxgf3S8c3LlQg",
			payload:           []byte("{\"data\":\"this is a secret message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}"),
			footer:            []byte(""),
			implicitAssertion: []byte(""),
		},
		{
			name:              "4-E-2",
			expectFail:        false,
			key:               "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
			nonce:             "0000000000000000000000000000000000000000000000000000000000000000",
			token:             "v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAr68PS4AXe7If_ZgesdkUMvS2csCgglvpk5HC0e8kApeaqMfGo_7OpBnwJOAbY9V7WU6abu74MmcUE8YWAiaArVI8XIemu9chy3WVKvRBfg6t8wwYHK0ArLxxfZP73W_vfwt5A",
			payload:           []byte("{\"data\":\"this is a hidden message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}"),
			footer:            []byte(""),
			implicitAssertion: []byte(""),
		},
		{
			name:              "4-E-3",
			expectFail:        false,
			nonce:             "df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8",
			key:               "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
			token:             "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WkwMsYXw6FSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t6-tyebyWG6Ov7kKvBdkrrAJ837lKP3iDag2hzUPHuMKA",
			payload:           []byte("{\"data\":\"this is a secret message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}"),
			footer:            []byte(""),
			implicitAssertion: []byte(""),
		},
		{
			name:              "4-E-4",
			expectFail:        false,
			nonce:             "df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8",
			key:               "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
			token:             "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WiA8rd3wgFSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t4gt6TiLm55vIH8c_lGxxZpE3AWlH4WTR0v45nsWoU3gQ",
			payload:           []byte("{\"data\":\"this is a hidden message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}"),
			footer:            []byte(""),
			implicitAssertion: []byte(""),
		},
		{
			name:              "4-E-5",
			expectFail:        false,
			nonce:             "df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8",
			key:               "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
			token:             "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WkwMsYXw6FSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t4x-RMNXtQNbz7FvFZ_G-lFpk5RG3EOrwDL6CgDqcerSQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
			payload:           []byte("{\"data\":\"this is a secret message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}"),
			footer:            []byte("{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}"),
			implicitAssertion: []byte(""),
		},
		{
			name:              "4-E-6",
			expectFail:        false,
			nonce:             "df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8",
			key:               "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
			token:             "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WiA8rd3wgFSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t6pWSA5HX2wjb3P-xLQg5K5feUCX4P2fpVK3ZLWFbMSxQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
			payload:           []byte("{\"data\":\"this is a hidden message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}"),
			footer:            []byte("{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}"),
			implicitAssertion: []byte(""),
		},
		{
			name:              "4-E-7",
			expectFail:        false,
			nonce:             "df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8",
			key:               "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
			token:             "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WkwMsYXw6FSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t40KCCWLA7GYL9KFHzKlwY9_RnIfRrMQpueydLEAZGGcA.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
			payload:           []byte("{\"data\":\"this is a secret message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}"),
			footer:            []byte("{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}"),
			implicitAssertion: []byte("{\"test-vector\":\"4-E-7\"}"),
		},
		{
			name:              "4-E-8",
			expectFail:        false,
			nonce:             "df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8",
			key:               "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
			token:             "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WiA8rd3wgFSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t5uvqQbMGlLLNYBc7A6_x7oqnpUK5WLvj24eE4DVPDZjw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
			payload:           []byte("{\"data\":\"this is a hidden message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}"),
			footer:            []byte("{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}"),
			implicitAssertion: []byte("{\"test-vector\":\"4-E-8\"}"),
		},
		{
			name:              "4-E-9",
			expectFail:        false,
			nonce:             "df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8",
			key:               "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
			token:             "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WiA8rd3wgFSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t6tybdlmnMwcDMw0YxA_gFSE_IUWl78aMtOepFYSWYfQA.YXJiaXRyYXJ5LXN0cmluZy10aGF0LWlzbid0LWpzb24",
			payload:           []byte("{\"data\":\"this is a hidden message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}"),
			footer:            []byte("arbitrary-string-that-isn't-json"),
			implicitAssertion: []byte("{\"test-vector\":\"4-E-9\"}"),
		},
	}

	// For each testcase
	for _, tc := range testCases {
		testCase := tc
		t.Run(testCase.name, func(t *testing.T) {
			// Decode input
			keyRaw := [32]byte{}
			_, err := hex.Decode(keyRaw[:], []byte(testCase.key))
			assert.NoError(t, err)
			key, err := LocalKeyFromSeed(keyRaw[:])
			assert.NoError(t, err)

			n, err := hex.DecodeString(testCase.nonce)
			assert.NoError(t, err)

			// Encrypt
			token, err := Encrypt(bytes.NewReader(n), key, testCase.payload, testCase.footer, testCase.implicitAssertion)
			if (err != nil) != testCase.expectFail {
				t.Errorf("error during the encrypt call, error = %v, wantErr %v", err, testCase.expectFail)
				return
			}
			assert.Equal(t, testCase.token, string(token))

			// Decrypt
			message, err := Decrypt(key, testCase.token, testCase.footer, testCase.implicitAssertion)
			if (err != nil) != testCase.expectFail {
				t.Errorf("error during the decrypt call, error = %v, wantErr %v", err, testCase.expectFail)
				return
			}
			assert.Equal(t, testCase.payload, message)
		})
	}
}

func Test_Paseto_Local_EncryptDecrypt(t *testing.T) {
	keyRaw := [32]byte{}
	_, err := hex.Decode(keyRaw[:], []byte("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f"))
	assert.NoError(t, err)
	key, err := LocalKeyFromSeed(keyRaw[:])
	assert.NoError(t, err)

	m := []byte("{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}")
	f := []byte("{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}")
	i := []byte("{\"test-vector\":\"4-S-3\"}")

	token1, err := Encrypt(rand.Reader, key, m, f, i)
	assert.NoError(t, err)
	assert.NotEmpty(t, token1)

	token2, err := Encrypt(rand.Reader, key, m, f, i)
	assert.NoError(t, err)
	assert.NotEmpty(t, token2)

	assert.NotEqual(t, token1, token2)

	p, err := Decrypt(key, token1, f, i)
	assert.NoError(t, err)
	assert.Equal(t, m, p)
}

// -----------------------------------------------------------------------------

func benchmarkEncrypt(key *LocalKey, m, f, i []byte, b *testing.B) {
	for n := 0; n < b.N; n++ {
		_, err := Encrypt(rand.Reader, key, m, f, i)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func Benchmark_Paseto_Encrypt(b *testing.B) {
	keyRaw := [32]byte{}
	_, err := hex.Decode(keyRaw[:], []byte("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f"))
	assert.NoError(b, err)
	key := LocalKey(keyRaw)

	m := []byte("{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}")
	f := []byte("{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}")
	i := []byte("{\"test-vector\":\"4-S-3\"}")

	b.ReportAllocs()
	b.ResetTimer()

	benchmarkEncrypt(&key, m, f, i, b)
}

func benchmarkDecrypt(key *LocalKey, t string, f, i []byte, b *testing.B) {
	for n := 0; n < b.N; n++ {
		_, err := Decrypt(key, t, f, i)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func Benchmark_Paseto_Decrypt(b *testing.B) {
	keyRaw := [32]byte{}
	_, err := hex.Decode(keyRaw[:], []byte("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f"))
	assert.NoError(b, err)
	key := LocalKey(keyRaw)

	t := "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WiA8rd3wgFSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t5uvqQbMGlLLNYBc7A6_x7oqnpUK5WLvj24eE4DVPDZjw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9"
	f := []byte("{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}")
	i := []byte("{\"test-vector\":\"4-E-8\"}")

	b.ReportAllocs()
	b.ResetTimer()

	benchmarkDecrypt(&key, t, f, i, b)
}
