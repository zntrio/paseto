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
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

// https://github.com/paseto-standard/test-vectors/blob/master/v3.json
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
			name:              "3-E-1",
			expectFail:        false,
			key:               "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
			nonce:             "0000000000000000000000000000000000000000000000000000000000000000",
			token:             "v3.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADbfcIURX_0pVZVU1mAESUzrKZAsRm2EsD6yBoZYn6cpVZNzSJOhSDN-sRaWjfLU-yn9OJH1J_B8GKtOQ9gSQlb8yk9Iza7teRdkiR89ZFyvPPsVjjFiepFUVcMa-LP18zV77f_crJrVXWa5PDNRkCSeHfBBeg",
			payload:           []byte("{\"data\":\"this is a secret message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}"),
			footer:            []byte(""),
			implicitAssertion: []byte(""),
		},
		{
			name:              "3-E-2",
			expectFail:        false,
			key:               "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
			nonce:             "0000000000000000000000000000000000000000000000000000000000000000",
			token:             "v3.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADbfcIURX_0pVZVU1mAESUzrKZAqhWxBMDgyBoZYn6cpVZNzSJOhSDN-sRaWjfLU-yn9OJH1J_B8GKtOQ9gSQlb8yk9IzZfaZpReVpHlDSwfuygx1riVXYVs-UjcrG_apl9oz3jCVmmJbRuKn5ZfD8mHz2db0A",
			payload:           []byte("{\"data\":\"this is a hidden message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}"),
			footer:            []byte(""),
			implicitAssertion: []byte(""),
		},

		{
			name:              "3-E-3",
			expectFail:        false,
			nonce:             "26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2",
			key:               "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
			token:             "v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0ROIIykcrGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJlxnt5xyhQjFJomwnt7WW_7r2VT0G704ifult011-TgLCyQ2X8imQhniG_hAQ4BydM",
			payload:           []byte("{\"data\":\"this is a secret message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}"),
			footer:            []byte(""),
			implicitAssertion: []byte(""),
		},
		{
			name:              "3-E-4",
			expectFail:        false,
			nonce:             "26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2",
			key:               "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
			token:             "v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0X-4P3EcxGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJlBZa_gOpVj4gv0M9lV6Pwjp8JS_MmaZaTA1LLTULXybOBZ2S4xMbYqYmDRhh3IgEk",
			payload:           []byte("{\"data\":\"this is a hidden message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}"),
			footer:            []byte(""),
			implicitAssertion: []byte(""),
		},
		{
			name:              "3-E-5",
			expectFail:        false,
			nonce:             "26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2",
			key:               "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
			token:             "v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0ROIIykcrGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJlkYSIbXOgVuIQL65UMdW9WcjOpmqvjqD40NNzed-XPqn1T3w-bJvitYpUJL_rmihc.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9",
			payload:           []byte("{\"data\":\"this is a secret message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}"),
			footer:            []byte("{\"kid\":\"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo\"}"),
			implicitAssertion: []byte(""),
		},
		{
			name:              "3-E-6",
			expectFail:        false,
			nonce:             "26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2",
			key:               "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
			token:             "v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0X-4P3EcxGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJmSeEMphEWHiwtDKJftg41O1F8Hat-8kQ82ZIAMFqkx9q5VkWlxZke9ZzMBbb3Znfo.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9",
			payload:           []byte("{\"data\":\"this is a hidden message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}"),
			footer:            []byte("{\"kid\":\"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo\"}"),
			implicitAssertion: []byte(""),
		},
		{
			name:              "3-E-7",
			expectFail:        false,
			nonce:             "26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2",
			key:               "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
			token:             "v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0ROIIykcrGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJkzWACWAIoVa0bz7EWSBoTEnS8MvGBYHHo6t6mJunPrFR9JKXFCc0obwz5N-pxFLOc.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9",
			payload:           []byte("{\"data\":\"this is a secret message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}"),
			footer:            []byte("{\"kid\":\"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo\"}"),
			implicitAssertion: []byte("{\"test-vector\":\"3-E-7\"}"),
		},
		{
			name:              "3-E-8",
			expectFail:        false,
			nonce:             "26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2",
			key:               "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
			token:             "v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0X-4P3EcxGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJmZHSSKYR6AnPYJV6gpHtx6dLakIG_AOPhu8vKexNyrv5_1qoom6_NaPGecoiz6fR8.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9",
			payload:           []byte("{\"data\":\"this is a hidden message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}"),
			footer:            []byte("{\"kid\":\"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo\"}"),
			implicitAssertion: []byte("{\"test-vector\":\"3-E-8\"}"),
		},
		{
			name:              "3-E-9",
			expectFail:        false,
			nonce:             "26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2",
			key:               "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
			token:             "v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0X-4P3EcxGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJlk1nli0_wijTH_vCuRwckEDc82QWK8-lG2fT9wQF271sgbVRVPjm0LwMQZkvvamqU.YXJiaXRyYXJ5LXN0cmluZy10aGF0LWlzbid0LWpzb24",
			payload:           []byte("{\"data\":\"this is a hidden message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}"),
			footer:            []byte("arbitrary-string-that-isn't-json"),
			implicitAssertion: []byte("{\"test-vector\":\"3-E-9\"}"),
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
			token, err := Encrypt(bytes.NewReader(n), key, []byte(testCase.payload), testCase.footer, testCase.implicitAssertion)
			if (err != nil) != testCase.expectFail {
				t.Errorf("error during the encrypt call, error = %v, wantErr %v", err, testCase.expectFail)
				return
			}
			assert.Equal(t, testCase.token, string(token))

			// Decrypt
			message, err := Decrypt(key, []byte(testCase.token), testCase.footer, testCase.implicitAssertion)
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
	i := []byte("{\"test-vector\":\"3-E-3\"}")

	b.ReportAllocs()
	b.ResetTimer()

	benchmarkEncrypt(&key, m, f, i, b)
}

func benchmarkDecrypt(key *LocalKey, m, f, i []byte, b *testing.B) {
	for n := 0; n < b.N; n++ {
		_, err := Decrypt(key, m, f, i)
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

	m := []byte("v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0X-4P3EcxGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJmZHSSKYR6AnPYJV6gpHtx6dLakIG_AOPhu8vKexNyrv5_1qoom6_NaPGecoiz6fR8.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9")
	f := []byte("{\"kid\":\"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo\"}")
	i := []byte("{\"test-vector\":\"3-E-8\"}")

	b.ReportAllocs()
	b.ResetTimer()

	benchmarkDecrypt(&key, m, f, i, b)
}
