# PASETO

This go library exposed as `zntr.io/paseto` provides :

* `v3` - NIST compliant PASETO : `HKDF-HMAC-SH384` / `AES-CTR` / `HMAC-SHA384` / `ECDSA with RFC6979` (deterministic signatures) - [PASETO Version 3 specification](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version3.md)
* `v4` - `BLAKE2B` / `XCHACHA20` / `Ed25519` - [PASETO Version 4 specification](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md)

> This is used in my OIDC framework [SolID](https://github.com/zntrio/solid).

I removed the JSON part encoding requirement to allow PASETO to be used as a 
generic data container. You can still use JSON, but also more bytes oriented 
serialization for `message`,  `footer` and `implicit-assertion`.

## What is PASETO?

From https://github.com/paragonie/paseto :

> PASETO: Platform-Agnostic Security Tokens
> Paseto is everything you love about JOSE (JWT, JWE, JWS) without any of the many design deficits that plague the JOSE standards.

## How to use the library?

```go
import (
  pasetov4 "zntr.io/paseto/v4"
)

func main () {
	// Generate an encryption key.
	localKey, err := pasetov4.GenerateLocalKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	// Prepare the message
	m := []byte("my super secret message")

	// Encrypt the token
	token, err := pasetov4.Encrypt(rand.Reader, localKey, m, nil, nil)
	if err != nil {
		panic(err)
	}
}
```

More examples - [here](example_test.go)

## Benchmarks

> Go version 1.23.1 / Mac M1

### V3

```sh
❯ go test -bench=. -test.benchtime=1s
goos: darwin
goarch: arm64
pkg: zntr.io/paseto/v3
cpu: Apple M1 Pro
Benchmark_Paseto_Encrypt-10    	  213638	      5511 ns/op	    7378 B/op	      52 allocs/op
Benchmark_Paseto_Decrypt-10    	  226226	      5268 ns/op	    7154 B/op	      52 allocs/op
Benchmark_Paseto_Sign-10       	   10000	    124865 ns/op	    9060 B/op	      86 allocs/op
Benchmark_Paseto_Verify-10     	    2292	    536478 ns/op	    2504 B/op	      36 allocs/op
PASS
ok  	zntr.io/paseto/v3	6.052s
```

### V4

```sh
❯ go test -bench=. -test.benchtime=1s
goos: darwin
goarch: arm64
pkg: zntr.io/paseto/v4
cpu: Apple M1 Pro
Benchmark_Paseto_Encrypt-10    	  511538	      2397 ns/op	    2288 B/op	      12 allocs/op
Benchmark_Paseto_Decrypt-10    	  528723	      2260 ns/op	    2064 B/op	      12 allocs/op
Benchmark_Paseto_Sign-10       	   51476	     24680 ns/op	     928 B/op	       4 allocs/op
Benchmark_Paseto_Verify-10     	   22828	     52875 ns/op	     704 B/op	       4 allocs/op
PASS
ok  	zntr.io/paseto/v4	7.119s
```

### V4X (XCHACHA20-BLAKE3) - Non standard

> This is a non-standard version of PASETO using XCHACHA20-BLAKE3 instead of XCHACHA20-POLY1305.
> https://kerkour.com/chacha20-blake3/

```sh
❯ go test -bench=. -test.benchtime=1s
goos: darwin
goarch: arm64
pkg: zntr.io/paseto/v4x
cpu: Apple M1 Pro
Benchmark_Paseto_Encrypt-10    	  496018	      2336 ns/op	    1056 B/op	       6 allocs/op
Benchmark_Paseto_Decrypt-10    	  531135	      2314 ns/op	     832 B/op	       6 allocs/op
PASS
ok  	zntr.io/paseto/v4x	2.832s
```

## License

All artifacts and source code are released under [Apache 2.0 Software License](LICENSE).

## Reference(s)

- <https://developer.okta.com/blog/2019/10/17/a-thorough-introduction-to-paseto>
- <https://dev.to/techschoolguru/why-paseto-is-better-than-jwt-for-token-based-authentication-1b0c>
- <https://paragonie.com/blog/2021/08/paseto-is-even-more-secure-alternative-jose-standards-jwt-etc>
- <https://kerkour.com/chacha20-blake3>
