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

> Go version 1.19.3 / Mac M1

### V3

```sh
$ go test -bench=. -test.benchtime=1s
goos: darwin
goarch: arm64
pkg: zntr.io/paseto/v3
Benchmark_Paseto_Encrypt-10    	   75150	     15071 ns/op	    9328 B/op	      76 allocs/op
Benchmark_Paseto_Decrypt-10    	   82350	     14535 ns/op	    8200 B/op	      69 allocs/op
Benchmark_Paseto_Sign-10       	    7507	    159817 ns/op	   10004 B/op	     101 allocs/op
Benchmark_Paseto_Verify-10     	    1945	    614350 ns/op	    3770 B/op	      61 allocs/op
PASS
ok  	zntr.io/paseto/v3	5.276s
```

### V4

```sh
$ go test -bench=. -test.benchtime=1s
goos: darwin
goarch: arm64
pkg: zntr.io/paseto/v4
Benchmark_Paseto_Encrypt-10    	  423649	      2823 ns/op	    3296 B/op	      29 allocs/op
Benchmark_Paseto_Decrypt-10    	  503470	      2389 ns/op	    2208 B/op	      22 allocs/op
Benchmark_Paseto_Sign-10       	   46567	     25378 ns/op	    1720 B/op	      17 allocs/op
Benchmark_Paseto_Verify-10     	   22294	     53853 ns/op	     792 B/op	      12 allocs/op
PASS
ok  	zntr.io/paseto/v4	6.723s
```

## License

All artifacts and source code are released under [Apache 2.0 Software License](LICENSE).

## Reference(s)

- <https://developer.okta.com/blog/2019/10/17/a-thorough-introduction-to-paseto>
- <https://dev.to/techschoolguru/why-paseto-is-better-than-jwt-for-token-based-authentication-1b0c>
- <https://paragonie.com/blog/2021/08/paseto-is-even-more-secure-alternative-jose-standards-jwt-etc>
