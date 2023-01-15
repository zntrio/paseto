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

> Go version 1.19.5 / Mac M1

### V3

```sh
❯ go test -bench=. -test.benchtime=1s
goos: darwin
goarch: arm64
pkg: zntr.io/paseto/v3
Benchmark_Paseto_Encrypt-10    	   74997	     14869 ns/op	    8800 B/op	      70 allocs/op
Benchmark_Paseto_Decrypt-10    	   83835	     14272 ns/op	    7912 B/op	      66 allocs/op
Benchmark_Paseto_Sign-10       	    7545	    156930 ns/op	    9812 B/op	      99 allocs/op
Benchmark_Paseto_Verify-10     	    1986	    615306 ns/op	    3578 B/op	      59 allocs/op
PASS
ok  	zntr.io/paseto/v3	5.400s
```

### V4

```sh
❯ go test -bench=. -test.benchtime=1s
goos: darwin
goarch: arm64
pkg: zntr.io/paseto/v4
Benchmark_Paseto_Encrypt-10    	  426136	      2811 ns/op	    2752 B/op	      23 allocs/op
Benchmark_Paseto_Decrypt-10    	  517602	      2244 ns/op	    1920 B/op	      19 allocs/op
Benchmark_Paseto_Sign-10       	   48186	     24887 ns/op	    1480 B/op	      15 allocs/op
Benchmark_Paseto_Verify-10     	   22714	     52885 ns/op	     552 B/op	      10 allocs/op
PASS
ok  	zntr.io/paseto/v4	6.851s
```

## License

All artifacts and source code are released under [Apache 2.0 Software License](LICENSE).

## Reference(s)

- <https://developer.okta.com/blog/2019/10/17/a-thorough-introduction-to-paseto>
- <https://dev.to/techschoolguru/why-paseto-is-better-than-jwt-for-token-based-authentication-1b0c>
- <https://paragonie.com/blog/2021/08/paseto-is-even-more-secure-alternative-jose-standards-jwt-etc>
