# PASETO

This go library exposed as `zntr.io/paseto` provides :

* `v3` - NIST compliant PASETO : `HKDF-HMAC-SH384` / `AES-CTR` / `HMAC-SHA384` / `ECDSA with RFC6979` (deterministic signatures) - [PASETO Version 3 specification](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version3.md)
* `v4` - `BLAKE2B` / `XCHACHA20` / `Ed25519` - [PASETO Version 4 specification](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md)

> This is used in my OIDC framework [SolID](https://github.com/zntrio/solid).

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
	token, err := pasetov4.Encrypt(rand.Reader, localKey, m, "", "")
	if err != nil {
		panic(err)
	}
}
```

More examples - [here](example_test.go)

## Benchmarks

### V3

```sh
$ go test -bench=. -test.benchtime=1s
goos: darwin
goarch: amd64
pkg: zntr.io/paseto/v3
cpu: Intel(R) Core(TM) i9-9980HK CPU @ 2.40GHz
Benchmark_Paseto_Encrypt-16    	   95533	     12378 ns/op	    9616 B/op	      78 allocs/op
Benchmark_Paseto_Decrypt-16    	  108386	     11064 ns/op	    8488 B/op	      71 allocs/op
Benchmark_Paseto_Sign-16       	     360	   3370568 ns/op	 1718026 B/op	   14190 allocs/op
Benchmark_Paseto_Verify-16     	     186	   6457398 ns/op	 3476564 B/op	   28712 allocs/op
PASS
ok  	zntr.io/paseto/v3	6.361s
```

### V4

```sh
$ go test -bench=. -test.benchtime=1s
goos: darwin
goarch: amd64
pkg: zntr.io/paseto/v4
cpu: Intel(R) Core(TM) i9-9980HK CPU @ 2.40GHz
Benchmark_Paseto_Encrypt-16    	  317936	      3437 ns/op	    3536 B/op	      29 allocs/op
Benchmark_Paseto_Decrypt-16    	  459136	      2484 ns/op	    2448 B/op	      22 allocs/op
Benchmark_Paseto_Sign-16       	   51328	     23316 ns/op	    1672 B/op	      18 allocs/op
Benchmark_Paseto_Verify-16     	   22741	     52872 ns/op	     744 B/op	      13 allocs/op
PASS
ok  	zntr.io/paseto/v4	5.624s
```

## License

All artifacts and source code are released under [Apache 2.0 Software License](LICENSE).

## Reference(s)

- <https://developer.okta.com/blog/2019/10/17/a-thorough-introduction-to-paseto>
- <https://dev.to/techschoolguru/why-paseto-is-better-than-jwt-for-token-based-authentication-1b0c>
- <https://paragonie.com/blog/2021/08/paseto-is-even-more-secure-alternative-jose-standards-jwt-etc>
