# PASETO

This go library exposed as `zntr.io/paseto` provides :

* `v4` - `local` and `public` implementation of [PASETO Version 4 specification](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md). 

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
	localKey, err := pasetov4.GenerateKey(rand.Reader)
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

All artifacts and source code is released under [Apache 2.0 Software License](LICENSE).

## Reference(s)

- <https://developer.okta.com/blog/2019/10/17/a-thorough-introduction-to-paseto>
- <https://dev.to/techschoolguru/why-paseto-is-better-than-jwt-for-token-based-authentication-1b0c>
- <https://paragonie.com/blog/2021/08/paseto-is-even-more-secure-alternative-jose-standards-jwt-etc>
