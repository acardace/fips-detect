# fips-detect

Detect whether your system/container and your Golang binary are ready to run in FIPS mode.

# How it works

**fips-detect** does a couple of checks on the running system and the supplied binary to see if everything is in place to correctly run in FIPS mode*, these checks are:

- Checks if `/proc/sys/crypto/fips_enabled` is `1`
- Looks inside `/usr/lib[64]` and `/lib[64]` for a (OpenSSL lib) `libcrypto.so` that is FIPS-capable.
- Checks if the ELF binary has undefined references to FIPS symbols in `libcrypto.so` (which means it was compiled with [Red Hat's Go toolset] or that it's using goboring)

*the correct definitions is actually: if the binary has everything it should to run using a FIPS-capable cryptographic module.

# Install

Just `go get github.com/acardace/fips-detect`.

Run `go build fips-detect.go`

# Usage

Run `./fips-detect <executable>`

[Red Hat's Go toolset]: https://developers.redhat.com/blog/2019/06/24/go-and-fips-140-2-on-red-hat-enterprise-linux
