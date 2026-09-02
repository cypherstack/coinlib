# libsecp256k1

Vendored copy of [bitcoin-core/secp256k1](https://github.com/bitcoin-core/secp256k1)
at v0.5.0 (commit `e3a885d42a7800c1ccebad94ad1e2b82c4df5c65`), MIT licensed
(see `COPYING`).

Only the files needed to compile the shared library are kept: the public
headers in `include/`, the implementation in `src/` and the `ecdh`,
`extrakeys`, `recovery` and `schnorrsig` modules. Tests, benchmarks, build
system files and the table generators are omitted.

The library is compiled by the build hook in `hook/build.dart`. To update to
a new upstream release, replace these files with the same subset from the new
release, update the commit hash above and regenerate the Dart bindings with
`dart run ffigen`.
