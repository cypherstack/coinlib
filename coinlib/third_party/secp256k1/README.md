# libsecp256k1

Vendored copy of [peercoin/secp256k1-coinlib](https://github.com/peercoin/secp256k1-coinlib)
at v0.7.0 (commit `69018e5b939d8d540ca6b237945100f4ecb5681e`), MIT licensed
(see `COPYING`).

Only the files needed to compile the shared library are kept: the public
headers in `include/`, the implementation in `src/` and the `ecdh`,
`extrakeys`, `musig`, `recovery` and `schnorrsig` modules. Tests, benchmarks,
build system files and the table generators are omitted.

The library is compiled by the build hook in `hook/build.dart`. To update to
a new upstream release, replace these files with the same subset from the new
release, update the commit hash above and regenerate the Dart bindings with
`dart run ffigen`.
