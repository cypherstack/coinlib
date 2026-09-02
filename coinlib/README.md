<p align="center">
  <img
    src="https://raw.githubusercontent.com/peercoin/coinlib/master/logo.svg"
    alt="Coinlib"
    width="250px"
  >
</p>

<p align="center">
  <a href="https://chainz.cryptoid.info/ppc/address.dws?p77CZFn9jvg9waCzKBzkQfSvBBzPH1nRre">
    <img src="https://badgen.net/badge/peercoin/Donate/green?icon=https://raw.githubusercontent.com/peercoin/media/84710cca6c3c8d2d79676e5260cc8d1cd729a427/Peercoin%202020%20Logo%20Files/01.%20Icon%20Only/Inside%20Circle/Transparent/Green%20Icon/peercoin-icon-green-transparent.svg" alt="Peercoin Donate">
  </a>
  <a href="https://pub.dev/packages/coinlib">
    <img alt="pub.dev" src="https://img.shields.io/pub/v/coinlib?logo=dart&label=pub.dev">
  </a>
</p>

# Coinlib

Coinlib is a straight-forward and modular library for Peercoin and other similar
cryptocoins including Taproot support. This library allows for the construction
and signing of transactions and management of BIP32 wallets.

## Installation and Usage

If you are using flutter, please see
[coinlib_flutter](https://pub.dev/packages/coinlib_flutter) instead. Otherwise
you may add `coinlib` to your project via:

```
dart pub add coinlib
```

The native secp256k1 library is compiled from source by a
[build hook](https://dart.dev/tools/hooks) when the application is built or
run, so no separate build step is required. A C compiler for the target
platform must be available: Clang or GCC on Linux, Xcode on macOS and iOS,
Visual Studio with the C++ build tools on Windows and the NDK for Android. Web
builds use a pre-compiled WebAssembly module and need no compiler.

The library can be imported via:

```
import 'package:coinlib/coinlib.dart';
```

The library must be asynchronously loaded by awaiting the `loadCoinlib()`
function before any part of the library is used.

The library uses a functional-style of OOP. With some exceptions, objects are
immutable. New modified objects are returned from methods. For example, signing
a transaction returns a new signed transaction object:

```dart
final signedTx = unsignedTx.sign(inputN: 0, key: privateKey);
```

An example is found in the `example/` directory.

## Development

This section is only relevant to developers of the library.

### Bindings and WebAssembly

The WebAssembly (WASM) module is pre-compiled and ready to use. FFI bindings
are pre-generated. These only need to be updated when the underlying secp256k1
library is changed.

The secp256k1 sources are vendored under `third_party/secp256k1` and compiled by
the build hook in `hook/build.dart`. Bindings for the native libraries
(excluding WebAssembly) are generated from the vendored headers using `dart run
ffigen` within the `coinlib` package.

The WebAssembly module has been pre-built to
`lib/src/secp256k1/secp256k1.wasm.g.dart`. It may be rebuilt using `dart run
bin/build_wasm.dart` in the `coinlib` root directory.
