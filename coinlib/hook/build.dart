import 'package:code_assets/code_assets.dart';
import 'package:hooks/hooks.dart';
import 'package:native_toolchain_c/native_toolchain_c.dart';

/// Compiles the vendored libsecp256k1 into a shared library that is bundled
/// with the application and bound to the `@Native` functions in
/// `lib/src/secp256k1/secp256k1.ffi.g.dart`.
///
/// This mirrors the configuration that was previously used with the autotools
/// and CMake builds: -O2, the ecdh, extrakeys, recovery and schnorrsig modules
/// and the default precomputed table sizes.
void main(List<String> args) async {
  await build(args, (input, output) async {
    if (!input.config.buildCodeAssets) return;

    final os = input.config.code.targetOS;
    final arch = input.config.code.targetArchitecture;

    final builder = CBuilder.library(
      name: 'secp256k1',
      assetName: 'src/secp256k1/secp256k1.ffi.g.dart',
      sources: [
        'third_party/secp256k1/src/secp256k1.c',
        'third_party/secp256k1/src/precomputed_ecmult.c',
        'third_party/secp256k1/src/precomputed_ecmult_gen.c',
      ],
      includes: ['third_party/secp256k1/include'],
      optimizationLevel: OptimizationLevel.o2,
      defines: {
        'ENABLE_MODULE_ECDH': '1',
        'ENABLE_MODULE_EXTRAKEYS': '1',
        'ENABLE_MODULE_RECOVERY': '1',
        'ENABLE_MODULE_SCHNORRSIG': '1',
        // Precomputed table sizes matching the upstream "AUTO" defaults.
        'ECMULT_WINDOW_SIZE': '15',
        'COMB_BLOCKS': '11',
        'COMB_TEETH': '6',
        // Use the x86_64 inline assembly in the scalar implementation where
        // the compiler is GCC or Clang, as the autotools build does.
        if (arch == Architecture.x64 && os != OS.windows) 'USE_ASM_X86_64': '1',
        // Export the public API from the DLL.
        if (os == OS.windows) 'SECP256K1_DLL_EXPORT': null,
      },
      flags: [
        // Only export symbols marked with SECP256K1_API.
        if (os != OS.windows) '-fvisibility=hidden',
      ],
    );

    await builder.run(input: input, output: output);
  });
}
