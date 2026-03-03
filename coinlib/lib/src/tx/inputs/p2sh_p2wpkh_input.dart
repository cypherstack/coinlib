import 'dart:typed_data';
import 'package:coinlib/src/crypto/ec_private_key.dart';
import 'package:coinlib/src/crypto/ec_public_key.dart';
import 'package:coinlib/src/crypto/ecdsa_signature.dart';
import 'package:coinlib/src/crypto/hash.dart';
import 'package:coinlib/src/scripts/operations.dart';
import 'package:coinlib/src/scripts/programs/p2wpkh.dart';
import 'package:coinlib/src/scripts/script.dart';
import 'package:coinlib/src/tx/sighash/witness_signature_hasher.dart';
import 'package:coinlib/src/tx/sign_details.dart';
import 'input.dart';
import 'input_signature.dart';
import 'pkh_input.dart';
import 'raw_input.dart';

/// An input for a Pay-to-Script-Hash wrapping Pay-to-Witness-Public-Key-Hash
/// output (P2SH-P2WPKH / BIP49).
///
/// The scriptSig contains only the push of the redeemScript (the P2WPKH
/// witness program), and the witness contains the signature and public key.
/// Signing uses the BIP143 witness sighash algorithm (same as P2WPKH).
class P2SHP2WPKHInput extends RawInput with PKHInput {
  @override
  final ECPublicKey publicKey;

  @override
  final ECDSAInputSignature? insig;

  /// Witness stack: empty when unsigned, or [sig, pubkey] when signed.
  final List<Uint8List> witness;

  // The redeemScript is the compiled P2WPKH witness program: OP_0 <20-byte-pkHash>
  static Uint8List _makeScriptSig(ECPublicKey publicKey) {
    final redeemScript = P2WPKH.fromPublicKey(publicKey).script.compiled;
    return Script([ScriptPushData(redeemScript)]).compiled;
  }

  P2SHP2WPKHInput({
    required super.prevOut,
    required this.publicKey,
    this.insig,
    super.sequence = Input.sequenceFinal,
  })  : witness = insig != null
            ? List.unmodifiable([insig.bytes, publicKey.data])
            : const [],
        super(scriptSig: _makeScriptSig(publicKey));

  @override
  P2SHP2WPKHInput addSignature(ECDSAInputSignature insig) => P2SHP2WPKHInput(
        prevOut: prevOut,
        publicKey: publicKey,
        insig: insig,
        sequence: sequence,
      );

  @override
  P2SHP2WPKHInput filterSignatures(
    bool Function(InputSignature insig) predicate,
  ) =>
      insig == null || predicate(insig!)
          ? this
          : P2SHP2WPKHInput(
              prevOut: prevOut,
              publicKey: publicKey,
              sequence: sequence,
            );

  /// Signs the input using the BIP143 witness sighash algorithm.
  P2SHP2WPKHInput sign({
    required LegacyWitnessSignDetails details,
    required ECPrivateKey key,
  }) {
    checkKey(key);
    final detailsWithScript = details.addScript(scriptCode);
    final sig = ECDSAInputSignature(
      ECDSASignature.sign(key, WitnessSignatureHasher(detailsWithScript).hash),
      detailsWithScript.hashType,
    );
    return addSignature(sig);
  }

  /// Attempts to match a [RawInput] and its [witness] data as a
  /// [P2SHP2WPKHInput]. Returns null if the format doesn't match.
  static P2SHP2WPKHInput? match(RawInput raw, List<Uint8List> witness) {
    // Must have a non-empty scriptSig and 0-2 witness items
    if (raw.scriptSig.isEmpty) return null;
    if (witness.length > 2) return null;

    try {
      final script = Script.decompile(raw.scriptSig);
      final ops = script.ops;
      // scriptSig must be exactly one push data (the redeemScript)
      if (ops.length != 1 || ops[0] is! ScriptPushData) return null;

      final pushed = (ops[0] as ScriptPushData).data;

      // The pushed data must be a valid P2WPKH witness program
      late P2WPKH p2wpkh;
      try {
        p2wpkh = P2WPKH.decompile(pushed);
      } catch (_) {
        return null;
      }

      if (witness.isEmpty) return null;

      final pubkey = ECPublicKey(witness.last);

      // Verify pubkey hash matches the P2WPKH program
      if (!_bytesEqual(hash160(pubkey.data), p2wpkh.pkHash)) return null;

      final insig = witness.length == 2
          ? ECDSAInputSignature.fromBytes(witness[0])
          : null;

      return P2SHP2WPKHInput(
        prevOut: raw.prevOut,
        sequence: raw.sequence,
        publicKey: pubkey,
        insig: insig,
      );
    } catch (_) {
      return null;
    }
  }
}

bool _bytesEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (int i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
