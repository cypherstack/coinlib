import 'dart:typed_data';
import 'package:coinlib/coinlib.dart';
import 'package:test/test.dart';
import '../../vectors/keys.dart';
import '../../vectors/signatures.dart';
import '../../vectors/inputs.dart';
import '../../vectors/tx.dart';

void main() {
  group("P2SHP2WPKHInput", () {
    // Private key = 1, compressed
    // Public key  = 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
    // HASH160(pubkey) = 751e76e8199196d454941c45d1b3a323f1433bd6
    // redeemScript (P2WPKH) = 0014751e76e8199196d454941c45d1b3a323f1433bd6  (22 bytes)
    // scriptSig = push(redeemScript) = 160014751e76e8199196d454941c45d1b3a323f1433bd6 (23 bytes)
    final expectedScriptSigHex =
        "160014751e76e8199196d454941c45d1b3a323f1433bd6";

    final der = validDerSigs[0];
    final pkBytes = hexToBytes(pubkeyVec);
    late ECPublicKey pk;
    late ECPrivateKey privKey;
    late ECDSAInputSignature insig;

    setUpAll(() async {
      await loadCoinlib();
      pk = ECPublicKey(pkBytes);
      privKey = keyPairVectors[0].privateObj; // private key = 1
      insig = ECDSAInputSignature(
        ECDSASignature.fromDerHex(der),
        SigHashType.none(),
      );
    });

    getWitness(bool hasSig) => [
          if (hasSig)
            Uint8List.fromList([
              ...hexToBytes(der),
              SigHashType.none().value,
            ]),
          hexToBytes(pubkeyVec),
        ];

    test("constructs correct scriptSig and witness", () {
      final noSig = P2SHP2WPKHInput(
        prevOut: prevOut,
        sequence: sequence,
        publicKey: pk,
      );

      // scriptSig should be the push of the P2WPKH redeemScript
      expect(bytesToHex(noSig.scriptSig), expectedScriptSigHex);
      expect(noSig.witness, isEmpty);
      expect(noSig.complete, false);
      expect(noSig.insig, isNull);

      final withSig = P2SHP2WPKHInput(
        prevOut: prevOut,
        sequence: sequence,
        publicKey: pk,
        insig: insig,
      );

      expect(bytesToHex(withSig.scriptSig), expectedScriptSigHex);
      expect(withSig.witness, getWitness(true));
      expect(withSig.complete, true);
      expect(withSig.insig, isNotNull);
    });

    test("addSignature returns new input with witness data", () {
      final noSig = P2SHP2WPKHInput(
        prevOut: prevOut,
        sequence: sequence,
        publicKey: pk,
      );

      final withSig = noSig.addSignature(insig);

      expect(bytesToHex(withSig.scriptSig), expectedScriptSigHex);
      expect(withSig.witness, getWitness(true));
      expect(withSig.complete, true);

      // Original unchanged
      expect(noSig.complete, false);
    });

    test("filterSignatures removes signature", () {
      final withSig = P2SHP2WPKHInput(
        prevOut: prevOut,
        publicKey: pk,
        insig: insig,
      );

      expect(withSig.filterSignatures((s) => false).insig, isNull);
      expect(withSig.filterSignatures((s) => true).insig, isNotNull);
    });

    test("match recognises P2SH-P2WPKH format", () {
      // Build raw input with the P2SH-P2WPKH scriptSig
      final scriptSigBytes = hexToBytes(expectedScriptSigHex);
      final raw = RawInput(
        prevOut: prevOut,
        scriptSig: scriptSigBytes,
        sequence: sequence,
      );

      // Should match with witness (signed)
      final matchedSigned = Input.match(raw, getWitness(true));
      expect(matchedSigned, isA<P2SHP2WPKHInput>());
      final input = matchedSigned as P2SHP2WPKHInput;
      expect(input.complete, true);
      expect(bytesToHex(input.scriptSig), expectedScriptSigHex);
      expect(input.publicKey.hex, pubkeyVec);
      expect(input.insig, isNotNull);

      // Should also match unsigned (just pubkey in witness)
      final matchedUnsigned = Input.match(raw, getWitness(false));
      expect(matchedUnsigned, isA<P2SHP2WPKHInput>());
      expect((matchedUnsigned as P2SHP2WPKHInput).complete, false);
    });

    test("doesn't match non-P2SH-P2WPKH inputs", () {
      expectNoMatch(Uint8List scriptSig, List<Uint8List> witness) => expect(
            P2SHP2WPKHInput.match(
              RawInput(
                  prevOut: prevOut, scriptSig: scriptSig, sequence: sequence),
              witness,
            ),
            isNull,
          );

      // Empty scriptSig (native witness, not P2SH)
      expectNoMatch(Uint8List(0), getWitness(true));

      // Wrong scriptSig: too many ops
      expectNoMatch(
        Script.fromAsm("0 0").compiled,
        getWitness(true),
      );

      // Wrong pushed data: not a P2WPKH script
      expectNoMatch(
        Script([ScriptPushData(Uint8List(22))]).compiled,
        getWitness(true),
      );

      // No witness
      expectNoMatch(hexToBytes(expectedScriptSigHex), []);

      // Too many witness items
      expectNoMatch(
        hexToBytes(expectedScriptSigHex),
        [...getWitness(true), Uint8List(33)],
      );
    });

    test("sign produces valid witness sighash (BIP143)", () {
      // Build a minimal transaction with one P2SHP2WPKHInput and one output
      final utxoValue = BigInt.from(100000);

      var tx = Transaction(
        version: 1,
        inputs: [
          P2SHP2WPKHInput(
            prevOut: examplePrevOut,
            publicKey: pk,
          ),
        ],
        outputs: [exampleOutput],
      );

      // Sign using the witness sighash method
      tx = tx.signP2SHP2WPKH(
        inputN: 0,
        key: privKey,
        value: utxoValue,
      );

      final signedInput = tx.inputs[0] as P2SHP2WPKHInput;

      // Input should now be complete
      expect(signedInput.complete, true);
      expect(signedInput.insig, isNotNull);

      // scriptSig unchanged (still push of redeemScript)
      expect(bytesToHex(signedInput.scriptSig), expectedScriptSigHex);

      // Witness should have [sig, pubkey]
      expect(signedInput.witness.length, 2);
      expect(signedInput.witness[1], pk.data);

      // Transaction should be serialised as a witness transaction
      expect(tx.isWitness, true);

      // legacy (txid) serialisation should not contain witness data
      final legacy = tx.legacy;
      expect(legacy.isWitness, false);
      expect(legacy.inputs[0], isA<RawInput>());
      // The legacy input's scriptSig should still be the redeemScript push
      expect(bytesToHex(legacy.inputs[0].scriptSig), expectedScriptSigHex);

      // Re-serialise and parse: signed input should survive round-trip
      final reserialised = Transaction.fromBytes(tx.toBytes());
      expect(reserialised.inputs[0], isA<P2SHP2WPKHInput>());
      final roundTripped = reserialised.inputs[0] as P2SHP2WPKHInput;
      expect(roundTripped.complete, true);
      expect(bytesToHex(roundTripped.scriptSig), expectedScriptSigHex);
      expect(roundTripped.publicKey.hex, pubkeyVec);
    });

    test("isWitness is true for transactions with P2SHP2WPKHInput", () {
      final tx = Transaction(
        version: 1,
        inputs: [
          P2SHP2WPKHInput(
            prevOut: examplePrevOut,
            publicKey: pk,
          ),
        ],
        outputs: [exampleOutput],
      );

      expect(tx.isWitness, true);
    });
  });
}
