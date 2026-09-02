import "dart:ffi";
import "package:coinlib/src/crypto/random.dart";
import 'package:ffi/ffi.dart';
import "heap_array_ffi.dart";
import "secp256k1.ffi.g.dart";
import "secp256k1_base.dart";

/// Specialises Secp256k1Base to use the FFI
class Secp256k1 extends Secp256k1Base<
  Pointer<secp256k1_context>,
  UCharPointer,
  Pointer<secp256k1_pubkey>,
  Pointer<Size>,
  Pointer<secp256k1_ecdsa_signature>,
  Pointer<secp256k1_ecdsa_recoverable_signature>,
  Pointer<secp256k1_keypair>,
  Pointer<secp256k1_xonly_pubkey>,
  Pointer<Int>,
  Pointer<Never>
> {

  Secp256k1() {

    // Set functions
    extEcSeckeyVerify = secp256k1_ec_seckey_verify;
    extEcPubkeyCreate = secp256k1_ec_pubkey_create;
    extEcPubkeySerialize = secp256k1_ec_pubkey_serialize;
    extEcPubkeyParse = secp256k1_ec_pubkey_parse;
    extEcdsaSign = secp256k1_ecdsa_sign;
    extEcdsaSignatureSerializeCompact
      = secp256k1_ecdsa_signature_serialize_compact;
    extEcdsaSignatureParseCompact
      = secp256k1_ecdsa_signature_parse_compact;
    extEcdsaSignatureNormalize = secp256k1_ecdsa_signature_normalize;
    extEcdsaSignatureSerializeDer =
      secp256k1_ecdsa_signature_serialize_der;
    extEcdsaSignatureParseDer = secp256k1_ecdsa_signature_parse_der;
    extEcdsaVerify = secp256k1_ecdsa_verify;
    extEcdsaRecoverableSignatureSerializeCompact
      = secp256k1_ecdsa_recoverable_signature_serialize_compact;
    extEcdsaRecoverableSignatureParseCompact
      = secp256k1_ecdsa_recoverable_signature_parse_compact;
    extEcdsaSignRecoverable = secp256k1_ecdsa_sign_recoverable;
    extEcdsaRecover = secp256k1_ecdsa_recover;
    extEcSeckeyTweakAdd = secp256k1_ec_seckey_tweak_add;
    extEcPubkeyTweakAdd = secp256k1_ec_pubkey_tweak_add;
    extEcSeckeyNegate = secp256k1_ec_seckey_negate;
    extKeypairCreate = secp256k1_keypair_create;
    extXOnlyPubkeyParse = secp256k1_xonly_pubkey_parse;
    extSchnorrSign32 = secp256k1_schnorrsig_sign32;
    extSchnorrVerify = secp256k1_schnorrsig_verify;
    extEcdh = secp256k1_ecdh;

    // Set heap arrays
    key32Array = HeapArrayFfi(Secp256k1Base.privkeySize);
    scalarArray = HeapArrayFfi(Secp256k1Base.privkeySize);
    serializedPubKeyArray = HeapArrayFfi(Secp256k1Base.uncompressedPubkeySize);
    hashArray = HeapArrayFfi(Secp256k1Base.hashSize);
    entropyArray = HeapArrayFfi(Secp256k1Base.entropySize);
    serializedSigArray = HeapArrayFfi(Secp256k1Base.sigSize);
    derSigArray = HeapArrayFfi(Secp256k1Base.derSigSize);

    // Set other pointers
    // A finalizer could be added to free allocated memory but as this class will
    // used for a singleton object throughout the entire lifetime of the program,
    // it doesn't matter
    sizeTPtr = malloc();
    pubKeyPtr = malloc();
    sigPtr = malloc();
    recSigPtr = malloc();
    keyPairPtr = malloc();
    xPubKeyPtr = malloc();
    recIdPtr = malloc();
    nullPtr = nullptr;

    // Create context
    ctxPtr = secp256k1_context_create(Secp256k1Base.contextNone);

    // Randomise context with 32 bytes

    final randBytes = generateRandomBytes(32);
    final randArray = HeapArrayFfi(32);
    randArray.load(randBytes);

    if (secp256k1_context_randomize(ctxPtr, randArray.ptr) != 1) {
      throw Secp256k1Exception("Secp256k1 context couldn't be randomised");
    }

  }

  @override
  set sizeT(int size) => sizeTPtr.value = size;

  @override
  int get sizeT => sizeTPtr.value;

  @override
  int get internalRecId => recIdPtr.value;

}
