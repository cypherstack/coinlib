import "dart:ffi";
import "package:coinlib/src/crypto/random.dart";
import "package:coinlib/src/secp256k1/heap.dart";
import 'package:ffi/ffi.dart';
import "heap_ffi.dart";
import "secp256k1.ffi.g.dart";
import "secp256k1_base.dart";

typedef PubKeyPtr = Pointer<secp256k1_pubkey>;
typedef MuSigAggCachePtr = Pointer<secp256k1_musig_keyagg_cache>;
typedef MuSigSecNoncePtr = Pointer<secp256k1_musig_secnonce>;
typedef MuSigPublicNoncePtr = Pointer<secp256k1_musig_pubnonce>;
typedef MuSigSessionPtr = Pointer<secp256k1_musig_session>;
typedef MuSigPartialSigPtr = Pointer<secp256k1_musig_partial_sig>;

typedef OpaqueMuSigCache = OpaqueGeneric<MuSigAggCachePtr>;
typedef OpaqueMuSigSecretNonce = OpaqueGeneric<MuSigSecNoncePtr>;
typedef OpaqueMuSigPublicNonce = OpaqueGeneric<MuSigPublicNoncePtr>;
typedef OpaqueMuSigSession = OpaqueGeneric<MuSigSessionPtr>;
typedef OpaqueMuSigPartialSig = OpaqueGeneric<MuSigPartialSigPtr>;

/// Specialises Secp256k1Base to use the FFI
class Secp256k1
    extends
        Secp256k1Base<
          Pointer<secp256k1_context>,
          Pointer<UnsignedChar>,
          PubKeyPtr,
          Pointer<Size>,
          Pointer<secp256k1_ecdsa_signature>,
          Pointer<secp256k1_ecdsa_recoverable_signature>,
          Pointer<secp256k1_keypair>,
          Pointer<secp256k1_xonly_pubkey>,
          Pointer<Int>,
          MuSigAggCachePtr,
          Pointer<PubKeyPtr>,
          MuSigSecNoncePtr,
          MuSigPublicNoncePtr,
          Pointer<secp256k1_musig_aggnonce>,
          Pointer<MuSigPublicNoncePtr>,
          MuSigSessionPtr,
          MuSigPartialSigPtr,
          Pointer<MuSigPartialSigPtr>,
          Pointer<Never>
        > {
  Secp256k1() {
    // Set functions
    extEcSeckeyVerify = secp256k1_ec_seckey_verify;
    extEcPubkeyCreate = secp256k1_ec_pubkey_create;
    extEcPubkeySerialize = secp256k1_ec_pubkey_serialize;
    extEcPubkeyParse = secp256k1_ec_pubkey_parse;
    extEcdsaSign = secp256k1_ecdsa_sign;
    extEcdsaSignatureSerializeCompact =
        secp256k1_ecdsa_signature_serialize_compact;
    extEcdsaSignatureParseCompact = secp256k1_ecdsa_signature_parse_compact;
    extEcdsaSignatureNormalize = secp256k1_ecdsa_signature_normalize;
    extEcdsaSignatureSerializeDer = secp256k1_ecdsa_signature_serialize_der;
    extEcdsaSignatureParseDer = secp256k1_ecdsa_signature_parse_der;
    extEcdsaVerify = secp256k1_ecdsa_verify;
    extEcdsaRecoverableSignatureSerializeCompact =
        secp256k1_ecdsa_recoverable_signature_serialize_compact;
    extEcdsaRecoverableSignatureParseCompact =
        secp256k1_ecdsa_recoverable_signature_parse_compact;
    extEcdsaSignRecoverable = secp256k1_ecdsa_sign_recoverable;
    extEcdsaRecover = secp256k1_ecdsa_recover;
    extEcSeckeyTweakAdd = secp256k1_ec_seckey_tweak_add;
    extEcPubkeyTweakAdd = secp256k1_ec_pubkey_tweak_add;
    extEcSeckeyNegate = secp256k1_ec_seckey_negate;
    extKeypairCreate = secp256k1_keypair_create;
    extXOnlyPubkeyParse = secp256k1_xonly_pubkey_parse;
    extXOnlyPubkeySerialize = secp256k1_xonly_pubkey_serialize;
    extSchnorrSign32 = secp256k1_schnorrsig_sign32;
    extSchnorrVerify = secp256k1_schnorrsig_verify;
    extEcdh = secp256k1_ecdh;
    extEcPubkeySort = secp256k1_ec_pubkey_sort;
    extMuSigPubkeyAgg = secp256k1_musig_pubkey_agg;
    extMuSigPubkeyXOnlyTweakAdd = secp256k1_musig_pubkey_xonly_tweak_add;
    extMuSigNonceGen = secp256k1_musig_nonce_gen;
    extMuSigPubNonceParse = secp256k1_musig_pubnonce_parse;
    extMuSigPubNonceSerialize = secp256k1_musig_pubnonce_serialize;
    extMuSigNonceAgg = secp256k1_musig_nonce_agg;
    extMuSigNonceProcess = secp256k1_musig_nonce_process;
    extMuSigPartialSign = secp256k1_musig_partial_sign;
    extMuSigPartialSigParse = secp256k1_musig_partial_sig_parse;
    extMuSigPartialSigSerialize = secp256k1_musig_partial_sig_serialize;
    extMuSigPartialSigVerify = secp256k1_musig_partial_sig_verify;
    extMuSigPartialSigAgg = secp256k1_musig_partial_sig_agg;
    extMuSigNonceParity = secp256k1_musig_nonce_parity;
    extMuSigAdapt = secp256k1_musig_adapt;
    extMuSigExtractAdaptor = secp256k1_musig_extract_adaptor;

    // Set heap arrays
    key32Array = HeapBytesFfi(Secp256k1Base.privkeySize);
    scalarArray = HeapBytesFfi(Secp256k1Base.privkeySize);
    serializedPubKeyArray = HeapBytesFfi(Secp256k1Base.uncompressedPubkeySize);
    hashArray = HeapBytesFfi(Secp256k1Base.hashSize);
    entropyArray = HeapBytesFfi(Secp256k1Base.entropySize);
    preSigArray = HeapBytesFfi(Secp256k1Base.sigSize);
    serializedSigArray = HeapBytesFfi(Secp256k1Base.sigSize);
    derSigArray = HeapBytesFfi(Secp256k1Base.derSigSize);
    muSigPubNonceArray = HeapBytesFfi(Secp256k1Base.muSigPubNonceSize);

    // Set other heap data
    sizeT = HeapSizeFfi();
    integer = HeapIntFfi();
    pubKey = HeapFfi(malloc());
    sig = HeapFfi(malloc());
    recSig = HeapFfi(malloc());
    keyPair = HeapFfi(malloc());
    xPubKey = HeapFfi(malloc());
    muSigAggNonce = HeapFfi(malloc());
    recId = HeapIntFfi();

    nullPtr = nullptr;

    // Create context
    ctxPtr = secp256k1_context_create(Secp256k1Base.contextNone);

    // Randomise context with 32 bytes

    final randBytes = generateRandomBytes(32);
    final randArray = HeapBytesFfi(32);
    randArray.load(randBytes);

    if (secp256k1_context_randomize(ctxPtr, randArray.ptr) != 1) {
      throw Secp256k1Exception("Secp256k1 context couldn't be randomised");
    }
  }

  @override
  HeapPointerArray<Pointer<PubKeyPtr>, PubKeyPtr> allocPubKeyArray(int size) =>
      HeapPointerArrayFfi.alloc(malloc(size), size, () => malloc());

  @override
  HeapPointerArray<Pointer<MuSigPublicNoncePtr>, MuSigPublicNoncePtr>
  setMuSigPubNonceArray(Iterable<Heap<MuSigPublicNoncePtr>> objs) =>
      HeapPointerArrayFfi.assign(malloc(objs.length), objs.cast());

  @override
  HeapPointerArray<Pointer<MuSigPartialSigPtr>, MuSigPartialSigPtr>
  setMuSigPartialSigArray(Iterable<Heap<MuSigPartialSigPtr>> objs) =>
      HeapPointerArrayFfi.assign(malloc(objs.length), objs.cast());

  @override
  Heap<MuSigAggCachePtr> allocMuSigCache() => HeapFfi(malloc());

  @override
  Heap<MuSigAggCachePtr> copyMuSigCache(MuSigAggCachePtr copyFrom) {
    final newCache = HeapFfi<secp256k1_musig_keyagg_cache>(malloc());
    newCache.ptr.ref = copyFrom.ref;
    return newCache;
  }

  @override
  Heap<MuSigSecNoncePtr> allocMuSigSecNonce() => HeapFfi(malloc());

  @override
  Heap<MuSigPublicNoncePtr> allocMuSigPubNonce() => HeapFfi(malloc());

  @override
  Heap<MuSigSessionPtr> allocMuSigSession() => HeapFfi(malloc());

  @override
  Heap<MuSigPartialSigPtr> allocMuSigPartialSig() => HeapFfi(malloc());
}
