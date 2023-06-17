import 'dart:typed_data';
import 'package:coinlib/src/crypto/hash.dart';
import 'package:coinlib/src/scripts/operations.dart';
import 'package:coinlib/src/scripts/program.dart';
import 'package:coinlib/src/scripts/script.dart';

/// Pay-to-Script-Hash program taking a 20-byte script hash for a redeem script.
class P2SH implements Program {

  static Script template = Script.fromAsm("OP_HASH160 <20-bytes> OP_EQUAL");

  @override
  final Script script;
  late final Uint8List scriptHash;

  /// Construct using an output script, not to be confused with the redeem
  /// script. For that use [fromRedeemScript].
  P2SH.fromScript(this.script) {
    if (!template.match(script)) throw NoProgramMatch();
    scriptHash = (script[1] as ScriptPushData).data;
  }

  P2SH.decompile(Uint8List script)
    : this.fromScript(Script.decompile(script, requireMinimal: true));

  P2SH.fromAsm(String asm) : this.fromScript(Script.fromAsm(asm));

  P2SH.fromHash(this.scriptHash) : script = template.fill([scriptHash]);

  P2SH.fromRedeemScript(Script redeemScript)
    : this.fromHash(hash160(redeemScript.compiled));

}