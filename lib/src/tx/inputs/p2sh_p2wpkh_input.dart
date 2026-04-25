import 'dart:typed_data';
import 'witness_input.dart';
import 'input_sig.dart';

/// BIP-49 nested SegWit: P2SH-wrapped P2WPKH.
///
/// The scriptSig is a single push of the redeemScript (the P2WPKH witness
/// program `0x0014<hash160(pubkey)>`); the actual signature lives in the
/// witness `[derSig+hashType, pubkey]`, exactly like a native P2WPKH spend.
class P2shP2wpkhInput extends WitnessInput {
  final InputSig inputSig;
  final Uint8List publicKey;

  /// The P2WPKH witness program being wrapped: `0x0014 <20-byte hash160>`.
  final Uint8List redeemScript;

  P2shP2wpkhInput({
    required super.prevOut,
    required this.inputSig,
    required this.publicKey,
    required this.redeemScript,
    super.sequence,
  });

  @override
  Uint8List get scriptSig {
    // scriptSig = single push of the redeemScript. The redeemScript is 22 bytes
    // (<= 75), so a single length-prefixed push suffices.
    return Uint8List.fromList([redeemScript.length, ...redeemScript]);
  }

  @override
  List<Uint8List> get witness => [inputSig.toBytes(), publicKey];
  @override
  bool get complete => true;
  @override
  int get signedSize => 91; // outpoint+seq+scriptSig(~24) + witness/4
}
