import 'dart:typed_data';
import '../sighash/sighash_type.dart';

/// DER-encoded ECDSA sig + sighash byte.
class InputSig {
  final Uint8List derSig;
  final SigHashType hashType;

  InputSig({required this.derSig, required this.hashType});

  Uint8List toBytes() =>
      Uint8List.fromList([...derSig, hashType.flag]);

  factory InputSig.fromBytes(Uint8List bytes) {
    if (bytes.isEmpty) throw ArgumentError('Empty signature');
    final flag = bytes.last;
    return InputSig(
      derSig: bytes.sublist(0, bytes.length - 1),
      hashType: SigHashType.fromFlag(flag),
    );
  }
}

/// Schnorr sig: 64 bytes, or 65 with non-default sighash.
class SchnorrInputSig {
  final Uint8List sig;
  final SigHashType hashType;

  SchnorrInputSig({required this.sig, required this.hashType});

  Uint8List toBytes() {
    // BIP-341: a bare 64-byte witness means SIGHASH_DEFAULT (0x00). Every
    // other sighash type - INCLUDING explicit SIGHASH_ALL (0x01) - appends its
    // 1-byte flag, giving a 65-byte witness.
    if (hashType.isTaprootDefault) return sig; // 64 bytes, no suffix
    return Uint8List.fromList([...sig, hashType.flag]);
  }

  factory SchnorrInputSig.fromBytes(Uint8List bytes) {
    if (bytes.length == 64) {
      // No trailing flag => SIGHASH_DEFAULT (0x00).
      return SchnorrInputSig(
          sig: bytes, hashType: SigHashType.taprootDefault);
    }
    if (bytes.length == 65) {
      final flag = bytes[64];
      // A trailing 0x00 is invalid per BIP-341: SIGHASH_DEFAULT must be
      // encoded as a bare 64-byte witness, never 64 bytes + 0x00.
      if (flag == 0x00) {
        throw ArgumentError(
            'Invalid Schnorr signature: 65-byte witness with trailing 0x00');
      }
      return SchnorrInputSig(
        sig: bytes.sublist(0, 64),
        hashType: SigHashType.fromFlag(flag),
      );
    }
    throw ArgumentError('Invalid Schnorr signature length');
  }
}
