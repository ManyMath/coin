import 'dart:typed_data';

import '../../core/bytes.dart';
import '../../core/hex.dart';
import '../../hash/digest.dart';

class EvmAddr {
  final Uint8List _data;

  EvmAddr(Uint8List bytes) : _data = copyCheckBytes(bytes, 20, 'address');

  /// Derives from a 64- or 65-byte uncompressed secp256k1 public key.
  /// Takes last 20 bytes of keccak256 over the 64-byte x||y (no 0x04 prefix).
  factory EvmAddr.fromPublicKey(Uint8List publicKey) {
    Uint8List raw;
    if (publicKey.length == 65) {
      raw = publicKey.sublist(1);
    } else if (publicKey.length == 64) {
      raw = publicKey;
    } else {
      throw ArgumentError(
        'Public key must be 64 or 65 bytes (uncompressed), got ${publicKey.length}',
      );
    }
    final hash = keccak256(raw);
    return EvmAddr(hash.sublist(12));
  }

  factory EvmAddr.fromHex(String hex) {
    final bytes = hexDecode(hex);
    if (bytes.length != 20) {
      throw ArgumentError('Address must decode to 20 bytes, got ${bytes.length}');
    }
    return EvmAddr(bytes);
  }

  /// EIP-1014 CREATE2 deterministic deployment address.
  ///
  ///   address = keccak256(0xff ++ deployer ++ salt ++ keccak256(initCode))[12:]
  ///
  /// [deployer] is the 20-byte address of the contract calling CREATE2,
  /// [salt] is a 32-byte value, and [initCode] is the contract creation code.
  /// See https://eips.ethereum.org/EIPS/eip-1014.
  factory EvmAddr.create2({
    required Uint8List deployer,
    required Uint8List salt,
    required Uint8List initCode,
  }) {
    final deployerBytes = copyCheckBytes(deployer, 20, 'deployer');
    if (salt.length != 32) {
      throw ArgumentError('Salt must be 32 bytes, got ${salt.length}');
    }
    final initCodeHash = keccak256(initCode);
    final preimage = concatBytes([
      Uint8List.fromList([0xff]),
      deployerBytes,
      salt,
      initCodeHash,
    ]);
    final hash = keccak256(preimage);
    return EvmAddr(hash.sublist(12));
  }

  Uint8List get bytes => Uint8List.fromList(_data);

  /// EIP-55 mixed-case checksum encoding.
  String toChecksumHex() {
    final lower = hexEncode(_data);
    final hash = keccak256(Uint8List.fromList(lower.codeUnits));
    final hashHex = hexEncode(hash);

    final buf = StringBuffer('0x');
    for (var i = 0; i < lower.length; i++) {
      final c = lower[i];
      if (c.compareTo('a') >= 0 && c.compareTo('f') <= 0) {
        // Uppercase when corresponding hash nibble >= 8.
        final nibble = int.parse(hashHex[i], radix: 16);
        buf.write(nibble >= 8 ? c.toUpperCase() : c);
      } else {
        buf.write(c);
      }
    }
    return buf.toString();
  }

  String toHex() => hexEncode(_data);

  @override
  String toString() => toChecksumHex();

  @override
  bool operator ==(Object other) =>
      other is EvmAddr && bytesEqual(_data, other._data);

  @override
  int get hashCode => Object.hashAll(_data);
}
