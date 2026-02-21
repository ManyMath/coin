import 'dart:typed_data';

import '../hash/digest.dart';
import 'vault_keeper.dart';
import 'secret_key.dart';
import 'public_key.dart';

abstract class DerivedKey {
  static const int hardenBit = 0x80000000;
  static const int maxIndex = 0xffffffff;
  static const int encodedLength = 78;

  final Uint8List chainCode;
  final int depth;
  final int index;
  final int parentFingerprint;

  DerivedKey({
    required this.chainCode,
    required this.depth,
    required this.index,
    required this.parentFingerprint,
  });

  PublicKey get publicKey;
  Uint8List get identifier => hash160(publicKey.bytes);
  int get fingerprint {
    final id = identifier;
    return (id[0] << 24) | (id[1] << 16) | (id[2] << 8) | id[3];
  }

  DerivedKey derive(int index);
  DerivedKey deriveHardened(int index) => derive(index | hardenBit);

  DerivedKey derivePath(String path) {
    final parts = path.split('/');
    DerivedKey current = this;
    for (var i = 0; i < parts.length; i++) {
      var part = parts[i];
      if (i == 0 && (part == 'm' || part == 'M')) continue;
      final hardened = part.endsWith("'") || part.endsWith('h');
      if (hardened) part = part.substring(0, part.length - 1);
      final idx = int.parse(part);
      current = hardened ? current.deriveHardened(idx) : current.derive(idx);
    }
    return current;
  }

  factory DerivedKey.fromSeed(Uint8List seed) {
    final mat = VaultKeeper.vault.keyForge.masterFromSeed(seed);
    return DerivedSecretKey(
      secretKey: SecretKey(mat.key),
      chainCode: mat.chainCode,
      depth: 0,
      index: 0,
      parentFingerprint: 0,
    );
  }
}

class DerivedSecretKey extends DerivedKey {
  final SecretKey secretKey;

  DerivedSecretKey({
    required this.secretKey,
    required super.chainCode,
    required super.depth,
    required super.index,
    required super.parentFingerprint,
  });

  @override
  PublicKey get publicKey => secretKey.publicKey;

  @override
  DerivedSecretKey derive(int index) {
    final hardened = index >= DerivedKey.hardenBit;
    final mat = VaultKeeper.vault.keyForge.deriveChild(
      parentKey: secretKey.bytes,
      parentChainCode: chainCode,
      index: index,
      hardened: hardened,
      isPrivate: true,
      parentPublicKey: publicKey.bytes,
    );
    return DerivedSecretKey(
      secretKey: SecretKey(mat.key),
      chainCode: mat.chainCode,
      depth: depth + 1,
      index: index,
      parentFingerprint: fingerprint,
    );
  }

  String encode({int version = 0x0488ADE4}) {
    final data = Uint8List(78);
    data[0] = (version >> 24) & 0xff;
    data[1] = (version >> 16) & 0xff;
    data[2] = (version >> 8) & 0xff;
    data[3] = version & 0xff;
    data[4] = depth;
    data[5] = (parentFingerprint >> 24) & 0xff;
    data[6] = (parentFingerprint >> 16) & 0xff;
    data[7] = (parentFingerprint >> 8) & 0xff;
    data[8] = parentFingerprint & 0xff;
    data[9] = (index >> 24) & 0xff;
    data[10] = (index >> 16) & 0xff;
    data[11] = (index >> 8) & 0xff;
    data[12] = index & 0xff;
    data.setRange(13, 45, chainCode);
    data[45] = 0x00;
    data.setRange(46, 78, secretKey.bytes);
    return VaultKeeper.vault.codec.base58CheckEncode(data);
  }
}

class DerivedPublicKey extends DerivedKey {
  final PublicKey _publicKey;

  DerivedPublicKey({
    required PublicKey publicKey,
    required super.chainCode,
    required super.depth,
    required super.index,
    required super.parentFingerprint,
  }) : _publicKey = publicKey;

  @override
  PublicKey get publicKey => _publicKey;

  @override
  DerivedPublicKey derive(int index) {
    if (index >= DerivedKey.hardenBit) {
      throw ArgumentError('Cannot derive hardened child from public key');
    }
    final mat = VaultKeeper.vault.keyForge.deriveChild(
      parentKey: _publicKey.bytes,
      parentChainCode: chainCode,
      index: index,
      hardened: false,
      isPrivate: false,
      parentPublicKey: _publicKey.bytes,
    );
    return DerivedPublicKey(
      publicKey: PublicKey(mat.key),
      chainCode: mat.chainCode,
      depth: depth + 1,
      index: index,
      parentFingerprint: fingerprint,
    );
  }

  String encode({int version = 0x0488B21E}) {
    final data = Uint8List(78);
    data[0] = (version >> 24) & 0xff;
    data[1] = (version >> 16) & 0xff;
    data[2] = (version >> 8) & 0xff;
    data[3] = version & 0xff;
    data[4] = depth;
    data[5] = (parentFingerprint >> 24) & 0xff;
    data[6] = (parentFingerprint >> 16) & 0xff;
    data[7] = (parentFingerprint >> 8) & 0xff;
    data[8] = parentFingerprint & 0xff;
    data[9] = (index >> 24) & 0xff;
    data[10] = (index >> 16) & 0xff;
    data[11] = (index >> 8) & 0xff;
    data[12] = index & 0xff;
    data.setRange(13, 45, chainCode);
    data.setRange(45, 78, _publicKey.bytes);
    return VaultKeeper.vault.codec.base58CheckEncode(data);
  }

  /// Decode a base58check extended PUBLIC key (xpub-form) back into a
  /// [DerivedPublicKey]. The version bytes are not interpreted (any
  /// xpub/ypub/zpub-style prefix is accepted); only the 78-byte body matters.
  /// Throws [FormatException] / [ArgumentError] on a malformed key.
  factory DerivedPublicKey.decode(String encoded) {
    final data = VaultKeeper.vault.codec.base58CheckDecode(encoded);
    if (data.length != DerivedKey.encodedLength) {
      throw FormatException(
        'Extended key must decode to ${DerivedKey.encodedLength} bytes, '
        'got ${data.length}',
      );
    }
    final depth = data[4];
    final parentFingerprint =
        (data[5] << 24) | (data[6] << 16) | (data[7] << 8) | data[8];
    final index = (data[9] << 24) | (data[10] << 16) | (data[11] << 8) | data[12];
    final chainCode = Uint8List.fromList(data.sublist(13, 45));
    final keyBytes = Uint8List.fromList(data.sublist(45, 78));
    if (keyBytes[0] != 0x02 && keyBytes[0] != 0x03) {
      throw FormatException(
        'Decoded extended key is not a public key (prefix '
        '0x${keyBytes[0].toRadixString(16)}); private xprv import is not '
        'supported here',
      );
    }
    return DerivedPublicKey(
      publicKey: PublicKey(keyBytes),
      chainCode: chainCode,
      depth: depth,
      index: index,
      parentFingerprint: parentFingerprint,
    );
  }
}
