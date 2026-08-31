import 'dart:typed_data';

import '../core/bytes.dart';
import '../core/hex.dart';
import 'vault_keeper.dart';

class SchnorrSig {
  final Uint8List _data;

  SchnorrSig(Uint8List bytes) : _data = copyCheckBytes(bytes, 64, 'signature');

  factory SchnorrSig.fromHex(String hex) => SchnorrSig(hexDecode(hex));

  factory SchnorrSig.sign(Uint8List hash32, Uint8List privKey,
      {Uint8List? auxRand}) {
    // BIP-340 signing input validation: the message is exactly 32 bytes, the
    // secret key a valid secp256k1 scalar (32 bytes, 1 <= d < n - a zero or
    // out-of-range secret has no public key to verify against), and the
    // auxiliary randomness, when supplied, exactly 32 bytes.
    copyCheckBytes(hash32, 32, 'message');
    if (!VaultKeeper.vault.curve.isValidPrivateKey(privKey)) {
      throw ArgumentError(
          'Invalid BIP-340 secret key: must be 32 bytes with 1 <= d < n');
    }
    if (auxRand != null) {
      copyCheckBytes(auxRand, 32, 'auxRand');
    }
    return SchnorrSig(VaultKeeper.vault.curve
        .schnorrSign(hash32, privKey, auxRand: auxRand));
  }

  Uint8List get bytes => Uint8List.fromList(_data);

  bool verify(Uint8List hash32, Uint8List xPubKey) {
    copyCheckBytes(hash32, 32, 'message');
    return VaultKeeper.vault.curve.schnorrVerify(_data, hash32, xPubKey);
  }

  String toHex() => hexEncode(_data);

  @override
  bool operator ==(Object other) =>
      other is SchnorrSig && bytesEqual(_data, other._data);

  @override
  int get hashCode => Object.hashAll(_data);
}
