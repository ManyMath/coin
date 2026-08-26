// BIP-86 published test vectors.
//   https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki (Test vectors)
//
// These pin the address-level result, not just the tweak. coin 0.1.0 shipped a
// Taproot.tweakedKey that tweaked the internal key as derived instead of its
// BIP-341 lift_x (even-Y) form; the first vector below has an odd-Y internal
// key and is the one that regressed.

import 'dart:typed_data';

import 'package:coin/coin.dart';
import 'package:test/test.dart';

const _bitcoin = Chain(
  wifPrefix: 0x80,
  p2pkhPrefix: 0x00,
  p2shPrefix: 0x05,
  bech32Hrp: "bc",
  name: "Bitcoin",
  bip44CoinType: 0,
);

/// Seed for the BIP-86 mnemonic
/// "abandon abandon abandon abandon abandon abandon abandon abandon abandon
///  abandon abandon about".
const _seedHex =
    '5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1'
    '9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4';

const _vectors = <String, String>{
  "m/86'/0'/0'/0/0":
      'bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr',
  "m/86'/0'/0'/0/1":
      'bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh',
  "m/86'/0'/0'/1/0":
      'bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7',
};

Uint8List get _seed => Uint8List.fromList([
      for (var i = 0; i < _seedHex.length; i += 2)
        int.parse(_seedHex.substring(i, i + 2), radix: 16),
    ]);

void main() {
  setUpAll(() async {
    await VaultKeeper.initialize();
  });

  group('BIP-86 key-path addresses', () {
    _vectors.forEach((path, expected) {
      test(path, () {
        final key =
            DerivedKey.fromSeed(_seed).derivePath(path) as DerivedSecretKey;
        final taproot = Taproot(internalKey: key.publicKey);
        expect(
          TaprootAddr(taproot.tweakedKey).encode(_bitcoin),
          expected,
          reason: 'internal key Y is '
              '${key.publicKey.yIsEven ? "even" : "odd"}',
        );
      });
    });

    test('at least one vector has an odd-Y internal key', () {
      // Guards the guard: if every vector were even-Y the suite would pass
      // even with the lift_x normalisation removed.
      expect(
        _vectors.keys.any(
          (p) =>
              !((DerivedKey.fromSeed(_seed).derivePath(p) as DerivedSecretKey)
                  .publicKey
                  .yIsEven),
        ),
        isTrue,
      );
    });
  });
}
