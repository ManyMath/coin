import 'dart:typed_data';

import 'package:coin/coin.dart';
import 'package:test/test.dart';

/// RIPEMD-160 test vectors from the algorithm's reference publication
/// (Dobbertin, Bosselaers, Preneel - "RIPEMD-160: A Strengthened Version of
/// RIPEMD"), also in ISO/IEC 10118-3. Reference table:
///   RIPEMD160("")="9c1185a5...8d31",
///   RIPEMD160("abc")="8eb208f7...0bfc",
///   RIPEMD160("message digest")="5d0689ef...5f36":
///   https://homes.esat.kuleuven.be/~bosselae/ripemd160.html (Appendix, test vectors)
///
/// Exercises coin's public `ripemd160`, which routes through
/// `VaultKeeper.vault.digest` (the in-house `SoftDigestGate`, backed by
/// PointyCastle's RIPEMD160 implementation).
void main() {
  setUpAll(() async {
    await VaultKeeper.initialize();
  });

  Uint8List ascii(String s) => Uint8List.fromList(s.codeUnits);

  group('RIPEMD-160 test vectors', () {
    test('RIPEMD160("") = 9c1185a5...', () {
      expect(
        hexEncode(ripemd160(Uint8List(0))),
        '9c1185a5c5e9fc54612808977ee8f548b2258d31',
      );
    });

    test('RIPEMD160("abc") = 8eb208f7...', () {
      expect(
        hexEncode(ripemd160(ascii('abc'))),
        '8eb208f7e05d987a9b044a8e98c6b087f15a0bfc',
      );
    });

    test('RIPEMD160("message digest") = 5d0689ef...', () {
      expect(
        hexEncode(ripemd160(ascii('message digest'))),
        '5d0689ef49d2fae572b881b123a85ffa21595f36',
      );
    });
  });
}
