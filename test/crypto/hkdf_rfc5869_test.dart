import 'dart:typed_data';

import 'package:coin/coin.dart';
import 'package:coin/src/hash/hkdf.dart';
import 'package:test/test.dart';

/// HKDF-SHA256 test vectors from RFC 5869 Appendix A.
/// https://www.rfc-editor.org/rfc/rfc5869#appendix-A
///
/// `hkdfSha256` exposes the combined extract+expand step (it returns the
/// output keying material, OKM, of the requested length); the intermediate
/// PRK is not surfaced, so each case asserts the final OKM. The function's
/// named parameters map onto the RFC inputs as:
///   IKM  -> the positional `ikm` argument
///   salt -> `salt:`   (null/empty means HashLen zero bytes, per the RFC)
///   info -> `info:`
///   L    -> `length:`
void main() {
  setUpAll(() async {
    // hkdfSha256 -> hmacSha256 -> VaultKeeper.vault.digest.
    await VaultKeeper.initialize();
  });

  group('HKDF-SHA256 (RFC 5869 App. A)', () {
    // Case 1: basic test case with SHA-256.
    test('Case 1 (with salt and info)', () {
      final ikm = hexDecode('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
      final salt = hexDecode('000102030405060708090a0b0c');
      final info = hexDecode('f0f1f2f3f4f5f6f7f8f9');
      final okm = hkdfSha256(
        Uint8List.fromList(ikm),
        salt: Uint8List.fromList(salt),
        info: Uint8List.fromList(info),
        length: 42,
      );
      expect(
        hexEncode(okm),
        equals(
          '3cb25f25faacd57a90434f64d0362f2a'
          '2d2d0a90cf1a5a4c5db02d56ecc4c5bf'
          '34007208d5b887185865',
        ),
      );
    });

    // Case 3: test with zero-length salt and info.
    test('Case 3 (zero-length salt and info)', () {
      final ikm = hexDecode('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
      final okm = hkdfSha256(
        Uint8List.fromList(ikm),
        salt: Uint8List(0),
        info: Uint8List(0),
        length: 42,
      );
      expect(
        hexEncode(okm),
        equals(
          '8da4e775a563c18f715f802a063c5a31'
          'b8a11f5c5ee1879ec3454e5f3c738d2d'
          '9d201395faa4b61a96c8',
        ),
      );
    });
  });
}
