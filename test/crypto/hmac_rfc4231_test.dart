import 'dart:typed_data';

import 'package:coin/coin.dart';
import 'package:test/test.dart';

/// HMAC-SHA256 and HMAC-SHA512 test vectors from RFC 4231
/// ("Identifiers and Test Vectors for HMAC-SHA-224, HMAC-SHA-256,
/// HMAC-SHA-384, and HMAC-SHA-512").
/// https://www.rfc-editor.org/rfc/rfc4231#section-4
///
/// These exercise coin's public `hmacSha256` / `hmacSha512`, which route
/// through `VaultKeeper.vault.digest` (the in-house `SoftDigestGate`).
void main() {
  setUpAll(() async {
    await VaultKeeper.initialize();
  });

  Uint8List hx(String h) => Uint8List.fromList(hexDecode(h));

  group('HMAC-SHA256 / HMAC-SHA512 (RFC 4231)', () {
    // Case 1: key = 0x0b x20, data = "Hi There".
    test('Case 1', () {
      final key = hx('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
      final data = hx('4869205468657265'); // "Hi There"
      expect(
        hexEncode(hmacSha256(key, data)),
        'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7',
      );
      expect(
        hexEncode(hmacSha512(key, data)),
        '87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde'
        'daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854',
      );
    });

    // Case 2: key = "Jefe", data = "what do ya want for nothing?".
    test('Case 2', () {
      final key = hx('4a656665'); // "Jefe"
      // "what do ya want for nothing?"
      final data = hx('7768617420646f2079612077616e7420666f72206e6f7468696e673f');
      expect(
        hexEncode(hmacSha256(key, data)),
        '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
      );
      expect(
        hexEncode(hmacSha512(key, data)),
        '164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554'
        '9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737',
      );
    });
  });
}
