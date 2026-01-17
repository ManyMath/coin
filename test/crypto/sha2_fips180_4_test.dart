import 'dart:typed_data';

import 'package:coin/coin.dart';
import 'package:test/test.dart';

/// SHA-256 and SHA-512 test vectors from FIPS PUB 180-4 and the accompanying
/// NIST "Secure Hashing" example documents:
///   https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
///   https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/sha256.pdf
///   https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/sha512.pdf
///
/// These exercise coin's public hashing API (`sha256`, `sha512`), which routes
/// through `VaultKeeper.vault.digest` - by default the in-house `SoftDigestGate`
/// backed by package:crypto.
///
/// Digests:
///   SHA-256("")  = e3b0c442...  (FIPS 180-4 / NIST empty-string vector)
///   SHA-256("abc") = ba7816bf... (FIPS 180-4, Appendix B.1)
///   SHA-256(448-bit two-block message) = 248d6a61... (FIPS 180-4, Appendix B.2)
///   SHA-512("abc") = ddaf35a1... (FIPS 180-4, Appendix C.1)
void main() {
  setUpAll(() async {
    // sha256/sha512 -> VaultKeeper.vault.digest.
    await VaultKeeper.initialize();
  });

  Uint8List ascii(String s) => Uint8List.fromList(s.codeUnits);

  group('SHA-256 (FIPS 180-4)', () {
    // Empty string. NIST canonical empty-input digest.
    test('SHA256("") = e3b0c442...', () {
      expect(
        hexEncode(sha256(Uint8List(0))),
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      );
    });

    // FIPS 180-4 Appendix B.1: one-block message "abc".
    test('SHA256("abc") = ba7816bf...', () {
      expect(
        hexEncode(sha256(ascii('abc'))),
        'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
      );
    });

    // FIPS 180-4 Appendix B.2: two-block, 448-bit message.
    test('SHA256(448-bit message) = 248d6a61...', () {
      expect(
        hexEncode(sha256(ascii(
          'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',
        ))),
        '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1',
      );
    });
  });

  group('SHA-512 (FIPS 180-4)', () {
    // FIPS 180-4 Appendix C.1: one-block message "abc".
    test('SHA512("abc") = ddaf35a1...', () {
      expect(
        hexEncode(sha512(ascii('abc'))),
        'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a'
        '2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f',
      );
    });
  });
}
