import 'dart:typed_data';

import 'package:coin/coin.dart' show hexEncode, hexDecode;
import 'package:coin/src/crypto/soft/chacha20_poly1305.dart';
import 'package:test/test.dart';

Uint8List _hex(String h) => Uint8List.fromList(hexDecode(h));

void main() {
  group('ChaCha20-Poly1305 AEAD (RFC 8439)', () {
    // RFC 8439 sec. 2.8.2 "Example and Test Vector for AEAD_CHACHA20_POLY1305".
    // Key, nonce, AAD, plaintext, and expected ciphertext+tag are from that
    // section.
    // https://www.rfc-editor.org/rfc/rfc8439#section-2.8.2
    final plaintextHex =
        '4c616469657320616e642047656e746c656d656e206f662074686520636c6173'
        '73206f66202739393a204966204920636f756c64206f6666657220796f75206f'
        '6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73'
        '637265656e20776f756c642062652069742e';
    final aad = _hex('50515253c0c1c2c3c4c5c6c7');
    final key = _hex(
        '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f');
    final nonce = _hex('070000004041424344454647');
    final expectedCiphertext =
        'd31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6'
        '3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36'
        '92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc'
        '3ff4def08e4b7a9de576d26586cec64b6116';
    final expectedTag = '1ae10b594f09e26a7e902ecbd0600691';

    test('sec. 2.8.2 encryption vector', () {
      final out = chacha20Poly1305Encrypt(
        key32: key,
        nonce12: nonce,
        plaintext: _hex(plaintextHex),
        aad: aad,
      );
      expect(hexEncode(out), equals(expectedCiphertext + expectedTag));
      expect(out.length, equals(_hex(plaintextHex).length + 16));
    });

    test('decrypt round-trip returns plaintext', () {
      final ctWithTag = _hex(expectedCiphertext + expectedTag);
      final pt = chacha20Poly1305Decrypt(
        key32: key,
        nonce12: nonce,
        ciphertextWithTag: ctWithTag,
        aad: aad,
      );
      expect(hexEncode(pt), equals(plaintextHex));
    });

    // Negative and round-trip tests below reuse the RFC 8439 sec. 2.8.2 vector
    // above and assert behavior (tamper detection, empty-AAD round-trip).
    test('corrupted tag throws FormatException', () {
      final ctWithTag = _hex(expectedCiphertext + expectedTag);
      // Flip a bit in the last (tag) byte.
      ctWithTag[ctWithTag.length - 1] ^= 0x01;
      expect(
        () => chacha20Poly1305Decrypt(
          key32: key,
          nonce12: nonce,
          ciphertextWithTag: ctWithTag,
          aad: aad,
        ),
        throwsA(isA<FormatException>()),
      );
    });

    test('corrupted ciphertext throws FormatException', () {
      final ctWithTag = _hex(expectedCiphertext + expectedTag);
      ctWithTag[0] ^= 0x01;
      expect(
        () => chacha20Poly1305Decrypt(
          key32: key,
          nonce12: nonce,
          ciphertextWithTag: ctWithTag,
          aad: aad,
        ),
        throwsA(isA<FormatException>()),
      );
    });

    test('empty aad round-trips and authenticates', () {
      final pt = _hex(plaintextHex);
      final out = chacha20Poly1305Encrypt(
        key32: key,
        nonce12: nonce,
        plaintext: pt,
      );
      final back = chacha20Poly1305Decrypt(
        key32: key,
        nonce12: nonce,
        ciphertextWithTag: out,
      );
      expect(hexEncode(back), equals(plaintextHex));
    });
  });

  group('Poly1305 (RFC 8439 sec. 2.5.2)', () {
    // RFC 8439 sec. 2.5.2 "Poly1305 Example and Test Vector". Key
    // 85d6be78..f51b, message "Cryptographic Forum Research Group", tag
    // a8061dc1305136c6c22b8baf0c0127a9.
    // https://www.rfc-editor.org/rfc/rfc8439#section-2.5.2
    test('MAC vector', () {
      final key = _hex(
          '85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b');
      final msg = _hex(
          '43727970746f6772617068696320466f72756d2052657365617263682047726f7570');
      final tag = poly1305Mac(key, msg);
      expect(hexEncode(tag), equals('a8061dc1305136c6c22b8baf0c0127a9'));
    });
  });

  group('ChaCha20 block (RFC 8439 sec. 2.3.2)', () {
    // RFC 8439 sec. 2.3.2 "Test Vector for the ChaCha20 Block Function". Key
    // 000102..1f, block counter 1, nonce 00000009 0000004a 00000000, expected
    // 64-byte keystream block 10f1e7e4..3c4e.
    // https://www.rfc-editor.org/rfc/rfc8439#section-2.3.2
    test('keystream block vector', () {
      final key = _hex(
          '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
      final nonce = _hex('000000090000004a00000000');
      final block = chacha20Block(key, 1, nonce);
      expect(
        hexEncode(block),
        equals(
            '10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e'
            'd2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e'),
      );
    });
  });
}
