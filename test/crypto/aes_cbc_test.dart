import 'dart:typed_data';

import 'package:coin/coin.dart';
import 'package:coin/src/crypto/soft/aes.dart';
import 'package:test/test.dart';

Uint8List _hex(String s) => Uint8List.fromList(hexDecode(s));

void main() {
  group('AES-256 / CBC / PKCS7', () {
    test('FIPS-197 AES-256 single-block test vector', () {
      // FIPS-197 "Advanced Encryption Standard (AES)", Appendix C.3 (AES-256
      // example): key 000102..1f, input 00112233..ff,
      // output 8ea2b7ca516745bfeafc49904b496089.
      // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf (Appendix C.3)
      // We exercise the single-block primitive by encrypting one block via CBC
      // with an all-zero IV, so the first ciphertext block equals the raw
      // AES-256 block encryption of the plaintext block.
      final key = _hex(
          '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
      final pt = _hex('00112233445566778899aabbccddeeff');
      final iv = Uint8List(16); // all zeros
      const expected = '8ea2b7ca516745bfeafc49904b496089';

      final ct = aes256CbcEncrypt(key, iv, pt);
      // With zero IV the first block is raw AES block encryption.
      expect(hexEncode(ct.sublist(0, 16)), equals(expected));
    });

    test('NIST SP800-38A AES-256-CBC vector (F.2.5/F.2.6)', () {
      // NIST SP 800-38A (2001 ed.), Appendix F.2.5 (CBC-AES256.Encrypt) and
      // F.2.6 (CBC-AES256.Decrypt). Key 603deb.., IV 000102..0f, the four
      // standard plaintext blocks 6bc1bee2..3710 and ciphertext f58c4c04..9d1b.
      // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
      final key = _hex(
          '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4');
      final iv = _hex('000102030405060708090a0b0c0d0e0f');
      final pt = _hex('6bc1bee22e409f96e93d7e117393172a'
          'ae2d8a571e03ac9c9eb76fac45af8e51'
          '30c81c46a35ce411e5fbc1191a0a52ef'
          'f69f2445df4f9b17ad2b417be66c3710');
      const expected = 'f58c4c04d6e5f1ba779eabfb5f7bfbd6'
          '9cfc4e967edb808d679f777bc6702c7d'
          '39f23369a9d9bacfa530e26304231461'
          'b2eb05e2c39be9fcda6c19078c6a9d1b';

      // SP800-38A vectors are raw (unpadded) CBC. aes256CbcEncrypt adds a 5th
      // PKCS7 block; compare only the first 64 bytes (the 4 data blocks).
      final ct = aes256CbcEncrypt(key, iv, pt);
      expect(ct.length, equals(80)); // 64 data + 16 padding
      expect(hexEncode(ct.sublist(0, 64)), equals(expected));

      // And it decrypts back to the original 64-byte plaintext.
      final back = aes256CbcDecrypt(key, iv, ct);
      expect(hexEncode(back), equals(hexEncode(pt)));
    });

    // Round-trip consistency (encrypt-then-decrypt) over a range of lengths;
    // key/IV reuse the SP800-38A constants.
    test('round-trip for several message lengths (0,15,16,31,...)', () {
      final key = _hex(
          '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4');
      final iv = _hex('000102030405060708090a0b0c0d0e0f');

      for (final len in <int>[0, 1, 15, 16, 17, 31, 32, 33, 64, 100]) {
        final msg = Uint8List(len);
        for (var i = 0; i < len; i++) {
          msg[i] = (i * 7 + 13) & 0xff;
        }
        final ct = aes256CbcEncrypt(key, iv, msg);
        expect(ct.length % 16, equals(0), reason: 'len=$len output aligned');
        expect(ct.length, greaterThan(len), reason: 'len=$len padded');
        final back = aes256CbcDecrypt(key, iv, ct);
        expect(hexEncode(back), equals(hexEncode(msg)), reason: 'len=$len');
      }
    });

    // Negative tests: the API must reject corrupted padding and invalid
    // key/IV/ciphertext lengths.
    test('bad PKCS7 padding throws FormatException', () {
      final key = _hex(
          '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4');
      final iv = _hex('000102030405060708090a0b0c0d0e0f');
      final ct = aes256CbcEncrypt(key, iv, _hex('00112233'));
      // Corrupt the last ciphertext byte -> padding check should fail.
      final bad = Uint8List.fromList(ct);
      bad[bad.length - 1] ^= 0xff;
      expect(() => aes256CbcDecrypt(key, iv, bad),
          throwsA(isA<FormatException>()));
    });

    test('rejects wrong key/iv lengths and bad ciphertext length', () {
      expect(() => aes256CbcEncrypt(Uint8List(31), Uint8List(16), Uint8List(0)),
          throwsArgumentError);
      expect(() => aes256CbcEncrypt(Uint8List(32), Uint8List(15), Uint8List(0)),
          throwsArgumentError);
      expect(
          () => aes256CbcDecrypt(Uint8List(32), Uint8List(16), Uint8List(10)),
          throwsA(isA<FormatException>()));
    });
  });
}
