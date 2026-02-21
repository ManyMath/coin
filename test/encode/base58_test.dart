import 'dart:typed_data';

import 'package:coin/coin.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(() async {
    await VaultKeeper.initialize();
  });

  // Well-known Bitcoin Base58Check address pairs.
  // - 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa is the address that received the
  //   block-0 (genesis) coinbase output; its 21-byte payload is version 0x00 +
  //   HASH160 62e907b1..8f18. https://blockstream.info/block/0
  // - 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy is the canonical P2SH example address
  //   (version 0x05 + HASH160 b472a266..9fcb), reused in
  //   address_test.dart / script_test.dart.
  // These are the standard Base58 examples in BIP-13/Bitcoin wiki "Base58Check".
  group('Base58Check encode/decode known pairs', () {
    test('Satoshi genesis address 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', () {
      final payload = hexDecode(
          '0062e907b15cbf27d5425399ebf6f0fb50ebb88f18');
      final encoded = base58Encode(payload);
      expect(encoded, equals('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'));

      final decoded = base58Decode('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa');
      expect(decoded, equals(payload));
    });

    test('P2SH address 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy', () {
      final payload = hexDecode(
          '05b472a266d0bd89c13706a4132ccfb16f7c3b9fcb');
      final encoded = base58Encode(payload);
      expect(encoded, equals('3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy'));

      final decoded = base58Decode('3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy');
      expect(hexEncode(decoded),
          equals('05b472a266d0bd89c13706a4132ccfb16f7c3b9fcb'));
    });

    // Base58Check of 21 zero bytes -> the all-'1' prefix string (sha256d
    // checksum + base58).
    test('encode/decode version 0x00 with 20 zero bytes', () {
      final payload = Uint8List(21);
      final encoded = base58Encode(payload);
      expect(encoded, equals('1111111111111111111114oLvT2'));

      final decoded = base58Decode(encoded);
      expect(decoded, equals(payload));
    });

    // Round-trip (encode-then-decode) consistency check.
    test('encode/decode single byte payload', () {
      final payload = Uint8List.fromList([0x05]);
      final encoded = base58Encode(payload);
      final decoded = base58Decode(encoded);
      expect(decoded, equals(payload));
    });

    // Key e8f32e... is the BIP-32 Test Vector 1 chain-m child key;
    // see https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
    test('encode/decode WIF private key payload', () {
      final payload = hexDecode(
          '80e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35');
      final encoded = base58Encode(payload);
      expect(encoded, isNotEmpty);

      final decoded = base58Decode(encoded);
      expect(decoded, equals(payload));
    });
  });

  // Round-trip and negative (corrupted checksum / truncation / invalid char /
  // empty) behavioral tests.
  group('Base58Check round-trip', () {
    test('round-trip with random-like data', () {
      final payload = hexDecode('0102030405060708090a0b0c0d0e0f10');
      final encoded = base58Encode(payload);
      final decoded = base58Decode(encoded);
      expect(decoded, equals(payload));
    });

    test('round-trip with all 0xff bytes', () {
      final payload = Uint8List.fromList(List.filled(20, 0xff));
      final encoded = base58Encode(payload);
      final decoded = base58Decode(encoded);
      expect(decoded, equals(payload));
    });

    test('round-trip preserves leading zero bytes', () {
      final payload = Uint8List.fromList([0, 0, 0, 1, 2, 3]);
      final encoded = base58Encode(payload);
      final decoded = base58Decode(encoded);
      expect(decoded, equals(payload));
    });

    test('round-trip with various sizes', () {
      for (var size in [1, 5, 10, 20, 25, 32, 50]) {
        final payload = Uint8List(size);
        for (var i = 0; i < size; i++) {
          payload[i] = (i * 7 + 13) & 0xff;
        }
        final encoded = base58Encode(payload);
        final decoded = base58Decode(encoded);
        expect(decoded, equals(payload), reason: 'failed for size $size');
      }
    });
  });

  group('Base58Check invalid checksum detection', () {
    test('corrupted checksum throws FormatException', () {
      final payload = hexDecode('00112233445566778899aabbccddeeff00112233');
      final encoded = base58Encode(payload);

      final chars = encoded.split('');
      final lastChar = chars.last;
      chars[chars.length - 1] = lastChar == 'z' ? 'y' : 'z';
      final corrupted = chars.join();

      expect(() => base58Decode(corrupted), throwsFormatException);
    });

    test('truncated string throws', () {
      final payload = hexDecode('00112233445566778899aabbccddeeff00112233');
      final encoded = base58Encode(payload);
      final truncated = encoded.substring(0, encoded.length - 2);

      expect(() => base58Decode(truncated), throwsFormatException);
    });

    test('invalid base58 character throws', () {
      expect(() => base58Decode('0invalid'), throwsFormatException);
    });

    test('empty string throws', () {
      expect(() => base58Decode(''), throwsA(anything));
    });
  });
}
