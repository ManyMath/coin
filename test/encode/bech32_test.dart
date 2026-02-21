import 'dart:typed_data';

import 'package:coin/coin.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(() async {
    await VaultKeeper.initialize();
  });

  // Recurring programs in this file:
  // - 751e76e8...3bd6 is HASH160 of the compressed pubkey for private key 1
  //   (generator G); it is the witness program in the BIP-173 P2WPKH example
  //   address bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 (asserted below).
  //   https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
  // - a60869f0...b32c is the x-only taproot output key from the BIP-86 test
  //   vector (m/86'/0'/0'/0/0), encoded as the BIP-350 bech32m P2TR address;
  //   also used in bip86_address_test.dart and bech32m_bip350_test.dart.
  //   https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki#test-vectors
  group('Bech32 encode/decode (BIP-173)', () {
    test('encode and decode 20-byte witness program (P2WPKH style)', () {
      final data = hexDecode('751e76e8199196d454941c45d1b3a323f1433bd6');
      final encoded = Bech32.encode('bc', data, version: 0);

      expect(encoded, startsWith('bc1'));
      expect(encoded.toLowerCase(), encoded);

      final (hrp, version, decoded) = Bech32.decode(encoded);
      expect(hrp, 'bc');
      expect(version, 0);
      expect(decoded, equals(data));
    });

    // Round-trip over an arbitrary 32-byte program; encode-then-decode
    // returns the input.
    test('encode and decode 32-byte witness program (P2WSH style)', () {
      final data = hexDecode(
          '1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262');
      final encoded = Bech32.encode('bc', data, version: 0);

      final (hrp, version, decoded) = Bech32.decode(encoded);
      expect(hrp, 'bc');
      expect(version, 0);
      expect(decoded, equals(data));
    });

    test('testnet hrp "tb"', () {
      final data = hexDecode('751e76e8199196d454941c45d1b3a323f1433bd6');
      final encoded = Bech32.encode('tb', data, version: 0);
      expect(encoded, startsWith('tb1'));

      final (hrp, version, decoded) = Bech32.decode(encoded);
      expect(hrp, 'tb');
      expect(version, 0);
      expect(decoded, equals(data));
    });

    // BIP-173 test vectors: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
    test('BIP-173 valid vector: bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4', () {
      const addr = 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4';
      final (hrp, version, data) = Bech32.decode(addr);
      expect(hrp, 'bc');
      expect(version, 0);
      expect(data.length, 20);
      expect(hexEncode(data),
          '751e76e8199196d454941c45d1b3a323f1433bd6');

      final reencoded = Bech32.encode('bc', data, version: 0);
      expect(reencoded, addr);
    });

    // BIP-173 citation: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
    test('BIP-173 valid vector: tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx', () {
      const addr = 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx';
      final (hrp, version, data) = Bech32.decode(addr);
      expect(hrp, 'tb');
      expect(version, 0);
      expect(data.length, 20);
      expect(hexEncode(data), '751e76e8199196d454941c45d1b3a323f1433bd6');

      final reencoded = Bech32.encode('tb', data, version: 0);
      expect(reencoded, addr);
    });

    test('BIP-173 valid vector: bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4ncga7cu6', () {
      const addr = 'bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4ncga7cu6';
      final (hrp, version, data) = Bech32.decode(addr);
      expect(hrp, 'bc');
      expect(version, 0);
      expect(data.length, 20);

      final reencoded = Bech32.encode('bc', data, version: 0);
      expect(reencoded, addr);
    });
  });

  group('Bech32m encode/decode (BIP-350)', () {
    test('encode and decode 32-byte taproot program', () {
      final data = hexDecode(
          'a60869f0dbcf1dc659c9cecbee090e9cc79da1e52f1f16e81b8df7e8f3b8b32c');
      final encoded = Bech32.encodem('bc', data, version: 1);
      expect(encoded, startsWith('bc1p'));

      final (hrp, version, decoded) = Bech32.decode(encoded);
      expect(hrp, 'bc');
      expect(version, 1);
      expect(decoded, equals(data));
    });

    // BIP-350 test vector: https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki
    test('BIP-350 valid vector: bc1p taproot address', () {
      final xOnly = hexDecode(
          'a60869f0dbcf1dc659c9cecbee090e9cc79da1e52f1f16e81b8df7e8f3b8b32c');
      final encoded = Bech32.encodem('bc', xOnly, version: 1);
      expect(encoded, startsWith('bc1p'));

      final (hrp, version, decoded) = Bech32.decode(encoded);
      expect(hrp, 'bc');
      expect(version, 1);
      expect(decoded, equals(xOnly));
    });

    test('testnet taproot address', () {
      final data = hexDecode(
          'a60869f0dbcf1dc659c9cecbee090e9cc79da1e52f1f16e81b8df7e8f3b8b32c');
      final encoded = Bech32.encodem('tb', data, version: 1);
      expect(encoded, startsWith('tb1p'));

      final (hrp, version, decoded) = Bech32.decode(encoded);
      expect(hrp, 'tb');
      expect(version, 1);
      expect(decoded, equals(data));
    });

    // Round-trip over a synthetic all-0xaa 32-byte program.
    test('bech32m round-trip with various witness versions', () {
      final data = hexDecode(
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
      final encoded = Bech32.encodem('bc', data, version: 1);
      final (hrp, version, decoded) = Bech32.decode(encoded);
      expect(hrp, 'bc');
      expect(version, 1);
      expect(decoded, equals(data));
    });
  });

  // Negative tests: corrupt a known-good address and assert rejection. The
  // spec invalid-string vectors live in bech32m_bip350_test.dart.
  group('Bech32 invalid string detection', () {
    test('invalid character in data part throws', () {
      expect(
          () => Bech32.decode('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kBEEF'),
          throwsFormatException);
    });

    test('empty data part throws', () {
      expect(() => Bech32.decode('bc1'), throwsFormatException);
    });

    test('no separator throws', () {
      expect(() => Bech32.decode('abcdefg'), throwsFormatException);
    });

    test('checksum mismatch throws', () {
      const valid = 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4';
      final invalid =
          '${valid.substring(0, 10)}x${valid.substring(11)}';
      expect(() => Bech32.decode(invalid), throwsFormatException);
    });

    test('mixed case throws or rejects', () {
      expect(() => Bech32.decode('Bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'),
          throwsFormatException);
    });
  });

  // Round-trip consistency over synthetic 20/32-byte programs.
  group('Bech32 round-trip', () {
    test('round-trip encode/decode for 20-byte program', () {
      final data = Uint8List(20);
      for (var i = 0; i < 20; i++) {
        data[i] = (i * 13 + 7) & 0xff;
      }
      final encoded = Bech32.encode('bc', data, version: 0);
      final (_, _, decoded) = Bech32.decode(encoded);
      expect(decoded, equals(data));
    });

    test('round-trip encode/decode for 32-byte program', () {
      final data = Uint8List(32);
      for (var i = 0; i < 32; i++) {
        data[i] = (i * 17 + 3) & 0xff;
      }
      final encoded = Bech32.encode('bc', data, version: 0);
      final (_, _, decoded) = Bech32.decode(encoded);
      expect(decoded, equals(data));
    });
  });
}
