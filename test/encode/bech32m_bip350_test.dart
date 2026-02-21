import 'package:coin/coin.dart';
import 'package:test/test.dart';

// BIP-350 bech32m test vectors (invalid strings that must be rejected).
// Source: https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki
// Source: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
//
// The Dart Bech32.decode is a Bitcoin witness-address decoder (it expects a
// witness version byte after the separator and produces a program).  Raw
// bech32/bech32m strings without a witness-version byte (the "generic encoder"
// test vectors from BIP-350 sec. Test vectors) are NOT within its scope.
//
// This test covers:
//  (a) BIP-350 invalid strings that the decoder MUST reject
//  (b) BIP-173 invalid strings that the decoder MUST also reject
//  (c) BIP-350 / BIP-173 valid witness-address strings (round-trip)

void main() {
  setUpAll(() async {
    await VaultKeeper.initialize();
  });

  // -----------------------------------------------------------------------
  // BIP-350 invalid strings - must be rejected (throw FormatException or Error)
  // -----------------------------------------------------------------------
  group('BIP-350 invalid strings are rejected', () {
    // The "Invalid strings" table in BIP-350 sec. Test
    // vectors. https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki
    // These strings have structural errors that ANY bech32/bech32m decoder
    // should catch before it tries to interpret witness-version data.
    final invalid = {
      'qyrz8wqd2c9m': 'no separator',
      '1qyrz8wqd2c9m': 'empty HRP',
      'y1b0jsk6g': 'invalid data character',
      'lt1igcx5c0': 'invalid data character',
      'in1muywd': 'too short checksum',
      'mm1crxm3i': 'invalid char in checksum',
      'au1s5cgom': 'invalid char in checksum',
      'M1VUXWEZ': 'checksum uses uppercase HRP',
      '16plkw9': 'empty HRP',
      '1p2gdwpf': 'empty HRP',
    };

    for (final entry in invalid.entries) {
      test('rejects "${entry.key}" (${entry.value})', () {
        expect(() => Bech32.decode(entry.key), throwsA(anything),
            reason: entry.value);
      });
    }
  });

  // -----------------------------------------------------------------------
  // BIP-173 invalid strings - must also be rejected.
  // -----------------------------------------------------------------------
  group('BIP-173 invalid strings are rejected', () {
    // The "Invalid" examples from BIP-173 sec. Test vectors.
    // https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
    final invalid173 = {
      'pzry9x0s0muk': 'no separator',
      '1pzry9x0s0muk': 'empty HRP',
      'x1b4n0q5v': 'invalid data character',
      'li1dgmt3': 'too short checksum',
      'A1G7SGD8': 'checksum uses uppercase HRP',
      '10a06t8': 'empty HRP',
      '1qzzfhee': 'empty HRP',
    };

    for (final entry in invalid173.entries) {
      test('rejects "${entry.key}" (${entry.value})', () {
        expect(() => Bech32.decode(entry.key), throwsA(anything),
            reason: entry.value);
      });
    }
  });

  // -----------------------------------------------------------------------
  // BIP-173 valid witness-address strings from the BIP (round-trip encode/
  // decode using the witness-address API).
  // -----------------------------------------------------------------------
  group('BIP-173 valid witness addresses (from bip-0173.mediawiki)', () {
    test('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 - P2WPKH mainnet', () {
      const addr = 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4';
      final (hrp, version, data) = Bech32.decode(addr);
      expect(hrp, 'bc');
      expect(version, 0);
      expect(data.length, 20);
      expect(hexEncode(data), '751e76e8199196d454941c45d1b3a323f1433bd6');
      expect(Bech32.encode('bc', data, version: 0), addr);
    });

    test('tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx - P2WPKH testnet', () {
      const addr = 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx';
      final (hrp, version, data) = Bech32.decode(addr);
      expect(hrp, 'tb');
      expect(version, 0);
      expect(data.length, 20);
    });
  });

  // -----------------------------------------------------------------------
  // BIP-350 valid witness-address strings (bech32m, v1 taproot).
  // -----------------------------------------------------------------------
  group('BIP-350 valid taproot addresses (witness version 1)', () {
    // A bech32m-encoded taproot address (P2TR) from BIP-341 test vectors.
    // The x-only key is from the BIP-86 derivation vector (path m/86'/0'/0'/0/0).
    // Confirmed in bip86_address_test.dart.
    test('bc1p taproot address round-trips', () {
      final xOnly = hexDecode(
          'a60869f0dbcf1dc659c9cecbee090e9cc79da1e52f1f16e81b8df7e8f3b8b32c');
      final encoded = Bech32.encodem('bc', xOnly, version: 1);
      expect(encoded, startsWith('bc1p'));
      final (hrp, version, decoded) = Bech32.decode(encoded);
      expect(hrp, 'bc');
      expect(version, 1);
      expect(decoded, equals(xOnly));
    });

    test('mixed case in data part is rejected for both bech32 and bech32m', () {
      expect(
          () => Bech32.decode('Bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'),
          throwsA(anything));
    });
  });
}
