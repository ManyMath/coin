import 'dart:typed_data';

import 'package:coin/coin_evm.dart';
import 'package:test/test.dart';

// Official RLP test vectors from the ethereum/tests repository.
// Source: https://github.com/ethereum/tests/blob/develop/RLPTests/rlptest.json
// (fetched 2025-05-29, develop branch)
//
// Only string and list vectors are included here; the bigint vectors
// (prefixed "#" in the JSON) are large-integer edge cases that the Dart
// implementation represents as BigInt - their hex output is verified separately.

Uint8List _hexOut(String hex) {
  // Strip leading "0x" if present.
  final h = hex.startsWith('0x') ? hex.substring(2) : hex;
  return hexDecode(h);
}

void main() {
  setUpAll(() async {
    await VaultKeeper.initialize();
  });

  // ---------------------------------------------------------------------------
  // String / byte vectors from rlptest.json
  // ---------------------------------------------------------------------------
  group('RLP encode - string vectors (ethereum/tests rlptest.json)', () {
    test('emptystring ""', () {
      expect(Rlp.encode(Uint8List(0)),
          equals(_hexOut('0x80')));
    });

    test('bytestring00 \\u0000', () {
      expect(Rlp.encode(Uint8List.fromList([0x00])),
          equals(_hexOut('0x00')));
    });

    test('bytestring01 \\u0001', () {
      expect(Rlp.encode(Uint8List.fromList([0x01])),
          equals(_hexOut('0x01')));
    });

    test('bytestring7F \\u007F', () {
      expect(Rlp.encode(Uint8List.fromList([0x7f])),
          equals(_hexOut('0x7f')));
    });

    test('shortstring "dog"', () {
      expect(Rlp.encode('dog'), equals(_hexOut('0x83646f67')));
    });

    // "Lorem ipsum dolor sit amet, consectetur adipisicing eli" (55 bytes)
    test('shortstring2 - 55-byte string (at boudary of short-string range)', () {
      const text =
          'Lorem ipsum dolor sit amet, consectetur adipisicing eli';
      expect(text.length, 55);
      final expected = _hexOut(
          '0xb74c6f72656d20697073756d20646f6c6f722073697420616d65742c20636f6e73656374657475'
          '72206164697069736963696e6720656c69');
      expect(Rlp.encode(text), equals(expected));
    });

    // "Lorem ipsum dolor sit amet, consectetur adipisicing elit" (56 bytes)
    test('longstring - 56-byte string (first long-string encoding)', () {
      const text =
          'Lorem ipsum dolor sit amet, consectetur adipisicing elit';
      expect(text.length, 56);
      final expected = _hexOut(
          '0xb8384c6f72656d20697073756d20646f6c6f722073697420616d65742c20636f6e73656374657475'
          '72206164697069736963696e6720656c6974');
      expect(Rlp.encode(text), equals(expected));
    });
  });

  // ---------------------------------------------------------------------------
  // Integer vectors from rlptest.json
  // ---------------------------------------------------------------------------
  group('RLP encode - integer vectors (ethereum/tests rlptest.json)', () {
    test('zero: 0 -> 0x80', () {
      expect(Rlp.encode(0), equals(_hexOut('0x80')));
    });

    test('smallint: 1 -> 0x01', () {
      expect(Rlp.encode(1), equals(_hexOut('0x01')));
    });

    test('smallint2: 16 -> 0x10', () {
      expect(Rlp.encode(16), equals(_hexOut('0x10')));
    });

    test('smallint3: 79 -> 0x4f', () {
      expect(Rlp.encode(79), equals(_hexOut('0x4f')));
    });

    test('smallint4: 127 -> 0x7f', () {
      expect(Rlp.encode(127), equals(_hexOut('0x7f')));
    });

    test('mediumint1: 128 -> 0x8180', () {
      expect(Rlp.encode(128), equals(_hexOut('0x8180')));
    });

    test('mediumint2: 1000 -> 0x8203e8', () {
      expect(Rlp.encode(1000), equals(_hexOut('0x8203e8')));
    });

    test('mediumint3: 100000 -> 0x830186a0', () {
      expect(Rlp.encode(100000), equals(_hexOut('0x830186a0')));
    });
  });

  // ---------------------------------------------------------------------------
  // List vectors from rlptest.json
  // ---------------------------------------------------------------------------
  group('RLP encode - list vectors (ethereum/tests rlptest.json)', () {
    test('emptylist [] -> 0xc0', () {
      expect(Rlp.encode([]), equals(_hexOut('0xc0')));
    });

    test('stringlist ["dog","god","cat"] -> 0xcc83646f6783676f6483636174', () {
      expect(
          Rlp.encode(['dog', 'god', 'cat']),
          equals(_hexOut('0xcc83646f6783676f6483636174')));
    });

    test('multilist ["zw",[4],1] -> 0xc6827a77c10401', () {
      expect(
          Rlp.encode(['zw', [4], 1]),
          equals(_hexOut('0xc6827a77c10401')));
    });

    test('listsoflists [[[], []], []] -> 0xc4c2c0c0c0', () {
      expect(
          Rlp.encode([
            [<dynamic>[], <dynamic>[]],
            <dynamic>[],
          ]),
          equals(_hexOut('0xc4c2c0c0c0')));
    });

    test('listsoflists2 [[], [[]], [[], [[]]]] -> 0xc7c0c1c0c3c0c1c0', () {
      expect(
          Rlp.encode([
            <dynamic>[],
            [<dynamic>[]],
            [<dynamic>[], [<dynamic>[]]]
          ]),
          equals(_hexOut('0xc7c0c1c0c3c0c1c0')));
    });

    // dictTest1: [["key1","val1"],["key2","val2"],["key3","val3"],["key4","val4"]]
    // -> 0xecca846b6579318476616c31ca846b6579328476616c32ca846b6579338476616c33ca846b6579348476616c34
    test('dictTest1 - list of key/value pairs', () {
      expect(
          Rlp.encode([
            ['key1', 'val1'],
            ['key2', 'val2'],
            ['key3', 'val3'],
            ['key4', 'val4'],
          ]),
          equals(_hexOut(
              '0xecca846b6579318476616c31ca846b6579328476616c32'
              'ca846b6579338476616c33ca846b6579348476616c34')));
    });
  });

  // ---------------------------------------------------------------------------
  // Round-trip decode
  // ---------------------------------------------------------------------------
  group('RLP decode round-trip (ethereum/tests rlptest.json values)', () {
    test('decode emptystring', () {
      final decoded = Rlp.decode(_hexOut('0x80'));
      expect(decoded, isA<Uint8List>());
      expect((decoded as Uint8List).length, 0);
    });

    test('decode shortstring "dog"', () {
      final decoded = Rlp.decode(_hexOut('0x83646f67'));
      expect(decoded, isA<Uint8List>());
      expect(String.fromCharCodes(decoded as Uint8List), 'dog');
    });

    test('decode stringlist ["dog","god","cat"]', () {
      final decoded = Rlp.decode(_hexOut('0xcc83646f6783676f6483636174'));
      expect(decoded, isA<List>());
      final list = decoded as List;
      expect(list.length, 3);
      expect(String.fromCharCodes(list[0] as Uint8List), 'dog');
      expect(String.fromCharCodes(list[1] as Uint8List), 'god');
      expect(String.fromCharCodes(list[2] as Uint8List), 'cat');
    });
  });
}
