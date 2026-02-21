import 'dart:typed_data';

import 'package:coin/coin.dart';
import 'package:coin/src/encode/rlp.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(() async {
    await VaultKeeper.initialize();
  });

  // Derived from spec: the encode/decode/round-trip groups below are computed
  // by hand from the RLP encoding rules in the Ethereum Yellow Paper Appendix B
  // (single byte <0x80 self-encodes; 0x80+len for 0-55 byte strings; 0xb7+ for
  // longer; 0xc0/0xf7 list prefixes). https://ethereum.github.io/yellowpaper/paper.pdf
  // Canonical published examples ("dog", ["cat","dog"], the set-of-three nested
  // lists, integers 0/15/1024) are pinned in the "Known Ethereum RLP test
  // vectors" group at the bottom; the rest are spec-rule expectations and
  // round-trips (no separate external vector).
  group('RLP encode single values', () {
    test('empty byte string', () {
      final encoded = Rlp.encode(Uint8List(0));
      expect(encoded, equals(Uint8List.fromList([0x80])));
    });

    test('single byte <= 0x7f (self-encoded)', () {
      final encoded = Rlp.encode(Uint8List.fromList([0x42]));
      expect(encoded, equals(Uint8List.fromList([0x42])));
    });

    test('single byte 0x00 is self-encoded', () {
      final encoded = Rlp.encode(Uint8List.fromList([0x00]));
      expect(encoded, equals(Uint8List.fromList([0x00])));
    });

    test('single byte 0x7f is self-encoded', () {
      final encoded = Rlp.encode(Uint8List.fromList([0x7f]));
      expect(encoded, equals(Uint8List.fromList([0x7f])));
    });

    test('single byte 0x80 gets length prefix', () {
      final encoded = Rlp.encode(Uint8List.fromList([0x80]));
      expect(encoded, equals(Uint8List.fromList([0x81, 0x80])));
    });

    test('short string (2-55 bytes)', () {
      final encoded = Rlp.encode(Uint8List.fromList([0x64, 0x6f, 0x67]));
      expect(encoded, equals(Uint8List.fromList([0x83, 0x64, 0x6f, 0x67])));
    });

    test('string encoding for "dog"', () {
      final encoded = Rlp.encode('dog');
      expect(encoded, equals(Uint8List.fromList([0x83, 0x64, 0x6f, 0x67])));
    });

    test('long string (> 55 bytes)', () {
      final data = Uint8List.fromList(List.filled(56, 0xaa));
      final encoded = Rlp.encode(data);
      expect(encoded[0], 0xb8);
      expect(encoded[1], 56);
      expect(encoded.length, 56 + 2);
      expect(encoded.sublist(2), equals(data));
    });

    test('very long string (256 bytes)', () {
      final data = Uint8List.fromList(List.filled(256, 0xbb));
      final encoded = Rlp.encode(data);
      // 256 = 0x0100 => 2-byte length
      expect(encoded[0], 0xb9);
      expect(encoded[1], 0x01);
      expect(encoded[2], 0x00);
      expect(encoded.length, 256 + 3);
    });
  });

  group('RLP encode integers', () {
    test('integer 0', () {
      final encoded = Rlp.encode(0);
      expect(encoded, equals(Uint8List.fromList([0x80])));
    });

    test('integer 1', () {
      final encoded = Rlp.encode(1);
      expect(encoded, equals(Uint8List.fromList([0x01])));
    });

    test('integer 127 (0x7f)', () {
      final encoded = Rlp.encode(127);
      expect(encoded, equals(Uint8List.fromList([0x7f])));
    });

    test('integer 128 (0x80)', () {
      final encoded = Rlp.encode(128);
      expect(encoded, equals(Uint8List.fromList([0x81, 0x80])));
    });

    test('integer 1024', () {
      final encoded = Rlp.encode(1024);
      expect(encoded, equals(Uint8List.fromList([0x82, 0x04, 0x00])));
    });

    test('BigInt encoding', () {
      final encoded = Rlp.encode(BigInt.from(256));
      expect(encoded, equals(Uint8List.fromList([0x82, 0x01, 0x00])));
    });
  });

  group('RLP encode lists', () {
    test('empty list', () {
      final encoded = Rlp.encode([]);
      expect(encoded, equals(Uint8List.fromList([0xc0])));
    });

    test('list with single short string', () {
      final encoded = Rlp.encode(['dog']);
      expect(encoded,
          equals(Uint8List.fromList([0xc4, 0x83, 0x64, 0x6f, 0x67])));
    });

    test('list with multiple strings', () {
      final encoded = Rlp.encode(['cat', 'dog']);
      expect(encoded, equals(Uint8List.fromList([
        0xc8, 0x83, 0x63, 0x61, 0x74, 0x83, 0x64, 0x6f, 0x67
      ])));
    });

    test('nested empty lists', () {
      // [ [], [[]], [ [], [[]] ] ]
      final encoded = Rlp.encode([
        <dynamic>[],
        [<dynamic>[]],
        [<dynamic>[], [<dynamic>[]]]
      ]);
      expect(
          encoded,
          equals(Uint8List.fromList([
            0xc7, 0xc0, 0xc1, 0xc0, 0xc3, 0xc0, 0xc1, 0xc0
          ])));
    });

    test('list with integer', () {
      final encoded = Rlp.encode([1, 2, 3]);
      expect(encoded, equals(Uint8List.fromList([0xc3, 0x01, 0x02, 0x03])));
    });
  });

  group('RLP decode', () {
    test('decode empty byte string', () {
      final result = Rlp.decode(Uint8List.fromList([0x80]));
      expect(result, isA<Uint8List>());
      expect((result as Uint8List).length, 0);
    });

    test('decode single byte', () {
      final result = Rlp.decode(Uint8List.fromList([0x42]));
      expect(result, isA<Uint8List>());
      expect(result as Uint8List, equals(Uint8List.fromList([0x42])));
    });

    test('decode short string', () {
      final result =
          Rlp.decode(Uint8List.fromList([0x83, 0x64, 0x6f, 0x67]));
      expect(result, isA<Uint8List>());
      expect(
          result as Uint8List, equals(Uint8List.fromList([0x64, 0x6f, 0x67])));
    });

    test('decode long string', () {
      final data = Uint8List.fromList(List.filled(56, 0xaa));
      final encoded = Rlp.encode(data);
      final decoded = Rlp.decode(encoded);
      expect(decoded, isA<Uint8List>());
      expect(decoded as Uint8List, equals(data));
    });

    test('decode empty list', () {
      final result = Rlp.decode(Uint8List.fromList([0xc0]));
      expect(result, isA<List>());
      expect((result as List).length, 0);
    });

    test('decode nested lists', () {
      final encoded = Uint8List.fromList(
          [0xc7, 0xc0, 0xc1, 0xc0, 0xc3, 0xc0, 0xc1, 0xc0]);
      final result = Rlp.decode(encoded);
      expect(result, isA<List>());
      final list = result as List;
      expect(list.length, 3);
      expect(list[0], isA<List>());
      expect((list[0] as List).length, 0);
      expect(list[1], isA<List>());
      expect((list[1] as List).length, 1);
    });

    test('decode list with strings', () {
      final encoded = Uint8List.fromList(
          [0xc8, 0x83, 0x63, 0x61, 0x74, 0x83, 0x64, 0x6f, 0x67]);
      final result = Rlp.decode(encoded);
      expect(result, isA<List>());
      final list = result as List;
      expect(list.length, 2);
      expect(list[0], equals(Uint8List.fromList([0x63, 0x61, 0x74])));
      expect(list[1], equals(Uint8List.fromList([0x64, 0x6f, 0x67])));
    });
  });

  group('RLP encode/decode round-trip', () {
    test('round-trip empty bytes', () {
      final original = Uint8List(0);
      final decoded = Rlp.decode(Rlp.encode(original));
      expect(decoded, isA<Uint8List>());
      expect((decoded as Uint8List).length, 0);
    });

    test('round-trip single byte values', () {
      for (var b = 0; b <= 0xff; b++) {
        final original = Uint8List.fromList([b]);
        final decoded = Rlp.decode(Rlp.encode(original));
        expect(decoded as Uint8List, equals(original),
            reason: 'failed for byte 0x${b.toRadixString(16)}');
      }
    });

    test('round-trip complex nested structure', () {
      final data = [
        Uint8List.fromList([1, 2, 3]),
        <dynamic>[],
        [Uint8List.fromList([0xff])],
      ];
      final encoded = Rlp.encode(data);
      final decoded = Rlp.decode(encoded) as List;

      expect(decoded.length, 3);
      expect(decoded[0], equals(Uint8List.fromList([1, 2, 3])));
      expect((decoded[1] as List).length, 0);
      expect((decoded[2] as List).length, 1);
      expect((decoded[2] as List)[0], equals(Uint8List.fromList([0xff])));
    });
  });

  // Vectors from the Ethereum Yellow Paper, Appendix B.
  // https://github.com/ethereum/yellowpaper  (Paper.tex, sec. B)
  // Also mirrored at https://github.com/ethereum/wiki/wiki/RLP
  group('Known Ethereum RLP test vectors', () {
    test('encode empty string ""', () {
      final encoded = Rlp.encode(Uint8List(0));
      expect(encoded, equals(Uint8List.fromList([0x80])));
    });

    test('encode "dog"', () {
      final encoded = Rlp.encode('dog');
      expect(encoded,
          equals(Uint8List.fromList([0x83, 0x64, 0x6f, 0x67])));
    });

    test('encode ["cat", "dog"]', () {
      final encoded = Rlp.encode(['cat', 'dog']);
      expect(
          encoded,
          equals(Uint8List.fromList(
              [0xc8, 0x83, 0x63, 0x61, 0x74, 0x83, 0x64, 0x6f, 0x67])));
    });

    test('encode integer 15 (\\x0f)', () {
      final encoded = Rlp.encode(15);
      expect(encoded, equals(Uint8List.fromList([0x0f])));
    });

    test('encode integer 1024', () {
      final encoded = Rlp.encode(1024);
      expect(encoded, equals(Uint8List.fromList([0x82, 0x04, 0x00])));
    });

    test('encode set theoretical representation of three', () {
      // [ [], [[]], [ [], [[]] ] ]
      final encoded = Rlp.encode([
        <dynamic>[],
        [<dynamic>[]],
        [<dynamic>[], [<dynamic>[]]]
      ]);
      expect(
          encoded,
          equals(Uint8List.fromList(
              [0xc7, 0xc0, 0xc1, 0xc0, 0xc3, 0xc0, 0xc1, 0xc0])));
    });

    test('encode/decode lorem ipsum (long string > 55 bytes)', () {
      const text =
          'Lorem ipsum dolor sit amet, consectetur adipisicing elit';
      final encoded = Rlp.encode(text);
      expect(encoded[0], 0xb8);
      expect(encoded[1], 56);

      final decoded = Rlp.decode(encoded) as Uint8List;
      expect(String.fromCharCodes(decoded), text);
    });

    test('null encodes as empty bytes', () {
      final encoded = Rlp.encode(null);
      expect(encoded, equals(Uint8List.fromList([0x80])));
    });
  });
}
