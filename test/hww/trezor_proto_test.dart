import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:coin/coin_hww.dart';

void main() {
  group('buildInitialize / buildButtonAck', () {
    test('buildInitialize returns zero bytes', () {
      expect(buildInitialize(), equals(Uint8List(0)));
    });
    test('buildButtonAck returns zero bytes', () {
      expect(buildButtonAck(), equals(Uint8List(0)));
    });
  });

  group('buildGetPublicKey', () {
    test('encodes m/84\'/0\'/0\' as unpacked repeated uint32', () {
      final expected = Uint8List.fromList([
        0x08, 0xD4, 0x80, 0x80, 0x80, 0x08, // 84|0x80000000
        0x08, 0x80, 0x80, 0x80, 0x80, 0x08, // 0x80000000
        0x08, 0x80, 0x80, 0x80, 0x80, 0x08, // 0x80000000
      ]);
      final result = buildGetPublicKey(
        addressN: [84 | 0x80000000, 0x80000000, 0x80000000],
      );
      expect(result, equals(expected));
    });
    test('omits field 3 when showDisplay is false', () {
      final result = buildGetPublicKey(addressN: [0]);
      expect(result, equals(Uint8List.fromList([0x08, 0x00])));
      expect(result.indexOf(0x18), equals(-1));
    });
    test('omits field 4 (script_type) always', () {
      final result = buildGetPublicKey(
        addressN: [84 | 0x80000000, 0x80000000, 0x80000000],
      );
      expect(result.indexOf(0x20), equals(-1));
      expect(result.indexOf(0x22), equals(-1));
    });
  });

  group('parseFeatures', () {
    test('reads field 10 for label and field 21 for model', () {
      final bytes = Uint8List.fromList([
        0x52, 0x04, 0x54, 0x65, 0x73, 0x74, // label='Test'
        0xAA, 0x01, 0x01, 0x31, // model='1'
      ]);
      final features = parseFeatures(bytes);
      expect(features.label, equals('Test'));
      expect(features.model, equals('1'));
    });

    test('reads field 12 for initialized (true)', () {
      final w = ProtoWriter();
      w.writeBool(12, true);
      w.writeString(10, 'Label');
      final features = parseFeatures(w.toBytes());
      expect(features.initialized, isTrue);
      expect(features.label, equals('Label'));
    });

    test('reads field 12 for initialized (false)', () {
      final w = ProtoWriter();
      w.writeBool(12, false);
      final features = parseFeatures(w.toBytes());
      expect(features.initialized, isFalse);
    });
  });

  group('parsePublicKey', () {
    test('reads field 2 for xpub', () {
      final bytes = Uint8List.fromList([
        0x12, 0x09,
        0x78, 0x70, 0x75, 0x62, 0x36, 0x74, 0x65, 0x73, 0x74, // 'xpub6test'
      ]);
      final pk = parsePublicKey(bytes);
      expect(pk.xpub, equals('xpub6test'));
    });
    test('throws StateError when field 2 absent', () {
      expect(() => parsePublicKey(Uint8List(0)), throwsStateError);
    });
  });

  group('parseFailure', () {
    test('reads code and message', () {
      final bytes = Uint8List.fromList([
        0x08, 0x03,
        0x12, 0x0B,
        0x50, 0x49, 0x4E, 0x20, 0x69, 0x6E, 0x76, 0x61, 0x6C, 0x69, 0x64,
      ]);
      final failure = parseFailure(bytes);
      expect(failure.code, equals(3));
      expect(failure.message, equals('PIN invalid'));
    });
  });

  group('buildPinMatrixAck', () {
    test('encodes PIN as field 1 string', () {
      expect(
        buildPinMatrixAck('159'),
        equals(Uint8List.fromList([0x0A, 0x03, 0x31, 0x35, 0x39])),
      );
    });
  });

  group('buildPassphraseAck', () {
    test('encodes empty passphrase as field 1 empty string', () {
      expect(
        buildPassphraseAck(),
        equals(Uint8List.fromList([0x0A, 0x00])),
      );
    });
  });

  group('round-trip', () {
    test('ProtoWriter -> parseFeatures preserves label and model', () {
      final w = ProtoWriter();
      w.writeString(10, 'MyLabel');
      w.writeString(21, 'T1');
      final features = parseFeatures(w.toBytes());
      expect(features.label, equals('MyLabel'));
      expect(features.model, equals('T1'));
    });

    test('ProtoWriter -> parseFeatures preserves initialized', () {
      final w = ProtoWriter();
      w.writeString(10, 'Label');
      w.writeString(21, '1');
      w.writeBool(12, true);
      final features = parseFeatures(w.toBytes());
      expect(features.initialized, isTrue);
    });
  });
}
