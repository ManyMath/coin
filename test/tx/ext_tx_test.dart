import 'dart:typed_data';

import 'package:coin/coin.dart';
import 'package:test/test.dart';

// All vectors in this file are hand-crafted for round-trip / structural
// testing; no external reference.
void main() {
  setUpAll(() async {
    await VaultKeeper.initialize();
  });

  RawInput makeInput({int voutByte = 0x00}) {
    final txid = Uint8List(32);
    txid[0] = voutByte;
    return RawInput(
      prevOut: Outpoint(txid: txid, vout: 0),
      scriptSig: Uint8List.fromList([0x00]),
    );
  }

  TxOutput makeOutput({int valueSat = 50000}) => TxOutput(
        value: BigInt.from(valueSat),
        scriptPubKey: Uint8List.fromList([Op.returnOp]),
      );

  group('ExTx without payload', () {
    test('serializes identically to Tx', () {
      final input = makeInput();
      final output = makeOutput();

      final tx = Tx(
        version: 1,
        inputs: [input],
        outputs: [output],
        locktime: 0,
      );

      final exTx = ExTx(
        version: 1,
        inputs: [input],
        outputs: [output],
        locktime: 0,
      );

      expect(exTx.toBytes(), equals(tx.toBytes()));
      expect(exTx.toHex(), equals(tx.toHex()));
    });

    test('txid matches Tx txid when no payload', () {
      final input = makeInput();
      final output = makeOutput();

      final tx = Tx(
        version: 1,
        inputs: [input],
        outputs: [output],
        locktime: 0,
      );

      final exTx = ExTx(
        version: 1,
        inputs: [input],
        outputs: [output],
        locktime: 0,
      );

      expect(exTx.txid, equals(tx.txid));
    });

    test('hasPayload is false when no payload', () {
      final exTx = ExTx(
        version: 1,
        inputs: [makeInput()],
        outputs: [makeOutput()],
      );

      expect(exTx.hasPayload, isFalse);
      expect(exTx.payload, isEmpty);
    });
  });

  group('ExTx with payload', () {
    test('serializes with payload after locktime', () {
      final input = makeInput();
      final output = makeOutput();
      final payload = Uint8List.fromList([0xde, 0xad, 0xbe, 0xef]);

      final exTx = ExTx(
        version: 1,
        inputs: [input],
        outputs: [output],
        locktime: 0,
        payload: payload,
      );

      final exBytes = exTx.toBytes();

      final tx = Tx(
        version: 1,
        inputs: [input],
        outputs: [output],
        locktime: 0,
      );
      final txBytes = tx.toBytes();

      expect(exBytes.length, txBytes.length + 5);
      expect(exBytes.sublist(0, txBytes.length), equals(txBytes));
      expect(exBytes.sublist(txBytes.length),
          equals(Uint8List.fromList([0x04, 0xde, 0xad, 0xbe, 0xef])));
    });

    test('hasPayload is true', () {
      final exTx = ExTx(
        version: 1,
        inputs: [makeInput()],
        outputs: [makeOutput()],
        payload: Uint8List.fromList([0x01]),
      );

      expect(exTx.hasPayload, isTrue);
    });

    test('txid with payload differs from txid without', () {
      final input = makeInput();
      final output = makeOutput();
      final payload = Uint8List.fromList([0xde, 0xad, 0xbe, 0xef]);

      final withPayload = ExTx(
        version: 1,
        inputs: [input],
        outputs: [output],
        payload: payload,
      );

      final withoutPayload = ExTx(
        version: 1,
        inputs: [input],
        outputs: [output],
      );

      expect(withPayload.txid, isNot(equals(withoutPayload.txid)));
      expect(withPayload.txid.length, 64);
      expect(withoutPayload.txid.length, 64);
    });
  });

  group('version field parsing', () {
    test('txVersion returns lower 16 bits', () {
      final exTx = ExTx(
        version: 3 | (9 << 16),
        inputs: [makeInput()],
        outputs: [makeOutput()],
      );

      expect(exTx.txVersion, 3);
    });

    test('txType returns upper 16 bits', () {
      final exTx = ExTx(
        version: 3 | (9 << 16),
        inputs: [makeInput()],
        outputs: [makeOutput()],
      );

      expect(exTx.txType, 9);
    });

    test('txVersion and txType for plain version', () {
      final exTx = ExTx(
        version: 2,
        inputs: [makeInput()],
        outputs: [makeOutput()],
      );

      expect(exTx.txVersion, 2);
      expect(exTx.txType, 0);
    });
  });

  group('copyWith', () {
    test('preserves all fields when no arguments given', () {
      final payload = Uint8List.fromList([0x01, 0x02]);
      final input = makeInput();
      final output = makeOutput();

      final original = ExTx(
        version: 3 | (9 << 16),
        inputs: [input],
        outputs: [output],
        locktime: 42,
        payload: payload,
      );

      final copy = original.copyWith();

      expect(copy.version, original.version);
      expect(copy.inputs.length, original.inputs.length);
      expect(copy.outputs.length, original.outputs.length);
      expect(copy.locktime, original.locktime);
      expect(copy.payload, equals(original.payload));
    });

    test('overrides given fields', () {
      final original = ExTx(
        version: 1,
        inputs: [makeInput()],
        outputs: [makeOutput()],
        locktime: 0,
        payload: Uint8List.fromList([0x01]),
      );

      final newPayload = Uint8List.fromList([0xff, 0xfe]);
      final copy = original.copyWith(
        version: 2,
        locktime: 100,
        payload: newPayload,
      );

      expect(copy.version, 2);
      expect(copy.locktime, 100);
      expect(copy.payload, equals(newPayload));
      expect(copy.inputs.length, 1);
      expect(copy.outputs.length, 1);
    });
  });

  group('addInput / addOutput', () {
    test('addInput returns new ExTx with added input', () {
      final original = ExTx(
        version: 1,
        inputs: [makeInput(voutByte: 0xaa)],
        outputs: [makeOutput()],
        payload: Uint8List.fromList([0x01]),
      );

      final newInput = makeInput(voutByte: 0xbb);
      final updated = original.addInput(newInput);

      expect(updated.inputs.length, 2);
      expect(original.inputs.length, 1);
      expect(updated.payload, equals(original.payload));
    });

    test('addOutput returns new ExTx with added output', () {
      final original = ExTx(
        version: 1,
        inputs: [makeInput()],
        outputs: [makeOutput(valueSat: 50000)],
        payload: Uint8List.fromList([0x02]),
      );

      final newOutput = makeOutput(valueSat: 30000);
      final updated = original.addOutput(newOutput);

      expect(updated.outputs.length, 2);
      expect(original.outputs.length, 1);
      expect(updated.payload, equals(original.payload));
    });
  });

  group('setPayload', () {
    test('returns new ExTx with updated payload', () {
      final original = ExTx(
        version: 1,
        inputs: [makeInput()],
        outputs: [makeOutput()],
      );

      expect(original.hasPayload, isFalse);

      final newPayload = Uint8List.fromList([0xca, 0xfe]);
      final updated = original.setPayload(newPayload);

      expect(updated.hasPayload, isTrue);
      expect(updated.payload, equals(newPayload));
      expect(original.hasPayload, isFalse);
    });
  });

  group('round-trip serialization', () {
    test('construct, serialize, and verify bytes', () {
      final input = makeInput(voutByte: 0xab);
      final output = makeOutput(valueSat: 100000);
      final payload = Uint8List.fromList([0x01, 0x02, 0x03, 0x04, 0x05]);

      final exTx = ExTx(
        version: 3 | (9 << 16),
        inputs: [input],
        outputs: [output],
        locktime: 500000,
        payload: payload,
      );

      final bytes = exTx.toBytes();
      expect(bytes, isNotEmpty);

      final txid = exTx.txid;
      expect(txid.length, 64);
      expect(RegExp(r'^[0-9a-f]{64}$').hasMatch(txid), isTrue);
      expect(exTx.wireSize, bytes.length);
    });

    test('wireSize matches toBytes length without payload', () {
      final exTx = ExTx(
        version: 1,
        inputs: [makeInput()],
        outputs: [makeOutput()],
      );

      expect(exTx.wireSize, exTx.toBytes().length);
    });

    test('wireSize matches toBytes length with payload', () {
      final exTx = ExTx(
        version: 1,
        inputs: [makeInput()],
        outputs: [makeOutput()],
        payload: Uint8List.fromList(List.filled(200, 0xab)),
      );

      expect(exTx.wireSize, exTx.toBytes().length);
    });
  });
}
