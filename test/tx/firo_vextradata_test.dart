import 'dart:typed_data';

import 'package:coin/coin.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(() async {
    await VaultKeeper.initialize();
  });

  // Firo coinbase special tx (nVersion=3, nType=5 = TRANSACTION_COINBASE),
  // mainnet block 1314399. The trailing 71 bytes are vExtraPayload: a
  // 1-byte varint 0x46 (=70) followed by a 70-byte payload appearing
  // immediately after locktime. From coinlib branch
  // fix/firo-vextradata-read (e31d4a5).
  const firoCbTxHex =
      '03000500010000000000000000000000000000000000000000000000000000000000000000'
      'ffffffff25035f0e1404316c186a0400000000162f576f6f6c79506f6f6c79204b522d6669'
      '726f2d312fffffffff04f0829605000000001976a91447d60f128a0b1e9af86cc57e80e972c'
      '259ac773e88aca0acb903000000001976a9149e6778ee1011af76f6f800873032ea8e15ada4'
      'ca88ac60b8131a000000001976a9141d8d54d65458beb3a898c69f5be2dad18034b7c988ace'
      '4dadc01000000001976a9148ce509fc8fc2b152f017f1dad6971b27542585c588ac00000000'
      '4602005f0e140023ae9725e66fa2ba5745467785b0123f67be8c00064a0cb535ee7a9abbaa5'
      '2a86608e4393c17c8841dada21035b0e5d831c9f80af647de5fe8f2b73bc014d510';

  // sha256d of the full 295-byte serialization in natural (little-endian, as
  // transmitted) byte order.
  const expectedSha256dRaw =
      '2ce7ff107898bd459928b949acb60b2d61f8b481cb1efc950bf3579832e84f08';
  // Bitcoin-style displayed txid: the sha256d bytes reversed.
  const expectedTxid =
      '084fe8329857f30b95fc1ecb81b4f8612d0bb6ac49b9289945bd987810ffe72c';

  group('Firo cbTx vExtraPayload', () {
    test('parses as ExTx with the right version/type', () {
      final tx = Tx.fromHex(firoCbTxHex);
      expect(tx, isA<ExTx>());
      final exTx = tx as ExTx;
      expect(exTx.txVersion, 3);
      expect(exTx.txType, 5);
    });

    test('preserves a non-empty payload', () {
      final exTx = Tx.fromHex(firoCbTxHex) as ExTx;
      expect(exTx.hasPayload, isTrue);
      expect(exTx.payload.length, 70);
    });

    test('round-trips unchanged', () {
      final exTx = Tx.fromHex(firoCbTxHex) as ExTx;
      final bytes = exTx.toBytes();
      expect(bytes.length, 295);
      expect(hexEncode(bytes), firoCbTxHex);
    });

    test('produces the correct sha256d and txid', () {
      final exTx = Tx.fromHex(firoCbTxHex) as ExTx;
      final rawHash = sha256d(exTx.toBytes());
      expect(hexEncode(rawHash), expectedSha256dRaw);
      expect(exTx.txid, expectedTxid);
    });
  });

  group('negative: normal (nType=0) tx', () {
    test('v2 tx parses as plain Tx with no payload', () {
      // A minimal v2 tx (version word 0x00000002, high 16 bits zero): one
      // input, one output, no payload.
      final input = RawInput(
        prevOut: Outpoint(txid: Uint8List(32), vout: 0),
        scriptSig: Uint8List.fromList([0x00]),
      );
      final output = TxOutput(
        value: BigInt.from(1000),
        scriptPubKey: Uint8List.fromList([Op.returnOp]),
      );
      final tx = Tx(version: 2, inputs: [input], outputs: [output]);

      final reparsed = Tx.fromBytes(tx.toBytes());
      expect(reparsed, isNot(isA<ExTx>()));
      expect(reparsed.version, 2);
    });

    test('v3 tx with nType=0 parses as plain Tx with no payload', () {
      // Raw version word 0x00000003: nVersion=3, nType=0. High 16 bits are
      // zero, so the special-tx dispatch must not fire.
      final input = RawInput(
        prevOut: Outpoint(txid: Uint8List(32), vout: 0),
        scriptSig: Uint8List.fromList([0x00]),
      );
      final output = TxOutput(
        value: BigInt.from(1000),
        scriptPubKey: Uint8List.fromList([Op.returnOp]),
      );
      final tx = Tx(version: 3, inputs: [input], outputs: [output]);

      final reparsed = Tx.fromBytes(tx.toBytes());
      expect(reparsed, isNot(isA<ExTx>()));
      expect(reparsed.version, 3);
    });
  });

  group('boundary: two cbTxs in one buffer', () {
    test('both parse with correct boundaries', () {
      final one = hexDecode(firoCbTxHex);
      final buffer = Uint8List(one.length * 2)
        ..setAll(0, one)
        ..setAll(one.length, one);

      final reader = WireReader(buffer);

      final first = Tx.fromReader(reader) as ExTx;
      // After the first tx the reader must sit exactly at the boundary.
      expect(reader.offset, one.length);
      expect(first.txid, expectedTxid);
      expect(first.payload.length, 70);

      final second = Tx.fromReader(reader) as ExTx;
      expect(reader.atEnd, isTrue);
      expect(second.txid, expectedTxid);
      expect(second.payload.length, 70);
    });
  });
}
