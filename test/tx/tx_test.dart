import 'dart:typed_data';

import 'package:coin/coin.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(() async {
    await VaultKeeper.initialize();
  });

  // Bitcoin mainnet block 170  -  first person-to-person BTC transfer (2009-01-12).
  // https://blockstream.info/tx/f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16
  const block170RawHex =
      '0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704'
      '000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548'
      'ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d'
      '1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f715'
      '9b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1bade'
      'd5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1e'
      'b68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4'
      'c03f999b8643f656b412a3ac00000000';

  group('Tx deserialization from known transaction', () {
    test('parses block 170 transaction', () {
      final tx = Tx.fromHex(block170RawHex);

      expect(tx.version, 1);
      expect(tx.inputs.length, 1);
      expect(tx.outputs.length, 2);
      expect(tx.locktime, 0);
    });

    test('block 170 tx input has correct outpoint', () {
      final tx = Tx.fromHex(block170RawHex);
      final input = tx.inputs[0];

      expect(input.prevOut.txidHex,
          '0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9');
      expect(input.prevOut.vout, 0);
    });

    test('block 170 tx input has correct scriptSig', () {
      final tx = Tx.fromHex(block170RawHex);
      final input = tx.inputs[0];

      expect(input.scriptSig.length, 72);
      expect(input.sequence, 0xffffffff);
    });

    test('block 170 tx output values', () {
      final tx = Tx.fromHex(block170RawHex);

      expect(tx.outputs[0].value, BigInt.from(1000000000));
      expect(tx.outputs[1].value, BigInt.from(4000000000));
    });

    test('block 170 tx output scriptPubKeys are P2PK (uncompressed)', () {
      final tx = Tx.fromHex(block170RawHex);

      expect(tx.outputs[0].scriptPubKey.length, 67);
      expect(tx.outputs[0].scriptPubKey.last, Op.checkSig);

      expect(tx.outputs[1].scriptPubKey.length, 67);
      expect(tx.outputs[1].scriptPubKey.last, Op.checkSig);
    });

    test('computes correct txid', () {
      final tx = Tx.fromHex(block170RawHex);
      expect(tx.txid,
          'f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16');
    });
  });

  group('Tx serialization round-trip', () {
    test('block 170 tx serializes back to original hex', () {
      final tx = Tx.fromHex(block170RawHex);
      final reserialized = tx.toHex();
      expect(reserialized, block170RawHex);
    });

    test('toBytes round-trips through fromBytes', () {
      final tx = Tx.fromHex(block170RawHex);
      final bytes = tx.toBytes();
      final tx2 = Tx.fromBytes(bytes);

      expect(tx2.version, tx.version);
      expect(tx2.inputs.length, tx.inputs.length);
      expect(tx2.outputs.length, tx.outputs.length);
      expect(tx2.locktime, tx.locktime);
      expect(tx2.txid, tx.txid);
    });
  });

  group('Tx construction', () {
    test('construct minimal transaction', () {
      final prevTxid = Uint8List(32);
      final input = RawInput(
        prevOut: Outpoint(txid: prevTxid, vout: 0),
        scriptSig: Uint8List(0),
      );

      final output = TxOutput(
        value: BigInt.from(50000),
        scriptPubKey: Uint8List.fromList([Op.returnOp]),
      );

      final tx = Tx(
        version: 1,
        inputs: [input],
        outputs: [output],
        locktime: 0,
      );

      expect(tx.version, 1);
      expect(tx.inputs.length, 1);
      expect(tx.outputs.length, 1);
      expect(tx.locktime, 0);
    });

    test('constructed tx can serialize and compute txid', () {
      final prevTxid = Uint8List(32);
      prevTxid[0] = 0xaa;
      final input = RawInput(
        prevOut: Outpoint(txid: prevTxid, vout: 1),
        scriptSig: Uint8List.fromList([0x00]),
        sequence: 0xfffffffe,
      );

      final output = TxOutput(
        value: BigInt.from(100000),
        scriptPubKey: PayToPubKeyHash(
          hexDecode('751e76e8199196d454941c45d1b3a323f1433bd6'),
        ).compiled,
      );

      final tx = Tx(
        version: 2,
        inputs: [input],
        outputs: [output],
        locktime: 500000,
      );

      final bytes = tx.toBytes();
      expect(bytes, isNotEmpty);

      final txid = tx.txid;
      expect(txid.length, 64);

      final tx2 = Tx.fromBytes(bytes);
      expect(tx2.txid, txid);
    });

    test('transaction with multiple inputs and outputs', () {
      final input1 = RawInput(
        prevOut: Outpoint(txid: Uint8List(32), vout: 0),
      );
      final input2 = RawInput(
        prevOut: Outpoint(txid: Uint8List(32), vout: 1),
      );

      final output1 = TxOutput(
        value: BigInt.from(50000),
        scriptPubKey: Uint8List.fromList([Op.returnOp]),
      );
      final output2 = TxOutput(
        value: BigInt.from(40000),
        scriptPubKey: Uint8List.fromList([Op.returnOp]),
      );

      final tx = Tx(
        version: 1,
        inputs: [input1, input2],
        outputs: [output1, output2],
      );

      expect(tx.inputs.length, 2);
      expect(tx.outputs.length, 2);

      final bytes = tx.toBytes();
      final tx2 = Tx.fromBytes(bytes);
      expect(tx2.inputs.length, 2);
      expect(tx2.outputs.length, 2);
      expect(tx2.txid, tx.txid);
    });
  });

  group('TxOutput', () {
    test('fromLocking creates output with correct scriptPubKey', () {
      final locking = PayToPubKeyHash(
        hexDecode('751e76e8199196d454941c45d1b3a323f1433bd6'),
      );
      final output = TxOutput.fromLocking(BigInt.from(100000), locking);

      expect(output.value, BigInt.from(100000));
      expect(output.scriptPubKey, equals(locking.compiled));
      expect(output.locking, isNotNull);
    });

    test('script getter decompiles scriptPubKey', () {
      final locking = PayToWitnessPubKey(
        hexDecode('751e76e8199196d454941c45d1b3a323f1433bd6'),
      );
      final output = TxOutput(
        value: BigInt.from(50000),
        scriptPubKey: locking.compiled,
      );

      final script = output.script;
      expect(script.ops.length, 2);
    });
  });

  group('Outpoint', () {
    test('stores txid and vout', () {
      final txid = hexDecode(
          'c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704');
      final outpoint = Outpoint(txid: txid, vout: 3);

      expect(outpoint.vout, 3);
      expect(outpoint.txid, equals(txid));
    });

    test('txidHex returns reversed hex', () {
      final txid = hexDecode(
          'c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704');
      final outpoint = Outpoint(txid: txid, vout: 0);

      expect(outpoint.txidHex,
          '0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9');
    });

    test('equality and hashCode', () {
      final txid1 = Uint8List(32);
      txid1[0] = 0xab;
      final txid2 = Uint8List.fromList(txid1);

      final a = Outpoint(txid: txid1, vout: 0);
      final b = Outpoint(txid: txid2, vout: 0);
      final c = Outpoint(txid: txid1, vout: 1);

      expect(a, equals(b));
      expect(a.hashCode, b.hashCode);
      expect(a, isNot(equals(c)));
    });

    test('rejects txid of wrong length', () {
      expect(() => Outpoint(txid: Uint8List(31), vout: 0), throwsA(anything));
      expect(() => Outpoint(txid: Uint8List(33), vout: 0), throwsA(anything));
    });

    test('serialization round-trip', () {
      final txid = Uint8List(32);
      for (var i = 0; i < 32; i++) txid[i] = i;
      final original = Outpoint(txid: txid, vout: 42);
      final bytes = original.toBytes();

      final reader = WireReader(bytes);
      final parsed = Outpoint.fromReader(reader);

      expect(parsed.txid, equals(txid));
      expect(parsed.vout, 42);
      expect(reader.atEnd, isTrue);
    });
  });

  group('Tx wireSize', () {
    test('wireSize matches toBytes length', () {
      final tx = Tx.fromHex(block170RawHex);
      expect(tx.wireSize, tx.toBytes().length);
    });

    test('wireSize matches raw hex byte count', () {
      final tx = Tx.fromHex(block170RawHex);
      expect(tx.wireSize, block170RawHex.length ~/ 2);
    });
  });

  group('segwit flag bitfield', () {
    // version=02000000, marker=00, flag=??, 1 input (prevout 32 zero bytes +
    // vout 00000000, empty scriptSig 00, seq ffffffff), 1 output
    // (value 0000000000000000, empty scriptPubKey 00), locktime 00000000.
    // No witness vectors, no MWEB tail.
    String fixture(String flag) =>
        '02000000' // version
        '00' // marker
        '$flag' // flag
        '01' // input count
        '${'00' * 32}' // prevout txid
        '00000000' // prevout vout
        '00' // scriptSig length 0
        'ffffffff' // sequence
        '01' // output count
        '0000000000000000' // value
        '00' // scriptPubKey length 0
        '00000000'; // locktime

    test('flag 0x02 throws', () {
      expect(() => Tx.fromHex(fixture('02')), throwsFormatException);
    });

    test('flag 0x10 throws', () {
      expect(() => Tx.fromHex(fixture('10')), throwsFormatException);
    });

    test('flag 0xff throws', () {
      expect(() => Tx.fromHex(fixture('ff')), throwsFormatException);
    });

    test('flag 0x04 throws', () {
      expect(() => Tx.fromHex(fixture('04')), throwsFormatException);
    });

    test('flag 0x08 (MWEB-only, no trailing blob) parses to locktime', () {
      // With no trailing MWEB bytes, the read path must still consume the
      // input/output count via the sawMarker branch (not hasWitness) and not
      // attempt to read witness vectors.
      final tx = Tx.fromHex(fixture('08'));
      expect(tx.inputs.length, 1);
      expect(tx.outputs.length, 1);
      expect(tx.locktime, 0);
    });

    test('flag 0x01 (witness) still parses', () {
      // flag 0x01 with one empty witness vector (00) before locktime.
      final hex = '02000000' // version
          '00' // marker
          '01' // flag
          '01' // input count
          '${'00' * 32}' // prevout txid
          '00000000' // prevout vout
          '00' // scriptSig length 0
          'ffffffff' // sequence
          '01' // output count
          '0000000000000000' // value
          '00' // scriptPubKey length 0
          '00' // witness vector for input 0: 0 items
          '00000000'; // locktime
      final tx = Tx.fromHex(hex);
      expect(tx.inputs.length, 1);
      expect(tx.outputs.length, 1);
    });
  });

  group('MWEB round-trip', () {
    // LTC mainnet HogEx tx from block 2680000. Flag 0x08 (MWEB only,
    // no witness vectors); mwebBytes is the single byte 0x00; locktime is
    // 00000000. mwebBytes sits between the output and the 4-byte locktime.
    const hogExHex =
        '02000000000801055b9501fc80f092ec6a1fc82a130fbc4126d76aaccc8ff09d47'
        'bcacd439facf0000000000ffffffff0119a0e168b702000022582055b14302a081'
        '2dcfad58dc83b0d2c96d3bf36cc08735cd36987f721b69f6faa10000000000';

    test('parses mwebBytes and round-trips unchanged', () {
      final tx = Tx.fromHex(hogExHex);
      expect(tx.mwebBytes, isNotNull);
      expect(tx.mwebBytes!.length, 1);
      expect(tx.mwebBytes![0], 0x00);
      expect(tx.inputs.length, 1);
      expect(tx.outputs.length, 1);
      expect(tx.locktime, 0);
      expect(tx.toHex(), hogExHex);
    });
  });

  group('RawInput', () {
    test('default sequence is 0xffffffff', () {
      final input = RawInput(
        prevOut: Outpoint(txid: Uint8List(32), vout: 0),
      );
      expect(input.sequence, 0xffffffff);
    });

    test('witness is empty list', () {
      final input = RawInput(
        prevOut: Outpoint(txid: Uint8List(32), vout: 0),
      );
      expect(input.witness, isEmpty);
    });

    test('complete is false', () {
      final input = RawInput(
        prevOut: Outpoint(txid: Uint8List(32), vout: 0),
      );
      expect(input.complete, isFalse);
    });
  });
}
