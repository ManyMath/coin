import 'dart:convert';
import 'dart:typed_data';

import 'package:coin/coin.dart';
import 'package:coin/coin_chains.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(() async {
    await VaultKeeper.initialize();
  });

  group('PsbtCodec encode/decode round-trip', () {
    test('empty global section round-trips', () {
      final sections = <List<PsbtKeyValue>>[
        <PsbtKeyValue>[], // global with no key-value pairs
      ];
      final encoded = PsbtCodec.encode(sections);
      expect(PsbtCodec.hasMagic(encoded), isTrue);

      final decoded = PsbtCodec.decode(encoded);
      expect(decoded.length, 1);
      expect(decoded[0].length, 0);
    });

    test('single key-value pair round-trips', () {
      final key = Uint8List.fromList([0x00]);
      final value = Uint8List.fromList([0x01, 0x02, 0x03]);
      final sections = <List<PsbtKeyValue>>[
        [PsbtKeyValue(key: key, value: value)],
      ];

      final encoded = PsbtCodec.encode(sections);
      final decoded = PsbtCodec.decode(encoded);

      expect(decoded.length, 1);
      expect(decoded[0].length, 1);
      expect(decoded[0][0].key, equals(key));
      expect(decoded[0][0].value, equals(value));
    });

    test('multiple sections round-trip', () {
      final sections = <List<PsbtKeyValue>>[
        [
          PsbtKeyValue(
            key: Uint8List.fromList([PsbtGlobal.unsignedTx.keyType]),
            value: Uint8List.fromList([0xaa, 0xbb]),
          ),
        ],
        [
          PsbtKeyValue(
            key: Uint8List.fromList([PsbtInputEntry.witnessUtxo.keyType]),
            value: Uint8List.fromList([0xcc, 0xdd]),
          ),
        ],
        <PsbtKeyValue>[],
      ];

      final encoded = PsbtCodec.encode(sections);
      final decoded = PsbtCodec.decode(encoded);

      expect(decoded.length, 3);
      expect(decoded[0].length, 1);
      expect(decoded[0][0].key[0], PsbtGlobal.unsignedTx.keyType);
      expect(decoded[1].length, 1);
      expect(decoded[1][0].key[0], PsbtInputEntry.witnessUtxo.keyType);
      expect(decoded[2].length, 0);
    });

    test('large value round-trips', () {
      final key = Uint8List.fromList([0x42]);
      final value = Uint8List.fromList(List.filled(300, 0xfe));
      final sections = <List<PsbtKeyValue>>[
        [PsbtKeyValue(key: key, value: value)],
      ];

      final encoded = PsbtCodec.encode(sections);
      final decoded = PsbtCodec.decode(encoded);

      expect(decoded[0][0].key, equals(key));
      expect(decoded[0][0].value, equals(value));
      expect(decoded[0][0].value.length, 300);
    });

    test('multiple key-value pairs in one section', () {
      final sections = <List<PsbtKeyValue>>[
        [
          PsbtKeyValue(
            key: Uint8List.fromList([0x01]),
            value: Uint8List.fromList([0x10]),
          ),
          PsbtKeyValue(
            key: Uint8List.fromList([0x02]),
            value: Uint8List.fromList([0x20, 0x21]),
          ),
          PsbtKeyValue(
            key: Uint8List.fromList([0x03]),
            value: Uint8List.fromList([0x30, 0x31, 0x32]),
          ),
        ],
      ];

      final encoded = PsbtCodec.encode(sections);
      final decoded = PsbtCodec.decode(encoded);

      expect(decoded[0].length, 3);
      expect(decoded[0][0].key, equals(Uint8List.fromList([0x01])));
      expect(decoded[0][1].key, equals(Uint8List.fromList([0x02])));
      expect(decoded[0][2].key, equals(Uint8List.fromList([0x03])));
      expect(decoded[0][2].value, equals(Uint8List.fromList([0x30, 0x31, 0x32])));
    });
  });

  // Magic bytes 0x70736274ff ("psbt\xff") and key-type constants per BIP-174:
  // https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
  // (V2 fields from BIP-370: https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki)
  group('PsbtCodec magic bytes', () {
    test('hasMagic detects valid PSBT header', () {
      final valid = Uint8List.fromList([0x70, 0x73, 0x62, 0x74, 0xff, 0x00]);
      expect(PsbtCodec.hasMagic(valid), isTrue);
    });

    test('hasMagic rejects invalid header', () {
      final invalid = Uint8List.fromList([0x00, 0x00, 0x00, 0x00, 0x00]);
      expect(PsbtCodec.hasMagic(invalid), isFalse);
    });

    test('hasMagic rejects short buffer', () {
      final short = Uint8List.fromList([0x70, 0x73]);
      expect(PsbtCodec.hasMagic(short), isFalse);
    });

    test('hasMagic rejects empty buffer', () {
      expect(PsbtCodec.hasMagic(Uint8List(0)), isFalse);
    });

    test('decode rejects non-PSBT data', () {
      final garbage = Uint8List.fromList([0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);
      expect(() => PsbtCodec.decode(garbage), throwsFormatException);
    });

    test('encoded output starts with magic bytes', () {
      final sections = <List<PsbtKeyValue>>[<PsbtKeyValue>[]];
      final encoded = PsbtCodec.encode(sections);
      expect(encoded[0], 0x70);
      expect(encoded[1], 0x73);
      expect(encoded[2], 0x62);
      expect(encoded[3], 0x74);
      expect(encoded[4], 0xff);
    });
  });

  group('PartialTxV1 construction', () {
    test('basic PSBT with unsigned tx round-trips', () {
      final prevTxid = Uint8List(32);
      prevTxid[0] = 0x01;

      final tx = Tx(
        version: 2,
        inputs: [
          RawInput(
            prevOut: Outpoint(txid: prevTxid, vout: 0),
            sequence: 0xffffffff,
          ),
        ],
        outputs: [
          TxOutput(
            value: BigInt.from(50000),
            scriptPubKey: Uint8List.fromList([
              0x00, 0x14, // OP_0 PUSH20
              ...List.filled(20, 0xab),
            ]),
          ),
        ],
        locktime: 0,
      );

      final psbt = PartialTxV1(unsignedTx: tx);
      expect(psbt.version, 0);
      expect(psbt.unsignedTx, isNotNull);
      expect(psbt.inputCount, 1);
      expect(psbt.outputCount, 1);

      final bytes = psbt.toBytes();
      expect(PsbtCodec.hasMagic(bytes), isTrue);

      final parsed = PartialTx.fromBytes(bytes);
      expect(parsed.version, 0);
      expect(parsed.inputCount, 1);
      expect(parsed.outputCount, 1);

      final restoredTx = parsed.unsignedTx!;
      expect(restoredTx.version, 2);
      expect(restoredTx.locktime, 0);
      expect(restoredTx.inputs[0].prevOut.vout, 0);
      expect(restoredTx.outputs[0].value, equals(BigInt.from(50000)));
    });

    test('toBase64 and fromBase64 round-trip', () {
      final prevTxid = Uint8List(32);
      prevTxid[31] = 0xff;

      final tx = Tx(
        version: 1,
        inputs: [
          RawInput(
            prevOut: Outpoint(txid: prevTxid, vout: 1),
            sequence: 0xfffffffe,
          ),
        ],
        outputs: [
          TxOutput(
            value: BigInt.from(100000),
            scriptPubKey: Uint8List.fromList([
              0x76, 0xa9, 0x14, // OP_DUP OP_HASH160 PUSH20
              ...List.filled(20, 0xcc),
              0x88, 0xac, // OP_EQUALVERIFY OP_CHECKSIG
            ]),
          ),
        ],
        locktime: 0,
      );

      final psbt = PartialTxV1(unsignedTx: tx);
      final b64 = psbt.toBase64();
      expect(b64.isNotEmpty, isTrue);

      expect(() => base64Decode(b64), returnsNormally);

      final restored = PartialTx.fromBase64(b64);
      expect(restored.version, 0);
      expect(restored.inputCount, 1);
      expect(restored.outputCount, 1);

      expect(restored.unsignedTx!.outputs[0].value,
          equals(BigInt.from(100000)));
    });

    test('PSBT with two inputs and two outputs', () {
      final txid0 = Uint8List(32)..fillRange(0, 32, 0xaa);
      final txid1 = Uint8List(32)..fillRange(0, 32, 0xbb);

      final tx = Tx(
        version: 2,
        inputs: [
          RawInput(
            prevOut: Outpoint(txid: txid0, vout: 0),
            sequence: 0xffffffff,
          ),
          RawInput(
            prevOut: Outpoint(txid: txid1, vout: 1),
            sequence: 0xffffffff,
          ),
        ],
        outputs: [
          TxOutput(
            value: BigInt.from(149990000),
            scriptPubKey: Uint8List.fromList([
              0x00, 0x14, ...List.filled(20, 0xd8),
            ]),
          ),
          TxOutput(
            value: BigInt.from(100000000),
            scriptPubKey: Uint8List.fromList([
              0x00, 0x14, ...List.filled(20, 0xae),
            ]),
          ),
        ],
        locktime: 0,
      );

      final psbt = PartialTxV1(unsignedTx: tx);
      expect(psbt.inputCount, 2);
      expect(psbt.outputCount, 2);

      final bytes = psbt.toBytes();
      final restored = PartialTx.fromBytes(bytes);
      expect(restored.inputCount, 2);
      expect(restored.outputCount, 2);
      expect(restored.unsignedTx!.outputs[0].value,
          equals(BigInt.from(149990000)));
      expect(restored.unsignedTx!.outputs[1].value,
          equals(BigInt.from(100000000)));
    });

    test('parser requires exactly one map per input and output', () {
      final tx = Tx(
        inputs: [
          RawInput(
            prevOut: Outpoint(txid: Uint8List(32)..[0] = 1, vout: 0),
          ),
        ],
        outputs: [
          TxOutput(value: BigInt.one, scriptPubKey: Uint8List(0)),
        ],
      );
      final sections = PsbtCodec.decode(PartialTxV1(unsignedTx: tx).toBytes());
      while (sections.length < 3) {
        sections.add(<PsbtKeyValue>[]);
      }

      final missing = [for (final section in sections.take(2)) section];
      final extra = [for (final section in sections) section, <PsbtKeyValue>[]];
      for (final malformed in [missing, extra]) {
        expect(
          () => PartialTxV1.fromBytes(PsbtCodec.encode(malformed)),
          throwsA(isA<FormatException>().having(
            (error) => error.message,
            'message',
            contains('map count'),
          )),
        );
      }
    });
  });

  group('PartialTxV1 addInput and addOutput', () {
    test('adding inputs increments count', () {
      final psbt = PartialTxV1();
      expect(psbt.inputCount, 0);

      final prevTxid = Uint8List(32)..fillRange(0, 32, 0x11);
      psbt.addInput(
        outpoint: Outpoint(txid: prevTxid, vout: 0),
      );
      expect(psbt.inputCount, 1);

      final prevTxid2 = Uint8List(32)..fillRange(0, 32, 0x22);
      psbt.addInput(
        outpoint: Outpoint(txid: prevTxid2, vout: 1),
      );
      expect(psbt.inputCount, 2);
    });

    test('adding outputs increments count', () {
      final psbt = PartialTxV1();
      expect(psbt.outputCount, 0);

      psbt.addOutput(
        scriptPubKey: Uint8List.fromList([0x00, 0x14, ...List.filled(20, 0xaa)]),
        value: BigInt.from(50000),
      );
      expect(psbt.outputCount, 1);
    });

    test('constructed PSBT with addInput/addOutput serializes and deserializes', () {
      final psbt = PartialTxV1();

      final txid1 = Uint8List(32)..fillRange(0, 32, 0x01);
      psbt.addInput(outpoint: Outpoint(txid: txid1, vout: 0));

      final txid2 = Uint8List(32)..fillRange(0, 32, 0x02);
      psbt.addInput(outpoint: Outpoint(txid: txid2, vout: 1));

      psbt.addOutput(
        scriptPubKey: Uint8List.fromList([0x00, 0x14, ...List.filled(20, 0xbb)]),
        value: BigInt.from(100000),
      );
      psbt.addOutput(
        scriptPubKey: Uint8List.fromList([0x00, 0x14, ...List.filled(20, 0xcc)]),
        value: BigInt.from(200000),
      );

      final bytes = psbt.toBytes();
      final restored = PartialTx.fromBytes(bytes);
      expect(restored.inputCount, 2);
      expect(restored.outputCount, 2);
    });

    test('addInput with custom sequence', () {
      final psbt = PartialTxV1();
      final txid = Uint8List(32)..fillRange(0, 32, 0x55);
      psbt.addInput(
        outpoint: Outpoint(txid: txid, vout: 3),
        sequence: 0xfffffffe,
      );

      expect(psbt.inputCount, 1);
      final tx = psbt.unsignedTx!;
      expect(tx.inputs[0].sequence, 0xfffffffe);
      expect(tx.inputs[0].prevOut.vout, 3);
    });
  });

  group('PartialTx.fromBytes error handling', () {
    test('rejects data without PSBT magic', () {
      final garbage = Uint8List.fromList([0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);
      expect(() => PartialTx.fromBytes(garbage), throwsFormatException);
    });

    test('rejects invalid base64 content (no magic)', () {
      final notPsbt = base64Encode([0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);
      expect(() => PartialTx.fromBase64(notPsbt), throwsFormatException);
    });
  });

  group('PsbtGlobal and PsbtInputEntry key types', () {
    test('global key types have expected values', () {
      expect(PsbtGlobal.unsignedTx.keyType, 0x00);
      expect(PsbtGlobal.xpub.keyType, 0x01);
      expect(PsbtGlobal.txVersion.keyType, 0x02);
      expect(PsbtGlobal.fallbackLocktime.keyType, 0x03);
      expect(PsbtGlobal.inputCount.keyType, 0x04);
      expect(PsbtGlobal.outputCount.keyType, 0x05);
      expect(PsbtGlobal.txModifiable.keyType, 0x06);
      expect(PsbtGlobal.version.keyType, 0xfb);
      expect(PsbtGlobal.proprietary.keyType, 0xfc);
    });

    test('input entry key types have expected values', () {
      expect(PsbtInputEntry.nonWitnessUtxo.keyType, 0x00);
      expect(PsbtInputEntry.witnessUtxo.keyType, 0x01);
      expect(PsbtInputEntry.partialSig.keyType, 0x02);
      expect(PsbtInputEntry.sighashType.keyType, 0x03);
      expect(PsbtInputEntry.redeemScript.keyType, 0x04);
      expect(PsbtInputEntry.witnessScript.keyType, 0x05);
      expect(PsbtInputEntry.bip32Derivation.keyType, 0x06);
      expect(PsbtInputEntry.finalScriptSig.keyType, 0x07);
      expect(PsbtInputEntry.finalScriptWitness.keyType, 0x08);
      expect(PsbtInputEntry.tapKeySig.keyType, 0x13);
      expect(PsbtInputEntry.tapInternalKey.keyType, 0x17);
    });

    test('output entry key types have expected values', () {
      expect(PsbtOutputEntry.redeemScript.keyType, 0x00);
      expect(PsbtOutputEntry.witnessScript.keyType, 0x01);
      expect(PsbtOutputEntry.bip32Derivation.keyType, 0x02);
      expect(PsbtOutputEntry.amount.keyType, 0x03);
      expect(PsbtOutputEntry.script.keyType, 0x04);
      expect(PsbtOutputEntry.tapInternalKey.keyType, 0x05);
      expect(PsbtOutputEntry.tapTree.keyType, 0x06);
      expect(PsbtOutputEntry.tapBip32Derivation.keyType, 0x07);
      expect(PsbtOutputEntry.proprietary.keyType, 0xfc);
    });
  });

  group('PSBT global unsigned tx section', () {
    test('global section contains unsigned tx key type 0x00', () {
      final txid = Uint8List(32)..fillRange(0, 32, 0x42);
      final tx = Tx(
        version: 2,
        inputs: [
          RawInput(
            prevOut: Outpoint(txid: txid, vout: 0),
            sequence: 0xffffffff,
          ),
        ],
        outputs: [
          TxOutput(
            value: BigInt.from(10000),
            scriptPubKey: Uint8List.fromList([0x00, 0x14, ...List.filled(20, 0xee)]),
          ),
        ],
        locktime: 0,
      );

      final psbt = PartialTxV1(unsignedTx: tx);
      final bytes = psbt.toBytes();
      final sections = PsbtCodec.decode(bytes);

      expect(sections.isNotEmpty, isTrue);
      final global = sections[0];
      final hasTxEntry = global.any(
        (kv) => kv.key.isNotEmpty && kv.key[0] == PsbtGlobal.unsignedTx.keyType,
      );
      expect(hasTxEntry, isTrue);

      final txEntry = global.firstWhere(
        (kv) => kv.key[0] == PsbtGlobal.unsignedTx.keyType,
      );
      final parsedTx = Tx.fromBytes(txEntry.value);
      expect(parsedTx.version, 2);
      expect(parsedTx.inputs.length, 1);
      expect(parsedTx.outputs.length, 1);
      expect(parsedTx.outputs[0].value, equals(BigInt.from(10000)));
    });
  });

  group('PartialTxV1 singleton key key-data validation', () {
    Tx buildUnsignedTx() => Tx(
          version: 2,
          inputs: [
            RawInput(
              prevOut: Outpoint(txid: Uint8List(32)..[0] = 0x42, vout: 0),
              sequence: 0xffffffff,
            ),
          ],
          outputs: [
            TxOutput(
              value: BigInt.from(1000),
              scriptPubKey:
                  Uint8List.fromList([0x00, 0x14, ...List.filled(20, 0x11)]),
            ),
          ],
          locktime: 0,
        );

    PsbtKeyValue kv(List<int> key, [List<int> value = const [0x00]]) =>
        PsbtKeyValue(
          key: Uint8List.fromList(key),
          value: Uint8List.fromList(value),
        );

    Uint8List buildPsbt({
      List<PsbtKeyValue>? globalKvs,
      List<PsbtKeyValue> inputKvs = const [],
      List<PsbtKeyValue> outputKvs = const [],
    }) {
      final global = globalKvs ??
          [
            PsbtKeyValue(
              key: Uint8List.fromList([PsbtGlobal.unsignedTx.keyType]),
              value: buildUnsignedTx().toBytes(),
            ),
          ];
      return PsbtCodec.encode([global, inputKvs, outputKvs]);
    }

    test('rejects unsigned tx key with trailing key data', () {
      final bytes = buildPsbt(
        globalKvs: [kv([0x00, 0x99], buildUnsignedTx().toBytes())],
      );
      expect(() => PartialTxV1.fromBytes(bytes), throwsFormatException);
    });

    test('rejects aliased unsigned tx key next to the valid one', () {
      final txBytes = buildUnsignedTx().toBytes();
      final bytes = buildPsbt(
        globalKvs: [kv([0x00], txBytes), kv([0x00, 0x99], txBytes)],
      );
      expect(() => PartialTxV1.fromBytes(bytes), throwsFormatException);
    });

    test('rejects key data on keydata-less input key types', () {
      for (final type in [0x00, 0x01, 0x03, 0x04, 0x05, 0x07, 0x08]) {
        final bytes = buildPsbt(inputKvs: [kv([type, 0x99])]);
        expect(
          () => PartialTxV1.fromBytes(bytes),
          throwsFormatException,
          reason: 'input key type 0x${type.toRadixString(16)}',
        );
      }
    });

    test('rejects key data on keydata-less output key types', () {
      for (final type in [0x00, 0x01]) {
        final bytes = buildPsbt(outputKvs: [kv([type, 0x99])]);
        expect(
          () => PartialTxV1.fromBytes(bytes),
          throwsFormatException,
          reason: 'output key type 0x${type.toRadixString(16)}',
        );
      }
    });

    test('accepts key data on keydata-bearing and unknown key types', () {
      final bytes = buildPsbt(
        inputKvs: [
          kv([0x02, ...List.filled(33, 0x02)], [0x30, 0x44]), // partial sig
          kv([0x06, ...List.filled(33, 0x03)], List.filled(4, 0x00)), // bip32
          kv([0xfc, 0xaa], [0x01]), // proprietary
          kv([0xee, 0xbb], [0x02]), // unknown type
        ],
        outputKvs: [
          kv([0x02, ...List.filled(33, 0x02)], List.filled(4, 0x00)), // bip32
          kv([0xfc, 0xcc], [0x03]), // proprietary
        ],
      );
      final parsed = PartialTxV1.fromBytes(bytes);
      expect(parsed.inputCount, 1);
      expect(parsed.outputCount, 1);
    });
  });
}
