import 'dart:typed_data';

import 'package:coin/coin.dart';
import 'package:test/test.dart';

// Differential / round-trip tests for the Firo special-tx legacy sighash.
//
// Firo Core (CTransactionSignatureSerializer::Serialize) appends
// vExtraPayload to the legacy sighash preimage when
// nVersion == 3 && nType != TRANSACTION_NORMAL. The corresponding gate in
// LegacySigHasher is (tx is ExTx && (version >> 16) != 0 && hasPayload).
//
// Coverage:
//  - the payload changes the sighash (presence and content),
//  - a normal (nType=0) tx ignores any payload,
//  - the cbTx still round-trips.
//
// Signature-verification tests for ProRegTx (nType=1) and ProUpServTx
// (nType=2) live in firo_special_tx_vectors_test.dart.
void main() {
  setUpAll(() async {
    await VaultKeeper.initialize();
  });

  // Firo mainnet block-1314399 coinbase special tx (nVersion=3,
  // nType=5), 295 bytes, 70-byte vExtraPayload.
  const firoCbTxHex =
      '03000500010000000000000000000000000000000000000000000000000000000000000000'
      'ffffffff25035f0e1404316c186a0400000000162f576f6f6c79506f6f6c79204b522d6669'
      '726f2d312fffffffff04f0829605000000001976a91447d60f128a0b1e9af86cc57e80e972c'
      '259ac773e88aca0acb903000000001976a9149e6778ee1011af76f6f800873032ea8e15ada4'
      'ca88ac60b8131a000000001976a9141d8d54d65458beb3a898c69f5be2dad18034b7c988ace'
      '4dadc01000000001976a9148ce509fc8fc2b152f017f1dad6971b27542585c588ac00000000'
      '4602005f0e140023ae9725e66fa2ba5745467785b0123f67be8c00064a0cb535ee7a9abbaa5'
      '2a86608e4393c17c8841dada21035b0e5d831c9f80af647de5fe8f2b73bc014d510';

  // An arbitrary P2PKH scriptCode used as the spent script for the sighash.
  final prevScript = Uint8List.fromList([
    0x76, 0xa9, 0x14, // OP_DUP OP_HASH160 push20
    ...List<int>.filled(20, 0x11),
    0x88, 0xac, // OP_EQUALVERIFY OP_CHECKSIG
  ]);

  final hasher = LegacySigHasher();

  group('Firo cbTx legacy sighash', () {
    test('round-trips unchanged', () {
      final exTx = Tx.fromHex(firoCbTxHex) as ExTx;
      expect(hexEncode(exTx.toBytes()), firoCbTxHex);
      expect(exTx.hasPayload, isTrue);
    });

    test('payload is included in the sighash preimage', () {
      final exTx = Tx.fromHex(firoCbTxHex) as ExTx;

      // Same special tx but with the payload removed: the gate must no longer
      // append anything, so the digest must differ.
      final emptyPayload = exTx.setPayload(Uint8List(0));

      final withPayload =
          hasher.hash(exTx, 0, SigHashType.all, prevScript: prevScript);
      final withoutPayload =
          hasher.hash(emptyPayload, 0, SigHashType.all, prevScript: prevScript);

      expect(withPayload, isNot(equals(withoutPayload)));
    });

    test('distinct payloads produce distinct sighashes', () {
      final exTx = Tx.fromHex(firoCbTxHex) as ExTx;
      final mutated =
          exTx.setPayload(Uint8List.fromList([0xff, 0xff, 0xff, 0xff]));

      final a = hasher.hash(exTx, 0, SigHashType.all, prevScript: prevScript);
      final b =
          hasher.hash(mutated, 0, SigHashType.all, prevScript: prevScript);

      expect(a, isNot(equals(b)));
    });

    test('special-tx sighash differs from the equivalent plain Tx sighash',
        () {
      final exTx = Tx.fromHex(firoCbTxHex) as ExTx;

      // A plain Tx with identical version word, inputs, outputs, and locktime
      // but no payload concept: the hasher must not append a payload.
      final plain = Tx(
        version: exTx.version,
        inputs: exTx.inputs,
        outputs: exTx.outputs,
        locktime: exTx.locktime,
      );

      final exHash =
          hasher.hash(exTx, 0, SigHashType.all, prevScript: prevScript);
      final plainHash =
          hasher.hash(plain, 0, SigHashType.all, prevScript: prevScript);

      // The plain Tx is not an ExTx, so the gate does not fire and the
      // payload bytes are absent from its preimage.
      expect(exHash, isNot(equals(plainHash)));
    });
  });

  group('normal (nType=0) tx ignores payload', () {
    test('an nType=0 ExTx with a payload hashes like one without', () {
      // Raw version word 0x00000003: nVersion=3, nType=0. High 16 bits are
      // zero, so the payload-append gate must not fire even if a payload is
      // somehow present on the ExTx.
      final input = RawInput(
        prevOut: Outpoint(txid: Uint8List(32), vout: 0),
        scriptSig: Uint8List(0),
      );
      final output = TxOutput(
        value: BigInt.from(1000),
        scriptPubKey: Uint8List.fromList([Op.returnOp]),
      );

      final withPayload = ExTx(
        version: 3,
        inputs: [input],
        outputs: [output],
        payload: Uint8List.fromList([0x42, 0x42, 0x42]),
      );
      final withoutPayload = ExTx(
        version: 3,
        inputs: [input],
        outputs: [output],
      );

      final a = hasher.hash(withPayload, 0, SigHashType.all,
          prevScript: prevScript);
      final b = hasher.hash(withoutPayload, 0, SigHashType.all,
          prevScript: prevScript);

      expect(a, equals(b));
    });
  });
}
