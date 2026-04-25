import 'dart:typed_data';

import 'package:coin/coin_chains.dart';
import 'package:test/test.dart';

// BIP-69 deterministic lexicographic input/output ordering.
// Source: https://github.com/bitcoin/bips/blob/master/bip-0069.mediawiki
// Both example transactions from the spec are used below.

// The assembler sorts inputs (lexicographic on txid, then vout)
// and outputs (ascending value, then scriptPubKey) when TxOrdering.bip69 is set.
// This test verifies that ordering against the two canonical BIP-69 examples.

Uint8List _txid(String hex) => hexDecode(hex);
Uint8List _spk(String hex) => hexDecode(hex);

// Dummy signer returns a fixed DER signature - the ordering test only
// cares about input/output ordering, not signature validity.
Uint8List _dummySigner(Tx tx, int i, Uint8List digest, SigHashType ht) {
  // Minimal DER: 30 06 02 01 01 02 01 01 (valid enough for the assembler)
  return Uint8List.fromList([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]);
}

final _chain = BitcoinParams.bitcoin;
final _amount = BigInt.from(100000000);

AssemblerInput _inp(String txidHex, int vout) {
  return AssemblerInput(
    outpoint: Outpoint(txid: _txid(txidHex), vout: vout),
    value: _amount,
    scriptPubKey: _spk('76a9145be32612930b8323add2212a4ec03c1562084f8488ac'),
    type: AssemblerInputType.p2pkh,
    publicKey: hexDecode(
        '02f8b6371bae0a3f1c7a0f48f4e9e0bdebe41f40f91d0b0a4c7a3c96a9b6a7d03'),
  );
}

void main() {
  setUpAll(() async {
    await VaultKeeper.initialize();
  });

  // -------------------------------------------------------------------------
  // BIP-69 Transaction 2 (simpler: 2 inputs with SAME txid, different vout).
  // Txid: 28204cad1d7fc1d199e8ef4fa22f182de6258a3eaafe1bbe56ebdcacd3069a5f
  //
  // Expected input order (sorted by txid then vout):
  //   [0] txid=35288d...5c65d6055, vout=0  (vout=0 before vout=1)
  //   [1] txid=35288d...5c65d6055, vout=1
  //
  // Expected output order (sorted by value ascending, then scriptPubKey):
  //   [0] 100000000 sat, scriptPubKey=41046a07...
  //   [1] 2400000000 sat, scriptPubKey=41044a65...
  // -------------------------------------------------------------------------
  group('BIP-69 ordering - transaction 2 (2 inputs, same txid)', () {
    const tx2Txid =
        '35288d269cee1941eaebb2ea85e32b42cdb2b04284a56d8b14dcc3f5c65d6055';
    final tx2out0Spk = _spk(
        '41046a0765b5865641ce08dd39690aade26dfbf5511430ca428a3089261361cef170'
        'e3929a68aee3d8d4848b0c5111b0a37b82b86ad559fd2a745b44d8e8d9dfdc0cac');
    final tx2out1Spk = _spk(
        '41044a656f065871a353f216ca26cef8dde2f03e8c16202d2e8ad769f02032cb86a5'
        'eb5e56842e92e19141d60a01928f8dd2c875a390f67c1f6c94cfc617c0ea45afac');

    test('inputs with same txid are sorted by vout (ascending)', () {
      // Provide inputs in REVERSED vout order (vout=1 first).
      final asm = TxAssembler(
        chainParams: _chain,
        inputs: [
          _inp(tx2Txid, 1), // wrong order
          _inp(tx2Txid, 0),
        ],
        outputs: [
          TxOutput(value: BigInt.from(100000000), scriptPubKey: tx2out0Spk),
          TxOutput(value: BigInt.from(2400000000), scriptPubKey: tx2out1Spk),
        ],
        ordering: TxOrdering.bip69,
      );
      final tx = asm.build(_dummySigner);
      expect(tx.inputs[0].prevOut.vout, 0, reason: 'vout=0 must come first');
      expect(tx.inputs[1].prevOut.vout, 1, reason: 'vout=1 must come second');
    });

    test('outputs sorted by value ascending', () {
      final asm = TxAssembler(
        chainParams: _chain,
        inputs: [
          _inp(tx2Txid, 0),
          _inp(tx2Txid, 1),
        ],
        outputs: [
          // Provide in reversed order (higher value first).
          TxOutput(value: BigInt.from(2400000000), scriptPubKey: tx2out1Spk),
          TxOutput(value: BigInt.from(100000000), scriptPubKey: tx2out0Spk),
        ],
        ordering: TxOrdering.bip69,
      );
      final tx = asm.build(_dummySigner);
      expect(tx.outputs[0].value, BigInt.from(100000000),
          reason: 'smaller value must come first');
      expect(tx.outputs[1].value, BigInt.from(2400000000),
          reason: 'larger value must come second');
    });
  });

  // -------------------------------------------------------------------------
  // BIP-69 Transaction 1 (17 inputs, lexicographic txid ordering).
  // Txid: 0a6a357e2f7796444e02638749d9611c008b253fb55f5dc88b739b230ed0c4c3
  //
  // Source: the 17 inputs are listed in the BIP in the CORRECT (sorted) order.
  // We provide them shuffled and check that the first few come out right.
  // -------------------------------------------------------------------------
  group('BIP-69 ordering - transaction 1 (17 inputs, lexicographic txid)', () {
    // First 3 txids in BIP-69 sorted order:
    const sorted0Txid =
        '0e53ec5dfb2cb8a71fec32dc9a634a35b7e24799295ddd5278217822e0b31f57';
    const sorted1Txid =
        '26aa6e6d8b9e49bb0630aac301db6757c02e3619feb4ee0eea81eb1672947024';
    const sorted2Txid =
        '28e0fdd185542f2c6ea19030b0796051e7772b6026dd5ddccd7a2f93b73e6fc2';

    // Last txid in BIP-69 sorted order:
    const sortedLastTxid =
        'f320832a9d2e2452af63154bc687493484a0e7745ebd3aaf9ca19eb80834ad60';

    test('first input has smallest txid lexicographically', () {
      // Provide 4 inputs in reverse order of the BIP's sorted list.
      final asm = TxAssembler(
        chainParams: _chain,
        inputs: [
          _inp(sorted2Txid, 0),
          _inp(sortedLastTxid, 0),
          _inp(sorted1Txid, 1),
          _inp(sorted0Txid, 0),
        ],
        outputs: [
          TxOutput(
            value: BigInt.from(400057456),
            scriptPubKey: _spk(
                '76a9144a5fba237213a062f6f57978f796390bdcf8d01588ac'),
          ),
        ],
        ordering: TxOrdering.bip69,
      );
      final tx = asm.build(_dummySigner);
      expect(
        hexEncode(tx.inputs[0].prevOut.txid),
        sorted0Txid,
        reason: 'sorted0 must be the first input',
      );
      expect(
        hexEncode(tx.inputs.last.prevOut.txid),
        sortedLastTxid,
        reason: 'sortedLast must be the last input',
      );
    });
  });

  group('BIP-69 ordering - identical outputs sorted by scriptPubKey', () {
    test('equal-value outputs sorted by scriptPubKey bytes', () {
      // Two outputs with the same value; the one with smaller scriptPubKey
      // bytes must come first.
      final spkSmall = Uint8List.fromList([0x00, 0x14, 0xaa, 0xbb]);
      final spkLarge = Uint8List.fromList([0x00, 0x14, 0xcc, 0xdd]);
      final asm = TxAssembler(
        chainParams: _chain,
        inputs: [_inp('0000000000000000000000000000000000000000000000000000000000000001', 0)],
        outputs: [
          TxOutput(value: BigInt.from(50000), scriptPubKey: spkLarge),
          TxOutput(value: BigInt.from(50000), scriptPubKey: spkSmall),
        ],
        ordering: TxOrdering.bip69,
      );
      final tx = asm.build(_dummySigner);
      expect(tx.outputs[0].scriptPubKey, equals(spkSmall));
      expect(tx.outputs[1].scriptPubKey, equals(spkLarge));
    });
  });
}
