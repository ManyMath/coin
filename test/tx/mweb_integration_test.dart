import 'package:coin/coin.dart';
import 'package:test/test.dart';

/// End-to-end Slice A integration: parse an LTC mainnet HogEx tx, confirm
/// the MWEB blob is captured, the txid matches, and the transaction
/// re-serializes unchanged.
void main() {
  setUpAll(() async {
    await VaultKeeper.initialize();
  });

  group('MWEB integration (Slice A)', () {
    // LTC mainnet block 2680000 HogEx tx (flag 0x08, MWEB-only).
    const hogExHex =
        '02000000000801055b9501fc80f092ec6a1fc82a130fbc4126d76aaccc8ff09d47'
        'bcacd439facf0000000000ffffffff0119a0e168b702000022582055b14302a081'
        '2dcfad58dc83b0d2c96d3bf36cc08735cd36987f721b69f6faa10000000000';

    const expectedTxid =
        'fd786dea0b4d16017897c66c80f40bbbaac6ed5dfc1d8540f8e69b39ae07b798';

    test('HogEx round-trips and matches canonical txid', () {
      final tx = Tx.fromHex(hogExHex);

      expect(tx.mwebBytes, isNotNull);
      expect(tx.mwebBytes!.length, greaterThan(0));
      expect(tx.txid, expectedTxid);
      expect(tx.toHex(), hogExHex);
    });

    // Further ltcsuite/ltcd vectors (HogEx, in-block peg-in, mempool peg-in
    // with full MWEB tail, and a pure MWEB-only tx) live in
    // test/tx/mweb_ltcd_vectors_test.dart, with per-regime assertions
    // (round-trip vs txid-only vs no-txid for kernel-hashed MWEB-only txs).
  });

  // A MWEB peg-OUT has no standalone wrapper tx: the peg-out is requested by a
  // kernel inside the MWEB extension block, and its canonical-chain effect is
  // an ordinary output appended to that block's HogEx transaction. So a
  // peg-out is observable (and serializable) as a HogEx whose outputs after
  // the witness-v8 balance output are the peg-out destinations. These are
  // LTC mainnet HogEx txs (flag 0x08) from litecoinspace.org; the txid
  // is computed with the MWEB bytes stripped (SERIALIZE_NO_MWEB).
  group('MWEB peg-out (HogEx canonical side)', () {
    test('P2SH peg-out - block 3115499', () {
      const hex =
          '0200000000080334deca06b4404281649ce20edcb757475b0dbfc18b55ca9d68e88'
          '79c95564ee60000000000ffffffff59f82ce926956c7ef652e7e5aa93c766e3b3f9'
          '5ea91b32f940bd502558826bde0000000000ffffffff6f3cc906516f39c5e2a9e82'
          'cae684292c124b448db737149dce0679ba38e74a10000000000ffffffff0208614a'
          '2eff200000225820a0de06cda14d558d9f237cb8870276935256c9f81d25d808d6b9'
          '32258cffac9f0027b9290000000017a91429dc4ac51a4fdc6433518b3283123a6656'
          '81e86b870000000000';
      const txid =
          '468ff805165c7987e03310e756fc904aa17031f1be466b7b10680a4b6f12e310';
      final tx = Tx.fromHex(hex);
      expect(tx.mwebBytes, isNotNull);
      expect(tx.txid, txid);
      expect(tx.toHex(), hex, reason: 'flag 0x08, no witness -> unchanged');
      // outputs[0] is the rolled-forward MWEB balance (witness v8); outputs[1]
      // is the peg-out: 7.0 LTC to a P2SH address.
      expect(tx.outputs.length, 2);
      expect(tx.outputs[1].value, BigInt.from(700000000));
      expect(
        hexEncode(tx.outputs[1].scriptPubKey),
        'a91429dc4ac51a4fdc6433518b3283123a665681e86b87',
      );
    });

    test('P2WPKH peg-out - block 3115498', () {
      const hex =
          '02000000000801af76b95c6766ffd4db42bcb022e682a2ac3d422e6ca78ec98da31'
          '2bc490bffd70000000000ffffffff024080c63afd20000022582069fe96e528a9fe'
          'd69c1e620d4305fc8a0f12f6aa355cfbb0dd160261eb94df1b035fc339000000001'
          '60014d40f690970c91a645ff3af4d8676ea1ef1b15d940000000000';
      const txid =
          'e64e56959c87e8689dca558bc1bf0d5b4757b7dc0ee29c64814240b406cade34';
      final tx = Tx.fromHex(hex);
      expect(tx.mwebBytes, isNotNull);
      expect(tx.txid, txid);
      expect(tx.toHex(), hex);
      // outputs[1] is a native-segwit (P2WPKH) peg-out destination.
      expect(tx.outputs.length, 2);
      expect(
        hexEncode(tx.outputs[1].scriptPubKey),
        '0014d40f690970c91a645ff3af4d8676ea1ef1b15d94',
      );
    });
  });
}
