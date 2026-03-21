import 'package:coin/coin.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(() async {
    await VaultKeeper.initialize();
  });

  group('MWEB txid / wtxid (SERIALIZE_NO_MWEB)', () {
    // LTC mainnet block 2680000 HogEx tx. The MWEB extension-block bytes must
    // be excluded from both txid (ComputeHash) and wtxid (ComputeWitnessHash).
    const hogExHex =
        '02000000000801055b9501fc80f092ec6a1fc82a130fbc4126d76aaccc8ff09d47'
        'bcacd439facf0000000000ffffffff0119a0e168b702000022582055b14302a081'
        '2dcfad58dc83b0d2c96d3bf36cc08735cd36987f721b69f6faa10000000000';

    const expectedTxid =
        'fd786dea0b4d16017897c66c80f40bbbaac6ed5dfc1d8540f8e69b39ae07b798';

    test('HogEx parses and yields canonical Litecoin txid', () {
      final tx = Tx.fromHex(hogExHex);
      // Vacuous otherwise: confirm the MWEB blob is present.
      expect(tx.mwebBytes, isNotNull);
      expect(tx.txid, expectedTxid);
    });

    test('HogEx wtxid excludes MWEB and equals txid (no witness)', () {
      final tx = Tx.fromHex(hogExHex);
      // The HogEx input carries no witness stack, so once mwebBytes is
      // excluded from the preimage, wtxid == txid.
      expect(tx.wtxid, expectedTxid);
    });

    test('re-serialized flag byte is 0x08 (MWEB only, not 0x09)', () {
      final tx = Tx.fromHex(hogExHex);
      final bytes = tx.toBytes();
      // Layout: [version:4][marker:1][flag:1]... - flag is at offset 5.
      expect(bytes[4], 0x00, reason: 'marker');
      expect(bytes[5], 0x08, reason: 'flag: MWEB bit only, no witness bit');
    });

    test('V8 synthetic: flag 0x09 reads witness then MWEB in order', () {
      // version=02000000, marker=00, flag=09 (witness + MWEB), 1 input
      // (32 zero bytes prevout, vout 0, empty scriptSig, seq ffffffff),
      // 1 output (value 0, empty spk), 1 witness vector (00 = 0 items),
      // then MWEB bytes (aabbcc), then locktime 00000000.
      final hex = '02000000' // version
          '00' // marker
          '09' // flag: witness + MWEB
          '01' // input count
          '${'00' * 32}' // prevout txid
          '00000000' // prevout vout
          '00' // scriptSig length 0
          'ffffffff' // sequence
          '01' // output count
          '0000000000000000' // value
          '00' // scriptPubKey length 0
          '00' // witness vector for input 0: 0 items
          'aabbcc' // MWEB extension bytes
          '00000000'; // locktime
      final tx = Tx.fromHex(hex);
      expect(tx.inputs.length, 1);
      expect(tx.outputs.length, 1);
      expect(tx.locktime, 0);
      // The MWEB blob must be exactly the bytes between the witness vectors
      // and the trailing 4-byte locktime.
      expect(tx.mwebBytes, isNotNull);
      expect(tx.mwebBytes, equals([0xaa, 0xbb, 0xcc]));
    });
  });
}
