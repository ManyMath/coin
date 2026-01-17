import 'dart:typed_data';

import 'package:coin/coin.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(() async {
    await VaultKeeper.initialize();
  });

  // Bitcoin mainnet block 170  -  the first person-to-person BTC transfer
  // (Satoshi to Hal Finney, 2009-01-12).
  // https://blockstream.info/tx/f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16
  // The prevScript is the block-9 coinbase P2PK output that this tx spends.
  // Sighash digest 7a05c614... matches Bitcoin Core SignatureHash() and the
  // on-chain DER signature embedded in the scriptSig.
  group('LegacySigHasher', () {
    // Block 170: f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16
    const rawHex =
        '0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce2585'
        '7fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f77'
        '32e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831c'
        'c56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b000000004341'
        '04ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414'
        'e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac'
        '00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1'
        '482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f'
        '999b8643f656b412a3ac00000000';

    // Block 9 coinbase pubkey
    final _prevScript = hexDecode(
        '410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a690'
        '9a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b4'
        '12a3ac');

    test('SIGHASH_ALL produces deterministic 32-byte hash', () {
      final tx = Tx.fromHex(rawHex);
      final hasher = LegacySigHasher();

      final hash =
          hasher.hash(tx, 0, SigHashType.all, prevScript: _prevScript);
      expect(hash.length, 32);

      final hash2 =
          hasher.hash(tx, 0, SigHashType.all, prevScript: _prevScript);
      expect(hash, equals(hash2));
    });

    test('block 170 scriptSig trailing byte is SIGHASH_ALL', () {
      final tx = Tx.fromHex(rawHex);
      final scriptSig = tx.inputs[0].scriptSig;
      expect(scriptSig[scriptSig.length - 1], SigHashType.all.flag);
    });

    test('SIGHASH_ALL known digest for block 170 tx', () {
      final tx = Tx.fromHex(rawHex);
      final hasher = LegacySigHasher();

      final hash =
          hasher.hash(tx, 0, SigHashType.all, prevScript: _prevScript);

      expect(hexEncode(hash),
          '7a05c6145f10101e9d6325494245adf1297d80f8f38d4d576d57cdba220bcb19');
    });

    test('SIGHASH_ALL vs SIGHASH_NONE produce different hashes', () {
      final tx = Tx.fromHex(rawHex);
      final hasher = LegacySigHasher();

      final hashAll =
          hasher.hash(tx, 0, SigHashType.all, prevScript: _prevScript);
      final hashNone =
          hasher.hash(tx, 0, SigHashType.none, prevScript: _prevScript);

      expect(hashAll, isNot(equals(hashNone)));
    });

    test('SIGHASH_ALL vs SIGHASH_SINGLE produce different hashes', () {
      final tx = Tx.fromHex(rawHex);
      final hasher = LegacySigHasher();

      final hashAll =
          hasher.hash(tx, 0, SigHashType.all, prevScript: _prevScript);
      final hashSingle =
          hasher.hash(tx, 0, SigHashType.single, prevScript: _prevScript);

      expect(hashAll, isNot(equals(hashSingle)));
    });

    test('ANYONE_CAN_PAY changes the hash', () {
      final tx = Tx.fromHex(rawHex);
      final hasher = LegacySigHasher();

      final hashAll =
          hasher.hash(tx, 0, SigHashType.all, prevScript: _prevScript);
      final hashAllAcp = hasher.hash(
          tx, 0, SigHashType.allAnyoneCanPay,
          prevScript: _prevScript);

      expect(hashAllAcp.length, 32);
      expect(hashAll, isNot(equals(hashAllAcp)));
    });

    test('requires prevScript', () {
      final tx = Tx.fromHex(rawHex);
      final hasher = LegacySigHasher();

      expect(
        () => hasher.hash(tx, 0, SigHashType.all),
        throwsArgumentError,
      );
    });
  });

  // Native P2WPKH signing example from BIP-143:
  // https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#native-p2wpkh
  group('WitnessSigHasher (BIP-143)', () {
    // BIP-143 example: https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
    const bip143TxHex =
        '0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541d'
        'b4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b30'
        '9fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb20600000000'
        '1976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac'
        '9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa8159'
        '88ac11000000';

    final _prevScript = hexDecode(
        '76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac');
    final _amount = BigInt.from(600000000); // 6 BTC

    test('SIGHASH_ALL for native P2WPKH produces known hash (BIP-143)', () {
      final tx = Tx.fromHex(bip143TxHex);
      final hasher = WitnessSigHasher();

      final hash = hasher.hash(tx, 1, SigHashType.all,
          prevScript: _prevScript, amount: _amount);

      expect(hash.length, 32);
      expect(hexEncode(hash),
          'c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670');
    });

    test('all three base sighash types produce different results', () {
      final tx = Tx.fromHex(bip143TxHex);
      final hasher = WitnessSigHasher();

      final hashAll = hasher.hash(tx, 1, SigHashType.all,
          prevScript: _prevScript, amount: _amount);
      final hashNone = hasher.hash(tx, 1, SigHashType.none,
          prevScript: _prevScript, amount: _amount);
      final hashSingle = hasher.hash(tx, 1, SigHashType.single,
          prevScript: _prevScript, amount: _amount);

      expect(hashAll, isNot(equals(hashNone)));
      expect(hashAll, isNot(equals(hashSingle)));
      expect(hashNone, isNot(equals(hashSingle)));
    });

    test('ANYONE_CAN_PAY changes the witness hash', () {
      final tx = Tx.fromHex(bip143TxHex);
      final hasher = WitnessSigHasher();

      final hashAll = hasher.hash(tx, 1, SigHashType.all,
          prevScript: _prevScript, amount: _amount);
      final hashAllAcp = hasher.hash(tx, 1, SigHashType.allAnyoneCanPay,
          prevScript: _prevScript, amount: _amount);

      expect(hashAllAcp.length, 32);
      expect(hashAll, isNot(equals(hashAllAcp)));
    });

    test('SIGHASH_NONE|ANYONE_CAN_PAY differs from SIGHASH_NONE', () {
      final tx = Tx.fromHex(bip143TxHex);
      final hasher = WitnessSigHasher();

      final hashNone = hasher.hash(tx, 1, SigHashType.none,
          prevScript: _prevScript, amount: _amount);
      final hashNoneAcp = hasher.hash(tx, 1, SigHashType.noneAnyoneCanPay,
          prevScript: _prevScript, amount: _amount);

      expect(hashNone, isNot(equals(hashNoneAcp)));
    });

    test('SIGHASH_SINGLE|ANYONE_CAN_PAY differs from SIGHASH_SINGLE', () {
      final tx = Tx.fromHex(bip143TxHex);
      final hasher = WitnessSigHasher();

      final hashSingle = hasher.hash(tx, 1, SigHashType.single,
          prevScript: _prevScript, amount: _amount);
      final hashSingleAcp = hasher.hash(
          tx, 1, SigHashType.singleAnyoneCanPay,
          prevScript: _prevScript, amount: _amount);

      expect(hashSingle, isNot(equals(hashSingleAcp)));
    });

    test('different amounts produce different hashes', () {
      final tx = Tx.fromHex(bip143TxHex);
      final hasher = WitnessSigHasher();

      final hash1 = hasher.hash(tx, 1, SigHashType.all,
          prevScript: _prevScript, amount: BigInt.from(600000000));
      final hash2 = hasher.hash(tx, 1, SigHashType.all,
          prevScript: _prevScript, amount: BigInt.from(500000000));

      expect(hash1, isNot(equals(hash2)));
    });

    test('requires prevScript', () {
      final tx = Tx.fromHex(bip143TxHex);
      final hasher = WitnessSigHasher();

      expect(
        () => hasher.hash(tx, 0, SigHashType.all,
            amount: BigInt.from(100000)),
        throwsArgumentError,
      );
    });

    test('requires amount', () {
      final tx = Tx.fromHex(bip143TxHex);
      final hasher = WitnessSigHasher();

      expect(
        () => hasher.hash(tx, 0, SigHashType.all, prevScript: _prevScript),
        throwsArgumentError,
      );
    });

    test('hash is deterministic', () {
      final tx = Tx.fromHex(bip143TxHex);
      final hasher = WitnessSigHasher();

      final hash1 = hasher.hash(tx, 1, SigHashType.all,
          prevScript: _prevScript, amount: _amount);
      final hash2 = hasher.hash(tx, 1, SigHashType.all,
          prevScript: _prevScript, amount: _amount);

      expect(hash1, equals(hash2));
    });
  });

  group('SigHashType', () {
    test('all has flag 0x01', () {
      expect(SigHashType.all.flag, 0x01);
    });

    test('none has flag 0x02', () {
      expect(SigHashType.none.flag, 0x02);
    });

    test('single has flag 0x03', () {
      expect(SigHashType.single.flag, 0x03);
    });

    test('anyoneCanPay flag', () {
      expect(SigHashType.all.anyoneCanPay, isFalse);
      expect(SigHashType.none.anyoneCanPay, isFalse);
      expect(SigHashType.single.anyoneCanPay, isFalse);
      expect(SigHashType.allAnyoneCanPay.anyoneCanPay, isTrue);
      expect(SigHashType.noneAnyoneCanPay.anyoneCanPay, isTrue);
      expect(SigHashType.singleAnyoneCanPay.anyoneCanPay, isTrue);
    });

    test('predefined ANYONE_CAN_PAY flags', () {
      expect(SigHashType.allAnyoneCanPay.flag, 0x81);
      expect(SigHashType.noneAnyoneCanPay.flag, 0x82);
      expect(SigHashType.singleAnyoneCanPay.flag, 0x83);
    });

    test('withAnyoneCanPay sets the 0x80 bit', () {
      final acp = SigHashType.all.withAnyoneCanPay();
      expect(acp.flag, 0x81);
      expect(acp.anyoneCanPay, isTrue);

      final noneAcp = SigHashType.none.withAnyoneCanPay();
      expect(noneAcp.flag, 0x82);

      final singleAcp = SigHashType.single.withAnyoneCanPay();
      expect(singleAcp.flag, 0x83);
    });

    test('baseType extracts lower 5 bits', () {
      expect(SigHashType.all.baseType, 0x01);
      expect(SigHashType.none.baseType, 0x02);
      expect(SigHashType.single.baseType, 0x03);
      expect(SigHashType.allAnyoneCanPay.baseType, 0x01);
      expect(SigHashType.noneAnyoneCanPay.baseType, 0x02);
      expect(SigHashType.singleAnyoneCanPay.baseType, 0x03);
    });

    test('equality works by flag value', () {
      expect(SigHashType.all, equals(SigHashType.fromFlag(0x01)));
      expect(SigHashType.none, equals(SigHashType.fromFlag(0x02)));
      expect(SigHashType.single, equals(SigHashType.fromFlag(0x03)));
      expect(SigHashType.all, isNot(equals(SigHashType.none)));
      expect(SigHashType.allAnyoneCanPay,
          equals(SigHashType.fromFlag(0x81)));
    });

    test('hashCode consistent with equality', () {
      expect(SigHashType.all.hashCode,
          equals(SigHashType.fromFlag(0x01).hashCode));
    });
  });
}
