import 'dart:typed_data';

import 'package:coin/coin.dart';
import 'package:test/test.dart';

// Firo special-transaction vectors (nVersion=3 with a non-zero nType).
// Firo includes vExtraPayload in the txid, so a txid round-trip also
// exercises payload parse and re-serialization.
//
// Source: Firo mainnet, fetched via cryptoID
// (https://chainz.cryptoid.info/explorer/tx.raw.dws?coin=firo&id=<txid>&hex=1).
//
// Dash DIP-2 uses the same nVersion|(nType<<16) encoding and sighash
// serializer, so it exercises this same ExTx/LegacySigHasher path; its
// vectors live in dash_special_tx_vectors_test.dart.
//
// For the two Firo vectors the legacy sighash (with vExtraPayload appended,
// per Firo Core's CTransactionSignatureSerializer::Serialize) is recomputed
// and the embedded ECDSA signature is verified against it and the embedded
// pubkey.

// --- Firo ProRegTx (nType=1), mainnet block 278362 ---
const _firoProRegTxid =
    'a9b66c9cbe7ed0c44ef601109ea8ca3f1d0ea651215379b384895f67870ecbfa';
const _firoProRegHex =
    '0300010001bd711bb87f49339f4a7326105f6f83d6d254d7f0d2faac286dca2a8eb06818'
    '4e000000006b483045022100d73db910c62b5f6ce2d8815c9d7062ba0143780808e24a6c'
    '2dbdef6880ca812f0220648d8ec82a953df949bda875e27d657285b3c468c8106488ef4dc'
    'b38386bd977012102a7f4bff537eea7c7ee36767309a7ebb79ec478861f4d16c9fc5a4af4'
    'fe5cc4a3feffffff019e8e980e000000001976a91462b846e27bc72fa391406aec48cb548'
    '365d4d71388ac00000000fd1201010000000000d2ab42cc4407029cee82890c9404e1c771'
    'b11d0c279ab1d821c8e1897809bd8b0100000000000000000000000000ffff3eabb82b1fe8'
    '22285ad2c25127627365e45c96c21413728d82411920e1c2aa0f1d52f1d1b8fd86af7cc73e'
    'fb6d45e1959e005bda3f3b60fa574c600ab6430d5b963ab88e9331ea1e84d122285ad2c251'
    '27627365e45c96c21413728d824100001976a914aa42f0bc2ce5e423ef6deb04ceefede9f8'
    'be297d88ac7a3a7011404bc97128cae0a86cb5ec1c7c35dfa909bfbb8659eb61b169db94bf'
    '411fc9d8795e4835775929fb939a3693fe0fac403a0c41b8d7110d1d3db7df0c2e063982dc'
    'c3ed1f4e31f2081184a841c57a969d3f2ddf4ed75e0093d7858d7585bc';
// Input 0: P2PKH prevout scriptPubKey, signature (SIGHASH_ALL) and pubkey
// pulled from the scriptSig.
const _firoProRegPrevScript =
    '76a91462b846e27bc72fa391406aec48cb548365d4d71388ac';
const _firoProRegSigDer =
    '3045022100d73db910c62b5f6ce2d8815c9d7062ba0143780808e24a6c2dbdef6880ca812'
    'f0220648d8ec82a953df949bda875e27d657285b3c468c8106488ef4dcb38386bd977';
const _firoProRegPubKey =
    '02a7f4bff537eea7c7ee36767309a7ebb79ec478861f4d16c9fc5a4af4fe5cc4a3';

// --- Firo ProUpServTx (nType=2), mainnet block 284597 ---
const _firoProUpServTxid =
    'aa87ebfcda23065fbbaa100f668e5df701f3eaec16b71581b519f176a3a0303c';
const _firoProUpServHex =
    '0300020002456c8724c699e4b9a1e185555fbb2a8b3302fc8ba8509165b7bd61cd163974'
    '9e010000006a473044022010ba59c06b81d1b52d9702cea116964d5a198863fb8cce4ce9d'
    '875bbf9bfcd8102202ec681b53dfab312c01760be81fa885959f394cb9ab44347d54c99f2'
    'adec61800121028e5b4bb69033ef458fd9d4d5b839e836191ef55adf5dbcb3552bf0e9b98'
    'e9e33feffffffefe846d36833024c48e94031871b29e6821e3b33f01b1eecd8c9e02bf411'
    '5ec5000000006b483045022100e398baabfb502a85b306305a65c849c4c499d0a65a49cb3'
    '8699e9ec381022b6502206e6e7b6a62b9409a2c4905b32525567a43489caab17a65b1133e'
    '848bc7f8cdeb0121028e5b4bb69033ef458fd9d4d5b839e836191ef55adf5dbcb3552bf0e'
    '9b98e9e33feffffff0191dec5aa030000001976a914dac9f75ffd9b0a9994ccdce48eddf2'
    'fc8891d02a88ac00000000b50100efe846d36833024c48e94031871b29e6821e3b33f01b1'
    'eecd8c9e02bf4115ec500000000000000000000ffff70ec43181fe800f9bf7781dec7ebf5'
    '5c61dda4814c95c769891835165e2aa38a56abea5d4b6eb808f09d78fd4b18ed07f102da92'
    'ed5ae373f765b2d5dd12afa1ee2460fa8bebe37f8211bfbcb2a6b22d53025b6b6f1d1c1874'
    '9348672dd4af45ba34e1e787126a9cd5f99fb01f3b74b6d332bee075246cf30872369d8e13'
    'a551e37bfd05200b1f';
// Both inputs share the same P2PKH prevout and pubkey; one DER sig each.
const _firoProUpServPrevScript =
    '76a914dac9f75ffd9b0a9994ccdce48eddf2fc8891d02a88ac';
const _firoProUpServPubKey =
    '028e5b4bb69033ef458fd9d4d5b839e836191ef55adf5dbcb3552bf0e9b98e9e33';
const _firoProUpServSig0Der =
    '3044022010ba59c06b81d1b52d9702cea116964d5a198863fb8cce4ce9d875bbf9bfcd81'
    '02202ec681b53dfab312c01760be81fa885959f394cb9ab44347d54c99f2adec6180';
const _firoProUpServSig1Der =
    '3045022100e398baabfb502a85b306305a65c849c4c499d0a65a49cb38699e9ec381022b'
    '6502206e6e7b6a62b9409a2c4905b32525567a43489caab17a65b1133e848bc7f8cdeb';

void main() {
  setUpAll(() async {
    await VaultKeeper.initialize();
  });

  final hasher = LegacySigHasher();

  // Shared structural assertions: parse, type, non-empty payload, exact
  // round-trip, and txid (which for Firo/Dash covers the payload too).
  void expectVector(String hex, String txid, int version, int type) {
    final tx = Tx.fromHex(hex);
    expect(tx, isA<ExTx>());
    final exTx = tx as ExTx;
    expect(exTx.txVersion, version);
    expect(exTx.txType, type);
    expect(exTx.payload, isNotEmpty);
    expect(exTx.hasPayload, isTrue);
    expect(exTx.toHex(), hex, reason: 'serialization must round-trip exactly');
    expect(hexEncode(exTx.toBytes()), hex);
    expect(exTx.txid, txid, reason: 'txid includes vExtraPayload');
  }

  group('Firo ProRegTx (nType=1) - mainnet block 278362', () {
    test('parses, round-trips, and matches txid', () {
      expectVector(_firoProRegHex, _firoProRegTxid, 3, 1);
    });

    test('embedded signature verifies against the payload-appended sighash',
        () {
      final tx = Tx.fromHex(_firoProRegHex) as ExTx;
      final sighash = hasher.hash(
        tx,
        0,
        SigHashType.all,
        prevScript: hexDecode(_firoProRegPrevScript),
      );
      final sig = EcdsaSig.fromDer(hexDecode(_firoProRegSigDer));
      final pub = hexDecode(_firoProRegPubKey);
      // The sighash has vExtraPayload appended, per Firo consensus.
      expect(sig.verify(sighash, pub), isTrue);
    });
  });

  group('Firo ProUpServTx (nType=2) - mainnet block 284597', () {
    test('parses, round-trips, and matches txid', () {
      expectVector(_firoProUpServHex, _firoProUpServTxid, 3, 2);
    });

    test('both embedded signatures verify against payload-appended sighashes',
        () {
      final tx = Tx.fromHex(_firoProUpServHex) as ExTx;
      final prevScript = hexDecode(_firoProUpServPrevScript);
      final pub = hexDecode(_firoProUpServPubKey);

      final sighash0 =
          hasher.hash(tx, 0, SigHashType.all, prevScript: prevScript);
      final sighash1 =
          hasher.hash(tx, 1, SigHashType.all, prevScript: prevScript);

      expect(
        EcdsaSig.fromDer(hexDecode(_firoProUpServSig0Der))
            .verify(sighash0, pub),
        isTrue,
        reason: 'input 0',
      );
      expect(
        EcdsaSig.fromDer(hexDecode(_firoProUpServSig1Der))
            .verify(sighash1, pub),
        isTrue,
        reason: 'input 1',
      );
    });
  });

  group('payload participates in the sighash (differential)', () {
    test('stripping the Firo ProRegTx payload changes the sighash', () {
      final tx = Tx.fromHex(_firoProRegHex) as ExTx;
      final prevScript = hexDecode(_firoProRegPrevScript);
      final withPayload =
          hasher.hash(tx, 0, SigHashType.all, prevScript: prevScript);
      final stripped = tx.setPayload(Uint8List(0));
      final withoutPayload =
          hasher.hash(stripped, 0, SigHashType.all, prevScript: prevScript);
      expect(withPayload, isNot(equals(withoutPayload)));
    });
  });
}
