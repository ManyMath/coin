import 'dart:typed_data';

import 'package:coin/coin.dart';
import 'package:test/test.dart';

// Dash DIP-2 special-transaction vectors. Dash packs the special-tx type in
// the high 16 bits of the version word (nVersion | (nType << 16)), like Firo,
// and its legacy sighash appends vExtraPayload between locktime and the
// hashType flag (CTransactionSignatureSerializer). The shared ExTx
// parse/serialize path and LegacySigHasher gate therefore cover Dash without
// Dash-specific code.
//
// The txid covers vExtraPayload, so a txid round-trip also exercises payload
// parse and re-serialization.
//
// For the ProRegTx and ProUpServTx vectors the DER signature and pubkey
// embedded in the funding input's P2PKH scriptSig (= push(sig+SIGHASH_ALL)
// push(pubkey)) are verified against the recomputed payload-appended legacy
// sighash. The prevout P2PKH scriptPubKey is reconstructed from the embedded
// pubkey as OP_DUP OP_HASH160 <hash160(pubkey)> OP_EQUALVERIFY OP_CHECKSIG
// (a P2PKH spend pays the key whose hash160 is in the prevout script).
//
// Source: Dash Core developer documentation (annotated tx hexdumps).

// ProRegTx (nType=1)
const _proRegTxid =
    'b43dadbd485e4d1e1d202ea5180f0ad4e8e7f05e97a7e566a764ed714356bd1f';
const _proRegHex =
    '03000100013ea08d68bd3038b8ea3d92d43fa38047522896724b04f246827d74b703bd3f'
    '28010000006a47304402201fe458e3dc2c6072848418fedd48fe79081be3c818301ce0a97'
    'de4c1dd5ee2da02206f601d0de9540ac53ef7f9c59c92ef594237f8b23dad3b04b1005ff8'
    '5fb61a5d0121022dce9621ff449fe1a12648da526b93e0c2f8e43d14f8c1650f95272569d'
    '932a6feffffff011ec89a3b000000001976a914955410003527bf2b360a7a390b9ff14b91'
    '06c63288ac00000000fd12010100000000005c71e5f46d35196e33b45c5d59d3fd2dc8438'
    '1942064cae21744fb717412c1ac0100000000000000000000000000ffff2f6fb5cf4e2199'
    'e9dff4cd5a0abc61b5287a0ba48c0553d6358890c0e9ec9dc5f08b1d4d0211920fe5d96a22'
    '5c555a4ba7dd7f6cb14e271c925f2fc72316a01282973f9ad9cf1e39e03829dcf16f7a66b8'
    '32d3b84dbab400a1e9eb7f30ac00001976a914955410003527bf2b360a7a390b9ff14b9106'
    'c63288ac835b69acdba709707c5cccdfcc342eacc87d6db0cc676896a01fe433a0620ae441'
    '1f5da2e5444c6a1556c3d45798b9f95567b1625b3f0cbe69936a70e35ca76b381f0a5506de'
    '07274e5e24db8be77234ad8fa023938f750a283b39b1bff17b2ad11f';
// The funding input's prevout scriptPubKey is a standard P2PKH; the tx's own
// (change) output uses the same script, reused here only for the differential
// sighash test below (its exact value is irrelevant to that comparison).
const _proRegP2pkh =
    '76a914955410003527bf2b360a7a390b9ff14b9106c63288ac';

// ProUpServTx (nType=2)
const _proUpServTxid =
    'f1d23a149955d48ef7bf81ce0a58d4f47ae28399ed3e4ef3c1f90a55a6a9e082';
const _proUpServHex =
    '0300020001f88750ccc24410679d87ee63df5c8dfd901329aa1fe60a74c183d560eee521'
    '8d010000006a473044022029090e49ba2e387e7b39df51fdd6ec1becdd568cdd0de79f5d'
    'ca6084bee677380220583bb62418aa986d927b4487d6a7f0469c4bc54a0e7baa0c484e8c1'
    '40c37b3d301210345184cc81d6cd98eef548206f23a1467c27fea65582d519daa0f7a88a6'
    'c45666feffffff01e7edd23b000000001976a9147f95c0f808aff27883260bfaf9cfe2b84'
    '519a6b288ac00000000b702000000ff92ce2d64657cc3d4d9d82547efca2206ec1d9f5dcf'
    '2776624bc0a58b12ed3b00000000000000000000ffffae22e9734e1f0026ad5ada35511fc'
    '5b9d762b14b22510325ef8b82d21d59567f8e1c3c9e0c955ab99a62829e6317b1943d97f6'
    '6191b1c6714146540788e2d26a1007498dce455603f55aebacf1a38131048abf7d5a05d00'
    'e9e93c1e91cc8cad239b4301b328f5fe1bcbae829ccd6a3f461e712873a188224829fc4b5'
    'fc01fa0fb29014b947d8f7';

// cbTx / coinbase special tx (nType=5)
const _cbTxid =
    'c550cae3f65d396a2f517a7220c7851cc3dc065e20141dadf9f19676348730f2';
const _cbHex =
    '03000500010000000000000000000000000000000000000000000000000000000000000000'
    'ffffffff2703da5c1e04d04580650800007588782d01000fe4b883e5bda9e7a59ee4bb99e9'
    'b1bc04f09f909f88f581b80253640f03000000001976a9147c086eada12bdb10a265c16c08'
    'a7ae87366bd48188acf82c2e09000000001976a91453dc8bffae84a3851ab9fe296417da85'
    'd5e7185888aca0f04c20af0300da5c1e0054e04067fa61cef61f1e91b0d52c21b28cdc69cc'
    '9d0383f0bb88ba0129b973e2f67e47d5580e70c7e77af8b1a6670669c7424b896ab3d44d34'
    '9a4988e9a8328d00b22fef542f5c630e4f2a67ad56d30cf2a3dac55848abcd2bac30bf7803'
    '18792bcdf32f7729443846c9fdc57050a131cd12c0e54a16f6265e900f459e3b9dd43421a0'
    'bc3f61efd49ce752e440e5131a8d2758a280ad883b8eb902c49ee5b878b30000000000000000';

void main() {
  setUpAll(() async {
    await VaultKeeper.initialize();
  });

  final hasher = LegacySigHasher();

  void expectDip2(String hex, String txid, int type) {
    final tx = Tx.fromHex(hex);
    expect(tx, isA<ExTx>(), reason: 'a DIP-2 special tx parses as ExTx');
    final exTx = tx as ExTx;
    expect(exTx.txVersion, 3);
    expect(exTx.txType, type);
    expect(exTx.payload, isNotEmpty);
    expect(exTx.toHex(), hex, reason: 'serialization must round-trip exactly');
    expect(exTx.txid, txid, reason: 'txid includes vExtraPayload');
  }

  group('Dash DIP-2 special transactions (Dash Core docs)', () {
    test('ProRegTx (nType=1) parses as ExTx, round-trips, matches txid', () {
      expectDip2(_proRegHex, _proRegTxid, 1);
    });

    test('ProUpServTx (nType=2) parses as ExTx, round-trips, matches txid', () {
      expectDip2(_proUpServHex, _proUpServTxid, 2);
    });

    test('cbTx (nType=5) parses as ExTx, round-trips, matches txid', () {
      expectDip2(_cbHex, _cbTxid, 5);
    });
  });

  // Extracts (derSig, pubkey) from a standard P2PKH scriptSig:
  //   push(<sig||hashType>) push(<pubkey>)
  // Returns the bare DER (flag stripped) and the pubkey, asserting the flag is
  // SIGHASH_ALL.
  ({Uint8List der, Uint8List pubkey}) p2pkhSig(Uint8List scriptSig) {
    final sigLen = scriptSig[0];
    final sigWithFlag = scriptSig.sublist(1, 1 + sigLen);
    expect(sigWithFlag.last, SigHashType.all.flag);
    final der =
        Uint8List.fromList(sigWithFlag.sublist(0, sigWithFlag.length - 1));
    final pkOff = 1 + sigLen;
    final pkLen = scriptSig[pkOff];
    final pubkey =
        Uint8List.fromList(scriptSig.sublist(pkOff + 1, pkOff + 1 + pkLen));
    return (der: der, pubkey: pubkey);
  }

  // P2PKH prevout scriptPubKey for the key whose hash160 is committed there.
  Uint8List p2pkhSpk(Uint8List pubkey) => Uint8List.fromList(
      [0x76, 0xa9, 0x14, ...hash160(pubkey), 0x88, 0xac]);

  group('Dash embedded signatures verify against the DIP-2 sighash', () {
    test('ProRegTx (nType=1): funding-input sig verifies', () {
      final tx = Tx.fromHex(_proRegHex) as ExTx;
      final sig = p2pkhSig(tx.inputs[0].scriptSig);
      final sighash = hasher.hash(
        tx,
        0,
        SigHashType.all,
        prevScript: p2pkhSpk(sig.pubkey),
      );
      // The payload-appended legacy sighash must match Dash consensus for
      // ProRegTx.
      expect(EcdsaSig.fromDer(sig.der).verify(sighash, sig.pubkey), isTrue);
    });

    test('ProUpServTx (nType=2): funding-input sig verifies',
        () {
      final tx = Tx.fromHex(_proUpServHex) as ExTx;
      final sig = p2pkhSig(tx.inputs[0].scriptSig);
      final sighash = hasher.hash(
        tx,
        0,
        SigHashType.all,
        prevScript: p2pkhSpk(sig.pubkey),
      );
      expect(EcdsaSig.fromDer(sig.der).verify(sighash, sig.pubkey), isTrue);
    });
  });

  group('Dash payload participates in the legacy sighash (gate fires)', () {
    test('stripping the ProRegTx payload changes the sighash', () {
      final tx = Tx.fromHex(_proRegHex) as ExTx;
      final prevScript = hexDecode(_proRegP2pkh);
      final withPayload =
          hasher.hash(tx, 0, SigHashType.all, prevScript: prevScript);
      final withoutPayload = hasher.hash(
        tx.setPayload(Uint8List(0)),
        0,
        SigHashType.all,
        prevScript: prevScript,
      );
      // The same payload-append gate also fires for Dash's identical
      // nType!=0 encoding.
      expect(withPayload, isNot(equals(withoutPayload)));
    });
  });
}
