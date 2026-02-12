import 'dart:typed_data';

import 'package:coin/coin_chains.dart';
import 'package:test/test.dart';

// BIP-327 MuSig2 official test vectors.
// Source: https://github.com/bitcoin/bips/blob/master/bip-0327/vectors/
// All hex strings are uppercase as they appear in the JSON files.

void main() {
  setUpAll(() async {
    await VaultKeeper.initialize();
  });

  // ---------------------------------------------------------------------------
  // key_agg_vectors.json
  // Source: https://raw.githubusercontent.com/bitcoin/bips/master/bip-0327/vectors/key_agg_vectors.json
  // ---------------------------------------------------------------------------
  group('BIP-327 KeyAgg vectors', () {
    // The 7 public keys from the vector file.
    final pubkeys = [
      hexDecode('02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9'),
      hexDecode('03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659'),
      hexDecode('023590A94E768F8E1815C2F24B4D80A8E3149316C3518CE7B7AD338368D038CA66'),
      // pubkeys[3] = low-order point (not on the curve with standard params) - error case
      hexDecode('020000000000000000000000000000000000000000000000000000000000000005'),
      // pubkeys[4] - x coordinate exceeds field size - error case
      hexDecode('02FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30'),
      // pubkeys[5] - uncompressed format (0x04 prefix) - error case
      hexDecode('04F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9'),
      hexDecode('03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9'),
    ].map((b) => PublicKey(b)).toList();

    // valid_test_case 0: key_indices [0,1,2]
    test('key_agg [0,1,2] -> 90539E...', () {
      final agg = AggregatedKey.fromKeys([pubkeys[0], pubkeys[1], pubkeys[2]]);
      expect(
        hexEncode(agg.xOnly).toUpperCase(),
        '90539EEDE565F5D054F32CC0C220126889ED1E5D193BAF15AEF344FE59D4610C',
      );
    });

    // valid_test_case 1: key_indices [2,1,0] - same keys, different order -> different result
    test('key_agg [2,1,0] -> 6204DE... (order-dependent per BIP-327)', () {
      final agg = AggregatedKey.fromKeys([pubkeys[2], pubkeys[1], pubkeys[0]]);
      expect(
        hexEncode(agg.xOnly).toUpperCase(),
        '6204DE8B083426DC6EAF9502D27024D53FC826BF7D2012148A0575435DF54B2B',
      );
    });

    // valid_test_case 2: key_indices [0,0,0] - all identical keys
    test('key_agg [0,0,0] -> B436E3... (all-same keys)', () {
      final agg = AggregatedKey.fromKeys([pubkeys[0], pubkeys[0], pubkeys[0]]);
      expect(
        hexEncode(agg.xOnly).toUpperCase(),
        'B436E3BAD62B8CD409969A224731C193D051162D8C5AE8B109306127DA3AA935',
      );
    });

    // valid_test_case 3: key_indices [0,0,1,1]
    test('key_agg [0,0,1,1] -> 69BC22...', () {
      final agg = AggregatedKey.fromKeys(
          [pubkeys[0], pubkeys[0], pubkeys[1], pubkeys[1]]);
      expect(
        hexEncode(agg.xOnly).toUpperCase(),
        '69BC22BFA5D106306E48A20679DE1D7389386124D07571D0D872686028C26A3E',
      );
    });

    // Ordering property: [0,1,2] != [2,1,0]
    test('key_agg result depends on key order (BIP-327 is NOT commutative)', () {
      final agg012 = AggregatedKey.fromKeys([pubkeys[0], pubkeys[1], pubkeys[2]]);
      final agg210 = AggregatedKey.fromKeys([pubkeys[2], pubkeys[1], pubkeys[0]]);
      expect(agg012.xOnly, isNot(equals(agg210.xOnly)));
    });

    // key_agg_vectors.json error_test_cases: each aggregates a key set containing
    // one invalid public key and MUST fail. The invalid keys are pubkeys[3]
    // (point not on the curve), [4] (x >= field size p), and [5] (invalid
    // 0x04-prefixed / wrong-length encoding) - the exact values from the JSON.
    test('key_agg rejects a not-on-curve point (error_test_case 0)', () {
      expect(() => AggregatedKey.fromKeys([pubkeys[1], pubkeys[3]]),
          throwsA(anything));
    });
    test('key_agg rejects an x-coord >= field size (error_test_case 1)', () {
      expect(() => AggregatedKey.fromKeys([pubkeys[1], pubkeys[4]]),
          throwsA(anything));
    });
    test('key_agg rejects an invalidly-encoded pubkey (error_test_case 2)', () {
      expect(() => AggregatedKey.fromKeys([pubkeys[1], pubkeys[5]]),
          throwsA(anything));
    });
  });

  // ---------------------------------------------------------------------------
  // sign_verify_vectors.json
  // Source: https://raw.githubusercontent.com/bitcoin/bips/master/bip-0327/vectors/sign_verify_vectors.json
  // ---------------------------------------------------------------------------
  group('BIP-327 PartialSig sign vectors', () {
    // Signer secret key.
    final sk = hexDecode(
        '7FB9E0E687ADA1EEBF7ECFE2F21E73EBDB51A7D450948DFE8D76D7F2D1007671');

    // The 4 public keys from sign_verify_vectors.json.
    final pubkeys = [
      PublicKey(hexDecode('03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9')),
      PublicKey(hexDecode('02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9')),
      PublicKey(hexDecode('02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA661')),
      PublicKey(hexDecode('020000000000000000000000000000000000000000000000000000000000000007')),
    ];

    // Secnonces: 97 bytes each - k1(32) || k2(32) || pk(33).
    final secnonces = [
      hexDecode(
          '508B81A611F100A6B2B6B29656590898AF488BCF2E1F55CF22E5CFB84421FE61'
          'FA27FD49B1D50085B481285E1CA205D55C82CC1B31FF5CD54A489829355901F7'
          '03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9'),
      // secnonce[1] has k1=k2=0 (invalid, used in error cases)
      hexDecode(
          '0000000000000000000000000000000000000000000000000000000000000000'
          '0000000000000000000000000000000000000000000000000000000000000000'
          '03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9'),
    ];

    // Pnonces: 66 bytes each - R1(33) || R2(33).
    final pnonces = [
      hexDecode('0337C87821AFD50A8644D820A8F3E02E499C931865C2360FB43D0A0D20DAFE07EA'
          '0287BF891D2A6DEAEBADC909352AA9405D1428C15F4B75F04DAE642A95C2548480'),
      hexDecode('0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798'
          '0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798'),
      hexDecode('032DE2662628C90B03F5E720284EB52FF7D71F4284F627B68A853D78C78E1FFE93'
          '03E4C5524E83FFE1493B9077CF1CA6BEB2090C93D930321071AD40B2F44E599046'),
      hexDecode('0237C87821AFD50A8644D820A8F3E02E499C931865C2360FB43D0A0D20DAFE07EA'
          '0387BF891D2A6DEAEBADC909352AA9405D1428C15F4B75F04DAE642A95C2548480'),
      hexDecode('020000000000000000000000000000000000000000000000000000000000000009'
          '0287BF891D2A6DEAEBADC909352AA9405D1428C15F4B75F04DAE642A95C2548480'),
    ];

    // Messages.
    final msgs = [
      hexDecode('F95466D086770E689964664219266FE5ED215C92AE20BAB5C9D79ADDDDF3C0CF'),
      Uint8List(0), // empty message
      hexDecode('2626262626262626262626262626262626262626262626262626262626262626'
          '262626262626'), // 38 bytes
    ];

    NoncePair pairFrom(Uint8List pnonce) =>
        NoncePair(r1: pnonce.sublist(0, 33), r2: pnonce.sublist(33, 66));

    Uint8List k1From(Uint8List secnonce) => secnonce.sublist(0, 32);
    Uint8List k2From(Uint8List secnonce) => secnonce.sublist(32, 64);

    NonceSession buildSession({
      required List<int> keyIndices,
      required List<int> nonceIndices,
      required Uint8List msg,
    }) {
      final aggKey = AggregatedKey.fromKeys(
          keyIndices.map((i) => pubkeys[i]).toList());
      final session = NonceSession(aggKey: aggKey, message: msg);
      for (final ni in nonceIndices) {
        session.addNonce(pairFrom(pnonces[ni]));
      }
      return session;
    }

    // valid_test_case 0: key_indices=[0,1,2], nonce_indices=[0,1,2], msg=0, signer=0
    test('partial sign case 0 (standard, 32-byte msg)', () {
      final session = buildSession(
          keyIndices: [0, 1, 2], nonceIndices: [0, 1, 2], msg: msgs[0]);
      final partial = PartialSig.sign(
        secretKey: sk,
        secretNonces: [k1From(secnonces[0]), k2From(secnonces[0])],
        session: session,
      );
      expect(
        hexEncode(partial.partialS).toUpperCase(),
        '012ABBCB52B3016AC03AD82395A1A415C48B93DEF78718E62A7A90052FE224FB',
      );
    });

    // valid_test_case 3: aggnonce both halves = infinity (aggnonce_index=1)
    test('partial sign case 3 (aggnonce both halves at infinity)', () {
      // key_indices=[0,1], nonce_indices=[0,3], signer=0, msg=0
      // pnonces[3].r2 is a point not on the standard curve coord (causes infinity after agg).
      // We use nonces[0] and nonces[3] (r1=0337C8..., r2=0387BF...).
      final session = buildSession(
          keyIndices: [0, 1], nonceIndices: [0, 3], msg: msgs[0]);
      final partial = PartialSig.sign(
        secretKey: sk,
        secretNonces: [k1From(secnonces[0]), k2From(secnonces[0])],
        session: session,
      );
      expect(
        hexEncode(partial.partialS).toUpperCase(),
        'AE386064B26105404798F75DE2EB9AF5EDA5387B064B83D049CB7C5E08879531',
      );
    });

    // valid_test_case 4: empty message
    test('partial sign case 4 (empty message)', () {
      final session = buildSession(
          keyIndices: [0, 1, 2], nonceIndices: [0, 1, 2], msg: msgs[1]);
      final partial = PartialSig.sign(
        secretKey: sk,
        secretNonces: [k1From(secnonces[0]), k2From(secnonces[0])],
        session: session,
      );
      expect(
        hexEncode(partial.partialS).toUpperCase(),
        'D7D63FFD644CCDA4E62BC2BC0B1D02DD32A1DC3030E155195810231D1037D82D',
      );
    });

    // valid_test_case 5: 38-byte message
    test('partial sign case 5 (38-byte message)', () {
      final session = buildSession(
          keyIndices: [0, 1, 2], nonceIndices: [0, 1, 2], msg: msgs[2]);
      final partial = PartialSig.sign(
        secretKey: sk,
        secretNonces: [k1From(secnonces[0]), k2From(secnonces[0])],
        session: session,
      );
      expect(
        hexEncode(partial.partialS).toUpperCase(),
        'E184351828DA5094A97C79CABDAAA0BFB87608C32E8829A4DF5340A6F243B78C',
      );
    });

    // PartialSig.verify positive check (using case 0 partial).
    test('PartialSig.verify passes for valid partial (case 0)', () {
      final session = buildSession(
          keyIndices: [0, 1, 2], nonceIndices: [0, 1, 2], msg: msgs[0]);
      final partial = PartialSig.sign(
        secretKey: sk,
        secretNonces: [k1From(secnonces[0]), k2From(secnonces[0])],
        session: session,
      );
      expect(partial.verify(session), isTrue);
    });
  });

  // ---------------------------------------------------------------------------
  // sig_agg_vectors.json - PartialSig.combine
  // Source: https://raw.githubusercontent.com/bitcoin/bips/master/bip-0327/vectors/sig_agg_vectors.json
  // ---------------------------------------------------------------------------
  group('BIP-327 SigAgg (combine) vectors', () {
    final pubkeys = [
      PublicKey(hexDecode('03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9')),
      PublicKey(hexDecode('02D2DC6F5DF7C56ACF38C7FA0AE7A759AE30E19B37359DFDE015872324C7EF6E05')),
      PublicKey(hexDecode('03C7FB101D97FF930ACD0C6760852EF64E69083DE0B06AC6335724754BB4B0522C')),
      PublicKey(hexDecode('02352433B21E7E05D3B452B81CAE566E06D2E003ECE16D1074AABA4289E0E3D581')),
    ];

    // 6 pnonces from sig_agg_vectors.json
    final pnonces = [
      hexDecode('036E5EE6E28824029FEA3E8A9DDD2C8483F5AF98F7177C3AF3CB6F47CAF8D94AE9'
          '02DBA67E4A1F3680826172DA15AFB1A8CA85C7C5CC88900905C8DC8C328511B53E'),
      hexDecode('03E4F798DA48A76EEC1C9CC5AB7A880FFBA201A5F064E627EC9CB0031D1D58FC51'
          '03E06180315C5A522B7EC7C08B69DCD721C313C940819296D0A7AB8E8795AC1F00'),
      hexDecode('02C0068FD25523A31578B8077F24F78F5BD5F2422AFF47C1FADA0F36B3CEB6C7D2'
          '02098A55D1736AA5FCC21CF0729CCE852575C06C081125144763C2C4C4A05C09B6'),
      hexDecode('031F5C87DCFBFCF330DEE4311D85E8F1DEA01D87A6F1C14CDFC7E4F1D8C441CFA4'
          '0277BF176E9F747C34F81B0D9F072B1B404A86F402C2D86CF9EA9E9C69876EA3B9'),
      hexDecode('023F7042046E0397822C4144A17F8B63D78748696A46C3B9F0A901D296EC3406C3'
          '02022B0B464292CF9751D699F10980AC764E6F671EFCA15069BBE62B0D1C62522A'),
      hexDecode('02D97DDA5988461DF58C5897444F116A7C74E5711BF77A9446E27806563F3B6C47'
          '020CBAD9C363A7737F99FA06B6BE093CEAFF5397316C5AC46915C43767AE867C00'),
    ];

    // 9 partial sigs from sig_agg_vectors.json
    final psigs = [
      hexDecode('B15D2CD3C3D22B04DAE438CE653F6B4ECF042F42CFDED7C41B64AAF9B4AF53FB'),
      hexDecode('6193D6AC61B354E9105BBDC8937A3454A6D705B6D57322A5A472A02CE99FCB64'),
      hexDecode('9A87D3B79EC67228CB97878B76049B15DBD05B8158D17B5B9114D3C226887505'),
      hexDecode('66F82EA90923689B855D36C6B7E032FB9970301481B99E01CDB4D6AC7C347A15'),
      hexDecode('4F5AEE41510848A6447DCD1BBC78457EF69024944C87F40250D3EF2C25D33EFE'),
      hexDecode('DDEF427BBB847CC027BEFF4EDB01038148917832253EBC355FC33F4A8E2FCCE4'),
      hexDecode('97B890A26C981DA8102D3BC294159D171D72810FDF7C6A691DEF02F0F7AF3FDC'),
      hexDecode('53FA9E08BA5243CBCB0D797C5EE83BC6728E539EB76C2D0BF0F971EE4E909971'),
    ];

    final msg = hexDecode(
        '599C67EA410D005B9DA90817CF03ED3B1C868E4DA4EDF00A5880B0082C237869');

    NoncePair pairFrom(Uint8List pnonce) =>
        NoncePair(r1: pnonce.sublist(0, 33), r2: pnonce.sublist(33, 66));

    // valid_test_case 0: nonce_indices=[0,1], key_indices=[0,1], no tweaks,
    //   psig_indices=[0,1] -> expected final sig.
    test('sig_agg case 0 (2-of-2, no tweaks)', () {
      final aggKey = AggregatedKey.fromKeys([pubkeys[0], pubkeys[1]]);
      final session = NonceSession(aggKey: aggKey, message: msg);
      session.addNonce(pairFrom(pnonces[0]));
      session.addNonce(pairFrom(pnonces[1]));

      final partials = [
        PartialSig(signerKey: pubkeys[0], partialS: psigs[0]),
        PartialSig(signerKey: pubkeys[1], partialS: psigs[1]),
      ];

      final combined = PartialSig.combine(aggKey, session, partials);
      expect(combined.length, 64);
      expect(
        hexEncode(combined).toUpperCase(),
        '041DA22223CE65C92C9A0D6C2CAC828AAF1EEE56304FEC371DDF91EBB2B9EF09'
        '12F1038025857FEDEB3FF696F8B99FA4BB2C5812F6095A2E0004EC99CE18DE1E',
      );
    });

    // valid_test_case 1: nonce_indices=[0,2], key_indices=[0,2], no tweaks,
    //   psig_indices=[2,3].
    test('sig_agg case 1 (2-of-2, different keys)', () {
      final aggKey = AggregatedKey.fromKeys([pubkeys[0], pubkeys[2]]);
      final session = NonceSession(aggKey: aggKey, message: msg);
      session.addNonce(pairFrom(pnonces[0]));
      session.addNonce(pairFrom(pnonces[2]));

      final partials = [
        PartialSig(signerKey: pubkeys[0], partialS: psigs[2]),
        PartialSig(signerKey: pubkeys[2], partialS: psigs[3]),
      ];

      final combined = PartialSig.combine(aggKey, session, partials);
      expect(combined.length, 64);
      expect(
        hexEncode(combined).toUpperCase(),
        '1069B67EC3D2F3C7C08291ACCB17A9C9B8F2819A52EB5DF8726E17E7D6B52E9'
        'F01800260A7E9DAC450F4BE522DE4CE12BA91AEAF2B4279219EF74BE1D286ADD9',
      );
    });
  });
}
