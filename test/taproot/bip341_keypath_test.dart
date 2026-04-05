import 'dart:typed_data';

import 'package:coin/coin.dart';
import 'package:test/test.dart';

/// BIP-341 keyPathSpending vectors from
/// https://raw.githubusercontent.com/bitcoin/bips/master/bip-0341/wallet-test-vectors.json
/// (the single `keyPathSpending` object). All signatures use aux_rand = 32
/// zero bytes, so they are byte-reproducible.
const _rawUnsignedTx =
    '02000000097de20cbff686da83a54981d2b9bab3586f4ca7e48f57f5b55963115f3b334e9c'
    '010000000000000000d7b7cab57b1393ace2d064f4d4a2cb8af6def61273e127517d44759b'
    '6dafdd990000000000fffffffff8e1f583384333689228c5d28eac13366be082dc57441760'
    'd957275419a418420000000000fffffffff0689180aa63b30cb162a73c6d2a38b7eeda2a83'
    'ece74310fda0843ad604853b0100000000feffffffaa5202bdf6d8ccd2ee0f0202afbbb746'
    '1d9264a25e5bfd3c5a52ee1239e0ba6c0000000000feffffff956149bdc66faa968eb2be2d'
    '2faa29718acbfe3941215893a2a3446d32acd050000000000000000000e664b9773b88c09c'
    '32cb70a2a3e4da0ced63b7ba3b22f848531bbb1d5d5f4c94010000000000000000e9aa6b8e'
    '6c9de67619e6a3924ae25696bb7b694bb677a632a74ef7eadfd4eabf0000000000ffffffff'
    'a778eb6a263dc090464cd125c466b5a99667720b1c110468831d058aa1b82af10100000000'
    'ffffffff0200ca9a3b000000001976a91406afd46bcdfd22ef94ac122aa11f241244a37ecc'
    '88ac807840cb0000000020ac9a87f5594be208f8532db38cff670c450ed2fea8fcdefcc9a6'
    '63f78bab962b0065cd1d';

/// utxosSpent: [scriptPubKey hex, amountSats]
const _utxos = <List<dynamic>>[
  ['512053a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343', 420000000],
  ['5120147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3', 462000000],
  ['76a914751e76e8199196d454941c45d1b3a323f1433bd688ac', 294000000],
  ['5120e4d810fd50586274face62b8a807eb9719cef49c04177cc6b76a9a4251d5450e', 504000000],
  ['512091b64d5324723a985170e4dc5a0f84c041804f2cd12660fa5dec09fc21783605', 630000000],
  ['00147dd65592d0ab2fe0d0257d571abf032cd9db93dc', 378000000],
  ['512075169f4001aa68f15bbed28b218df1d0a62cbbcf1188c6665110c293c907b831', 672000000],
  ['5120712447206d7a5238acc7ff53fbe94a3b64539ad291c7cdbc490b7577e4b17df5', 546000000],
  ['512077e30a5522dd9f894c3f8b8bd4c4b2cf82ca7da8a3ea6a239655c39c050ab220', 588000000],
];

/// inputSpending entries.
class _Vec {
  final int txinIndex;
  final String internalPrivkey;
  final String? merkleRoot;
  final int hashType;
  final String tweak;
  final String tweakedPrivkey;
  final String sigHash;
  final String witness;
  const _Vec(this.txinIndex, this.internalPrivkey, this.merkleRoot,
      this.hashType, this.tweak, this.tweakedPrivkey, this.sigHash, this.witness);
}

const _vectors = <_Vec>[
  _Vec(0, '6b973d88838f27366ed61c9ad6367663045cb456e28335c109e30717ae0c6baa',
      null, 3,
      'b86e7be8f39bab32a6f2c0443abbc210f0edac0e2c53d501b36b64437d9c6c70',
      '2405b971772ad26915c8dcdf10f238753a9b837e5f8e6a86fd7c0cce5b7296d9',
      '2514a6272f85cfa0f45eb907fcb0d121b808ed37c6ea160a5a9046ed5526d555',
      'ed7c1647cb97379e76892be0cacff57ec4a7102aa24296ca39af7541246d8ff1'
      '4d38958d4cc1e2e478e4d4a764bbfd835b16d4e314b72937b29833060b87276c03'),
  _Vec(1, '1e4da49f6aaf4e5cd175fe08a32bb5cb4863d963921255f33d3bc31e1343907f',
      '5b75adecf53548f3ec6ad7d78383bf84cc57b55a3127c72b9a2481752dd88b21', 131,
      'cbd8679ba636c1110ea247542cfbd964131a6be84f873f7f3b62a777528ed001',
      'ea260c3b10e60f6de018455cd0278f2f5b7e454be1999572789e6a9565d26080',
      '325a644af47e8a5a2591cda0ab0723978537318f10e6a63d4eed783b96a71a4d',
      '052aedffc554b41f52b521071793a6b88d6dbca9dba94cf34c83696de0c1ec35'
      'ca9c5ed4ab28059bd606a4f3a657eec0bb96661d42921b5f50a95ad33675b54f83'),
  _Vec(3, 'd3c7af07da2d54f7a7735d3d0fc4f0a73164db638b2f2f7c43f711f6d4aa7e64',
      'c525714a7f49c28aedbbba78c005931a81c234b2f6c99a73e4d06082adc8bf2b', 1,
      '6af9e28dbf9d6aaf027696e2598a5b3d056f5fd2355a7fd5a37a0e5008132d30',
      '97323385e57015b75b0339a549c56a948eb961555973f0951f555ae6039ef00d',
      'bf013ea93474aa67815b1b6cc441d23b64fa310911d991e713cd34c7f5d46669',
      'ff45f742a876139946a149ab4d9185574b98dc919d2eb6754f8abaa59d18b025'
      '637a3aa043b91817739554f4ed2026cf8022dbd83e351ce1fabc272841d2510a01'),
  _Vec(4, 'f36bb07a11e469ce941d16b63b11b9b9120a84d9d87cff2c84a8d4affb438f4e',
      'ccbd66c6f7e8fdab47b3a486f59d28262be857f30d4773f2d5ea47f7761ce0e2', 0,
      'b57bfa183d28eeb6ad688ddaabb265b4a41fbf68e5fed2c72c74de70d5a786f4',
      'a8e7aa924f0d58854185a490e6c41f6efb7b675c0f3331b7f14b549400b4d501',
      '4f900a0bae3f1446fd48490c2958b5a023228f01661cda3496a11da502a7f7ef',
      'b4010dd48a617db09926f729e79c33ae0b4e94b79f04a1ae93ede6315eb3669d'
      'e185a17d2b0ac9ee09fd4c64b678a0b61a0a86fa888a273c8511be83bfd6810f'),
  _Vec(6, '415cfe9c15d9cea27d8104d5517c06e9de48e2f986b695e4f5ffebf230e725d8',
      '2f6b2c5397b6d68ca18e09a3f05161668ffe93a988582d55c6f07bd5b3329def', 2,
      '6579138e7976dc13b6a92f7bfd5a2fc7684f5ea42419d43368301470f3b74ed9',
      '241c14f2639d0d7139282aa6abde28dd8a067baa9d633e4e7230287ec2d02901',
      '15f25c298eb5cdc7eb1d638dd2d45c97c4c59dcaec6679cfc16ad84f30876b85',
      'a3785919a2ce3c4ce26f298c3d51619bc474ae24014bcdd31328cd8cfbab2eff'
      '3395fa0a16fe5f486d12f22a9cedded5ae74feb4bbe5351346508c5405bcfee002'),
  _Vec(7, 'c7b0e81f0a9a0b0499e112279d718cca98e79a12e2f137c72ae5b213aad0d103',
      '6c2dc106ab816b73f9d07e3cd1ef2c8c1256f519748e0813e4edd2405d277bef', 130,
      '9e0517edc8259bb3359255400b23ca9507f2a91cd1e4250ba068b4eafceba4a9',
      '65b6000cd2bfa6b7cf736767a8955760e62b6649058cbc970b7c0871d786346b',
      'cd292de50313804dabe4685e83f923d2969577191a3e1d2882220dca88cbeb10',
      'ea0c6ba90763c2d3a296ad82ba45881abb4f426b3f87af162dd24d5109edc1cd'
      'd11915095ba47c3a9963dc1e6c432939872bc49212fe34c632cd3ab9fed429c482'),
  _Vec(8, '77863416be0d0665e517e1c375fd6f75839544eca553675ef7fdf4949518ebaa',
      'ab179431c28d3b68fb798957faf5497d69c883c6fb1e1cd9f81483d87bac90cc', 129,
      '639f0281b7ac49e742cd25b7f188657626da1ad169209078e2761cefd91fd65e',
      'ec18ce6af99f43815db543f47b8af5ff5df3b2cb7315c955aa4a86e8143d2bf5',
      'cccb739eca6c13a8a89e6e5cd317ffe55669bbda23f2fd37b0f18755e008edd2',
      'bbc9584a11074e83bc8c6759ec55401f0ae7b03ef290c3139814f545b58a9f81'
      '27258000874f44bc46db7646322107d4d86aec8e73b8719a61fff761d75b5dd981'),
];

// secp256k1 group order n.
final _n = BigInt.parse(
    'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',
    radix: 16);

BigInt _toBig(Uint8List b) {
  var v = BigInt.zero;
  for (final byte in b) {
    v = (v << 8) | BigInt.from(byte);
  }
  return v;
}

List<TxOutput> _prevOuts() => [
      for (final u in _utxos)
        TxOutput(
            value: BigInt.from(u[1] as int),
            scriptPubKey: hexDecode(u[0] as String)),
    ];

void main() {
  setUpAll(() async {
    await VaultKeeper.initialize();
  });

  group('BIP-341 keyPathSpending - crypto layer', () {
    for (final v in _vectors) {
      test('input ${v.txinIndex} (hashType ${v.hashType}): tweak + sign', () {
        // 1) Tweaked scalar matches the vector up to BIP-340 negation.
        //
        // BIP-341 tweaking is done on the even-Y representation of the
        // internal key: if d*G has odd Y, the secret key is negated before
        // adding the tweak. `Taproot.tweakSecretKey` performs this, so its
        // output equals the vector's tweakedPrivkey up to BIP-340 negation
        // for BOTH Y-parities. (A bare `SecretKey.tweak(t)` would only match
        // for even-Y internal keys - that parity handling was the library
        // bug fixed alongside these vectors.)
        final internal = SecretKey.fromHex(v.internalPrivkey);
        // Apply the given tweak to the even-Y representative of the internal
        // key, mirroring Taproot.tweakSecretKey (the inputs with a script tree
        // supply the merkle-committed tweak directly, so we use it as given
        // rather than recomputing a key-only TapTweak).
        final effective =
            internal.publicKey.yIsEven ? internal : internal.negate();
        final tweaked = effective.tweak(hexDecode(v.tweak));
        expect(tweaked, isNotNull,
            reason: 'tweak should not overflow the curve order');
        final got = _toBig(tweaked!.bytes);
        final want = _toBig(hexDecode(v.tweakedPrivkey));
        expect(got == want || got == _n - want, isTrue,
            reason: 'tweaked privkey must equal tweakedPrivkey or n - it; '
                'got ${tweaked.toHex()}');

        // 2) Signing the vector sigHash with the coin-derived tweaked scalar
        //    and aux_rand = zeros must reproduce the 64-byte witness exactly.
        final sig = SchnorrSig.sign(hexDecode(v.sigHash), tweaked.bytes,
            auxRand: Uint8List(32));
        final expectedSig = hexDecode(v.witness).sublist(0, 64);
        expect(sig.bytes, equals(expectedSig));

        // 3) The signature verifies against the output key (scriptPubKey[2:]).
        final scriptPubKey = hexDecode(_utxos[v.txinIndex][0] as String);
        final outputKey = scriptPubKey.sublist(2, 34);
        expect(sig.verify(hexDecode(v.sigHash), outputKey), isTrue);
      });
    }
  });

  group('BIP-341 keyPathSpending - output key (tweakedPubkey, both parities)',
      () {
    // Output-key check. The taproot output key is
    // scriptPubKey[2:] of the input's spent UTXO. BIP-341
    // `taproot_tweak_pubkey` tweaks the EVEN-Y lift (lift_x = 0x02||x-only) of
    // the internal key - NOT the raw-parity internal point. For inputs whose
    // internal key has an ODD Y (here: txin 3, 6, 8), tweaking the raw point
    // would yield the WRONG output key; that was the just-fixed bug. We tweak
    // the even-Y lift by the vector-supplied `tweak` (the exact curve op
    // `Taproot.tweakedKey` performs) and require it to equal the vector's
    // output key for EVERY input, covering both Y-parities.
    // Inputs 3, 6, 8 have ODD-Y internal keys; 0, 1, 4, 7 are even-Y. (We
    // can't compute parity at group-build time - it needs the initialized
    // vault - so the names list it explicitly for clarity.)
    const oddYInputs = {3, 6, 8};
    for (final v in _vectors) {
      final internalIsEven = !oddYInputs.contains(v.txinIndex);
      test('input ${v.txinIndex} (internal Y '
          '${internalIsEven ? 'even' : 'ODD'}): even-Y lift + tweak '
          '== scriptPubKey output key', () {
        // x-only of the internal key, then its even-Y lift 0x02||x.
        final internalXOnly =
            SecretKey.fromHex(v.internalPrivkey).publicKey.xOnly;
        // Confirm the documented parity actually holds.
        expect(SecretKey.fromHex(v.internalPrivkey).publicKey.yIsEven,
            equals(internalIsEven),
            reason: 'documented Y-parity for input ${v.txinIndex} must hold');
        final evenLift =
            Uint8List.fromList([0x02, ...internalXOnly]);

        // The same curve operation Taproot.tweakedKey uses.
        final tweaked = VaultKeeper.vault.curve
            .publicKeyTweakAdd(evenLift, hexDecode(v.tweak));
        expect(tweaked, isNotNull);
        final outputKey = PublicKey(tweaked!).xOnly;

        // Expected output key = scriptPubKey[2:34] of the UTXO.
        final scriptPubKey = hexDecode(_utxos[v.txinIndex][0] as String);
        final expected = scriptPubKey.sublist(2, 34);
        expect(hexEncode(outputKey), equals(hexEncode(expected)),
            reason: 'tweaked even-Y output key must equal the BIP-341 '
                'output key (scriptPubKey[2:]) for input '
                '${v.txinIndex}');
      });
    }

    test('input 0 (null merkleRoot): Taproot.tweakedKey == output key', () {
      // For the key-path-only input, the public `Taproot.tweakedKey` accessor
      // (internal key + key-only TapTweak, no script tree) must reproduce the
      // output key directly.
      final v = _vectors[0]; // merkleRoot == null
      final internalXOnly =
          SecretKey.fromHex(v.internalPrivkey).publicKey.xOnly;
      // Construct the internal PublicKey from its even-Y lift, mirroring how a
      // watch-only/bip86 path supplies an x-only-derived internal key.
      final internalKey =
          PublicKey(Uint8List.fromList([0x02, ...internalXOnly]));
      final taproot = Taproot(internalKey: internalKey);
      // Sanity: the key-only TapTweak must equal the vector tweak.
      expect(hexEncode(taproot.tweak), equals(v.tweak));

      final scriptPubKey = hexDecode(_utxos[v.txinIndex][0] as String);
      final expected = scriptPubKey.sublist(2, 34);
      expect(hexEncode(taproot.tweakedKey), equals(hexEncode(expected)));
    });

    test('ODD-Y internal key: tweakedKey is consistent with tweakSecretKey',
        () {
      // Regression for the parity bug: for an explicitly ODD-Y internal key,
      // the x-only output key from Taproot.tweakedKey must be the public key
      // of the scalar produced by tweakSecretKey (which negates odd-Y). A
      // signature made with that tweaked scalar must verify against the output
      // key - i.e. the tweaked-point and tweaked-scalar paths agree.
      final v = _vectors.firstWhere((e) => e.txinIndex == 3); // odd-Y
      final internal = SecretKey.fromHex(v.internalPrivkey);
      expect(internal.publicKey.yIsEven, isFalse,
          reason: 'this regression requires an odd-Y internal key');

      // Key-path-only Taproot (no script tree) over the odd-Y internal key.
      final taproot = Taproot(internalKey: internal.publicKey);
      final outputKey = taproot.tweakedKey;

      final tweakedScalar = taproot.tweakSecretKey(internal);
      final msg = hexDecode(v.sigHash);
      final sig =
          SchnorrSig.sign(msg, tweakedScalar.bytes, auxRand: Uint8List(32));
      expect(sig.verify(msg, outputKey), isTrue,
          reason: 'tweaked-scalar signature must verify against the '
              'tweaked-point output key for an odd-Y internal key');
    });
  });

  group('BIP-341 keyPathSpending - sighash (TaprootSigHasher)', () {
    final tx = Tx.fromHex(_rawUnsignedTx);
    final hasher = TaprootSigHasher(prevOuts: _prevOuts());

    for (final v in _vectors) {
      test('input ${v.txinIndex}: sigHash matches (hashType ${v.hashType})',
          () {
        final h = hasher.hash(
            tx, v.txinIndex, SigHashType.fromFlag(v.hashType));
        expect(hexEncode(h), equals(v.sigHash));
      });
    }
  });

  group('BIP-341 keyPathSpending - builder/witness path', () {
    test('input 0 (null merkleRoot, SINGLE): full bip86-style key-path sign',
        () {
      final v = _vectors[0]; // merkleRoot == null, hashType 3
      final tx = Tx.fromHex(_rawUnsignedTx);
      final hasher = TaprootSigHasher(prevOuts: _prevOuts());

      // Derive the taproot tweak the same way a key-path (bip86) signer does:
      // no script tree, so tweak = TapTweak(internalPubkey).
      final internal = SecretKey.fromHex(v.internalPrivkey);
      final taproot = Taproot(internalKey: internal.publicKey);
      expect(hexEncode(taproot.tweak), equals(v.tweak));

      final tweakedKey = taproot.tweakSecretKey(internal);
      final sighashType = SigHashType.fromFlag(v.hashType);
      final sigHash = hasher.hash(tx, v.txinIndex, sighashType);
      expect(hexEncode(sigHash), equals(v.sigHash));

      final sig = SchnorrSig.sign(sigHash, tweakedKey.bytes,
          auxRand: Uint8List(32));
      final inputSig =
          SchnorrInputSig(sig: sig.bytes, hashType: sighashType);

      // Build the actual witness via TaprootKeyInput and confirm the encoded
      // witness item equals the vector witness (65 bytes ending 0x03).
      final keyInput = TaprootKeyInput(
        prevOut: tx.inputs[v.txinIndex].prevOut,
        inputSig: inputSig,
        sequence: tx.inputs[v.txinIndex].sequence,
      );
      expect(keyInput.witness.length, 1);
      expect(hexEncode(keyInput.witness[0]), equals(v.witness));
    });

    test('a SIGHASH_DEFAULT (0x00) input yields a bare 64-byte witness', () {
      // Input txinIndex 4 (vectors[3]) has hashType 0 (SIGHASH_DEFAULT) and a
      // script-tree tweak supplied by the vector, so we use the given tweak
      // directly (parity-corrected) rather than recomputing it from a tree.
      final v = _vectors[3]; // hashType 0
      final tx = Tx.fromHex(_rawUnsignedTx);
      final hasher = TaprootSigHasher(prevOuts: _prevOuts());

      final internal = SecretKey.fromHex(v.internalPrivkey);
      final effective =
          internal.publicKey.yIsEven ? internal : internal.negate();
      final tweakedKey = effective.tweak(hexDecode(v.tweak))!;
      final sigHash = hasher.hash(tx, v.txinIndex, SigHashType.taprootDefault);
      expect(hexEncode(sigHash), equals(v.sigHash));
      final sig =
          SchnorrSig.sign(sigHash, tweakedKey.bytes, auxRand: Uint8List(32));
      final inputSig = SchnorrInputSig(
          sig: sig.bytes, hashType: SigHashType.taprootDefault);
      expect(inputSig.toBytes().length, 64);
      expect(hexEncode(inputSig.toBytes()), equals(v.witness));
    });
  });

  group('SchnorrInputSig encoding regression', () {
    final sig64 = Uint8List(64);
    for (var i = 0; i < 64; i++) {
      sig64[i] = i + 1;
    }

    test('SIGHASH_DEFAULT (0x00) encodes to bare 64 bytes', () {
      final s = SchnorrInputSig(
          sig: sig64, hashType: SigHashType.taprootDefault);
      final bytes = s.toBytes();
      expect(bytes.length, 64);
      expect(bytes, equals(sig64));
    });

    test('SIGHASH_ALL (0x01) encodes to 65 bytes ending 0x01', () {
      final s = SchnorrInputSig(sig: sig64, hashType: SigHashType.all);
      final bytes = s.toBytes();
      expect(bytes.length, 65);
      expect(bytes[64], 0x01);
      expect(bytes.sublist(0, 64), equals(sig64));
    });

    test('fromBytes: 64 bytes -> SIGHASH_DEFAULT', () {
      final s = SchnorrInputSig.fromBytes(sig64);
      expect(s.hashType, SigHashType.taprootDefault);
      expect(s.sig, equals(sig64));
    });

    test('fromBytes: 65 bytes ending 0x01 -> SIGHASH_ALL', () {
      final raw = Uint8List.fromList([...sig64, 0x01]);
      final s = SchnorrInputSig.fromBytes(raw);
      expect(s.hashType, SigHashType.all);
      expect(s.sig, equals(sig64));
    });

    test('round-trip DEFAULT and ALL', () {
      final d = SchnorrInputSig(
          sig: sig64, hashType: SigHashType.taprootDefault);
      expect(SchnorrInputSig.fromBytes(d.toBytes()).hashType,
          SigHashType.taprootDefault);
      final a = SchnorrInputSig(sig: sig64, hashType: SigHashType.all);
      expect(SchnorrInputSig.fromBytes(a.toBytes()).hashType, SigHashType.all);
    });

    test('fromBytes rejects 65-byte input with trailing 0x00', () {
      final raw = Uint8List.fromList([...sig64, 0x00]);
      expect(() => SchnorrInputSig.fromBytes(raw), throwsArgumentError);
    });
  });
}
