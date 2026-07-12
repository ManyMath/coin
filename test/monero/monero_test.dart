import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:coin/coin.dart';
import 'package:coin/coin_monero.dart';

// Ed25519 curve constants (G, l) from RFC 8032 sec. 5.1:
// https://datatracker.ietf.org/doc/html/rfc8032#section-5.1
//
// Key-derivation vectors (spend key -> view key, address encoding) from the
// Cryptonote Address Tests tool by luigi1111:
// https://github.com/luigi1111/xmr.llcoins.net  (site/addresstests.html)
// and from monero-project/monero unit tests:
// https://github.com/monero-project/monero/tree/master/tests
//
// Pedersen commitment uses the standard Monero H generator; see
// https://github.com/monero-project/monero/blob/master/src/ringct/rctTypes.h
//
// Monero key/address/subaddress/stealth/key-image/Pedersen vectors from the
// staging branch of github.com/ManyMath/monero-rust.
//
// Polyseed (16-word) vectors from tevador/polyseed (the C reference,
// https://github.com/tevador/polyseed), the Rust monero-wallet-util/polyseed,
// and cake-tech polyseed_dart.
void main() {
  setUpAll(() async {
    await initCoin();
  });

  group('Ed25519 math', () {
    test('generator point G is on the curve', () {
      expect(edIsOnCurve(ed25519G), isTrue);
    });

    test('identity element: G + identity = G', () {
      final identity = EdPoint.infinity();
      final result = edPointAdd(ed25519G, identity);
      expect(result, equals(ed25519G));
    });

    test('identity element: identity + G = G', () {
      final identity = EdPoint.infinity();
      final result = edPointAdd(identity, ed25519G);
      expect(result, equals(ed25519G));
    });

    test('scalar mult: 0 * G = identity', () {
      final result = edScalarMult(BigInt.zero, ed25519G);
      expect(result.isInfinity, isTrue);
    });

    test('scalar mult: 1 * G = G', () {
      final result = edScalarMult(BigInt.one, ed25519G);
      expect(result, equals(ed25519G));
    });

    test('group order: l * G = identity', () {
      final result = edScalarMult(ed25519L, ed25519G);
      expect(result.isInfinity, isTrue);
    });

    test('point compression round-trip: compress(decompress(G_bytes)) == G_bytes', () {
      final gBytes = edPointToBytes(ed25519G);
      expect(gBytes.length, 32);
      final decompressed = edBytesToPoint(gBytes);
      expect(edIsOnCurve(decompressed), isTrue);
      final recompressed = edPointToBytes(decompressed);
      expect(recompressed, equals(gBytes));
    });

    test('edIsOnCurve returns false for invalid points', () {
      final invalid = EdPoint(BigInt.from(42), BigInt.from(99));
      expect(edIsOnCurve(invalid), isFalse);
    });

    test('identity element is on the curve', () {
      expect(edIsOnCurve(EdPoint.infinity()), isTrue);
    });

    test('scalar reduce produces value less than l', () {
      final bigBytes = Uint8List(64);
      for (var i = 0; i < 64; i++) {
        bigBytes[i] = 0xff;
      }
      final reduced = edScalarReduce(bigBytes);
      expect(reduced < ed25519L, isTrue);
      expect(reduced >= BigInt.zero, isTrue);
    });

    test('2 * G = G + G', () {
      final doubleG = edScalarMult(BigInt.two, ed25519G);
      final addGG = edPointAdd(ed25519G, ed25519G);
      expect(doubleG, equals(addGG));
    });
  });

  group('Key derivation', () {
    test('English seed: spend key -> view key derivation', () {
      final spendKey = hexDecode(
          'c0af65c0dd837e666b9d0dfed62745f4df35aed7ea619b2798a709f0fe545403');
      final expectedViewKey =
          '513ba91c538a5a9069e0094de90e927c0cd147fa10428ce3ac1afd49f63e3b01';

      final keys = MoneroKeys.fromSpendKey(spendKey);
      expect(hexEncode(keys.privateViewKey), expectedViewKey);
    });

    test('Chinese seed: entropy -> view key derivation', () {
      final entropy = hexDecode(
          'a5e4fff1706ef9212993a69f246f5c95ad6d84371692d63e9bb0ea112a58340d');
      final expectedViewKey =
          '1176c43ce541477ea2f3ef0b49b25112b084e26b8a843e1304ac4677b74cdf02';

      final keys = MoneroKeys.fromSpendKey(entropy);
      expect(hexEncode(keys.privateViewKey), expectedViewKey);
    });

    test('French seed: entropy -> view key derivation', () {
      final entropy = hexDecode(
          '2dd39ff1a4628a94b5c2ec3e42fb3dfe15c2b2f010154dc3b3de6791e805b904');
      final expectedViewKey =
          '6725b32230400a1032f31d622b44c3a227f88258939b14a7c72e00939e7bdf0e';

      final keys = MoneroKeys.fromSpendKey(entropy);
      expect(hexEncode(keys.privateViewKey), expectedViewKey);
    });

    test('Polyseed: spend key -> all key derivation', () {
      final spendKey = hexDecode(
          'c584b326f1a8472e210d80e4fc87271ffa371f94b95a0794eef80e851fb4e303');
      final expectedViewKey =
          '3b8ffd9a88e9cdbbd311629c38d696df07551bcea08e0df1942507db8f832007';
      final expectedPubSpend =
          '759ca40019178944aa2fe8062dfe61af1e3678be2ceed67fe83c34edde8492c9';
      final expectedPubView =
          '0d57d0165de6015305e5c1e2c54f75cc9a385348929980f1db140ac459e9958e';

      final keys = MoneroKeys.fromSpendKey(spendKey);
      expect(hexEncode(keys.privateViewKey), expectedViewKey);
      expect(hexEncode(keys.publicSpendKey), expectedPubSpend);
      expect(hexEncode(keys.publicViewKey), expectedPubView);
    });

    test('public key derivation: private * G produces correct public key', () {
      final spendKey = hexDecode(
          'c584b326f1a8472e210d80e4fc87271ffa371f94b95a0794eef80e851fb4e303');
      final keys = MoneroKeys.fromSpendKey(spendKey);

      final spendScalar = edBytesToBigInt(keys.privateSpendKey);
      final pubPoint = edScalarMult(spendScalar, ed25519G);
      final pubBytes = edPointToBytes(pubPoint);
      expect(pubBytes, equals(keys.publicSpendKey));
    });

    test('generated keys have valid scalars (< l)', () {
      final keys = MoneroKeys.generate();
      final spendScalar = edBytesToBigInt(keys.privateSpendKey);
      final viewScalar = edBytesToBigInt(keys.privateViewKey);
      expect(spendScalar > BigInt.zero, isTrue);
      expect(spendScalar < ed25519L, isTrue);
      expect(viewScalar > BigInt.zero, isTrue);
      expect(viewScalar < ed25519L, isTrue);
    });

    test('public keys are valid curve points', () {
      final keys = MoneroKeys.generate();
      final spendPoint = edBytesToPoint(keys.publicSpendKey);
      final viewPoint = edBytesToPoint(keys.publicViewKey);
      expect(edIsOnCurve(spendPoint), isTrue);
      expect(edIsOnCurve(viewPoint), isTrue);
    });

    test('invalid seed length throws', () {
      expect(() => MoneroKeys.fromSeed(Uint8List(31)), throwsArgumentError);
      expect(() => MoneroKeys.fromSeed(Uint8List(33)), throwsArgumentError);
    });

    test('invalid spend key length throws', () {
      expect(
          () => MoneroKeys.fromSpendKey(Uint8List(31)), throwsArgumentError);
      expect(
          () => MoneroKeys.fromSpendKey(Uint8List(33)), throwsArgumentError);
    });

    test('zero spend key throws', () {
      expect(
          () => MoneroKeys.fromSpendKey(Uint8List(32)), throwsArgumentError);
    });
  });

  group('Address encoding/decoding', () {
    final spendPubKey = hexDecode(
        'f8631661f6ab4e6fda310c797330d86e23a682f20d5bc8cc27b18051191f16d7');
    final viewPubKey = hexDecode(
        '4a1535063ad1fee2dabbf909d4fd9a873e29541b401f0944754e17c9a41820ce');

    const expectedStandardAddr =
        '4B33mFPMq6mKi7Eiyd5XuyKRVMGVZz1Rqb9ZTyGApXW5d1aT7UBDZ89ewmnWFkzJ5wPd2SFbn313vCT8a4E2Qf4KQH4pNey';

    test('encode standard address from known keys', () {
      final addr = MoneroStandardAddr(spendPubKey, viewPubKey);
      final encoded = addr.encodeMainnet();
      expect(encoded, expectedStandardAddr);
    });

    test('decode known standard address and verify keys', () {
      final addr = MoneroAddr.mainnet(expectedStandardAddr);
      expect(addr, isA<MoneroStandardAddr>());
      expect(addr.addrType, MoneroAddrType.standard);
      expect(hexEncode(addr.publicSpendKey),
          'f8631661f6ab4e6fda310c797330d86e23a682f20d5bc8cc27b18051191f16d7');
      expect(hexEncode(addr.publicViewKey),
          '4a1535063ad1fee2dabbf909d4fd9a873e29541b401f0944754e17c9a41820ce');
    });

    test('encode integrated address with payment ID', () {
      final paymentId = hexDecode('b8963a57855cf73f');
      final addr =
          MoneroIntegratedAddr(spendPubKey, viewPubKey, paymentId);
      final encoded = addr.encodeMainnet();

      const expectedIntegratedAddr =
          '4Ljin4CrSNHKi7Eiyd5XuyKRVMGVZz1Rqb9ZTyGApXW5d1aT7UBDZ89ewmnWFkzJ5wPd2SFbn313vCT8a4E2Qf4KbaTH6MnpXSn88oBX35';
      expect(encoded, expectedIntegratedAddr);
    });

    test('decode integrated address and verify keys and payment ID', () {
      const integratedAddr =
          '4Ljin4CrSNHKi7Eiyd5XuyKRVMGVZz1Rqb9ZTyGApXW5d1aT7UBDZ89ewmnWFkzJ5wPd2SFbn313vCT8a4E2Qf4KbaTH6MnpXSn88oBX35';
      final addr = MoneroAddr.mainnet(integratedAddr);
      expect(addr, isA<MoneroIntegratedAddr>());
      expect(addr.addrType, MoneroAddrType.integrated);
      expect(hexEncode(addr.publicSpendKey),
          'f8631661f6ab4e6fda310c797330d86e23a682f20d5bc8cc27b18051191f16d7');
      expect(hexEncode(addr.publicViewKey),
          '4a1535063ad1fee2dabbf909d4fd9a873e29541b401f0944754e17c9a41820ce');
      expect(hexEncode((addr as MoneroIntegratedAddr).paymentId),
          'b8963a57855cf73f');
    });

    test('encode subaddress from known keys', () {
      final subSpendKey = hexDecode(
          'fe358188b528335ad1cfdc24a22a23988d742c882b6f19a602892eaab3c1b62b');
      final subViewKey = hexDecode(
          '9bc2b464de90d058468522098d5610c5019c45fd1711a9517db1eea7794f5470');
      final addr = MoneroSubaddr(subSpendKey, subViewKey);
      final encoded = addr.encodeMainnet();

      const expectedSubaddr =
          '8C5zHM5ud8nGC4hC2ULiBLSWx9infi8JUUmWEat4fcTf8J4H38iWYVdFmPCA9UmfLTZxD43RsyKnGEdZkoGij6csDeUnbEB';
      expect(encoded, expectedSubaddr);
    });

    test('decode subaddress and verify keys', () {
      const subAddr =
          '8C5zHM5ud8nGC4hC2ULiBLSWx9infi8JUUmWEat4fcTf8J4H38iWYVdFmPCA9UmfLTZxD43RsyKnGEdZkoGij6csDeUnbEB';
      final addr = MoneroAddr.mainnet(subAddr);
      expect(addr, isA<MoneroSubaddr>());
      expect(addr.addrType, MoneroAddrType.subaddress);
      expect(hexEncode(addr.publicSpendKey),
          'fe358188b528335ad1cfdc24a22a23988d742c882b6f19a602892eaab3c1b62b');
      expect(hexEncode(addr.publicViewKey),
          '9bc2b464de90d058468522098d5610c5019c45fd1711a9517db1eea7794f5470');
    });

    test('round-trip: decode(encode(standard addr)) recovers original keys', () {
      final addr = MoneroStandardAddr(spendPubKey, viewPubKey);
      final encoded = addr.encodeMainnet();
      final decoded = MoneroAddr.mainnet(encoded);
      expect(decoded.publicSpendKey, equals(spendPubKey));
      expect(decoded.publicViewKey, equals(viewPubKey));
    });

    test('round-trip: decode(encode(integrated addr)) recovers keys and payment ID', () {
      final paymentId = hexDecode('b8963a57855cf73f');
      final addr =
          MoneroIntegratedAddr(spendPubKey, viewPubKey, paymentId);
      final encoded = addr.encodeMainnet();
      final decoded = MoneroAddr.mainnet(encoded) as MoneroIntegratedAddr;
      expect(decoded.publicSpendKey, equals(spendPubKey));
      expect(decoded.publicViewKey, equals(viewPubKey));
      expect(decoded.paymentId, equals(paymentId));
    });

    test('round-trip: decode(encode(subaddr)) recovers original keys', () {
      final subSpendKey = hexDecode(
          'fe358188b528335ad1cfdc24a22a23988d742c882b6f19a602892eaab3c1b62b');
      final subViewKey = hexDecode(
          '9bc2b464de90d058468522098d5610c5019c45fd1711a9517db1eea7794f5470');
      final addr = MoneroSubaddr(subSpendKey, subViewKey);
      final encoded = addr.encodeMainnet();
      final decoded = MoneroAddr.mainnet(encoded);
      expect(decoded.publicSpendKey, equals(subSpendKey));
      expect(decoded.publicViewKey, equals(subViewKey));
    });

    test('polyseed: mainnet standard address', () {
      final spendKey = hexDecode(
          'c584b326f1a8472e210d80e4fc87271ffa371f94b95a0794eef80e851fb4e303');
      final keys = MoneroKeys.fromSpendKey(spendKey);
      final addr =
          MoneroStandardAddr(keys.publicSpendKey, keys.publicViewKey);
      final encoded = addr.encodeMainnet();
      expect(encoded,
          '465cUW8wTMSCV8oVVh7CuWWHs7yeB1oxhNPrsEM5FKSqadTXmobLqsNEtRnyGsbN1rbDuBtWdtxtXhTJda1Lm9vcH2ZdrD1');
    });

    test('polyseed: stagenet standard address', () {
      final spendKey = hexDecode(
          'c584b326f1a8472e210d80e4fc87271ffa371f94b95a0794eef80e851fb4e303');
      final keys = MoneroKeys.fromSpendKey(spendKey);
      final addr =
          MoneroStandardAddr(keys.publicSpendKey, keys.publicViewKey);
      final encoded = addr.encodeStagenet();
      expect(encoded,
          '56HeZM3u6xYCV8oVVh7CuWWHs7yeB1oxhNPrsEM5FKSqadTXmobLqsNEtRnyGsbN1rbDuBtWdtxtXhTJda1Lm9vcH73iSWn');
    });

    test('decode with wrong network bytes throws', () {
      expect(
        () => MoneroAddr.testnet(expectedStandardAddr),
        throwsA(isA<FormatException>()),
      );
    });

    test('invalid address string throws', () {
      expect(
        () => MoneroAddr.mainnet('notavalidmoneroaddress'),
        throwsA(anything),
      );
    });

    test('invalid key length in MoneroStandardAddr throws', () {
      expect(
        () => MoneroStandardAddr(Uint8List(31), viewPubKey),
        throwsArgumentError,
      );
      expect(
        () => MoneroStandardAddr(spendPubKey, Uint8List(33)),
        throwsArgumentError,
      );
    });

    test('invalid payment ID length throws', () {
      expect(
        () => MoneroIntegratedAddr(spendPubKey, viewPubKey, Uint8List(7)),
        throwsArgumentError,
      );
      expect(
        () => MoneroIntegratedAddr(spendPubKey, viewPubKey, Uint8List(9)),
        throwsArgumentError,
      );
    });
  });

  group('Subaddress derivation', () {
    late MoneroKeys keys;

    setUp(() {
      final spendKey = hexDecode(
          'c584b326f1a8472e210d80e4fc87271ffa371f94b95a0794eef80e851fb4e303');
      keys = MoneroKeys.fromSpendKey(spendKey);
    });

    test('subaddress(0,0) returns main keys', () {
      final sub = MoneroSubaddress.derive(keys, 0, 0);
      expect(sub.publicSpendKey, equals(keys.publicSpendKey));
      expect(sub.publicViewKey, equals(keys.publicViewKey));
      expect(sub.accountIndex, 0);
      expect(sub.addressIndex, 0);
    });

    test('subaddress(0,1) on stagenet matches test vector', () {
      final sub = MoneroSubaddress.derive(keys, 0, 1);
      final addr = MoneroSubaddr(sub.publicSpendKey, sub.publicViewKey);
      final encoded = addr.encodeStagenet();
      expect(encoded,
          '7BdZnJevfquGJ4DMR7E6UwAFVrpK1z1NYgd9RQi7YvH3SykuQRKtkNfbXfG4fPqkrGSeGhnCT79Gz1uL1KegPMbz3u6DKCJ');
    });

    test('subaddress(1,1) on stagenet matches test vector', () {
      final sub = MoneroSubaddress.derive(keys, 1, 1);
      final addr = MoneroSubaddr(sub.publicSpendKey, sub.publicViewKey);
      final encoded = addr.encodeStagenet();
      expect(encoded,
          '7AjduMBq2obQFyWuEYYZ6GcmCPDmyFJUpPTNmxiD3bv34cPbi7JzExeUKiieQzdhWoDJKcdn6N11Rf4aW794fmDQVXF8seo');
    });

    test('subaddress keys are valid curve points', () {
      final sub = MoneroSubaddress.derive(keys, 0, 1);
      final spendPoint = edBytesToPoint(sub.publicSpendKey);
      final viewPoint = edBytesToPoint(sub.publicViewKey);
      expect(edIsOnCurve(spendPoint), isTrue);
      expect(edIsOnCurve(viewPoint), isTrue);
    });

    test('different indices produce different subaddresses', () {
      final sub01 = MoneroSubaddress.derive(keys, 0, 1);
      final sub02 = MoneroSubaddress.derive(keys, 0, 2);
      final sub10 = MoneroSubaddress.derive(keys, 1, 0);

      expect(sub01.publicSpendKey, isNot(equals(sub02.publicSpendKey)));
      expect(sub01.publicSpendKey, isNot(equals(sub10.publicSpendKey)));
      expect(sub02.publicSpendKey, isNot(equals(sub10.publicSpendKey)));
    });

    test('subaddress derivation is deterministic', () {
      final sub1 = MoneroSubaddress.derive(keys, 2, 5);
      final sub2 = MoneroSubaddress.derive(keys, 2, 5);
      expect(sub1.publicSpendKey, equals(sub2.publicSpendKey));
      expect(sub1.publicViewKey, equals(sub2.publicViewKey));
    });
  });

  group('Monero base58', () {
    test('encode/decode empty data', () {
      final encoded = moneroBase58Encode(Uint8List(0));
      expect(encoded, '');
      final decoded = moneroBase58Decode('');
      expect(decoded, equals(Uint8List(0)));
    });

    test('encode/decode round-trip for 1 byte', () {
      final data = Uint8List.fromList([0x42]);
      final encoded = moneroBase58Encode(data);
      final decoded = moneroBase58Decode(encoded);
      expect(decoded, equals(data));
    });

    test('encode/decode round-trip for 8 bytes (full block)', () {
      final data = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]);
      final encoded = moneroBase58Encode(data);
      expect(encoded.length, 11); // full block = 11 chars
      final decoded = moneroBase58Decode(encoded);
      expect(decoded, equals(data));
    });

    test('encode/decode round-trip for 32 bytes', () {
      final data = Uint8List(32);
      for (var i = 0; i < 32; i++) {
        data[i] = i;
      }
      final encoded = moneroBase58Encode(data);
      final decoded = moneroBase58Decode(encoded);
      expect(decoded, equals(data));
    });

    test('encode/decode round-trip for 69 bytes (standard address payload)', () {
      final data = Uint8List(69);
      for (var i = 0; i < 69; i++) {
        data[i] = i & 0xff;
      }
      final encoded = moneroBase58Encode(data);
      final decoded = moneroBase58Decode(encoded);
      expect(decoded, equals(data));
    });

    test('encode/decode round-trip for 77 bytes (integrated address payload)', () {
      final data = Uint8List(77);
      for (var i = 0; i < 77; i++) {
        data[i] = (i * 7 + 3) & 0xff;
      }
      final encoded = moneroBase58Encode(data);
      final decoded = moneroBase58Decode(encoded);
      expect(decoded, equals(data));
    });

    test('decode a known address and re-encode matches', () {
      const addr =
          '4B33mFPMq6mKi7Eiyd5XuyKRVMGVZz1Rqb9ZTyGApXW5d1aT7UBDZ89ewmnWFkzJ5wPd2SFbn313vCT8a4E2Qf4KQH4pNey';
      final decoded = moneroBase58Decode(addr);
      final reencoded = moneroBase58Encode(decoded);
      expect(reencoded, addr);
    });

    test('all-zero bytes encode and decode correctly', () {
      final data = Uint8List(16);
      final encoded = moneroBase58Encode(data);
      final decoded = moneroBase58Decode(encoded);
      expect(decoded, equals(data));
    });

    test('all-0xFF bytes encode and decode correctly', () {
      final data = Uint8List(16);
      for (var i = 0; i < 16; i++) {
        data[i] = 0xff;
      }
      final encoded = moneroBase58Encode(data);
      final decoded = moneroBase58Decode(encoded);
      expect(decoded, equals(data));
    });

    test('invalid base58 character throws FormatException', () {
      expect(
        () => moneroBase58Decode('00000000000'),
        throwsA(isA<FormatException>()),
      );
    });
  });

  group('Stealth address', () {
    late MoneroKeys senderKeys;
    late MoneroKeys recipientKeys;

    setUp(() {
      senderKeys = MoneroKeys.generate();
      recipientKeys = MoneroKeys.generate();
    });

    test('deriveOutputKey + isOurOutput returns true for correct keys', () {
      final txSecretKey = senderKeys.privateSpendKey;
      final outputIndex = 0;

      final outputKey = StealthAddress.deriveOutputKey(
        txSecretKey: txSecretKey,
        recipientViewKey: recipientKeys.publicViewKey,
        recipientSpendKey: recipientKeys.publicSpendKey,
        outputIndex: outputIndex,
      );

      final txPubKey = StealthAddress.txPublicKey(txSecretKey);

      final isOurs = StealthAddress.isOurOutput(
        privateViewKey: recipientKeys.privateViewKey,
        publicSpendKey: recipientKeys.publicSpendKey,
        txPublicKey: txPubKey,
        outputKey: outputKey,
        outputIndex: outputIndex,
      );

      expect(isOurs, isTrue);
    });

    test('isOurOutput returns false for wrong recipient keys', () {
      final txSecretKey = senderKeys.privateSpendKey;
      final outputIndex = 0;

      final outputKey = StealthAddress.deriveOutputKey(
        txSecretKey: txSecretKey,
        recipientViewKey: recipientKeys.publicViewKey,
        recipientSpendKey: recipientKeys.publicSpendKey,
        outputIndex: outputIndex,
      );

      final txPubKey = StealthAddress.txPublicKey(txSecretKey);

      final wrongKeys = MoneroKeys.generate();

      final isOurs = StealthAddress.isOurOutput(
        privateViewKey: wrongKeys.privateViewKey,
        publicSpendKey: wrongKeys.publicSpendKey,
        txPublicKey: txPubKey,
        outputKey: outputKey,
        outputIndex: outputIndex,
      );

      expect(isOurs, isFalse);
    });

    test('isOurOutput returns false for wrong output index', () {
      final txSecretKey = senderKeys.privateSpendKey;

      final outputKey = StealthAddress.deriveOutputKey(
        txSecretKey: txSecretKey,
        recipientViewKey: recipientKeys.publicViewKey,
        recipientSpendKey: recipientKeys.publicSpendKey,
        outputIndex: 0,
      );

      final txPubKey = StealthAddress.txPublicKey(txSecretKey);

      final isOurs = StealthAddress.isOurOutput(
        privateViewKey: recipientKeys.privateViewKey,
        publicSpendKey: recipientKeys.publicSpendKey,
        txPublicKey: txPubKey,
        outputKey: outputKey,
        outputIndex: 1, // wrong index
      );

      expect(isOurs, isFalse);
    });

    test('deriveOutputPrivateKey: privKey * G = outputKey', () {
      final txSecretKey = senderKeys.privateSpendKey;
      final outputIndex = 0;

      final outputKey = StealthAddress.deriveOutputKey(
        txSecretKey: txSecretKey,
        recipientViewKey: recipientKeys.publicViewKey,
        recipientSpendKey: recipientKeys.publicSpendKey,
        outputIndex: outputIndex,
      );

      final txPubKey = StealthAddress.txPublicKey(txSecretKey);

      final outputPrivKey = StealthAddress.deriveOutputPrivateKey(
        privateSpendKey: recipientKeys.privateSpendKey,
        privateViewKey: recipientKeys.privateViewKey,
        txPublicKey: txPubKey,
        outputIndex: outputIndex,
      );

      final scalar = edBytesToBigInt(outputPrivKey) % ed25519L;
      final computed = edPointToBytes(edScalarMult(scalar, ed25519G));
      expect(computed, equals(outputKey));
    });

    test('output key is a valid curve point', () {
      final txSecretKey = senderKeys.privateSpendKey;

      final outputKey = StealthAddress.deriveOutputKey(
        txSecretKey: txSecretKey,
        recipientViewKey: recipientKeys.publicViewKey,
        recipientSpendKey: recipientKeys.publicSpendKey,
        outputIndex: 0,
      );

      final point = edBytesToPoint(outputKey);
      expect(edIsOnCurve(point), isTrue);
    });

    test('different output indices produce different output keys', () {
      final txSecretKey = senderKeys.privateSpendKey;

      final key0 = StealthAddress.deriveOutputKey(
        txSecretKey: txSecretKey,
        recipientViewKey: recipientKeys.publicViewKey,
        recipientSpendKey: recipientKeys.publicSpendKey,
        outputIndex: 0,
      );

      final key1 = StealthAddress.deriveOutputKey(
        txSecretKey: txSecretKey,
        recipientViewKey: recipientKeys.publicViewKey,
        recipientSpendKey: recipientKeys.publicSpendKey,
        outputIndex: 1,
      );

      expect(key0, isNot(equals(key1)));
    });

    test('txPublicKey is valid curve point', () {
      final txPubKey = StealthAddress.txPublicKey(senderKeys.privateSpendKey);
      expect(txPubKey.length, 32);
      final point = edBytesToPoint(txPubKey);
      expect(edIsOnCurve(point), isTrue);
    });
  });

  group('Key image', () {
    test('hashToPoint returns a point on the curve', () {
      final data = Uint8List.fromList('test data for hash to point'.codeUnits);
      final pointBytes = KeyImage.hashToPoint(data);
      expect(pointBytes.length, 32);
      final point = edBytesToPoint(pointBytes);
      expect(point.isInfinity, isFalse);
      expect(edIsOnCurve(point), isTrue);
    });

    test('hashToPoint with generator bytes returns on-curve point', () {
      final gBytes = edPointToBytes(ed25519G);
      final pointBytes = KeyImage.hashToPoint(gBytes);
      expect(pointBytes.length, 32);
      final point = edBytesToPoint(pointBytes);
      expect(edIsOnCurve(point), isTrue);
      expect(point.isInfinity, isFalse);
    });

    test('key images are deterministic (same inputs -> same output)', () {
      final keys = MoneroKeys.generate();
      final txSecretKey = MoneroKeys.generate().privateSpendKey;

      final outputKey = StealthAddress.deriveOutputKey(
        txSecretKey: txSecretKey,
        recipientViewKey: keys.publicViewKey,
        recipientSpendKey: keys.publicSpendKey,
        outputIndex: 0,
      );

      final txPubKey = StealthAddress.txPublicKey(txSecretKey);

      final outputPrivKey = StealthAddress.deriveOutputPrivateKey(
        privateSpendKey: keys.privateSpendKey,
        privateViewKey: keys.privateViewKey,
        txPublicKey: txPubKey,
        outputIndex: 0,
      );

      final image1 = KeyImage.compute(outputPrivKey, outputKey);
      final image2 = KeyImage.compute(outputPrivKey, outputKey);
      expect(image1, equals(image2));
    });

    test('key image is a valid curve point', () {
      final keys = MoneroKeys.generate();
      final txSecretKey = MoneroKeys.generate().privateSpendKey;

      final outputKey = StealthAddress.deriveOutputKey(
        txSecretKey: txSecretKey,
        recipientViewKey: keys.publicViewKey,
        recipientSpendKey: keys.publicSpendKey,
        outputIndex: 0,
      );

      final txPubKey = StealthAddress.txPublicKey(txSecretKey);

      final outputPrivKey = StealthAddress.deriveOutputPrivateKey(
        privateSpendKey: keys.privateSpendKey,
        privateViewKey: keys.privateViewKey,
        txPublicKey: txPubKey,
        outputIndex: 0,
      );

      final image = KeyImage.compute(outputPrivKey, outputKey);
      expect(image.length, 32);
      final point = edBytesToPoint(image);
      expect(edIsOnCurve(point), isTrue);
    });

    test('different outputs produce different key images', () {
      final keys = MoneroKeys.generate();
      final txSecretKey1 = MoneroKeys.generate().privateSpendKey;
      final txSecretKey2 = MoneroKeys.generate().privateSpendKey;

      final outputKey1 = StealthAddress.deriveOutputKey(
        txSecretKey: txSecretKey1,
        recipientViewKey: keys.publicViewKey,
        recipientSpendKey: keys.publicSpendKey,
        outputIndex: 0,
      );

      final txPubKey1 = StealthAddress.txPublicKey(txSecretKey1);
      final outputPrivKey1 = StealthAddress.deriveOutputPrivateKey(
        privateSpendKey: keys.privateSpendKey,
        privateViewKey: keys.privateViewKey,
        txPublicKey: txPubKey1,
        outputIndex: 0,
      );

      final outputKey2 = StealthAddress.deriveOutputKey(
        txSecretKey: txSecretKey2,
        recipientViewKey: keys.publicViewKey,
        recipientSpendKey: keys.publicSpendKey,
        outputIndex: 0,
      );

      final txPubKey2 = StealthAddress.txPublicKey(txSecretKey2);
      final outputPrivKey2 = StealthAddress.deriveOutputPrivateKey(
        privateSpendKey: keys.privateSpendKey,
        privateViewKey: keys.privateViewKey,
        txPublicKey: txPubKey2,
        outputIndex: 0,
      );

      final image1 = KeyImage.compute(outputPrivKey1, outputKey1);
      final image2 = KeyImage.compute(outputPrivKey2, outputKey2);
      expect(image1, isNot(equals(image2)));
    });
  });

  // -------------------------------------------------------------------------
  // Polyseed mnemonic
  //
  // Test vectors sourced from three independent implementations:
  //   - Dart reference (polyseed_dart v0.0.7, cake-tech)
  //   - C reference   (tevador/polyseed)
  //   - Rust reference (monero-wallet-util/polyseed)
  //
  // The Spanish vector (birthday=563) specifically exercises the multi-byte
  // path of _store32 in the PBKDF2 salt (salt bytes 20-21 = 0x33 0x02).
  // -------------------------------------------------------------------------
  group('Polyseed mnemonic', () {
    // -- English (Dart reference vector) ------------------------------------
    const enPhrase =
        'unaware yard donate shallow slot sing oil oxygen '
        'loyal bench near hill surround forum execute lamp';
    // PBKDF2-HMAC-SHA256 output; not yet scalar-reduced.
    const enSpendSeed =
        'cbbd142d38347773d44aa830f5f01442aa6d0d3bb48571884479531248e6fa1c';
    // Decoded birthday: epoch + 22 * timeStep = 1635768000 + 57854412.
    const enBirthday = 1693622412;

    test('English: birthday decodes correctly', () {
      final seed = PolyseedMnemonic.decode(enPhrase);
      expect(seed.birthday, enBirthday);
    });

    test('English: generateSpendKey matches Dart/C/Rust reference', () {
      final seed = PolyseedMnemonic.decode(enPhrase);
      expect(hexEncode(seed.generateSpendKey()), enSpendSeed);
    });

    test('English: fromSeed produces valid Ed25519 key pair', () {
      final seed = PolyseedMnemonic.decode(enPhrase);
      final keys = MoneroKeys.fromSeed(seed.generateSpendKey());
      expect(edIsOnCurve(edBytesToPoint(keys.publicSpendKey)), isTrue);
      expect(edIsOnCurve(edBytesToPoint(keys.publicViewKey)), isTrue);
    });

    // -- English (C reference vector, birthday=1) ---------------------------
    // This vector has birthday < 256, confirming correct LE encoding in salt.
    const cSeed1Phrase =
        'raven tail swear infant grief assist regular lamp '
        'duck valid someone little harsh puppy airport language';
    const cSeed1Key =
        '21268a76048a3b25a4a9ac179d86b12fab5800b8d858da9facf4b0a778dc2840';

    test('C-ref English (birthday=1): generateSpendKey matches C/Rust', () {
      final seed = PolyseedMnemonic.decode(cSeed1Phrase);
      expect(hexEncode(seed.generateSpendKey()), cSeed1Key);
    });

    // -- English (Rust reference vector) ------------------------------------
    const rustPhrase =
        'comic blanket chair inject end snow rural improve cereal '
        'better initial replace ribbon brother gather unaware';
    const rustKey =
        'd85225a4fc7aaa3d3498831ab5e2bf83cc03f2e1e5af2597128f35af88112f7e';

    test('Rust-ref English: generateSpendKey matches Rust reference', () {
      final seed = PolyseedMnemonic.decode(rustPhrase);
      expect(hexEncode(seed.generateSpendKey()), rustKey);
    });

    // -- Spanish (C reference vector, birthday=563) -------------------------
    // birthday=563 = 0x0233, so LE bytes are 0x33 0x02  -  tests upper byte of
    // _store32. Phrase uses NFC accented characters (é, ú, ñ, ó, á).
    const esPhrase =
        'eje fin parte c\u{00e9}lebre tab\u{00fa} pesta\u{00f1}a lienzo puma '
        'prisi\u{00f3}n hora regalo lengua existir l\u{00e1}piz lote sonoro';
    const esKey =
        '35797a77a65f86ed1b78ddca70842b4cc9f6b11b3efadedb72a0d44a522b9a4f';

    test('C-ref Spanish (birthday=563, accents): generateSpendKey matches C/Rust', () {
      final seed = PolyseedMnemonic.decode(esPhrase);
      expect(hexEncode(seed.generateSpendKey()), esKey);
    });

    // -- Japanese (polyseed_dart edge-case vector) ---------------------------
    // Japanese BIP-39 wordlist is NFD-encoded; NFC user input must still match.
    const jpPhrase =
        'せつぶん いせい てはい けんか たてる ねんきん くたびれる いよく やたい '
        'あいこくしん ちきゅう きたえる せたけ あひる かのう げつれい';
    const jpKey =
        '340593b3fd0b2670b4727b6a9b64f3f817e2b97fcb26ea3ae8467234eb857f95';

    test('Japanese (NFC input): generateSpendKey matches reference', () {
      final seed = PolyseedMnemonic.decode(jpPhrase);
      expect(hexEncode(seed.generateSpendKey()), jpKey);
    });

    test('Japanese: regular ASCII spaces accepted (auto-converted to U+3000)', () {
      final normalSpaces = jpPhrase.replaceAll('\u3000', ' ');
      final seed = PolyseedMnemonic.decode(normalSpaces);
      expect(hexEncode(seed.generateSpendKey()), jpKey);
    });

    // -- Validation helpers -------------------------------------------------
    test('isValid: true for valid English phrase', () {
      expect(PolyseedMnemonic.isValid(enPhrase), isTrue);
    });

    test('isValid: true for valid Spanish phrase', () {
      expect(PolyseedMnemonic.isValid(esPhrase), isTrue);
    });

    test('isValid: false for wrong word count', () {
      expect(PolyseedMnemonic.isValid('abandon ability able'), isFalse);
    });

    test('isValid: false for unknown words', () {
      expect(PolyseedMnemonic.isValid('notaword ' * 16), isFalse);
    });

    test('decode: throws FormatException on checksum mismatch', () {
      // "zoo" is a valid BIP-39 word but breaks the RS checksum.
      final words = enPhrase.split(' ');
      words[0] = 'zoo';
      expect(
        () => PolyseedMnemonic.decode(words.join(' ')),
        throwsA(isA<FormatException>()),
      );
    });

    test('isEncrypted: false for standard unencrypted seed', () {
      expect(PolyseedMnemonic.decode(enPhrase).isEncrypted, isFalse);
    });

    // An encrypted polyseed encodes features=16 (bit 4 set).
    // Vector: "arm dutch crystal..." is the CakeWallet-encrypted form of enPhrase.
    const encryptedPhrase =
        'arm dutch crystal reduce elephant mix squeeze garlic '
        'slam brand tent seed rubber fame summer sample';

    test('isEncrypted: true for passphrase-encrypted seed', () {
      expect(PolyseedMnemonic.decode(encryptedPhrase).isEncrypted, isTrue);
    });

    test('generateSpendKey: throws StateError for encrypted seed', () {
      final seed = PolyseedMnemonic.decode(encryptedPhrase);
      expect(() => seed.generateSpendKey(), throwsA(isA<StateError>()));
    });

    // decrypt: vector shared by the Dart/C/Rust Polyseed references.
    // encryptedPhrase is enPhrase encrypted with passphrase "CakeWallet".
    test('decrypt: CakeWallet passphrase restores original spend key', () {
      final decrypted =
          PolyseedMnemonic.decode(encryptedPhrase).decrypt('CakeWallet');
      expect(decrypted.isEncrypted, isFalse);
      expect(hexEncode(decrypted.generateSpendKey()), enSpendSeed);
    });

    test('decrypt: birthday is preserved after decryption', () {
      final decrypted =
          PolyseedMnemonic.decode(encryptedPhrase).decrypt('CakeWallet');
      expect(decrypted.birthday, enBirthday);
    });

    test('decrypt: throws StateError when seed is not encrypted', () {
      expect(
        () => PolyseedMnemonic.decode(enPhrase).decrypt('anything'),
        throwsA(isA<StateError>()),
      );
    });

    // -- _store32 correctness (verified against C reference salt layout) ----
    test('salt byte layout: coin=0, birthday=1 -> [20]=0x01, [21..23]=0x00', () {
      // C reference expected salt hex for this vector:
      // 504f4c5953454544 206b657900 ffffff 00000000 01000000 00000000 00000000
      //  "POLYSEED key"   \0  \xff x3  coin=0 LE  bday=1LE feat=0LE  pad
      final seed = PolyseedMnemonic.decode(cSeed1Phrase);
      // Confirm the key matches  -  this indirectly validates the salt.
      expect(hexEncode(seed.generateSpendKey()), cSeed1Key);
    });

    test('salt byte layout: birthday=563 -> [20]=0x33, [21]=0x02 (multi-byte LE)', () {
      // 563 = 0x0233 -> LE bytes [0x33, 0x02, 0x00, 0x00]
      // C reference expected key for this vector confirmed above via esKey.
      final seed = PolyseedMnemonic.decode(esPhrase);
      expect(hexEncode(seed.generateSpendKey()), esKey);
    });
  });

  group('Pedersen commitment', () {
    test('commit + verify passes for correct values', () {
      final mask = hexDecode(
          '0100000000000000000000000000000000000000000000000000000000000000');
      final amount = BigInt.from(12345);

      final commitment = PedersenCommitment.commit(amount, mask);
      expect(commitment.length, 32);
      expect(PedersenCommitment.verify(commitment, amount, mask), isTrue);
    });

    test('verify fails for wrong amount', () {
      final mask = hexDecode(
          '0200000000000000000000000000000000000000000000000000000000000000');
      final amount = BigInt.from(12345);

      final commitment = PedersenCommitment.commit(amount, mask);
      expect(
          PedersenCommitment.verify(commitment, BigInt.from(12346), mask),
          isFalse);
    });

    test('verify fails for wrong mask', () {
      final mask = hexDecode(
          '0300000000000000000000000000000000000000000000000000000000000000');
      final wrongMask = hexDecode(
          '0400000000000000000000000000000000000000000000000000000000000000');
      final amount = BigInt.from(99999);

      final commitment = PedersenCommitment.commit(amount, mask);
      expect(
          PedersenCommitment.verify(commitment, amount, wrongMask), isFalse);
    });

    test('commitment is a valid curve point', () {
      final mask = hexDecode(
          '0500000000000000000000000000000000000000000000000000000000000000');
      final amount = BigInt.from(42);

      final commitment = PedersenCommitment.commit(amount, mask);
      final point = edBytesToPoint(commitment);
      expect(edIsOnCurve(point), isTrue);
    });

    test('zero amount with zero-ish mask produces valid commitment', () {
      final mask = hexDecode(
          '0100000000000000000000000000000000000000000000000000000000000000');
      final amount = BigInt.zero;

      final commitment = PedersenCommitment.commit(amount, mask);
      expect(PedersenCommitment.verify(commitment, amount, mask), isTrue);
    });

    test('H generator point is on the curve', () {
      final hBytes = PedersenCommitment.h;
      final h = edBytesToPoint(hBytes);
      expect(edIsOnCurve(h), isTrue);
      expect(h.isInfinity, isFalse);
    });

    test('H is different from G', () {
      final hBytes = PedersenCommitment.h;
      final gBytes = edPointToBytes(ed25519G);
      expect(hBytes, isNot(equals(gBytes)));
    });

    test('different amounts produce different commitments with same mask', () {
      final mask = hexDecode(
          '0700000000000000000000000000000000000000000000000000000000000000');
      final c1 = PedersenCommitment.commit(BigInt.from(100), mask);
      final c2 = PedersenCommitment.commit(BigInt.from(200), mask);
      expect(c1, isNot(equals(c2)));
    });

    test('different masks produce different commitments with same amount', () {
      final mask1 = hexDecode(
          '0800000000000000000000000000000000000000000000000000000000000000');
      final mask2 = hexDecode(
          '0900000000000000000000000000000000000000000000000000000000000000');
      final amount = BigInt.from(555);
      final c1 = PedersenCommitment.commit(amount, mask1);
      final c2 = PedersenCommitment.commit(amount, mask2);
      expect(c1, isNot(equals(c2)));
    });
  });
}
