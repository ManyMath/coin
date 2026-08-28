import 'dart:typed_data';

import 'package:coin/coin.dart';
import 'package:coin/src/crypto/soft/soft_curve_gate.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(() async {
    await VaultKeeper.initialize();
  });

  group('Schnorr key generation', () {
    test('generate SecretKey and get x-only PublicKey', () {
      final sk = SecretKey.generate();
      final xOnly = sk.xOnly;
      expect(xOnly.length, 32);
    });

    test('x-only key matches PublicKey x coordinate', () {
      final sk = SecretKey.generate();
      final pk = sk.publicKey;
      final xOnly = sk.xOnly;
      expect(xOnly, equals(pk.xOnly));
      expect(xOnly, equals(pk.x));
    });

    test('known private key produces known x-only key', () {
      // Derived: private key = 1 => x-coordinate of the secp256k1 generator G
      // (Gx = 79be667e...f81798), from the curve params in SEC 2 v2 sec. 2.4.1.
      // https://www.secg.org/sec2-v2.pdf
      final sk = SecretKey.fromHex(
          '0000000000000000000000000000000000000000000000000000000000000001');
      final xOnly = sk.xOnly;
      expect(hexEncode(xOnly),
          '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
    });
  });

  // Behavioral sign-then-verify / round-trip tests using the
  // BIP-32 m/0' key (e8f32e..6b35) or generated keys; no published signature.
  // The published signatures are in the "BIP-340 test vectors" group below.
  group('Schnorr signing and verification', () {
    late SecretKey sk;
    late Uint8List xPub;

    setUp(() {
      sk = SecretKey.fromHex(
          'e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35');
      xPub = sk.xOnly;
    });

    test('sign and verify succeeds', () {
      final msg = sha256(Uint8List.fromList('schnorr test'.codeUnits));
      final sig = SchnorrSig.sign(msg, sk.bytes);
      expect(sig.bytes.length, 64);
      expect(sig.verify(msg, xPub), isTrue);
    });

    test('verify fails with wrong message', () {
      final msg = sha256(Uint8List.fromList('correct'.codeUnits));
      final wrongMsg = sha256(Uint8List.fromList('incorrect'.codeUnits));
      final sig = SchnorrSig.sign(msg, sk.bytes);
      expect(sig.verify(wrongMsg, xPub), isFalse);
    });

    test('verify fails with wrong public key', () {
      final msg = sha256(Uint8List.fromList('schnorr wrong pk'.codeUnits));
      final sig = SchnorrSig.sign(msg, sk.bytes);
      final otherSk = SecretKey.generate();
      expect(sig.verify(msg, otherSk.xOnly), isFalse);
    });

    test('signature hex round-trips', () {
      final msg = sha256(Uint8List.fromList('hex round-trip'.codeUnits));
      final sig = SchnorrSig.sign(msg, sk.bytes);
      final hexStr = sig.toHex();
      expect(hexStr.length, 128);
      final restored = SchnorrSig.fromHex(hexStr);
      expect(restored, equals(sig));
    });

    test('sign with explicit auxRand', () {
      final msg = sha256(Uint8List.fromList('aux rand test'.codeUnits));
      final auxRand = Uint8List(32); // all zeros
      final sig = SchnorrSig.sign(msg, sk.bytes, auxRand: auxRand);
      expect(sig.verify(msg, xPub), isTrue);
    });
  });

  // BIP-340 test vectors. Each (secret key, public key,
  // aux_rand, message, signature) tuple below is row index 0-4 of the official
  // CSV (vectors 0-3 sign+verify, vector 4 is verify-only).
  // https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
  // CSV: https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
  group('BIP-340 test vectors', () {
    // BIP-340 vector 0 (CSV index 0)
    test('vector 0 - sign and verify', () {
      final sk = SecretKey.fromHex(
          '0000000000000000000000000000000000000000000000000000000000000003');
      final xPub = sk.xOnly;
      expect(hexEncode(xPub),
          'f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9');

      final msg = hexDecode(
          '0000000000000000000000000000000000000000000000000000000000000000');
      final auxRand = hexDecode(
          '0000000000000000000000000000000000000000000000000000000000000000');
      final sig = SchnorrSig.sign(msg, sk.bytes, auxRand: auxRand);

      expect(sig.verify(msg, xPub), isTrue);

      expect(
          sig.toHex(),
          'e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca8215'
          '25f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0');
    });

    // BIP-340 vector 1
    test('vector 1 - sign and verify', () {
      final sk = SecretKey.fromHex(
          'b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef');
      final xPub = sk.xOnly;
      expect(hexEncode(xPub),
          'dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659');

      final msg = hexDecode(
          '243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89');
      final auxRand = hexDecode(
          '0000000000000000000000000000000000000000000000000000000000000001');
      final sig = SchnorrSig.sign(msg, sk.bytes, auxRand: auxRand);

      expect(sig.verify(msg, xPub), isTrue);

      expect(
          sig.toHex(),
          '6896bd60eeae296db48a229ff71dfe071bde413e6d43f917dc8dcf8c78de3341'
          '8906d11ac976abccb20b091292bff4ea897efcb639ea871cfa95f6de339e4b0a');
    });

    // BIP-340 vector 2
    test('vector 2 - sign and verify', () {
      final sk = SecretKey.fromHex(
          'c90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b14e5c9');
      final xPub = sk.xOnly;

      final msg = hexDecode(
          '7e2d58d8b3bcdf1abadec7829054f90dda9805aab56c77333024b9d0a508b75c');
      final auxRand = hexDecode(
          'c87aa53824b4d7ae2eb035a2b5bbbccc080e76cdc6d1692c4b0b62d798e6d906');
      final sig = SchnorrSig.sign(msg, sk.bytes, auxRand: auxRand);

      expect(sig.verify(msg, xPub), isTrue);

      expect(
          sig.toHex(),
          '5831aaeed7b44bb74e5eab94ba9d4294c49bcf2a60728d8b4c200f50dd313c1b'
          'ab745879a5ad954a72c45a91c3a51d3c7adea98d82f8481e0e1e03674a6f3fb7');
    });

    // BIP-340 vector 3 (max-value msg and aux_rand)
    test('vector 3 - sign and verify', () {
      final sk = SecretKey.fromHex(
          '0b432b2677937381aef05bb02a66ecd012773062cf3fa2549e44f58ed2401710');
      final xPub = sk.xOnly;

      final msg = hexDecode(
          'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff');
      final auxRand = hexDecode(
          'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff');
      final sig = SchnorrSig.sign(msg, sk.bytes, auxRand: auxRand);

      expect(sig.verify(msg, xPub), isTrue);

      expect(
          sig.toHex(),
          '7eb0509757e246f19449885651611cb965ecc1a187dd51b64fda1edc9637d5ec'
          '97582b9cb13db3933705b32ba982af5af25fd78881ebb32771fc5922efc66ea3');
    });

    // BIP-340 vector 4 (verification only)
    test('vector 4 - verify only', () {
      final xPub = hexDecode(
          'd69c3509bb99e412e68b0fe8544e72837dfa30746d8be2aa65975f29d22dc7b9');
      final msg = hexDecode(
          '4df3c3f68fcc83b27e9d42c90431a72499f17875c81a599b566c9889b9696703');
      final sig = SchnorrSig.fromHex(
          '00000000000000000000003b78ce563f89a0ed9414f5aa28ad0d96d6795f9c63'
          '76afb1548af603b3eb45c9f8207dee1060cb71c04e80f593060b07d28308d7f4');
      expect(sig.verify(msg, xPub), isTrue);
    });
  });

  // Behavioral edge-case tests (determinism with fixed auxRand,
  // distinctness across messages/keys, length validation).
  group('Schnorr edge cases', () {
    test('different messages produce different signatures', () {
      final sk = SecretKey.generate();
      final msg1 = sha256(Uint8List.fromList('message 1'.codeUnits));
      final msg2 = sha256(Uint8List.fromList('message 2'.codeUnits));
      final sig1 = SchnorrSig.sign(msg1, sk.bytes);
      final sig2 = SchnorrSig.sign(msg2, sk.bytes);
      expect(sig1, isNot(equals(sig2)));
    });

    test('same message with different keys produce different signatures', () {
      final sk1 = SecretKey.generate();
      final sk2 = SecretKey.generate();
      final msg = sha256(Uint8List.fromList('shared message'.codeUnits));
      final sig1 = SchnorrSig.sign(msg, sk1.bytes);
      final sig2 = SchnorrSig.sign(msg, sk2.bytes);
      expect(sig1, isNot(equals(sig2)));
    });

    test('invalid signature length throws', () {
      expect(() => SchnorrSig(Uint8List(63)), throwsArgumentError);
      expect(() => SchnorrSig(Uint8List(65)), throwsArgumentError);
    });

    test('sign is deterministic with same auxRand', () {
      final sk = SecretKey.fromHex(
          '0000000000000000000000000000000000000000000000000000000000000003');
      final msg = Uint8List(32);
      final auxRand = Uint8List(32);
      final sig1 = SchnorrSig.sign(msg, sk.bytes, auxRand: auxRand);
      final sig2 = SchnorrSig.sign(msg, sk.bytes, auxRand: auxRand);
      expect(sig1, equals(sig2));
    });

    test('different auxRand produces different signature that still verifies', () {
      final sk = SecretKey.fromHex(
          '0000000000000000000000000000000000000000000000000000000000000003');
      final msg = Uint8List(32);
      final aux1 = Uint8List(32);
      final aux2 = Uint8List(32)..[0] = 0x01;
      final sig1 = SchnorrSig.sign(msg, sk.bytes, auxRand: aux1);
      final sig2 = SchnorrSig.sign(msg, sk.bytes, auxRand: aux2);
      expect(sig1, isNot(equals(sig2)));
      expect(sig1.verify(msg, sk.xOnly), isTrue);
      expect(sig2.verify(msg, sk.xOnly), isTrue);
    });

    test('sign without explicit auxRand still verifies', () {
      final sk = SecretKey.fromHex(
          '0000000000000000000000000000000000000000000000000000000000000007');
      final msg = Uint8List(32)..[15] = 0x42;
      final sig = SchnorrSig.sign(msg, sk.bytes);
      expect(sig.verify(msg, sk.xOnly), isTrue);
    });
  });

  // BIP-340 input validation: the signing inputs are exactly specified -
  // a 32-byte message, a secret key in [1, n-1], and 32-byte aux randomness.
  // Anything else must be rejected, never silently hashed/negated into a
  // signature that encodes a different intent than the caller's.
  group('BIP-340 signing input validation', () {
    final msg = Uint8List(32);
    late SecretKey sk;

    setUp(() {
      sk = SecretKey.fromHex(
          'e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35');
    });

    test('a zero secret key is rejected', () {
      expect(() => SchnorrSig.sign(msg, Uint8List(32)), throwsArgumentError);
    });

    test('a secret key >= the curve order is rejected', () {
      // secp256k1 n itself (SEC 2 v2 sec. 2.4.1).
      final n = hexDecode(
          'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
      expect(() => SchnorrSig.sign(msg, n), throwsArgumentError);
      // 2^256 - 1 (above n).
      expect(
          () => SchnorrSig.sign(msg, Uint8List(32)..fillRange(0, 32, 0xff)),
          throwsArgumentError);
    });

    test('a short or long secret key is rejected', () {
      expect(() => SchnorrSig.sign(msg, sk.bytes.sublist(0, 31)),
          throwsArgumentError);
      expect(() => SchnorrSig.sign(msg, Uint8List(33)..[32] = 1),
          throwsArgumentError);
    });

    test('a non-32-byte message is rejected', () {
      expect(() => SchnorrSig.sign(Uint8List(31), sk.bytes),
          throwsArgumentError);
      expect(() => SchnorrSig.sign(Uint8List(33), sk.bytes),
          throwsArgumentError);
      expect(() => SchnorrSig(Uint8List(64)).verify(Uint8List(31), sk.xOnly),
          throwsArgumentError);
    });

    test('short or absent-allowed-only aux randomness is rejected', () {
      expect(() => SchnorrSig.sign(msg, sk.bytes, auxRand: Uint8List(31)),
          throwsArgumentError);
      expect(() => SchnorrSig.sign(msg, sk.bytes, auxRand: Uint8List(33)),
          throwsArgumentError);
      // Exactly 32 bytes is accepted.
      expect(SchnorrSig.sign(msg, sk.bytes, auxRand: Uint8List(32))
          .verify(msg, sk.xOnly), isTrue);
    });
  });

  group('pure curve gate BIP-340 validation', () {
    final message = Uint8List(32);
    final secret = hexDecode(
      '0000000000000000000000000000000000000000000000000000000000000003',
    );

    test('rejects malformed inputs at the backend boundary', () {
      final curve = SoftCurveGate();
      expect(
        () => curve.schnorrSign(message, Uint8List(32)),
        throwsArgumentError,
      );
      expect(
        () => curve.schnorrSign(Uint8List(31), secret),
        throwsArgumentError,
      );
      expect(
        () => curve.schnorrSign(message, secret, auxRand: Uint8List(31)),
        throwsArgumentError,
      );
    });

    test('rejects an x-only public key that is not on the curve', () {
      // Official BIP-340 verification vector 5.
      final publicKey = hexDecode(
        'EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34',
      );
      final vectorMessage = hexDecode(
        '243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89',
      );
      final signature = hexDecode(
        '6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769'
        '69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B',
      );
      expect(
        SoftCurveGate().schnorrVerify(
          signature,
          vectorMessage,
          publicKey,
        ),
        isFalse,
      );
    });
  });
}
