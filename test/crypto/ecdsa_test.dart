import 'dart:typed_data';

import 'package:coin/coin.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(() async {
    await VaultKeeper.initialize();
  });

  // Constants used in this file:
  // - priv=1 -> compressed pubkey 0279be66...f81798 is the secp256k1 generator
  //   point G (Gx = 79be667e..., 0x02 = even y). Curve params: SEC 2 v2
  //   sec. 2.4.1 (https://www.secg.org/sec2-v2.pdf).
  // - Key e8f32e...6b35 is the BIP-32 Test Vector 1 m/0' child private key:
  //   https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vector-1
  // - Half-order constant 7FFF..20A0 is secp256k1 n/2 (n from SEC 2 v2 sec. 2.4.1),
  //   used by BIP-62/BIP-146 low-S normalization.
  group('ECDSA key generation', () {
    test('generate SecretKey and derive PublicKey', () {
      final sk = SecretKey.generate();
      expect(sk.bytes.length, 32);

      final pk = sk.publicKey;
      expect(pk.bytes.length, 33);
      expect(pk.isCompressed, isTrue);
      expect(pk.bytes[0], anyOf(equals(0x02), equals(0x03)));
    });

    test('SecretKey from known hex produces deterministic PublicKey', () {
      // private key = 1 => G point
      final sk = SecretKey.fromHex(
          '0000000000000000000000000000000000000000000000000000000000000001');
      final pk = sk.publicKey;
      expect(pk.toHex(),
          '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
    });

    test('SecretKey from hex round-trips', () {
      final hex =
          'e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35';
      final sk = SecretKey.fromHex(hex);
      expect(sk.toHex(), hex);
    });

    test('two generated keys are different', () {
      final sk1 = SecretKey.generate();
      final sk2 = SecretKey.generate();
      expect(sk1, isNot(equals(sk2)));
    });
  });

  // The following groups (sign/verify, recoverable, low-S, DER<->compact) are
  // round-trip tests: they use the BIP-32 m/0' key or freshly generated keys and
  // assert internal consistency (sign-then-verify, encode-then-decode).
  // Fixed-key exact-signature vectors are in the "Deterministic ECDSA vectors"
  // group further down.
  group('ECDSA signing and verification', () {
    late SecretKey sk;
    late PublicKey pk;
    late Uint8List message;

    setUp(() {
      sk = SecretKey.fromHex(
          'e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35');
      pk = sk.publicKey;
      message = sha256(Uint8List.fromList('test message'.codeUnits));
    });

    test('sign and verify succeeds', () {
      final sig = EcdsaSig.sign(message, sk.bytes);
      expect(sig.bytes.length, 64);
      expect(sig.verify(message, pk.bytes), isTrue);
    });

    test('verify fails with wrong message', () {
      final sig = EcdsaSig.sign(message, sk.bytes);
      final wrongMsg = sha256(Uint8List.fromList('wrong message'.codeUnits));
      expect(sig.verify(wrongMsg, pk.bytes), isFalse);
    });

    test('verify fails with wrong public key', () {
      final sig = EcdsaSig.sign(message, sk.bytes);
      final otherSk = SecretKey.generate();
      expect(sig.verify(message, otherSk.publicKey.bytes), isFalse);
    });

    test('signature hex round-trips', () {
      final sig = EcdsaSig.sign(message, sk.bytes);
      final hexStr = sig.toHex();
      final restored = EcdsaSig.fromHex(hexStr);
      expect(restored, equals(sig));
    });
  });

  group('Recoverable ECDSA', () {
    late SecretKey sk;
    late PublicKey pk;
    late Uint8List message;

    setUp(() {
      sk = SecretKey.fromHex(
          'e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35');
      pk = sk.publicKey;
      message = sha256(Uint8List.fromList('recover me'.codeUnits));
    });

    test('sign recoverable and recover public key', () {
      final rsig = RecoverableEcdsaSig.sign(message, sk.bytes);
      expect(rsig.bytes.length, 64);
      expect(rsig.recId, inInclusiveRange(0, 3));

      final recovered = rsig.recover(message, compressed: true);
      expect(recovered.length, 33);
      expect(PublicKey(recovered), equals(pk));
    });

    test('recovered key matches original for multiple messages', () {
      for (final text in ['hello', 'world', 'foo bar baz 12345']) {
        final hash = sha256(Uint8List.fromList(text.codeUnits));
        final rsig = RecoverableEcdsaSig.sign(hash, sk.bytes);
        final recovered = rsig.recover(hash, compressed: true);
        expect(PublicKey(recovered), equals(pk),
            reason: 'recovery failed for "$text"');
      }
    });

    test('toCompact produces valid non-recoverable signature', () {
      final rsig = RecoverableEcdsaSig.sign(message, sk.bytes);
      final compact = rsig.toCompact();
      expect(compact.verify(message, pk.bytes), isTrue);
    });

    test('toBytes65 encodes recId at byte 64', () {
      final rsig = RecoverableEcdsaSig.sign(message, sk.bytes);
      final bytes65 = rsig.toBytes65();
      expect(bytes65.length, 65);
      expect(bytes65[64], rsig.recId);
      expect(bytes65.sublist(0, 64), equals(rsig.bytes));
    });
  });

  group('Low-S normalization', () {
    test('normalized signature verifies', () {
      final sk = SecretKey.generate();
      final msg = sha256(Uint8List.fromList('normalize me'.codeUnits));
      final sig = EcdsaSig.sign(msg, sk.bytes);
      final normalized = sig.normalize();
      expect(normalized.verify(msg, sk.publicKey.bytes), isTrue);
    });

    test('normalizing is idempotent', () {
      final sk = SecretKey.generate();
      final msg = sha256(Uint8List.fromList('idempotent'.codeUnits));
      final sig = EcdsaSig.sign(msg, sk.bytes);
      final norm1 = sig.normalize();
      final norm2 = norm1.normalize();
      expect(norm1, equals(norm2));
    });

    test('normalized S is in lower half of curve order', () {
      final halfOrder = BigInt.parse(
          '7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0',
          radix: 16);

      final sk = SecretKey.generate();
      final msg = sha256(Uint8List.fromList('low-s check'.codeUnits));
      final sig = EcdsaSig.sign(msg, sk.bytes);
      final normalized = sig.normalize();

      final sBytes = normalized.bytes.sublist(32, 64);
      var s = BigInt.zero;
      for (final b in sBytes) {
        s = (s << 8) + BigInt.from(b);
      }
      expect(s <= halfOrder, isTrue,
          reason: 'S should be in lower half of curve order');
    });
  });

  group('DER <-> compact conversion', () {
    test('compact -> DER -> compact round-trip', () {
      final sk = SecretKey.generate();
      final msg = sha256(Uint8List.fromList('der test'.codeUnits));
      final sig = EcdsaSig.sign(msg, sk.bytes);

      final der = sig.toDer();
      // DER starts with 0x30 (SEQUENCE tag)
      expect(der[0], 0x30);

      final restored = EcdsaSig.fromDer(der);
      expect(restored, equals(sig.normalize()));
    });

    test('DER encoding has correct structure', () {
      final sk = SecretKey.fromHex(
          '0000000000000000000000000000000000000000000000000000000000000001');
      final msg = sha256(Uint8List.fromList('structure'.codeUnits));
      final sig = EcdsaSig.sign(msg, sk.bytes).normalize();
      final der = sig.toDer();

      // DER: 0x30 <len> 0x02 <r-len> <r> 0x02 <s-len> <s>
      expect(der[0], 0x30, reason: 'Must start with SEQUENCE tag');
      final totalLen = der[1];
      expect(der.length, totalLen + 2, reason: 'Total length must match');
      expect(der[2], 0x02, reason: 'R must start with INTEGER tag');
    });

    test('DER from known signature verifies', () {
      final sk = SecretKey.generate();
      final msg = sha256(Uint8List.fromList('known sig'.codeUnits));
      final sig = EcdsaSig.sign(msg, sk.bytes);
      final der = sig.toDer();
      final fromDer = EcdsaSig.fromDer(der);
      expect(fromDer.verify(msg, sk.publicKey.bytes), isTrue);
    });

    test('DER encoding length is within expected bounds', () {
      final sk = SecretKey.fromHex(
          '0000000000000000000000000000000000000000000000000000000000000001');
      final msg = sha256(Uint8List.fromList('bounds check'.codeUnits));
      final sig = EcdsaSig.sign(msg, sk.bytes);
      final der = sig.toDer();
      // DER ECDSA sigs are 68-72 bytes
      expect(der.length, greaterThanOrEqualTo(68));
      expect(der.length, lessThanOrEqualTo(72));
    });
  });

  // Deterministic-signing vectors. RFC6979 nonce generation, low-S
  // normalization, and DER encoding are asserted against exact byte output;
  // the wallet tx-builder relies on this for reproducible signatures.
  group('Deterministic ECDSA vectors', () {
    // BIP-143 "Native P2WPKH" example:
    // https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
    // The 32-byte sighash digest is also asserted in test/tx/sighash_test.dart
    // via WitnessSigHasher; here it is signed and the DER signature from the
    // BIP's final signed transaction is asserted (hashtype 0x01 stripped).
    test('BIP-143 P2WPKH witness signature matches BIP exactly', () {
      final digest = hexDecode(
          'c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670');
      final priv = hexDecode(
          '619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9');

      final sig = EcdsaSig.sign(digest, priv);
      expect(
          hexEncode(sig.toDer()),
          '304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f'
          '01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed'
          '02de67eebee');

      // The signature must verify against the input's compressed pubkey,
      // and the assembled witness item [derSig + 0x01] must match the
      // witness in the BIP's final signed tx.
      final pubKey = hexDecode(
          '025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357');
      expect(sig.verify(digest, pubKey), isTrue);

      final der = sig.toDer();
      final witnessSig = Uint8List(der.length + 1)
        ..setRange(0, der.length, der)
        ..[der.length] = 0x01; // SIGHASH_ALL
      expect(
          hexEncode(witnessSig),
          '304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f'
          '01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed'
          '02de67eebee01');
    });

    // Bitcoin Core src/test/key_tests.cpp "key_signature_tests" (message
    // "Very deterministic message", hashed with double-SHA256, signed by the
    // two fixed WIF keys decoded to 12b004ff..f747 and b524c28b..d117; expected
    // DER outputs match the detsig/detsigc constants in that file).
    // https://github.com/bitcoin/bitcoin/blob/master/src/test/key_tests.cpp
    group('Bitcoin Core RFC6979 key_signature_tests', () {
      Uint8List msgHashOf() =>
          sha256d(Uint8List.fromList('Very deterministic message'.codeUnits));

      test('message double-SHA256 hash matches expected', () {
        expect(hexEncode(msgHashOf()),
            '5255683da567900bfd3e786ed8836a4e7763c221bf1ac20ece2a5171b9199e8a');
      });

      test('key 1 produces exact DER signature', () {
        final msgHash = msgHashOf();
        final priv = hexDecode(
            '12b004fff7f4b69ef8650e767f18f11ede158148b425660723b9f9a66e61f747');
        final sig = EcdsaSig.sign(msgHash, priv);
        expect(
            hexEncode(sig.toDer()),
            '304402205dbbddda71772d95ce91cd2d14b592cfbc1dd0aabd6a394b6c2d377b'
            'be59d31d022014ddda21494a4e221f0824f0b8b924c43fa43c0ad57dccdaa11'
            'f81a6bd4582f6');
      });

      test('key 2 produces exact DER signature', () {
        final msgHash = msgHashOf();
        final priv = hexDecode(
            'b524c28b61c9b2c49b2c7dd4c2d75887abb78768c054bd7c01af4029f6c0d117');
        final sig = EcdsaSig.sign(msgHash, priv);
        expect(
            hexEncode(sig.toDer()),
            '3044022052d8a32079c11e79db95af63bb9600c5b04f21a9ca33dc129c2bfa8a'
            'c9dc1cd5022061d8ae5e0f6c1a16bde3719c64c2fd70e404b6428ab9a695669'
            '62e8771b5944d');
      });
    });
  });

  // Property tests using priv=1 (generator G, see file header): curve facts
  // (x==xOnly, 0x02 prefix => even y) and round-trip key ops (negate/tweak).
  group('PublicKey properties', () {
    test('xOnly returns 32-byte x coordinate', () {
      final sk = SecretKey.fromHex(
          '0000000000000000000000000000000000000000000000000000000000000001');
      final pk = sk.publicKey;
      expect(pk.xOnly.length, 32);
      expect(pk.x.length, 32);
      expect(pk.xOnly, equals(pk.x));
    });

    test('yIsEven for generator point', () {
      final sk = SecretKey.fromHex(
          '0000000000000000000000000000000000000000000000000000000000000001');
      final pk = sk.publicKey;
      // 0x02 prefix means y is even
      expect(pk.bytes[0], equals(0x02));
      expect(pk.yIsEven, isTrue);
    });
  });

  // tweak/negate follow the secp256k1 group law, so a correct impl lands on
  // specific points. Curve parameters (G, n): SEC 2 v2 sec. 2.4.1
  // (https://www.secg.org/sec2-v2.pdf).
  group('SecretKey operations', () {
    test('negate of priv=1 yields (n-1), whose pubkey is -G (odd-y G)', () {
      final sk = SecretKey.fromHex(
          '0000000000000000000000000000000000000000000000000000000000000001');
      final negated = sk.negate();
      expect(negated.bytes.length, 32);
      expect(negated, isNot(equals(sk)));

      // negate(1) == n-1 (mod n). The private scalar must be n-1, the largest
      // valid secp256k1 key (n from SEC 2 v2 sec. 2.4.1).
      expect(
        negated.toHex(),
        'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140',
      );
      // (n-1)*G = -G, i.e. the generator point with its y-coordinate negated:
      // same x as G but odd y, so the 0x03-prefixed compressed form.
      expect(
        negated.publicKey.toHex(),
        '0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
      );
    });

    test('tweak(+1) of priv=1 yields priv=2, whose pubkey is 2*G', () {
      final sk = SecretKey.fromHex(
          '0000000000000000000000000000000000000000000000000000000000000001');
      final scalar = Uint8List(32)..[31] = 0x01; // tweak-add by 1
      final tweaked = sk.tweak(scalar);
      expect(tweaked, isNotNull);
      expect(tweaked!.bytes.length, 32);
      expect(tweaked, isNot(equals(sk)));

      // 1 + 1 == 2: the tweaked private scalar must be exactly 2.
      expect(
        tweaked.toHex(),
        '0000000000000000000000000000000000000000000000000000000000000002',
      );
      // 2*G in compressed form (even y => 0x02 prefix).
      expect(
        tweaked.publicKey.toHex(),
        '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5',
      );
    });
  });
}
