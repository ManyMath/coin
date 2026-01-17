import 'dart:typed_data';

import 'package:coin/coin.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(() async {
    await VaultKeeper.initialize();
  });

  // Private key 1 (the secp256k1 generator G) is a standard identity-element
  // test; its compressed pubkey 0279be66... is deterministic from the curve.
  // Key e8f32e... is the BIP-32 Test Vector 1 m/0' child key:
  // https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
  // Half-order constant: secp256k1 n/2 per SEC 2 sec. 2.4.1.
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

  group('SecretKey operations', () {
    test('negate produces valid key', () {
      final sk = SecretKey.fromHex(
          '0000000000000000000000000000000000000000000000000000000000000001');
      final negated = sk.negate();
      expect(negated.bytes.length, 32);
      expect(negated, isNot(equals(sk)));
    });

    test('tweak produces new key', () {
      final sk = SecretKey.fromHex(
          '0000000000000000000000000000000000000000000000000000000000000001');
      final scalar = Uint8List(32)..[31] = 0x01; // tweak by 1
      final tweaked = sk.tweak(scalar);
      expect(tweaked, isNotNull);
      expect(tweaked!.bytes.length, 32);
      expect(tweaked, isNot(equals(sk)));
    });
  });
}
