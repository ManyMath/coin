import 'dart:typed_data';

import 'package:coin/coin.dart' show hexDecode;
import 'package:coin/src/crypto/soft/p256.dart';
import 'package:test/test.dart';

/// In-house NIST P-256 (prime256v1) ECDSA verify, covered by:
///  - a WalletConnect Verify attestation ES256 JWT from reown's verify test
///    suite;
///  - two ECDSA-P256/SHA-256 vectors with distinct keys/signatures, generated
///    with the `cryptography` package.
/// Negative cases (tampered r/s, off-curve key, out-of-range scalar) must fail.
void main() {
  Uint8List bytes(String hex) => Uint8List.fromList(hexDecode(hex));
  BigInt big(String hex) => BigInt.parse(hex, radix: 16);

  group('P-256 ECDSA verify - positive vectors', () {
    test('reown WalletConnect Verify attestation (ES256) - published', () {
      // Raw values from the JWK + JWT in
      // reown_core/test/verify/jwt_validation_test.dart.
      final ok = P256.verify(
        hash: bytes(
            '67d806bbf89738ab50b65c52b9aef59660206b2b30c4e44269a48a9cb069cdba'),
        r: big(
            'be6d535287f1a4a73ac8b6170e047fa7b0188530bdfd632ef453a063b9777cc0'),
        s: big(
            '17fc23a0a88046698f4d13c4aaf169831a34c9ae8175e6ab32f710fc7545c873'),
        qx: big(
            '09b2f80ce60e6f59ed77ef0e984c4efa84b40d608c0b4d039edaf2989a01f2d9'),
        qy: big(
            '2931708c7b50c464c347dd55b0eca971d05fbdba3ab00323e69e166fef61440d'),
      );
      expect(ok, isTrue);
    });

    test('generated vector A (cryptography 41.0.7)', () {
      expect(
        P256.verify(
          hash: bytes(
              '3a06c18b937833fe0cf6eed736a74de9461539f8b40abac724d2f9c9ea158a3d'),
          r: big(
              'ce4c9e54685b6d6da929a6fc70f5e317f2fababafa125f415e870e7300769e3a'),
          s: big(
              '7bde43569b9c989fb51f719f53327f4e414db722ffa6fbc0a914073e8fd1a4da'),
          qx: big(
              '0217e617f0b6443928278f96999e69a23a4f2c152bdf6d6cdf66e5b80282d4ed'),
          qy: big(
              '194a7debcb97712d2dda3ca85aa8765a56f45fc758599652f2897c65306e5794'),
        ),
        isTrue,
      );
    });

    test('generated vector B (cryptography 41.0.7)', () {
      expect(
        P256.verify(
          hash: bytes(
              '0c3c80c51393b762d0ed88e148f97de9402e8b503ff4c0e2ef638bf1f3a13f15'),
          r: big(
              '4432a3fc057e38d00e20d53832ff9e76bfec1eb5ff8f481d9a702f5f74dc9161'),
          s: big(
              'a5579208f9cf535d6f491b9b8358bdfa2053261c7970d497b0466bbbf5095e8a'),
          qx: big(
              'd65a93977caa3d1b081852ff57a79e465f1660577304baead505dd3a48589cf3'),
          qy: big(
              '50185e895372df6221ea3a137557e473fddb6755f05bd507c3c533fce9c91285'),
        ),
        isTrue,
      );
    });
  });

  group('P-256 ECDSA verify - negative cases', () {
    final hash = bytes(
        '3a06c18b937833fe0cf6eed736a74de9461539f8b40abac724d2f9c9ea158a3d');
    final r = big(
        'ce4c9e54685b6d6da929a6fc70f5e317f2fababafa125f415e870e7300769e3a');
    final s = big(
        '7bde43569b9c989fb51f719f53327f4e414db722ffa6fbc0a914073e8fd1a4da');
    final qx = big(
        '0217e617f0b6443928278f96999e69a23a4f2c152bdf6d6cdf66e5b80282d4ed');
    final qy = big(
        '194a7debcb97712d2dda3ca85aa8765a56f45fc758599652f2897c65306e5794');

    test('tampered s fails', () {
      expect(
          P256.verify(hash: hash, r: r, s: s ^ BigInt.one, qx: qx, qy: qy),
          isFalse);
    });

    test('tampered hash fails', () {
      final h2 = Uint8List.fromList(hash)..[0] ^= 0x01;
      expect(P256.verify(hash: h2, r: r, s: s, qx: qx, qy: qy), isFalse);
    });

    test('off-curve public key fails', () {
      expect(
          P256.verify(hash: hash, r: r, s: s, qx: qx, qy: qy + BigInt.one),
          isFalse);
      expect(P256.isOnCurve(qx, qy + BigInt.one), isFalse);
      expect(P256.isOnCurve(qx, qy), isTrue);
    });

    test('out-of-range r/s fails', () {
      expect(P256.verify(hash: hash, r: BigInt.zero, s: s, qx: qx, qy: qy),
          isFalse);
      expect(P256.verify(hash: hash, r: r, s: P256.n, qx: qx, qy: qy), isFalse);
    });
  });

  group('JWK point decode', () {
    test('pointFromJwk decodes the reown attestation key', () {
      // x/y from the JWK in reown's verify test (base64url, no padding).
      final (qx, qy) = P256.pointFromJwk(
        'CbL4DOYOb1ntd-8OmExO-oS0DWCMC00DntrymJoB8tk',
        'KTFwjHtQxGTDR91VsOypcdBfvbo6sAMj5p4Wb-9hRA0',
      );
      expect(
          qx,
          BigInt.parse(
              '09b2f80ce60e6f59ed77ef0e984c4efa84b40d608c0b4d039edaf2989a01f2d9',
              radix: 16));
      expect(
          qy,
          BigInt.parse(
              '2931708c7b50c464c347dd55b0eca971d05fbdba3ab00323e69e166fef61440d',
              radix: 16));
      expect(P256.isOnCurve(qx, qy), isTrue);
    });
  });
}
