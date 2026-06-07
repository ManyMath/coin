import 'dart:convert';

import 'package:coin/coin_walletconnect.dart';
import 'package:test/test.dart';

/// Verify API attestation verification, built on the in-house P-256.
/// Uses the WalletConnect Verify attestation JWT + JWK from reown's verify
/// test suite.
///
/// Fixture source: reown_core/test/verify/jwt_validation_test.dart, repo
/// https://github.com/reown-com/reown_flutter
/// - attestationJwt: the Verify attestation JWT.
/// - publicKeyJson (P-256 crv/x/y + expiresAt) and defaultPublicKeyUrl: the
///   matching Verify service JWK from the same test.
/// - attestedOrigin: the `origin` claim embedded in that JWT.
/// ES256 verification follows the JOSE/JWT spec (RFC 7515/7518) over NIST
/// P-256. The tampered-signature / wrong-origin / cache cases are mutations of
/// that fixture.
void main() {
  setUpAll(() async {
    await VaultKeeper.initialize();
  });

  // Verify attestation JWT and the matching service JWK (from
  // reown_core/test/verify/jwt_validation_test.dart).
  const attestationJwt =
      'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.'
      'eyJleHAiOjE3MjI1Nzk5MDgsImlkIjoiNTEwNmEyNTU1MmU4OWFjZmI1YmVkODNlZTIxYmY0ZTgwZGJjZDUxYjBiMjAzZjY5MjVhMzY5YWFjYjFjODYwYiIsIm9yaWdpbiI6Imh0dHBzOi8vcmVhY3QtZGFwcC12Mi1naXQtY2hvcmUtdmVyaWZ5LXYyLXNhbXBsZXMtd2FsbGV0Y29ubmVjdDEudmVyY2VsLmFwcCIsImlzU2NhbSI6bnVsbCwiaXNWZXJpZmllZCI6dHJ1ZX0.'
      'vm1TUofxpKc6yLYXDgR_p7AYhTC9_WMu9FOgY7l3fMAX_COgqIBGaY9NE8Sq8WmDGjTJroF15qsy9xD8dUXIcw';
  const attestedOrigin =
      'https://react-dapp-v2-git-chore-verify-v2-samples-walletconnect1.vercel.app';
  const publicKeyJson = '''
  {"publicKey":{"crv":"P-256","ext":true,"key_ops":["verify"],"kty":"EC",
   "x":"CbL4DOYOb1ntd-8OmExO-oS0DWCMC00DntrymJoB8tk",
   "y":"KTFwjHtQxGTDR91VsOypcdBfvbo6sAMj5p4Wb-9hRA0"},
   "expiresAt":1722579908}''';

  final key = WcVerifyKey.fromPublicKeyJson(
      (jsonDecode(publicKeyJson) as Map).cast<String, dynamic>());

  group('WcVerify (static)', () {
    test('verifyJwt accepts the genuine attestation', () {
      expect(WcVerify.verifyJwt(attestationJwt, qx: key.qx, qy: key.qy),
          isTrue);
    });

    test('verifyJwt rejects a tampered signature', () {
      final parts = attestationJwt.split('.');
      // flip a char in the signature segment
      final badSig = parts[2].replaceRange(0, 1, parts[2][0] == 'a' ? 'b' : 'a');
      final tampered = '${parts[0]}.${parts[1]}.$badSig';
      expect(WcVerify.verifyJwt(tampered, qx: key.qx, qy: key.qy), isFalse);
    });

    test('decodeClaims reads origin / isScam / isVerified', () {
      final claims = WcVerify.decodeClaims(attestationJwt);
      expect(claims.origin, attestedOrigin);
      expect(claims.isScam, isNull);
      expect(claims.isVerified, isTrue);
      expect(claims.exp, 1722579908);
    });

    test('validate -> VALID when the origin matches the attestation', () {
      expect(
        WcVerify.validate(attestationJwt,
            qx: key.qx, qy: key.qy, origin: attestedOrigin),
        WcVerifyStatus.valid,
      );
    });

    test('validate -> INVALID when the origin does not match', () {
      expect(
        WcVerify.validate(attestationJwt,
            qx: key.qx, qy: key.qy, origin: 'https://evil.example'),
        WcVerifyStatus.invalid,
      );
    });

    test('validate -> INVALID on a bad signature', () {
      expect(
        WcVerify.validate('${attestationJwt}x',
            qx: key.qx, qy: key.qy, origin: attestedOrigin),
        WcVerifyStatus.invalid,
      );
    });

    test('statusForClaims -> SCAM when flagged', () {
      final scam = WcAttestationClaims(origin: 'https://phish.example', isScam: true);
      expect(WcVerify.statusForClaims(scam, origin: 'https://phish.example'),
          WcVerifyStatus.scam);
    });
  });

  group('WcVerifyClient (fetch + cache)', () {
    test('fetches the key once, caches it, and validates', () async {
      var fetches = 0;
      final client = WcVerifyClient((url) async {
        fetches++;
        expect(url, WcVerify.defaultPublicKeyUrl);
        return publicKeyJson;
      });

      // expiresAt is 2024; pin "now" before it so the cache is considered fresh.
      const now = 1722579000;
      final s1 = await client.getValidation(attestationJwt,
          origin: attestedOrigin, nowSeconds: now);
      final s2 = await client.getValidation(attestationJwt,
          origin: 'https://evil.example', nowSeconds: now);
      expect(s1, WcVerifyStatus.valid);
      expect(s2, WcVerifyStatus.invalid);
      expect(fetches, 1, reason: 'key should be cached until expiresAt');
    });

    test('refetches once the cached key has expired', () async {
      var fetches = 0;
      final client = WcVerifyClient((url) async {
        fetches++;
        return publicKeyJson;
      });
      await client.publicKey(nowSeconds: 1722579000); // fresh fetch
      await client.publicKey(nowSeconds: 1799999999); // past expiresAt -> refetch
      expect(fetches, 2);
    });
  });
}
