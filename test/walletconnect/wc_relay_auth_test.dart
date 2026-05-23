import 'dart:typed_data';

import 'package:coin/coin_walletconnect.dart';
import 'package:test/test.dart';

/// WalletConnect v2 relay-auth (EdDSA JWT) vectors.
///
/// Ed25519 (RFC 8032 PureEdDSA) signs deterministically, so the JWT is
/// reproducible. did:key encoding follows the W3C did:key / multicodec spec.
///
/// Fixture sources:
/// - wallet_connect_dart_v2 relay-auth fixtures (BSD-licensed), repo
///   https://github.com/Orange-Wallet/wallet-connect-dart-v2
///   (test/relay_auth/mock_data.dart: seedHex = TEST_SEED, expectedPublicKey =
///    EXPECTED_PUBLIC_KEY, expectedIss = EXPECTED_ISS, testSubject =
///    TEST_SUBJECT, testAudience = TEST_AUDIENCE, testIat = TEST_IAT,
///    testTtl = TEST_TTL, expectedJwt = EXPECTED_JWT).
/// - seed2/expected2: reown relay-auth fixture, repo
///   https://github.com/reown-com/reown_flutter
///   (reown_core/test/relay_auth_test.dart).
void main() {
  setUpAll(() async {
    await VaultKeeper.initialize();
  });

  const seedHex =
      '58e0254c211b858ef7896b00e3f36beeb13d568d47c6031c4218b87718061295';
  const expectedPublicKey =
      '884ab67f787b69e534bfdba8d5beb4e719700e90ac06317ed177d49e5a33be5a';
  const expectedIss =
      'did:key:z6MkodHZwneVRShtaLf8JKYkxpDGp1vGZnpGmdBpX8M2exxH';

  const testSubject =
      'c479fe5dc464e771e78b193d239a65b58d278cad1c34bfb0b5716e5bb514928e';
  const testAudience = 'wss://relay.walletconnect.com';
  const testTtl = 86400;
  const testIat = 1656910097;

  const expectedJwt =
      'eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJkaWQ6a2V5Ono2TWtvZEhad25lVlJTaHRhTGY4SktZa3hwREdwMXZHWm5wR21kQnBYOE0yZXh4SCIsInN1YiI6ImM0NzlmZTVkYzQ2NGU3NzFlNzhiMTkzZDIzOWE2NWI1OGQyNzhjYWQxYzM0YmZiMGI1NzE2ZTViYjUxNDkyOGUiLCJhdWQiOiJ3c3M6Ly9yZWxheS53YWxsZXRjb25uZWN0LmNvbSIsImlhdCI6MTY1NjkxMDA5NywiZXhwIjoxNjU2OTk2NDk3fQ.bAKl1swvwqqV_FgwvD4Bx3Yp987B9gTpZctyBviA-EkAuWc8iI8SyokOjkv9GJESgid4U8Tf2foCgrQp2qrxBA';

  test('did:key issuer encode/decode round-trip', () {
    final pub = hexDecode(expectedPublicKey);
    final iss = wcEncodeIss(Uint8List.fromList(pub));
    expect(iss, expectedIss);
    expect(hexEncode(wcDecodeIss(iss)), expectedPublicKey);
  });

  test('seed derives the expected relay-auth public key', () {
    expect(hexEncode(ed25519PublicKeyFromSeed(Uint8List.fromList(hexDecode(seedHex)))),
        expectedPublicKey);
  });

  test('signJWT reproduces the wallet_connect_dart_v2 JWT', () {
    final jwt = wcSignJwt(
      seed32: Uint8List.fromList(hexDecode(seedHex)),
      sub: testSubject,
      aud: testAudience,
      iat: testIat,
      ttl: testTtl,
    );
    expect(jwt, expectedJwt);
    expect(wcVerifyJwt(jwt), isTrue);
  });

  test('second relay-auth fixture (different keypair)', () {
    const seed2 = 'db74f4788fbaf87bc8e3cd6a84ae82586fd4fd701216a1d18f7ed936cb3a8cfb';
    const expected2 =
        'eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJkaWQ6a2V5Ono2TWtrTUhRRlYzYkNUOXVIV3Z6Z1N4UXNMbVZzMVc1c0NVdzhyQnBmamg5ZHNydiIsInN1YiI6IjZhMjZkMWMxM2I4ZjdiZmRhNmU3NDE1ZjZkYjk0MDg0YTNiOTdmMjk5MGRhNTIxNmZhNWFhN2I4MGYwODM5MWQiLCJhdWQiOiJ3c3M6Ly9yZWxheS53YWxsZXRjb25uZWN0LmNvbSIsImlhdCI6MTY3NDI0NDYzMiwiZXhwIjoxNjc0MzMxMDMyfQ.FUfsQtGuyMTOfEjQUdfr_KfBEaftEQPU9lpQ_mNwgpPlzqk2Hmn9RKnbTnvL9rPWzbm5wnWrc7LuzUQGqp99Cw';
    final jwt = wcSignJwt(
      seed32: Uint8List.fromList(hexDecode(seed2)),
      sub: '6a26d1c13b8f7bfda6e7415f6db94084a3b97f2990da5216fa5aa7b80f08391d',
      aud: testAudience,
      iat: 1674244632,
      ttl: 86400,
    );
    expect(jwt, expected2);
    expect(wcVerifyJwt(jwt), isTrue);
  });
}
