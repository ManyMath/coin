import 'dart:convert';
import 'dart:typed_data';

import 'package:coin/coin_walletconnect.dart';
import 'package:test/test.dart';

/// WalletConnect v2 transport-crypto vectors.
///
/// The pipeline is X25519 -> HKDF-SHA256 -> symKey -> SHA-256 topic ->
/// ChaCha20-Poly1305 type0/type1 envelopes (RFC 7748 X25519, RFC 5869
/// HKDF-SHA256, RFC 8439 ChaCha20-Poly1305).
///
/// Fixture source (every const below): wallet_connect_dart_v2 test fixtures
/// (BSD-licensed), repo
///   https://github.com/Orange-Wallet/wallet-connect-dart-v2
/// - privA/pubA/privB/pubB, testSharedKey, testHashedKey, testSymKey:
///     test/utils/mock_data.dart (TEST_SELF_*/TEST_PEER_* keys, TEST_SHARED_KEY,
///     TEST_HASHED_KEY, TEST_SYM_KEY).
/// - testIv ("717765636661617364616473"), testEncodedType0, testEncodedType1,
///   the type-0 encodedFixture, and the hashMessage digest:
///     test/utils/crypto_utils_test.dart (TEST_IV + the encrypt/decrypt vectors).
void main() {
  setUpAll(() async {
    await VaultKeeper.initialize();
  });

  // Shared X25519/symKey test values (as used by wallet_connect_dart_v2).
  const privA = '1fb63fca5c6ac731246f2f069d3bc2454345d5208254aa8ea7bffc6d110c8862';
  const pubA = 'ff7a7d5767c362b0a17ad92299ebdb7831dcbd9a56959c01368c7404543b3342';
  const privB = '36bf507903537de91f5e573666eaa69b1fa313974f23b2b59645f20fea505854';
  const pubB = '590c2c627be7af08597091ff80dd41f7fa28acd10ef7191d7e830e116d3a186a';

  const testSharedKey =
      '9c87e48e69b33a613907515bcd5b1b4cc10bbaf15167b19804b00f0a9217e607';
  const testHashedKey =
      'a492906ccc809a411bb53a84572b57329375378c6ad7566f3e1c688200123e77';
  const testSymKey =
      '0653ca620c7b4990392e1c53c4a51c14a2840cd20f0f1524cf435b17b6fe988c';

  // Envelope crypto test values (as used by wallet_connect_dart_v2).
  final testMessage = jsonEncode({
    'id': 1,
    'jsonrpc': '2.0',
    'method': 'test_method',
    'params': <String, dynamic>{},
  });
  const testIv = '717765636661617364616473';
  const testEncodedType0 =
      'AHF3ZWNmYWFzZGFkc3paHoQ96/mLAdanVxi17icRXq+jyrqXA8ocVgGmryQZBFMg+uwgc8yLa43EOeY+IWEv84g8hn4L3Ncsgz6397sgNKnsNcL7A9k3Mg==';
  const testEncodedType1 =
      'Af96fVdnw2KwoXrZIpnr23gx3L2aVpWcATaMdARUOzNCcXdlY2ZhYXNkYWRzeloehD3r+YsB1qdXGLXuJxFer6PKupcDyhxWAaavJBkEUyD67CBzzItrjcQ55j4hYS/ziDyGfgvc1yyDPrf3uyA0qew1wvsD2Tcy';

  group('WC v2 key agreement', () {
    test('X25519 shared secret (privA, pubB)', () {
      expect(hexEncode(x25519(hexDecode(privA), hexDecode(pubB))),
          testSharedKey);
    });

    test('X25519 public key from private (privA -> pubA)', () {
      expect(hexEncode(x25519Base(hexDecode(privA))), pubA);
    });

    test('deriveSymKey is HKDF-SHA256 of the shared secret', () {
      expect(wcDeriveSymKey(privA, pubB), testSymKey);
    });

    test('deriveSymKey is symmetric (A<->B agree)', () {
      expect(wcDeriveSymKey(privB, pubA), wcDeriveSymKey(privA, pubB));
    });

    test('topic = SHA-256(sharedKey) matches TEST_HASHED_KEY', () {
      expect(wcHashKey(testSharedKey), testHashedKey);
    });

    test('hashMessage matches wallet_connect_dart_v2 fixture', () {
      expect(wcHashMessage(testMessage),
          '15112289b5b794e68d1ea3cd91330db55582a37d0596f7b99ea8becdf9d10496');
    });
  });

  group('WC v2 ChaCha20-Poly1305 envelopes', () {
    final iv = hexDecode(testIv);

    test('encrypt type 0 matches fixture', () {
      final encoded = wcEncrypt(
        message: testMessage,
        symKeyHex: testSymKey,
        iv: Uint8List.fromList(iv),
      );
      expect(encoded, testEncodedType0);
    });

    test('decrypt type 0 recovers message', () {
      expect(wcDecrypt(symKeyHex: testSymKey, encoded: testEncodedType0),
          testMessage);
    });

    test('encrypt type 1 matches fixture', () {
      final encoded = wcEncrypt(
        message: testMessage,
        symKeyHex: testSymKey,
        type: 1,
        iv: Uint8List.fromList(iv),
        senderPublicKeyHex: pubA,
      );
      expect(encoded, testEncodedType1);
    });

    test('type 1 envelope carries sender public key; receiver derives symKey',
        () {
      final env = wcDeserialize(testEncodedType1);
      expect(env.type, 1);
      expect(hexEncode(env.senderPublicKey!), pubA);
      // Receiver (B) derives the same symKey from sender pubkey.
      final symKey = wcDeriveSymKey(privB, hexEncode(env.senderPublicKey!));
      expect(symKey, testSymKey);
      expect(wcDecrypt(symKeyHex: symKey, encoded: testEncodedType1),
          testMessage);
    });

    test('encode/decode round-trip with a known payload', () {
      const symKey =
          '5720435e682cd03ee45b484f9a213f0e3246a0ccc2cca183b72ab1cbfbefb702';
      final payload = jsonEncode({'id': 1, 'jsonrpc': '2.0', 'result': 'result'});
      final encoded = wcEncrypt(
        message: payload,
        symKeyHex: symKey,
        iv: Uint8List.fromList(hexDecode(testIv)),
      );
      expect(wcDecrypt(symKeyHex: symKey, encoded: encoded), payload);
      // The wallet_connect_dart_v2 ENCODED fixture (different IV) decrypts to
      // the same payload.
      const encodedFixture =
          'AG7iJl9mMl9K04REnuWaKLQU6kwMcQWUd69OxGOJ5/A+VRRKkxnKhBeIAl4JRaIft3qZKEfnBvc7/Fife1DWcERqAfJwzPI=';
      expect(wcDecrypt(symKeyHex: symKey, encoded: encodedFixture), payload);
    });
  });
}
