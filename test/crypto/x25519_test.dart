import 'package:coin/coin.dart';
import 'package:coin/src/crypto/soft/x25519.dart';
import 'package:test/test.dart';

void main() {
  group('X25519 (RFC 7748)', () {
    // RFC 7748 sec. 5.2, test vector 1.
    // https://www.rfc-editor.org/rfc/rfc7748#section-5.2
    test('RFC 7748 sec. 5.2 vector 1', () {
      final scalar = hexDecode(
        'a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4',
      );
      final u = hexDecode(
        'e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c',
      );
      final out = x25519(scalar, u);
      expect(
        hexEncode(out),
        equals(
          'c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552',
        ),
      );
    });

    // RFC 7748 sec. 5.2, test vector 2.
    // https://www.rfc-editor.org/rfc/rfc7748#section-5.2
    test('RFC 7748 sec. 5.2 vector 2', () {
      final scalar = hexDecode(
        '4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d',
      );
      final u = hexDecode(
        'e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493',
      );
      final out = x25519(scalar, u);
      expect(
        hexEncode(out),
        equals(
          '95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957',
        ),
      );
    });

    // RFC 7748 sec. 6.1, X25519 Diffie-Hellman example.
    // https://www.rfc-editor.org/rfc/rfc7748#section-6.1
    group('RFC 7748 sec. 6.1 ECDH', () {
      final alicePriv = hexDecode(
        '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a',
      );
      const alicePubHex =
          '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a';
      final bobPriv = hexDecode(
        '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb',
      );
      const bobPubHex =
          'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f';
      const sharedHex =
          '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742';

      test('Alice public key from x25519Base', () {
        expect(hexEncode(x25519Base(alicePriv)), equals(alicePubHex));
      });

      test('Bob public key from x25519Base', () {
        expect(hexEncode(x25519Base(bobPriv)), equals(bobPubHex));
      });

      test('shared secret (Alice with Bob public)', () {
        expect(
          hexEncode(x25519(alicePriv, hexDecode(bobPubHex))),
          equals(sharedHex),
        );
      });

      test('shared secret (Bob with Alice public)', () {
        expect(
          hexEncode(x25519(bobPriv, hexDecode(alicePubHex))),
          equals(sharedHex),
        );
      });
    });

    // WalletConnect v2 transport fixture from the
    // BSD-licensed wallet_connect_dart_v2 (Orange-Wallet) test data -
    // privA=TEST_SELF_PRIVATE_KEY, pubB=TEST_PEER_PUBLIC_KEY,
    // shared=TEST_SHARED_KEY, pubA(x25519Base)=TEST_SELF_PUBLIC_KEY. Same
    // values are exercised end-to-end in test/walletconnect/wc_v2_crypto_test.dart.
    // https://github.com/Orange-Wallet/wallet-connect-dart-v2
    //   test/utils/mock_data.dart
    test('WalletConnect fixture', () {
      final privA = hexDecode(
        '1fb63fca5c6ac731246f2f069d3bc2454345d5208254aa8ea7bffc6d110c8862',
      );
      final pubB = hexDecode(
        '590c2c627be7af08597091ff80dd41f7fa28acd10ef7191d7e830e116d3a186a',
      );
      final shared = x25519(privA, pubB);
      expect(
        hexEncode(shared),
        equals(
          '9c87e48e69b33a613907515bcd5b1b4cc10bbaf15167b19804b00f0a9217e607',
        ),
      );
      expect(
        hexEncode(x25519Base(privA)),
        equals(
          'ff7a7d5767c362b0a17ad92299ebdb7831dcbd9a56959c01368c7404543b3342',
        ),
      );
    });
  });
}
