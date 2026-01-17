import 'dart:typed_data';

import 'package:coin/coin.dart';
import 'package:coin/src/crypto/soft/ed25519_sign.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(() async {
    await VaultKeeper.initialize();
  });

  // RFC 8032 sec. 7.1 Ed25519 test vectors.
  // https://www.rfc-editor.org/rfc/rfc8032 sec. 7.1.
  // Each vector: secret seed (32 bytes) -> public key A (32 bytes);
  // sign(message) -> 64-byte signature.
  group('RFC 8032 sec. 7.1 Ed25519 test vectors', () {
    test('TEST 1 (empty message)', () {
      final seed = hexDecode(
          '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60');
      final pub = hexDecode(
          'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a');
      final msg = Uint8List(0);
      final sig = hexDecode(
          'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b');

      expect(hexEncode(ed25519PublicKeyFromSeed(seed)), hexEncode(pub));
      expect(hexEncode(ed25519Sign(seed, msg)), hexEncode(sig));
      expect(ed25519Verify(pub, msg, sig), isTrue);
    });

    test('TEST 2 (1-byte message)', () {
      final seed = hexDecode(
          '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb');
      final pub = hexDecode(
          '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c');
      final msg = hexDecode('72');
      final sig = hexDecode(
          '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00');

      expect(hexEncode(ed25519PublicKeyFromSeed(seed)), hexEncode(pub));
      expect(hexEncode(ed25519Sign(seed, msg)), hexEncode(sig));
      expect(ed25519Verify(pub, msg, sig), isTrue);
    });

    test('TEST 3 (2-byte message)', () {
      final seed = hexDecode(
          'c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7');
      final pub = hexDecode(
          'fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025');
      final msg = hexDecode('af82');
      final sig = hexDecode(
          '6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a');

      expect(hexEncode(ed25519PublicKeyFromSeed(seed)), hexEncode(pub));
      expect(hexEncode(ed25519Sign(seed, msg)), hexEncode(sig));
      expect(ed25519Verify(pub, msg, sig), isTrue);
    });
  });

  // WalletConnect relay-auth fixture. Seed 58e0254c..1295 -> public key
  // 884ab67f..be5a, from the reown relay_auth test fixture; also used in
  // test/walletconnect/wc_relay_auth_test.dart.
  // https://github.com/reown-com/reown_flutter
  //   packages/reown_core/test/relay_auth_test.dart
  group('WalletConnect/reown fixture', () {
    test('seed derives expected public key', () {
      final seed = hexDecode(
          '58e0254c211b858ef7896b00e3f36beeb13d568d47c6031c4218b87718061295');
      expect(
        hexEncode(ed25519PublicKeyFromSeed(seed)),
        '884ab67f787b69e534bfdba8d5beb4e719700e90ac06317ed177d49e5a33be5a',
      );
    });
  });

  // Round-trip (sign-then-verify) and tamper detection using the relay-auth
  // seed above.
  group('round-trip sign/verify', () {
    test('valid signature verifies; flipped bit fails', () {
      final seed = hexDecode(
          '58e0254c211b858ef7896b00e3f36beeb13d568d47c6031c4218b87718061295');
      final pub = ed25519PublicKeyFromSeed(seed);
      final msg = Uint8List.fromList('coin ed25519 round trip'.codeUnits);

      final sig = ed25519Sign(seed, msg);
      expect(ed25519Verify(pub, msg, sig), isTrue);

      // Flip one bit in the signature -> must fail.
      final bad = Uint8List.fromList(sig);
      bad[10] ^= 0x01;
      expect(ed25519Verify(pub, msg, bad), isFalse);

      // Tamper the message -> must fail.
      final badMsg = Uint8List.fromList(msg);
      badMsg[0] ^= 0x01;
      expect(ed25519Verify(pub, badMsg, sig), isFalse);
    });
  });
}
