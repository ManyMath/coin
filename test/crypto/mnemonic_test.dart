import 'package:coin/coin.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(() async {
    await VaultKeeper.initialize();
  });

  // The generation/parsing/validation/toString groups below are behavioral
  // (word counts per BIP-39 entropy sizes, whitespace handling, checksum
  // acceptance/rejection). The "abandon..about" and "zoo..vote" phrases are the
  // BIP-39 all-zeros / all-ones-entropy mnemonics; their seeds are asserted in
  // the "BIP-39 seed derivation" group (trezor vectors.json).
  group('Mnemonic generation', () {
    test('generate 12-word mnemonic (128 bits)', () {
      final m = Mnemonic.generate(strength: 128);
      expect(m.words.length, 12);
      expect(m.validate(), isTrue);
    });

    test('generate 15-word mnemonic (160 bits)', () {
      final m = Mnemonic.generate(strength: 160);
      expect(m.words.length, 15);
      expect(m.validate(), isTrue);
    });

    test('generate 18-word mnemonic (192 bits)', () {
      final m = Mnemonic.generate(strength: 192);
      expect(m.words.length, 18);
      expect(m.validate(), isTrue);
    });

    test('generate 21-word mnemonic (224 bits)', () {
      final m = Mnemonic.generate(strength: 224);
      expect(m.words.length, 21);
      expect(m.validate(), isTrue);
    });

    test('generate 24-word mnemonic (256 bits)', () {
      final m = Mnemonic.generate(strength: 256);
      expect(m.words.length, 24);
      expect(m.validate(), isTrue);
    });

    test('invalid strength throws', () {
      expect(() => Mnemonic.generate(strength: 100), throwsArgumentError);
      expect(() => Mnemonic.generate(strength: 127), throwsArgumentError);
      expect(() => Mnemonic.generate(strength: 129), throwsArgumentError);
      expect(() => Mnemonic.generate(strength: 512), throwsArgumentError);
    });

    test('two generated mnemonics are different', () {
      final m1 = Mnemonic.generate();
      final m2 = Mnemonic.generate();
      expect(m1.phrase, isNot(equals(m2.phrase)));
    });
  });

  group('Mnemonic.fromPhrase', () {
    test('parses space-separated words', () {
      const phrase =
          'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
      final m = Mnemonic.fromPhrase(phrase);
      expect(m.words.length, 12);
      expect(m.words.first, 'abandon');
      expect(m.words.last, 'about');
    });

    test('trims leading/trailing whitespace', () {
      const phrase =
          '  abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about  ';
      final m = Mnemonic.fromPhrase(phrase);
      expect(m.words.length, 12);
    });

    test('handles multiple spaces between words', () {
      const phrase =
          'abandon  abandon   abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
      final m = Mnemonic.fromPhrase(phrase);
      expect(m.words.length, 12);
    });

    test('phrase round-trips', () {
      const phrase =
          'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
      final m = Mnemonic.fromPhrase(phrase);
      expect(m.phrase, phrase);
    });
  });

  group('Mnemonic validation', () {
    test('valid 12-word mnemonic validates', () {
      final m = Mnemonic.fromPhrase(
        'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
      );
      expect(m.validate(), isTrue);
    });

    test('valid 24-word mnemonic validates', () {
      final m = Mnemonic.fromPhrase(
        'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote',
      );
      expect(m.validate(), isTrue);
    });

    test('invalid word count fails', () {
      final m = Mnemonic(['abandon', 'abandon', 'abandon']);
      expect(m.validate(), isFalse);
    });

    test('unknown word fails', () {
      final m = Mnemonic([
        'abandon', 'abandon', 'abandon', 'abandon', 'abandon', 'abandon',
        'abandon', 'abandon', 'abandon', 'abandon', 'abandon', 'zzzznotaword',
      ]);
      expect(m.validate(), isFalse);
    });

    test('empty phrase fails', () {
      final m = Mnemonic([]);
      expect(m.validate(), isFalse);
    });
  });

  group('Mnemonic toString', () {
    test('toString returns phrase', () {
      const phrase =
          'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
      final m = Mnemonic.fromPhrase(phrase);
      expect(m.toString(), phrase);
    });
  });

  // BIP-39 PBKDF2-HMAC-SHA512 seed vectors.
  // - "abandon..about" with passphrase "TREZOR" -> c55257c3..3b04: first entry
  //   of the Trezor vectors.json (english, 00000000000000000000000000000000
  //   entropy):
  //   https://github.com/trezor/python-mnemonic/blob/master/vectors.json
  // - Empty-passphrase seeds (abandon..about -> 5eb00bbd..38e4, zoo..vote ->
  //   e28a3705..4fef): PBKDF2-HMAC-SHA512(mnemonic, "mnemonic", 2048).
  group('BIP-39 seed derivation', () {
    test('12-word "abandon" mnemonic with empty passphrase', () {
      final m = Mnemonic.fromPhrase(
        'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
      );
      final seed = m.toSeed();
      expect(seed.length, 64);
      expect(
        hexEncode(seed),
        '5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1'
        '9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4',
      );
    });

    test('24-word "zoo" mnemonic with empty passphrase', () {
      final m = Mnemonic.fromPhrase(
        'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote',
      );
      final seed = m.toSeed();
      expect(seed.length, 64);
      expect(
        hexEncode(seed),
        'e28a37058c7f5112ec9e16a3437cf363a2572d70b6ceb3b6965447623d620f1'
        '4d06bb321a26b33ec15fcd84a3b5ddfd5520e230c924c87aaa0d559749e044fef',
      );
    });

    test('passphrase changes seed', () {
      final m = Mnemonic.fromPhrase(
        'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
      );
      final seedNoPass = m.toSeed();
      final seedWithPass = m.toSeed(passphrase: 'my secret');
      expect(seedNoPass, isNot(equals(seedWithPass)));
      expect(seedWithPass.length, 64);
    });

    test('12-word "abandon" mnemonic with "TREZOR" passphrase', () {
      final m = Mnemonic.fromPhrase(
        'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
      );
      final seed = m.toSeed(passphrase: 'TREZOR');
      expect(seed.length, 64);
      expect(
        hexEncode(seed),
        'c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553'
        '1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04',
      );
    });
  });

  // Behavioral integration: mnemonic seed -> BIP-32 master key shape.
  group('Mnemonic to HD key integration', () {
    test('mnemonic seed produces valid master key', () {
      final m = Mnemonic.fromPhrase(
        'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
      );
      final seed = m.toSeed();
      final master = DerivedKey.fromSeed(seed) as DerivedSecretKey;
      expect(master.depth, 0);
      expect(master.secretKey.bytes.length, 32);
      expect(master.publicKey.bytes.length, 33);
    });

    // Full mnemonic -> seed -> BIP-32 master pipeline for the all-zeros-entropy
    // BIP-39 phrase. The empty-passphrase seed (5eb00bbd..38e4, above) is the
    // BIP-32 input; the resulting mainnet master xprv is the value produced by
    // standard BIP-32 tooling (e.g. iancoleman.io/bip39, BIP32 Root Key field,
    // coin = BTC). Master private key and chain code follow from
    // HMAC-SHA512("Bitcoin seed", seed); the xprv is the base58check of those
    // plus version 0x0488ADE4. The 4-byte master key fingerprint (73c5da0a) is
    // hash160(masterPubKey)[:4].
    test('mnemonic master key matches published "abandon" BIP-32 root xprv',
        () {
      final m = Mnemonic.fromPhrase(
        'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
      );
      final seed = m.toSeed();
      final master = DerivedKey.fromSeed(seed) as DerivedSecretKey;

      // Master private key (IL of HMAC-SHA512("Bitcoin seed", seed)).
      expect(
        master.secretKey.toHex(),
        '1837c1be8e2995ec11cda2b066151be2cfb48adf9e47b151d46adab3a21cdf67',
      );
      // Master chain code (IR).
      expect(
        hexEncode(master.chainCode),
        '7923408dadd3c7b56eed15567707ae5e5dca089de972e07f3b860450e2a3b70e',
      );
      // Master public key (compressed 02/03 + x).
      expect(
        master.publicKey.toHex(),
        '03d902f35f560e0470c63313c7369168d9d7df2d49bf295fd9fb7cb109ccee0494',
      );
      // Master key fingerprint = hash160(masterPubKey)[:4].
      expect(master.fingerprint, 0x73c5da0a);
      // Full base58check mainnet extended root key (xprv, depth 0).
      expect(
        master.encode(),
        'xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHn'
        'LisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu',
      );
    });

    test('different mnemonics produce different master keys', () {
      final m1 = Mnemonic.generate();
      final m2 = Mnemonic.generate();
      final master1 = DerivedKey.fromSeed(m1.toSeed()) as DerivedSecretKey;
      final master2 = DerivedKey.fromSeed(m2.toSeed()) as DerivedSecretKey;
      expect(master1.secretKey.toHex(), isNot(equals(master2.secretKey.toHex())));
    });
  });
}
