import 'package:coin/coin_chains.dart';
import 'package:test/test.dart';

/// Canonical Trezor / iancoleman test mnemonic.
const _mnemonic =
    'abandon abandon abandon abandon abandon abandon abandon abandon '
    'abandon abandon abandon about';

void main() {
  setUpAll(() async {
    await VaultKeeper.initialize();
  });

  // ---------------------------------------------------------------------------
  // Vector #1: BIP-32 engine check.
  //
  // The canonical BIP-32 test vectors (seed 000102...0e0f) are already
  // asserted in test/crypto/hd_derivation_test.dart against
  // DerivedKey.fromSeed + derivePath + encode(). We re-assert the master xprv
  // here as a smoke check that the engine the wallet builds on is correct and
  // independent of any chain.
  group('BIP-32 engine', () {
    test('master xprv matches BIP-32 vector 1', () {
      final seed = hexDecode('000102030405060708090a0b0c0d0e0f');
      final master = DerivedKey.fromSeed(seed) as DerivedSecretKey;
      expect(
        master.encode(),
        'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvv'
        'NKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi',
      );
    });
  });

  // ---------------------------------------------------------------------------
  // Vector #2: end-to-end Litecoin (canonical mnemonic, empty passphrase).
  // The receive addresses below are derived from the canonical "abandon ...
  // about" mnemonic at the standard BIP-44/49/84 Litecoin paths (coin type 2)
  // and are verifiable with iancoleman's BIP39 tool
  // (https://iancoleman.io/bip39/, coin = Litecoin) for those exact paths.
  group('Litecoin end-to-end (HdAccount)', () {
    late HdWallet wallet;
    setUp(() {
      wallet = HdWallet.fromMnemonic(_mnemonic);
    });

    test("bip44 m/44'/2'/0'/0/0 -> P2PKH", () {
      final acct = wallet.account(
        LitecoinParams.litecoin,
        scheme: DerivationScheme.bip44,
      );
      expect(acct.receiveAddress(0), 'LUWPbpM43E2p7ZSh8cyTBEkvpHmr3cB8Ez');
    });

    test("bip49 m/49'/2'/0'/0/0 -> P2SH-P2WPKH", () {
      final acct = wallet.account(
        LitecoinParams.litecoin,
        scheme: DerivationScheme.bip49,
      );
      expect(acct.receiveAddress(0), 'M7wtsL7wSHDBJVMWWhtQfTMSYYkyooAAXM');
    });

    test("bip84 m/84'/2'/0'/0/0 -> P2WPKH", () {
      final acct = wallet.account(
        LitecoinParams.litecoin,
        scheme: DerivationScheme.bip84,
      );
      expect(
        acct.receiveAddress(0),
        'ltc1qjmxnz78nmc8nq77wuxh25n2es7rzm5c2rkk4wh',
      );
    });

    test('receive and change live on different chains', () {
      final acct = wallet.account(
        LitecoinParams.litecoin,
        scheme: DerivationScheme.bip44,
      );
      expect(acct.receiveAddress(0), isNot(equals(acct.changeAddress(0))));
    });

    test('accountXpub is a valid xpub string', () {
      final acct = wallet.account(LitecoinParams.litecoin);
      expect(acct.accountXpub, startsWith('xpub'));
    });
  });

  // ---------------------------------------------------------------------------
  // Vector #3: end-to-end Firo (legacy-only chain).
  // P2PKH receive address derived from the canonical mnemonic at m/44'/136'/0'
  // (Firo coin type 136); verifiable with iancoleman's BIP39 tool
  // (coin = Firo). Same vector as test/wallet/chains/firo_account_test.dart.
  group('Firo end-to-end (HdAccount)', () {
    late HdWallet wallet;
    setUp(() {
      wallet = HdWallet.fromMnemonic(_mnemonic);
    });

    test("bip44 m/44'/136'/0'/0/0 -> P2PKH", () {
      final acct = wallet.account(
        FiroParams.firo,
        scheme: DerivationScheme.bip44,
      );
      expect(acct.receiveAddress(0), 'a1bW3sVVUsLqgKuTMXtSaAHGvpxKwugxPH');
    });

    test('bip84 throws on Firo (no SegWit)', () {
      expect(
        () => wallet.account(
          FiroParams.firo,
          scheme: DerivationScheme.bip84,
        ),
        throwsA(isA<StateError>()),
      );
    });

    test('bip86 throws on Firo (no Taproot)', () {
      expect(
        () => wallet.account(
          FiroParams.firo,
          scheme: DerivationScheme.bip86,
        ),
        throwsA(isA<StateError>()),
      );
    });
  });

  // ---------------------------------------------------------------------------
  // Seed-based construction parity.
  group('Construction', () {
    test('fromMnemonic and fromSeed agree', () {
      final seed = Mnemonic.fromPhrase(_mnemonic).toSeed();
      final fromSeed = HdWallet.fromSeed(seed);
      final fromMnemonic = HdWallet.fromMnemonic(_mnemonic);
      expect(
        fromSeed.account(LitecoinParams.litecoin).receiveAddress(0),
        fromMnemonic.account(LitecoinParams.litecoin).receiveAddress(0),
      );
    });
  });
}
