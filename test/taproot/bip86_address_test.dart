import 'package:coin/coin_chains.dart';
import 'package:test/test.dart';

/// BIP-86 receive/change address vectors from
/// https://raw.githubusercontent.com/bitcoin/bips/master/bip-0086.mediawiki
///
///   mnemonic = "abandon abandon ... about" (empty passphrase)
///   account  = m/86'/0'/0'
///
/// Exercises the full derivation -> internal key -> BIP-341 even-Y
/// `taproot_tweak_pubkey` -> output key -> bech32m path, covering whatever
/// Y-parities these keys have.
const _mnemonic =
    'abandon abandon abandon abandon abandon abandon abandon abandon '
    'abandon abandon abandon about';

// m/86'/0'/0'/0/0, m/86'/0'/0'/0/1, m/86'/0'/0'/1/0
const _receive0 = 'bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr';
const _receive1 = 'bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh';
const _change0 = 'bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7';

void main() {
  setUpAll(() async {
    await VaultKeeper.initialize();
  });

  group('BIP-86 taproot address vectors', () {
    late final HdAccount account;

    setUpAll(() {
      final wallet = HdWallet.fromMnemonic(_mnemonic);
      account = wallet.account(
        BitcoinParams.bitcoin,
        scheme: DerivationScheme.bip86,
        account: 0,
      );
    });

    test("m/86'/0'/0'/0/0 receive address #0", () {
      expect(account.receiveAddress(0), equals(_receive0));
    });

    test("m/86'/0'/0'/0/1 receive address #1", () {
      expect(account.receiveAddress(1), equals(_receive1));
    });

    test("m/86'/0'/0'/1/0 change address #0", () {
      expect(account.changeAddress(0), equals(_change0));
    });
  });
}
