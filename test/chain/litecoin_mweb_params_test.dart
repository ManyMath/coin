import 'package:coin/src/chain/chain.dart';
import 'package:coin/src/crypto/vault_keeper.dart';
import 'package:coin/src/ext/chains/chain_params.dart';
import 'package:coin/src/ext/chains/litecoin_params.dart';
import 'package:test/test.dart';

// The asserted MWEB HRPs ("ltcmweb" mainnet, "tmweb" testnet) are Litecoin
// Core's MWEB address human-readable parts (litecoin-project/litecoin
// chainparams.cpp / mweb address encoding); the remaining expectations are
// flags on this library's own ChainParams model.
void main() {
  setUpAll(() async {
    await VaultKeeper.initialize();
  });

  group('Litecoin MWEB capability gating', () {
    test('mainnet advertises MWEB support and ltcmweb HRP', () {
      final p = LitecoinParams.litecoin;
      expect(p.supportsMweb, isTrue);
      expect(p.chain.mwebHrp, 'ltcmweb');
      expect(p.supportedAddrTypes, contains(AddrType.mweb));
    });

    test('testnet advertises MWEB support and tmweb HRP', () {
      final p = LitecoinParams.litecoinTestnet;
      expect(p.supportsMweb, isTrue);
      expect(p.chain.mwebHrp, 'tmweb');
      expect(p.supportedAddrTypes, contains(AddrType.mweb));
    });

    test('supportsMweb defaults to false / mwebHrp null elsewhere', () {
      // A chain without MWEB (Peercoin) must not advertise the capability.
      expect(Chain.peercoin.mwebHrp, isNull);
      expect(ChainParams(
        chain: Chain.peercoin,
        chainName: 'x',
        ticker: 'X',
        identifier: 'x',
        bip44CoinType: 0,
        supportedAddrTypes: const [],
      ).supportsMweb, isFalse);
    });
  });
}
