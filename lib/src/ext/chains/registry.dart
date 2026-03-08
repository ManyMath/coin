import 'chain_params.dart';
import 'bitcoin_params.dart';
import 'litecoin_params.dart';
import 'dogecoin_params.dart';
import 'dash_params.dart';
import 'firo_params.dart';
import 'bitcoin_cash_params.dart';
import 'bitcoin_sv_params.dart';
import 'monero_params.dart';
import 'particl_params.dart';

class ChainRegistry {
  ChainRegistry._();

  static final List<ChainParams> all = List<ChainParams>.unmodifiable([
    BitcoinParams.bitcoin,
    BitcoinParams.bitcoinTestnet,
    BitcoinParams.bitcoinSignet,
    LitecoinParams.litecoin,
    LitecoinParams.litecoinTestnet,
    DogecoinParams.dogecoin,
    DogecoinParams.dogecoinTestnet,
    DashParams.dash,
    DashParams.dashTestnet,
    FiroParams.firo,
    FiroParams.firoTestnet,
    BitcoinCashParams.bitcoinCash,
    BitcoinCashParams.bitcoinCashTestnet,
    BitcoinSvParams.bitcoinSv,
    BitcoinSvParams.bitcoinSvTestnet,
    MoneroParams.monero,
    MoneroParams.moneroTestnet,
    MoneroParams.moneroStagenet,
    ParticlParams.particl,
    ParticlParams.particlTestnet,
  ]);

  static ChainParams? byName(String name) {
    final lower = name.toLowerCase();
    for (final p in all) {
      if (p.chainName.toLowerCase() == lower) return p;
    }
    return null;
  }

  static ChainParams? byTicker(String ticker) {
    final upper = ticker.toUpperCase();
    for (final p in all) {
      if (p.ticker.toUpperCase() == upper) return p;
    }
    return null;
  }

  static ChainParams? byIdentifier(String identifier) {
    for (final p in all) {
      if (p.identifier == identifier) return p;
    }
    return null;
  }
}
