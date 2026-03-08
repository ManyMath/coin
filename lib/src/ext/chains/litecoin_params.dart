import '../../chain/chain.dart';
import 'chain_params.dart';

extension LitecoinParams on ChainParams {
  static final litecoin = ChainParams(
    chain: const Chain(
      wifPrefix: 0xb0,
      p2pkhPrefix: 0x30,
      p2shPrefix: 0x32,
      bech32Hrp: 'ltc',
      mwebHrp: 'ltcmweb',
      name: 'Litecoin',
      bip44CoinType: 2,
      supportsSegwit: true,
      supportsTaproot: true,
    ),
    chainName: 'Litecoin',
    ticker: 'LTC',
    identifier: 'litecoin',
    bip44CoinType: 2,
    supportedAddrTypes: [
      AddrType.p2pkh,
      AddrType.p2sh,
      AddrType.p2wpkh,
      AddrType.p2wsh,
      AddrType.p2tr,
      AddrType.mweb,
    ],
    supportsSegwit: true,
    supportsTaproot: true,
    supportsMweb: true,
  );

  static final litecoinTestnet = ChainParams(
    chain: const Chain(
      wifPrefix: 0xef,
      p2pkhPrefix: 0x6f,
      p2shPrefix: 0x3a,
      bech32Hrp: 'tltc',
      mwebHrp: 'tmweb',
      name: 'Litecoin Testnet',
      bip44CoinType: 1,
      supportsSegwit: true,
      supportsTaproot: true,
    ),
    chainName: 'Litecoin Testnet',
    ticker: 'tLTC',
    identifier: 'litecoin-testnet',
    bip44CoinType: 1,
    supportedAddrTypes: [
      AddrType.p2pkh,
      AddrType.p2sh,
      AddrType.p2wpkh,
      AddrType.p2wsh,
      AddrType.p2tr,
      AddrType.mweb,
    ],
    supportsSegwit: true,
    supportsTaproot: true,
    supportsMweb: true,
  );
}
