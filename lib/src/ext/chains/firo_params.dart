import '../../chain/chain.dart';
import 'chain_params.dart';

/// Firo (formerly Zcoin) chain parameters.
///
/// Byte values from firoorg/firo src/chainparams.cpp `base58Prefixes`. Firo
/// is legacy-base58 only: no SegWit, no Taproot, no Bech32.
extension FiroParams on ChainParams {
  static final firo = ChainParams(
    chain: const Chain(
      wifPrefix: 0xd2,
      p2pkhPrefix: 0x52,
      p2shPrefix: 0x07,
      bech32Hrp: null,
      name: 'Firo',
      bip44CoinType: 136,
      supportsSegwit: false,
      supportsTaproot: false,
    ),
    chainName: 'Firo',
    ticker: 'FIRO',
    identifier: 'firo',
    bip44CoinType: 136,
    supportedAddrTypes: [
      AddrType.p2pkh,
      AddrType.p2sh,
    ],
    supportsSegwit: false,
    supportsTaproot: false,
  );

  static final firoTestnet = ChainParams(
    chain: const Chain(
      wifPrefix: 0xb9,
      p2pkhPrefix: 0x41,
      p2shPrefix: 0xb2,
      bech32Hrp: null,
      name: 'Firo Testnet',
      bip44CoinType: 1,
      supportsSegwit: false,
      supportsTaproot: false,
    ),
    chainName: 'Firo Testnet',
    ticker: 'tFIRO',
    identifier: 'firo-testnet',
    bip44CoinType: 1,
    supportedAddrTypes: [
      AddrType.p2pkh,
      AddrType.p2sh,
    ],
    supportsSegwit: false,
    supportsTaproot: false,
  );
}
