import '../../chain/chain.dart';
import 'chain_params.dart';

/// Dash chain parameters.
///
/// DIP-2 special transactions (ProRegTx, ProUpServTx, ProUpRegTx, ProUpRevTx,
/// cbTx, QcTx) are supported at the wire level: Dash packs the special-tx type
/// in the high 16 bits of the version word (`nVersion | (nType << 16)`), so a
/// Dash special tx parses to an `ExTx` with `txType` exposing the nType and the
/// trailing `vExtraPayload` preserved unchanged through round-trips, txid,
/// and the legacy sighash preimage. This is the same path Firo uses; see
/// `test/tx/dash_special_tx_vectors_test.dart`. Structured DIP-2 payload
/// decoding and BLS operator-key handling are out of scope (the payload is an
/// opaque blob).
extension DashParams on ChainParams {
  static final dash = ChainParams(
    chain: const Chain(
      wifPrefix: 0xcc,
      p2pkhPrefix: 0x4c,
      p2shPrefix: 0x10,
      bech32Hrp: null,
      name: 'Dash',
      bip44CoinType: 5,
      supportsSegwit: false,
      supportsTaproot: false,
    ),
    chainName: 'Dash',
    ticker: 'DASH',
    identifier: 'dash',
    bip44CoinType: 5,
    supportedAddrTypes: [
      AddrType.p2pkh,
      AddrType.p2sh,
    ],
    supportsSegwit: false,
    supportsTaproot: false,
  );

  static final dashTestnet = ChainParams(
    chain: const Chain(
      wifPrefix: 0xef,
      p2pkhPrefix: 0x8c,
      p2shPrefix: 0x13,
      bech32Hrp: null,
      name: 'Dash Testnet',
      bip44CoinType: 1,
      supportsSegwit: false,
      supportsTaproot: false,
    ),
    chainName: 'Dash Testnet',
    ticker: 'tDASH',
    identifier: 'dash-testnet',
    bip44CoinType: 1,
    supportedAddrTypes: [
      AddrType.p2pkh,
      AddrType.p2sh,
    ],
    supportsSegwit: false,
    supportsTaproot: false,
  );
}
