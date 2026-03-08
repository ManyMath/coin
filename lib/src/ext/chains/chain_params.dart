import '../../chain/chain.dart';

enum AddrType {
  p2pkh,
  p2sh,
  p2wpkh,
  p2wsh,
  p2tr,

  /// Litecoin MWEB stealth address (routing tag only; does NOT imply the
  /// canonical-chain script contract of the other types).
  mweb,
}

class ChainParams {
  final Chain chain;
  final String chainName;
  final String ticker;
  final String identifier;
  final int bip44CoinType;
  final List<AddrType> supportedAddrTypes;
  final bool supportsSegwit;
  final bool supportsTaproot;

  /// Litecoin MWEB capability flag. Parallel to supportsSegwit / supportsTaproot.
  final bool supportsMweb;

  /// BCH / BSV set this to modify sighash computation.
  final bool usesForkId;

  const ChainParams({
    required this.chain,
    required this.chainName,
    required this.ticker,
    required this.identifier,
    required this.bip44CoinType,
    required this.supportedAddrTypes,
    this.supportsSegwit = true,
    this.supportsTaproot = true,
    this.supportsMweb = false,
    this.usesForkId = false,
  });

  int get wifPrefix => chain.wifPrefix;
  int get p2pkhPrefix => chain.p2pkhPrefix;
  int get p2shPrefix => chain.p2shPrefix;
  String? get bech32Hrp => chain.bech32Hrp;
}
