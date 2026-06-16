import 'dart:typed_data';

import '../addr/legacy_addr.dart';
import '../addr/segwit_addr.dart';
import '../addr/taproot_addr.dart';
import '../crypto/derived_key.dart';
import '../crypto/mnemonic.dart';
import '../crypto/public_key.dart';
import '../ext/chains/chain_params.dart';
import '../hash/digest.dart';
import '../script/lockings/pay_to_witness_pubkey.dart';
import '../taproot/taproot.dart';

/// BIP standard derivation schemes, each mapping to a single address type.
///
///  - [bip44]: `m/44'/coin'/account'` legacy P2PKH
///  - [bip49]: `m/49'/coin'/account'` P2SH-wrapped P2WPKH
///  - [bip84]: `m/84'/coin'/account'` native SegWit P2WPKH
///  - [bip86]: `m/86'/coin'/account'` Taproot P2TR (single-key, key-path only)
enum DerivationScheme {
  bip44(44, AddrType.p2pkh),
  bip49(49, AddrType.p2sh),
  bip84(84, AddrType.p2wpkh),
  bip86(86, AddrType.p2tr);

  const DerivationScheme(this.purpose, this.addrType);

  /// BIP purpose number used as the first hardened path element.
  final int purpose;

  /// Address type produced by this scheme.
  final AddrType addrType;
}

/// A hierarchical-deterministic wallet root.
///
/// Built from a BIP-39 mnemonic (with optional passphrase) or directly from a
/// raw seed. The root holds only the master [DerivedKey]; concrete addresses
/// are produced through [account].
///
/// This is the first slice of the wallet layer: it covers
/// derivation -> address only. It performs no UTXO tracking, coin selection,
/// transaction building, or network I/O.
class HdWallet {
  /// BIP-32 master key derived from the seed.
  final DerivedKey master;

  HdWallet._(this.master);

  /// Construct from a raw BIP-32 seed (typically 64 bytes from BIP-39).
  factory HdWallet.fromSeed(Uint8List seed) =>
      HdWallet._(DerivedKey.fromSeed(seed));

  /// Construct from a BIP-39 mnemonic phrase and optional passphrase.
  factory HdWallet.fromMnemonic(String mnemonic, {String passphrase = ''}) {
    final seed = Mnemonic.fromPhrase(mnemonic).toSeed(passphrase: passphrase);
    return HdWallet.fromSeed(seed);
  }

  /// Construct from a [Mnemonic] object and optional passphrase.
  factory HdWallet.fromMnemonicObject(
    Mnemonic mnemonic, {
    String passphrase = '',
  }) =>
      HdWallet.fromSeed(mnemonic.toSeed(passphrase: passphrase));

  /// Derive an [HdAccount] at `m/purpose'/coinType'/account'` for [params]
  /// using [scheme].
  ///
  /// The coin type is taken from [ChainParams.bip44CoinType]. Throws a
  /// [StateError] if [scheme] requires a chain capability the chain lacks
  /// (SegWit for BIP49/84, Taproot for BIP86).
  HdAccount account(
    ChainParams params, {
    DerivationScheme scheme = DerivationScheme.bip44,
    int account = 0,
  }) {
    _assertSupported(params, scheme);
    final path =
        "m/${scheme.purpose}'/${params.bip44CoinType}'/$account'";
    final node = master.derivePath(path);
    return HdAccount._(
      node: node,
      params: params,
      scheme: scheme,
      accountIndex: account,
    );
  }

  static void _assertSupported(ChainParams params, DerivationScheme scheme) {
    switch (scheme) {
      case DerivationScheme.bip44:
        break; // Always supported (legacy base58).
      case DerivationScheme.bip49:
      case DerivationScheme.bip84:
        if (!params.supportsSegwit) {
          throw StateError(
            '${params.chainName} does not support SegWit; '
            '${scheme.name} is unavailable. Use bip44.',
          );
        }
      case DerivationScheme.bip86:
        if (!params.supportsTaproot) {
          throw StateError(
            '${params.chainName} does not support Taproot; '
            'bip86 is unavailable. Use bip44.',
          );
        }
    }
  }
}

/// An account node `m/purpose'/coinType'/account'` bound to a [ChainParams]
/// and a [DerivationScheme].
///
/// Exposes the account-level extended public key plus external (receive) and
/// internal (change) address derivation. Addresses are encoded for the
/// account's chain using the address type implied by the scheme.
class HdAccount {
  /// The account-level BIP-32 node (`m/purpose'/coinType'/account'`).
  final DerivedKey node;

  /// Chain parameters this account is bound to.
  final ChainParams params;

  /// Derivation scheme (determines purpose and address type).
  final DerivationScheme scheme;

  /// Zero-based account index (the `account'` path element).
  final int accountIndex;

  HdAccount._({
    required this.node,
    required this.params,
    required this.scheme,
    required this.accountIndex,
  });

  /// Reconstruct a watch-only [HdAccount] from an account-level extended PUBLIC
  /// key ([accountXpub]) plus its [params], [scheme] and [account] index.
  ///
  /// The resulting account can derive addresses and back a [WalletAccount]'s
  /// state, but cannot sign (its [node] is a [DerivedPublicKey]). This is the
  /// restore path for persisted wallets: no private material is required.
  factory HdAccount.fromXpub(
    String xpub, {
    required ChainParams params,
    required DerivationScheme scheme,
    int account = 0,
  }) {
    HdWallet._assertSupported(params, scheme);
    return HdAccount._(
      node: DerivedPublicKey.decode(xpub),
      params: params,
      scheme: scheme,
      accountIndex: account,
    );
  }

  /// Account-level extended public key (xpub-form, BIP-32 version bytes).
  ///
  /// Uses the canonical 0x0488B21E version regardless of scheme; SLIP-0132
  /// scheme-specific prefixes (ypub/zpub) are out of scope for this slice.
  String get accountXpub {
    final pub = _neuter(node);
    return pub.encode();
  }

  /// External-chain receive address at index [i] (`.../0/i`).
  String receiveAddress(int i) => _addressAt(0, i);

  /// Internal-chain change address at index [i] (`.../1/i`).
  String changeAddress(int i) => _addressAt(1, i);

  String _addressAt(int change, int index) {
    final leaf = node.derive(change).derive(index);
    return _encodeAddress(leaf.publicKey);
  }

  String _encodeAddress(PublicKey pubKey) {
    final chain = params.chain;
    switch (scheme.addrType) {
      case AddrType.p2pkh:
        return P2pkhAddr(hash160(pubKey.bytes)).encode(chain);
      case AddrType.p2sh:
        // BIP49: P2SH-wrapping a P2WPKH program.
        final witnessProgram = PayToWitnessPubKey(hash160(pubKey.bytes));
        final scriptHash = hash160(witnessProgram.compiled);
        return P2shAddr(scriptHash).encode(chain);
      case AddrType.p2wpkh:
        return P2wpkhAddr(hash160(pubKey.bytes)).encode(chain);
      case AddrType.p2tr:
        // BIP86: key-path-only taproot. Output key is the internal key
        // tweaked with an empty script tree.
        final outputKey = Taproot(internalKey: pubKey).tweakedKey;
        return TaprootAddr(outputKey).encode(chain);
      case AddrType.p2wsh:
      case AddrType.mweb:
        throw StateError(
          'Address type ${scheme.addrType} is not produced by a single-key '
          'HD account scheme.',
        );
    }
  }

  static DerivedPublicKey _neuter(DerivedKey key) => DerivedPublicKey(
        publicKey: key.publicKey,
        chainCode: key.chainCode,
        depth: key.depth,
        index: key.index,
        parentFingerprint: key.parentFingerprint,
      );
}
