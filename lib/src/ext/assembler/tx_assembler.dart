import 'dart:typed_data';

import 'package:meta/meta.dart';

import '../../hash/digest.dart';
import '../../tx/tx.dart';
import '../../tx/tx_output.dart';
import '../../tx/inputs/tx_input.dart';
import '../../tx/inputs/input_sig.dart';
import '../../tx/inputs/p2pkh_input.dart';
import '../../tx/inputs/p2wpkh_input.dart';
import '../../tx/outpoint.dart';
import '../../tx/sighash/legacy_hasher.dart';
import '../../tx/sighash/sighash_type.dart';
import '../../tx/sighash/witness_hasher.dart';
import '../chains/chain_params.dart';
import 'ordering.dart';
import 'signing_callback.dart';

/// Describes how an [AssemblerInput] is spent. This drives both the BIP-143 /
/// legacy sighash computation and the construction of the signed input.
enum AssemblerInputType {
  /// Legacy pay-to-pubkey-hash. scriptSig = `[sig, pubkey]`.
  p2pkh,

  /// Nested segwit (P2SH-wrapped P2WPKH). scriptSig = push(redeemScript),
  /// witness = `[sig, pubkey]`.
  p2shP2wpkh,

  /// Native segwit v0 pay-to-witness-pubkey-hash. witness = `[sig, pubkey]`.
  p2wpkh,

  /// Taproot key-path spend. witness = `[schnorrSig]`.
  ///
  /// NOTE: not yet wired in [TxAssembler] - see [TxAssembler.build].
  p2tr,
}

/// Metadata for a UTXO being spent.
class AssemblerInput {
  final Outpoint outpoint;
  final BigInt value;
  final Uint8List scriptPubKey;
  final int sequence;
  final SigHashType hashType;

  /// The kind of script being spent. Determines the sighash algorithm and the
  /// shape of the signed input that is attached.
  final AssemblerInputType type;

  /// The public key controlling this UTXO. Required for every type currently
  /// supported (p2pkh / p2shP2wpkh / p2wpkh). Optional only for taproot
  /// key-path spends, which are not yet supported.
  final Uint8List? publicKey;

  const AssemblerInput({
    required this.outpoint,
    required this.value,
    required this.scriptPubKey,
    required this.type,
    this.publicKey,
    this.sequence = TxInput.sequenceFinal,
    this.hashType = SigHashType.all,
  });
}

/// High-level transaction builder that takes UTXOs, outputs, and a chain
/// config to produce a fully-signed [Tx].
///
/// For new code prefer the wallet-layer builder; this type is retained for the
/// chains barrel API. Unlike its previous (broken) incarnation, [build] /
/// [buildAsync] now attach the produced signatures and return a transaction
/// with `complete == true`.
class TxAssembler {
  final ChainParams chainParams;
  final List<AssemblerInput> inputs;
  final List<TxOutput> outputs;
  final int version;
  final int locktime;
  final TxOrdering ordering;

  TxAssembler({
    required this.chainParams,
    required this.inputs,
    required this.outputs,
    this.version = Tx.currentVersion,
    this.locktime = 0,
    this.ordering = TxOrdering.bip69,
  });

  /// Builds and signs the transaction synchronously.
  ///
  /// The [signer] is invoked once per input with the BIP-143 (segwit) or legacy
  /// sighash digest and must return DER-encoded ECDSA signature bytes WITHOUT
  /// the trailing sighash flag (the flag is appended when the input is
  /// serialized, via [InputSig.toBytes]).
  Tx build(SignerCallback signer) {
    final ordered = orderedInputs();
    final outs = orderedOutputs();
    final tx = unsignedTx(ordered, outs);

    final signed = List<TxInput>.generate(ordered.length, (i) {
      final meta = ordered[i];
      final digest = computeDigest(tx, i, meta);
      final sig = signer(tx, i, digest, meta.hashType);
      return buildSignedInput(meta, sig);
    });

    return Tx(
      version: version,
      inputs: signed,
      outputs: outs,
      locktime: locktime,
    );
  }

  /// Async variant of [build] for hardware wallets / remote signers.
  Future<Tx> buildAsync(AsyncSignerCallback signer) async {
    final ordered = orderedInputs();
    final outs = orderedOutputs();
    final tx = unsignedTx(ordered, outs);

    final signed = <TxInput>[];
    for (var i = 0; i < ordered.length; i++) {
      final meta = ordered[i];
      final digest = computeDigest(tx, i, meta);
      final sig = await signer(tx, i, digest, meta.hashType);
      signed.add(buildSignedInput(meta, sig));
    }

    return Tx(
      version: version,
      inputs: signed,
      outputs: outs,
      locktime: locktime,
    );
  }

  // --- internals (protected: overridable by subclasses such as
  //     ForkedTxAssembler) -------------------------------------------------

  @protected
  List<AssemblerInput> orderedInputs() {
    final list = List<AssemblerInput>.of(inputs);
    if (ordering == TxOrdering.bip69) {
      list.sort((a, b) {
        final c = compareBytes(a.outpoint.txid, b.outpoint.txid);
        if (c != 0) return c;
        return a.outpoint.vout.compareTo(b.outpoint.vout);
      });
    }
    return list;
  }

  @protected
  List<TxOutput> orderedOutputs() {
    final list = List<TxOutput>.of(outputs);
    if (ordering == TxOrdering.bip69) {
      list.sort((a, b) {
        final c = a.value.compareTo(b.value);
        if (c != 0) return c;
        return compareBytes(a.scriptPubKey, b.scriptPubKey);
      });
    }
    return list;
  }

  @protected
  Tx unsignedTx(List<AssemblerInput> ins, List<TxOutput> outs) => Tx(
        version: version,
        inputs: ins
            .map((i) => RawInput(prevOut: i.outpoint, sequence: i.sequence))
            .toList(),
        outputs: outs,
        locktime: locktime,
      );

  /// Computes the sighash digest for the input, choosing the algorithm and -
  /// for segwit - the BIP-143 scriptCode based on [AssemblerInput.type].
  ///
  /// Subclasses (e.g. [ForkedTxAssembler]) override this to substitute an
  /// alternative sighash algorithm.
  @protected
  Uint8List computeDigest(Tx tx, int index, AssemblerInput meta) {
    switch (meta.type) {
      case AssemblerInputType.p2pkh:
        final LegacySigHasher hasher = LegacySigHasher();
        return hasher.hash(tx, index, meta.hashType,
            prevScript: meta.scriptPubKey);
      case AssemblerInputType.p2wpkh:
      case AssemblerInputType.p2shP2wpkh:
        final WitnessSigHasher hasher = WitnessSigHasher();
        // BIP-143: the scriptCode for P2WPKH (incl. nested) is the P2PKH-form
        // script over the pubkey hash, NOT the witness program / redeemScript.
        return hasher.hash(tx, index, meta.hashType,
            prevScript: p2wpkhScriptCode(meta), amount: meta.value);
      case AssemblerInputType.p2tr:
        throw UnsupportedError(
          'Taproot key-path spends are not yet supported by TxAssembler. '
          'Use the segwit/legacy types, or sign taproot inputs directly.',
        );
    }
  }

  /// Builds the concrete signed [TxInput] for [meta] from the DER signature
  /// bytes returned by the signer (no sighash flag appended yet).
  @protected
  TxInput buildSignedInput(AssemblerInput meta, Uint8List derSig) {
    final pubKey = meta.publicKey;
    if (pubKey == null) {
      throw ArgumentError(
        'AssemblerInput.publicKey is required for type ${meta.type}',
      );
    }
    final inputSig = InputSig(derSig: derSig, hashType: meta.hashType);

    switch (meta.type) {
      case AssemblerInputType.p2pkh:
        return P2pkhInput(
          prevOut: meta.outpoint,
          inputSig: inputSig,
          publicKey: pubKey,
          sequence: meta.sequence,
        );
      case AssemblerInputType.p2wpkh:
        return P2wpkhInput(
          prevOut: meta.outpoint,
          inputSig: inputSig,
          publicKey: pubKey,
          sequence: meta.sequence,
        );
      case AssemblerInputType.p2shP2wpkh:
        return _P2shP2wpkhInput(
          prevOut: meta.outpoint,
          inputSig: inputSig,
          publicKey: pubKey,
          sequence: meta.sequence,
        );
      case AssemblerInputType.p2tr:
        throw UnsupportedError(
          'Taproot key-path spends are not yet supported by TxAssembler.',
        );
    }
  }

  /// BIP-143 scriptCode for P2WPKH / nested P2WPKH:
  /// `OP_DUP OP_HASH160 <20-byte keyhash> OP_EQUALVERIFY OP_CHECKSIG`.
  @protected
  Uint8List p2wpkhScriptCode(AssemblerInput meta) {
    final pubKey = meta.publicKey;
    if (pubKey == null) {
      throw ArgumentError(
        'AssemblerInput.publicKey is required for type ${meta.type}',
      );
    }
    final keyHash = hash160(pubKey);
    return Uint8List.fromList([
      0x76, // OP_DUP
      0xa9, // OP_HASH160
      0x14, // push 20 bytes
      ...keyHash,
      0x88, // OP_EQUALVERIFY
      0xac, // OP_CHECKSIG
    ]);
  }

  @protected
  int compareBytes(Uint8List a, Uint8List b) {
    final len = a.length < b.length ? a.length : b.length;
    for (var i = 0; i < len; i++) {
      if (a[i] != b[i]) return a[i].compareTo(b[i]);
    }
    return a.length.compareTo(b.length);
  }
}

/// Nested-segwit (P2SH-P2WPKH) signed input.
///
/// scriptSig is a single push of the witness redeemScript `0x00 0x14 <keyhash>`;
/// witness is `[sig, pubkey]`.
class _P2shP2wpkhInput extends TxInput {
  @override
  final Outpoint prevOut;
  @override
  final int sequence;
  final InputSig inputSig;
  final Uint8List publicKey;

  _P2shP2wpkhInput({
    required this.prevOut,
    required this.inputSig,
    required this.publicKey,
    this.sequence = TxInput.sequenceFinal,
  });

  @override
  Uint8List get scriptSig {
    final keyHash = hash160(publicKey);
    // redeemScript = OP_0 <20-byte push of keyhash>
    final redeem = <int>[0x00, 0x14, ...keyHash];
    // scriptSig = push(redeemScript)
    return Uint8List.fromList([redeem.length, ...redeem]);
  }

  @override
  List<Uint8List> get witness => [inputSig.toBytes(), publicKey];

  @override
  bool get complete => true;

  @override
  int get signedSize => 91; // ~ nested P2WPKH input vsize
}
