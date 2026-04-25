import 'dart:typed_data';

import 'package:meta/meta.dart';

import '../../tx/tx.dart';
import '../forked_tx/forked_hasher.dart';
import 'tx_assembler.dart';

/// [TxAssembler] subclass for SIGHASH_FORKID chains (BCH / BSV).
///
/// Reuses the parent's signing/attachment flow ([TxAssembler.build] /
/// [TxAssembler.buildAsync]) and only swaps in the fork-id sighash algorithm.
/// Like the parent, it now attaches the produced signatures and returns a
/// transaction with `complete == true`.
class ForkedTxAssembler extends TxAssembler {
  /// Fork-id value embedded in the upper 24 bits of the sighash type word.
  final int forkId;

  ForkedTxAssembler({
    required super.chainParams,
    required super.inputs,
    required super.outputs,
    super.version,
    super.locktime,
    super.ordering,
    this.forkId = 0,
  });

  @override
  @protected
  Uint8List computeDigest(Tx tx, int index, AssemblerInput meta) {
    final hasher = ForkedHasher(forkId: forkId);
    // For P2WPKH / nested P2WPKH the BIP-143-style scriptCode must still be the
    // P2PKH-form script over the pubkey hash; for legacy P2PKH it is the
    // scriptPubKey. (BCH is legacy-script + forkid, but mirror the parent's
    // scriptCode selection so witness-style inputs are handled correctly.)
    switch (meta.type) {
      case AssemblerInputType.p2wpkh:
      case AssemblerInputType.p2shP2wpkh:
        return hasher.hash(tx, index, meta.hashType,
            prevScript: p2wpkhScriptCode(meta), amount: meta.value);
      case AssemblerInputType.p2pkh:
        return hasher.hash(tx, index, meta.hashType,
            prevScript: meta.scriptPubKey, amount: meta.value);
      case AssemblerInputType.p2tr:
        throw UnsupportedError(
          'Taproot is not supported by ForkedTxAssembler.',
        );
    }
  }
}
