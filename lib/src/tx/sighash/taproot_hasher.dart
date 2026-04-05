import 'dart:typed_data';
import '../../core/wire.dart';
import '../../hash/tagged.dart';
import '../../hash/digest.dart';
import 'hasher.dart';
import 'sighash_type.dart';
import '../tx.dart';
import '../tx_output.dart';

/// BIP-341 taproot sighash.
class TaprootSigHasher implements SigHasher {
  final List<TxOutput> prevOuts;

  TaprootSigHasher({required this.prevOuts});

  @override
  Uint8List hash(Tx tx, int inputIndex, SigHashType hashType,
      {Uint8List? prevScript, BigInt? amount}) {
    final epoch = 0;
    final baseType = hashType.flag == 0 ? 0 : hashType.baseType;
    final anyoneCanPay = hashType.anyoneCanPay;

    final parts = <int>[epoch, hashType.flag];
    final buf = Uint8List(4);
    final bw = WireWriter(buf);
    bw.writeInt32(tx.version);
    parts.addAll(buf);

    bw.offset = 0;
    bw.writeUInt32(tx.locktime);
    parts.addAll(buf);

    if (!anyoneCanPay) {
      parts.addAll(_hashPrevouts(tx));
      parts.addAll(_hashAmounts());
      parts.addAll(_hashScriptPubKeys());
      parts.addAll(_hashSequences(tx));
    }

    if (baseType != 0x02 && baseType != 0x03) {
      parts.addAll(_hashOutputs(tx));
    }

    // Spend type
    final spendType = 0; // key path
    parts.add(spendType);

    if (anyoneCanPay) {
      final inp = tx.inputs[inputIndex];
      final measure = WireMeasure();
      inp.prevOut.writeTo(measure);
      final ob = Uint8List(measure.size);
      final ow = WireWriter(ob);
      inp.prevOut.writeTo(ow);
      parts.addAll(ob);
      parts.addAll(_outputBytes(prevOuts[inputIndex]));
      final sb = Uint8List(4);
      WireWriter(sb).writeUInt32(inp.sequence);
      parts.addAll(sb);
    } else {
      final ib = Uint8List(4);
      WireWriter(ib).writeUInt32(inputIndex);
      parts.addAll(ib);
    }

    if (baseType == 0x03) {
      parts.addAll(_hashSingleOutput(tx, inputIndex));
    }

    return taggedHash('TapSighash', Uint8List.fromList(parts));
  }

  // BIP-341 sub-hashes (sha_prevouts, sha_amounts, sha_scriptpubkeys,
  // sha_sequences, sha_outputs) are PLAIN single SHA256 over the concatenated
  // serialization - NOT tagged hashes.

  Uint8List _hashPrevouts(Tx tx) {
    final parts = <int>[];
    for (final inp in tx.inputs) {
      parts.addAll(inp.prevOut.toBytes());
    }
    return sha256(Uint8List.fromList(parts));
  }

  Uint8List _hashAmounts() {
    final parts = <int>[];
    for (final out in prevOuts) {
      final buf = Uint8List(8);
      WireWriter(buf).writeUInt64(out.value);
      parts.addAll(buf);
    }
    return sha256(Uint8List.fromList(parts));
  }

  Uint8List _hashScriptPubKeys() {
    final parts = <int>[];
    for (final out in prevOuts) {
      final spk = out.scriptPubKey;
      // Each scriptPubKey is length-prefixed as a varint (compact size).
      parts.addAll(_varIntBytes(spk.length));
      parts.addAll(spk);
    }
    return sha256(Uint8List.fromList(parts));
  }

  Uint8List _hashSequences(Tx tx) {
    final buf = Uint8List(tx.inputs.length * 4);
    final w = WireWriter(buf);
    for (final inp in tx.inputs) {
      w.writeUInt32(inp.sequence);
    }
    return sha256(buf);
  }

  Uint8List _hashOutputs(Tx tx) {
    final parts = <int>[];
    for (final out in tx.outputs) {
      parts.addAll(out.toBytes());
    }
    return sha256(Uint8List.fromList(parts));
  }

  Uint8List _hashSingleOutput(Tx tx, int index) {
    // SIGHASH_SINGLE with index out of range is undefined in BIP-341; the
    // signer must not produce such a signature. Be explicit rather than
    // silently committing to a zero hash.
    if (index >= tx.outputs.length) {
      throw ArgumentError(
          'SIGHASH_SINGLE: no matching output at index $index');
    }
    return sha256(tx.outputs[index].toBytes());
  }

  List<int> _varIntBytes(int n) {
    final measure = WireMeasure()..writeVarInt(BigInt.from(n));
    final buf = Uint8List(measure.size);
    WireWriter(buf).writeVarInt(BigInt.from(n));
    return buf;
  }

  Uint8List _outputBytes(TxOutput out) {
    return out.toBytes();
  }
}
