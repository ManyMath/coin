import 'dart:typed_data';
import '../../core/wire.dart';
import '../../hash/digest.dart';
import 'hasher.dart';
import 'sighash_type.dart';
import '../ext_tx.dart';
import '../tx.dart';

/// Legacy sighash (pre-segwit).
class LegacySigHasher implements SigHasher {
  @override
  Uint8List hash(Tx tx, int inputIndex, SigHashType hashType,
      {Uint8List? prevScript, BigInt? amount}) {
    if (prevScript == null) throw ArgumentError('prevScript required');

    final measure = WireMeasure();
    _writeForSig(measure, tx, inputIndex, hashType, prevScript);
    final bytes = Uint8List(measure.size);
    final writer = WireWriter(bytes);
    _writeForSig(writer, tx, inputIndex, hashType, prevScript);

    return sha256d(bytes);
  }

  void _writeForSig(WireWriting writer, Tx tx, int inputIndex,
      SigHashType hashType, Uint8List prevScript) {
    // NOTE: the legacy sighash preimage is hand-built here (version, inputs,
    // outputs, locktime, hashType.flag) and intentionally never references
    // tx.mwebBytes. This matches Litecoin Core's
    // CTransactionSignatureSerializer::Serialize (src/script/interpreter.cpp),
    // which omits the MWEB extension block from the preimage. Including it
    // would produce signatures the network rejects for the canonical-chain
    // inputs of an MWEB pegin tx. If this hasher is ever refactored to clone
    // a Tx and call tx.writeTo, the clone MUST drop mwebBytes to preserve this
    // invariant (see mweb_sighash_test.dart).
    writer.writeInt32(tx.version);

    final baseType = hashType.baseType;
    final anyoneCanPay = hashType.anyoneCanPay;

    if (anyoneCanPay) {
      writer.writeVarInt(BigInt.one);
      _writeInput(writer, tx, inputIndex, prevScript, tx.inputs[inputIndex].sequence);
    } else {
      writer.writeVarInt(BigInt.from(tx.inputs.length));
      for (var i = 0; i < tx.inputs.length; i++) {
        final script = i == inputIndex ? prevScript : Uint8List(0);
        var seq = tx.inputs[i].sequence;
        if (i != inputIndex && (baseType == 0x02 || baseType == 0x03)) {
          seq = 0;
        }
        _writeInput(writer, tx, i, script, seq);
      }
    }

    if (baseType == 0x02) {
      writer.writeVarInt(BigInt.zero);
    } else if (baseType == 0x03 && inputIndex >= tx.outputs.length) {
      writer.writeVarInt(BigInt.zero);
    } else if (baseType == 0x03) {
      writer.writeVarInt(BigInt.from(inputIndex + 1));
      for (var i = 0; i < inputIndex; i++) {
        writer.writeUInt64(BigInt.from(-1).toUnsigned(64));
        writer.writeVarSlice(Uint8List(0));
      }
      tx.outputs[inputIndex].writeTo(writer);
    } else {
      writer.writeVarInt(BigInt.from(tx.outputs.length));
      for (final out in tx.outputs) {
        out.writeTo(writer);
      }
    }

    writer.writeUInt32(tx.locktime);

    // Firo/Dash special transactions append vExtraPayload to the legacy
    // sighash preimage, between locktime and the hashType flag. This mirrors
    // Firo Core's CTransactionSignatureSerializer::Serialize, which appends
    // vExtraPayload when nVersion == 3 && nType != TRANSACTION_NORMAL. The
    // gate here is structural - non-zero high 16 bits of the version word
    // (nType != 0) - so it stays correct for future nVersion values.
    if (tx is ExTx && (tx.version >> 16) != 0 && tx.hasPayload) {
      writer.writeVarSlice(tx.payload);
    }

    writer.writeUInt32(hashType.flag);
  }

  void _writeInput(WireWriting writer, Tx tx, int i, Uint8List script, int seq) {
    tx.inputs[i].prevOut.writeTo(writer);
    writer.writeVarSlice(script);
    writer.writeUInt32(seq);
  }
}
