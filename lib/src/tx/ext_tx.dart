import 'dart:typed_data';
import '../core/hex.dart';
import '../core/wire.dart';
import '../hash/digest.dart';
import 'inputs/tx_input.dart';
import 'tx_output.dart';
import 'tx.dart';

class ExTx extends Tx {
  final Uint8List payload;

  ExTx({
    super.version,
    required super.inputs,
    required super.outputs,
    super.locktime,
    Uint8List? payload,
  }) : payload = payload ?? Uint8List(0);

  /// Parses an extended transaction from [reader], which must be positioned
  /// at the start of the transaction (before the version word).
  factory ExTx.fromReader(WireReader reader) =>
      ExTx.fromReaderWithVersion(reader, reader.readInt32());

  /// Parses the body of an extended transaction from [reader], given a
  /// [version] word that has already been consumed. After the standard tx
  /// body (inputs, outputs, optional witness, locktime) a trailing
  /// varint-length-prefixed `vExtraPayload` is read iff one is present.
  ///
  /// The payload read is a single bounded [WireReader.readVarSlice]; it is
  /// never a "read to end of buffer" - so this remains correct when several
  /// transactions share one buffer.
  factory ExTx.fromReaderWithVersion(WireReader reader, int version) {
    final body = Tx.readBody(reader);
    final payload = reader.atEnd ? Uint8List(0) : reader.readVarSlice();
    return ExTx(
      version: version,
      inputs: body.inputs,
      outputs: body.outputs,
      locktime: body.locktime,
      payload: payload,
    );
  }

  bool get hasPayload => payload.isNotEmpty;

  /// The base transaction version (`nVersion`), the low 16 bits of [version].
  ///
  /// Firo and Dash pack the special-tx type and version as
  /// `nVersion | (nType << 16)`.
  int get txVersion => version & 0xffff;

  /// The special-tx type (`nType`), the high 16 bits of [version].
  ///
  /// `0` (`TRANSACTION_NORMAL`) for ordinary transactions; non-zero for
  /// Firo/Dash special transactions (e.g. `5` = `TRANSACTION_COINBASE`).
  int get txType => (version >> 16) & 0xffff;

  ExTx copyWith({
    int? version,
    List<TxInput>? inputs,
    List<TxOutput>? outputs,
    int? locktime,
    Uint8List? payload,
  }) => ExTx(
    version: version ?? this.version,
    inputs: inputs ?? this.inputs,
    outputs: outputs ?? this.outputs,
    locktime: locktime ?? this.locktime,
    payload: payload ?? this.payload,
  );

  ExTx addInput(TxInput input) => copyWith(
    inputs: [...inputs, input],
  );

  ExTx addOutput(TxOutput output) => copyWith(
    outputs: [...outputs, output],
  );

  ExTx setPayload(Uint8List newPayload) => copyWith(
    payload: newPayload,
  );

  @override
  String get txid {
    final measure = WireMeasure();
    _writeForTxid(measure);
    final bytes = Uint8List(measure.size);
    _writeForTxid(WireWriter(bytes));
    final hash = sha256d(bytes);
    return hexEncode(Uint8List.fromList(hash.reversed.toList()));
  }

  @override
  void writeTo(WireWriting writer) {
    super.writeTo(writer);
    if (hasPayload) {
      writer.writeVarSlice(payload);
    }
  }

  void _writeForTxid(WireWriting writer) {
    writer.writeInt32(version);
    writer.writeVarInt(BigInt.from(inputs.length));
    for (final input in inputs) {
      input.writeTo(writer);
    }
    writer.writeVarInt(BigInt.from(outputs.length));
    for (final output in outputs) {
      output.writeTo(writer);
    }
    writer.writeUInt32(locktime);
    if (hasPayload) {
      writer.writeVarSlice(payload);
    }
  }
}
