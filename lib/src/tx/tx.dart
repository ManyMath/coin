import 'dart:typed_data';
import '../core/hex.dart';
import '../core/wire.dart';
import '../hash/digest.dart';
import 'ext_tx.dart';
import 'inputs/tx_input.dart';
import 'tx_output.dart';

/// Components of a transaction body (everything after the version word),
/// shared by [Tx.fromReader] and [ExTx.fromReader].
class TxBody {
  final List<TxInput> inputs;
  final List<TxOutput> outputs;
  final int locktime;

  /// Litecoin MWEB extension-block bytes, present only when the segwit flag
  /// had bit 3 (0x08) set; null otherwise. See [Tx.mwebBytes]. Always null for
  /// Firo/Dash special transactions (they carry a trailing payload instead,
  /// read by [ExTx], and never set the MWEB flag bit).
  final Uint8List? mwebBytes;

  TxBody(this.inputs, this.outputs, this.locktime, {this.mwebBytes});
}

class Tx with Serializable {
  static const int currentVersion = 2;
  static const int maxSize = 1000000;

  final int version;
  final List<TxInput> inputs;
  final List<TxOutput> outputs;
  final int locktime;

  /// Litecoin MWEB extension-block bytes (Slice A: opaque blob, see
  /// EXPAND_MWEB.md). Present only when the segwit flag has bit 3 (0x08) set.
  /// These bytes are serialized immediately before [locktime] and are
  /// excluded from txid/wtxid and legacy sighash preimages, matching Litecoin
  /// Core's SERIALIZE_NO_MWEB. The internal MWEB structure is NOT parsed.
  ///
  /// Reader-contract limitation: on read, the blob is taken as
  /// `readSlice(remaining - 4)` (everything up to the trailing 4-byte
  /// locktime). This is correct only when the reader's buffer is exactly one
  /// transaction (the only entry points today are Tx.fromBytes / Tx.fromHex).
  /// Block-level parsing of concatenated txs is not supported for MWEB.
  final Uint8List? mwebBytes;

  Tx({
    this.version = currentVersion,
    required this.inputs,
    required this.outputs,
    this.locktime = 0,
    this.mwebBytes,
  });

  factory Tx.fromBytes(Uint8List bytes) =>
      Tx.fromReader(WireReader(bytes));

  factory Tx.fromHex(String hex) => Tx.fromBytes(hexDecode(hex));

  factory Tx.fromReader(WireReader reader) {
    final version = reader.readInt32();

    // Firo/Dash special transactions pack the special-tx type in the high
    // 16 bits of the version word (nVersion | (nType << 16)). When that
    // type is non-zero the tx carries a trailing varint-length payload
    // after locktime; dispatch to ExTx, which reads it. (Litecoin MWEB is
    // orthogonal: it is signalled by the flag byte, not the version word, so
    // MWEB txs - version 1/2, high bits zero - take the path below.)
    if ((version >> 16) != 0) {
      return ExTx.fromReaderWithVersion(reader, version);
    }

    final body = readBody(reader);
    return Tx(
      version: version,
      inputs: body.inputs,
      outputs: body.outputs,
      locktime: body.locktime,
      mwebBytes: body.mwebBytes,
    );
  }

  /// Reads everything after the version word: inputs, outputs, optional
  /// witness data, an optional Litecoin MWEB extension block, and locktime.
  /// The reader must be positioned immediately after the 4-byte version.
  static TxBody readBody(WireReader reader) {
    var marker = reader.readUInt8();
    var flag = 0;
    // `sawMarker` is true when the 0x00 segwit marker byte was consumed. It
    // drives the input-count branch below. Do NOT conflate it with
    // `hasWitness`: an MWEB-only tx (flag 0x08) has the marker but no witness
    // vectors, and using `hasWitness` to gate the input-count read would
    // mis-parse such transactions.
    var sawMarker = false;
    var hasWitness = false;

    if (marker == 0x00) {
      flag = reader.readUInt8();
      // The segwit flag is a bitfield, not an enum: bit 0 (0x01) = witness
      // vectors present, bit 3 (0x08) = trailing MWEB extension block (LTC).
      // Mirrors Litecoin Core's UnserializeTransaction: any other set bit is
      // an error. Legal values: 0x01, 0x08, 0x09.
      if ((flag & ~0x09) != 0) {
        throw FormatException('Invalid witness flag');
      }
      sawMarker = true;
      hasWitness = (flag & 0x01) != 0;
      marker = reader.readVarInt().toInt();
    }

    final inputCount = sawMarker
        ? marker
        : (marker < 0xfd
            ? marker
            : (marker == 0xfd
                ? reader.readUInt16()
                : reader.readUInt32()));

    final inputs = <TxInput>[];
    for (var i = 0; i < inputCount; i++) {
      inputs.add(RawInput.fromReader(reader));
    }

    final outputCount = reader.readVarInt().toInt();
    final outputs = <TxOutput>[];
    for (var i = 0; i < outputCount; i++) {
      outputs.add(TxOutput.fromReader(reader));
    }

    if (hasWitness) {
      for (var i = 0; i < inputs.length; i++) {
        reader.readVector(); // witness data (consumed but not stored in RawInput)
      }
    }

    final hasMweb = (flag & 0x08) != 0;
    Uint8List? mwebBytes;
    if (hasMweb) {
      // Wire order: [...][witness?][mweb][nLockTime]. The MWEB block precedes
      // the 4-byte locktime and is not length-prefixed at this layer (Litecoin
      // Core consumes to end-of-stream). Slice A: opaque blob, see
      // EXPAND_MWEB.md. Read everything up to the trailing locktime.
      mwebBytes = reader.readSlice(reader.remaining - 4);
    }

    final locktime = reader.readUInt32();
    return TxBody(inputs, outputs, locktime, mwebBytes: mwebBytes);
  }

  bool get isWitness => inputs.any((i) => i.witness.isNotEmpty);

  bool get complete => inputs.every((i) => i.complete);

  String get txid {
    // Non-witness serialization, double-SHA256, reversed. _writeNonWitness
    // omits marker/flag/witness AND never emits mwebBytes, so the txid is
    // automatically MWEB-clean, matching Litecoin Core ComputeHash
    // (SERIALIZE_TRANSACTION_NO_WITNESS | SERIALIZE_NO_MWEB).
    final measure = WireMeasure();
    _writeNonWitness(measure);
    final bytes = Uint8List(measure.size);
    _writeNonWitness(WireWriter(bytes));
    final hash = sha256d(bytes);
    return hexEncode(Uint8List.fromList(hash.reversed.toList()));
  }

  /// Witness transaction id (wtxid): includes witness data but EXCLUDES the
  /// MWEB extension block, matching Litecoin Core ComputeWitnessHash
  /// (SERIALIZE_NO_MWEB alone). For a non-witness, non-MWEB tx this equals
  /// [txid].
  String get wtxid {
    final measure = WireMeasure();
    _writeNoMweb(measure);
    final bytes = Uint8List(measure.size);
    _writeNoMweb(WireWriter(bytes));
    final hash = sha256d(bytes);
    return hexEncode(Uint8List.fromList(hash.reversed.toList()));
  }

  @override
  void writeTo(WireWriting writer) {
    final hasWitnessInputs = isWitness;
    final hasMweb = mwebBytes != null;
    writer.writeInt32(version);

    if (hasWitnessInputs || hasMweb) {
      writer.writeUInt8(0x00); // marker
      // Flag is a bitfield: bit 0 = witness, bit 3 = MWEB. An MWEB-only tx
      // (LTC HogEx) serializes as 0x08, not 0x09.
      writer.writeUInt8((hasWitnessInputs ? 0x01 : 0x00) |
          (hasMweb ? 0x08 : 0x00));
    }

    writer.writeVarInt(BigInt.from(inputs.length));
    for (final input in inputs) {
      input.writeTo(writer);
    }

    writer.writeVarInt(BigInt.from(outputs.length));
    for (final output in outputs) {
      output.writeTo(writer);
    }

    if (hasWitnessInputs) {
      for (final input in inputs) {
        input.writeWitness(writer);
      }
    }

    if (hasMweb) {
      // MWEB extension block, raw (no length prefix), before locktime.
      writer.writeSlice(mwebBytes!);
    }

    writer.writeUInt32(locktime);
  }

  /// Mirrors [writeTo] but omits the trailing MWEB extension block and clears
  /// the MWEB flag bit (& ~0x08). Used for wtxid (SERIALIZE_NO_MWEB).
  void _writeNoMweb(WireWriting writer) {
    final hasWitnessInputs = isWitness;
    writer.writeInt32(version);

    if (hasWitnessInputs) {
      writer.writeUInt8(0x00); // marker
      writer.writeUInt8(0x01); // flag with MWEB bit (0x08) cleared
    }

    writer.writeVarInt(BigInt.from(inputs.length));
    for (final input in inputs) {
      input.writeTo(writer);
    }

    writer.writeVarInt(BigInt.from(outputs.length));
    for (final output in outputs) {
      output.writeTo(writer);
    }

    if (hasWitnessInputs) {
      for (final input in inputs) {
        input.writeWitness(writer);
      }
    }

    writer.writeUInt32(locktime);
  }

  void _writeNonWitness(WireWriting writer) {
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
  }
}
