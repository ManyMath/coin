import 'dart:convert';
import 'dart:typed_data';

import '../../core/wire.dart';
import '../../tx/inputs/tx_input.dart';
import '../../tx/outpoint.dart';
import '../../tx/tx.dart';
import '../../tx/tx_output.dart';
import 'partial_tx.dart';
import 'psbt_codec.dart';
import 'psbt_types.dart';

/// BIP-174 PSBT version 0 implementation.
class PartialTxV1 implements PartialTx {
  Tx? _unsignedTx;

  /// Sections: [global, input0, ..., inputN, output0, ..., outputN].
  List<List<PsbtKeyValue>> _sections;

  PartialTxV1({Tx? unsignedTx})
      : _unsignedTx = unsignedTx,
        _sections = [];

  factory PartialTxV1.fromBytes(Uint8List bytes) {
    final sections = PsbtCodec.decode(bytes);
    if (sections.isEmpty) {
      throw FormatException('Invalid PSBT: no global section');
    }

    final global = sections[0];
    Tx? unsignedTx;
    for (final kv in global) {
      if (kv.key.isNotEmpty &&
          kv.key[0] == PsbtGlobal.unsignedTx.keyType) {
        unsignedTx = _parseUnsignedTx(kv.value);
        break;
      }
    }

    final result = PartialTxV1(unsignedTx: unsignedTx);
    result._sections = sections;
    return result;
  }

  /// Parses the global unsigned transaction (PSBT_GLOBAL_UNSIGNED_TX, key
  /// type 0x00) per BIP-174.
  ///
  /// BIP-174 (Global Types, "Unsigned Transaction"):
  ///   "The transaction in network serialization. The scriptSigs and
  ///    witnesses for each input must be empty. The transaction must be in
  ///    the old serialization format (without witnesses)."
  ///
  /// The generic [Tx] reader auto-detects the segwit marker/flag, which both
  /// mis-parses a legacy unsigned tx whose first input count is 0x00 (it reads
  /// the count byte as a segwit marker and over-reads past the field - the
  /// "Cannot access N bytes" failure) and silently accepts witness-format
  /// transactions. PSBT requires the strict old (no-witness) serialization, so
  /// we parse it directly here and reject anything that violates the rule:
  ///   * a leading 0x00 segwit marker (witness serialization), and
  ///   * any input carrying a non-empty scriptSig.
  /// Reading must also consume exactly [value]; trailing bytes are an error.
  static Tx _parseUnsignedTx(Uint8List value) {
    final reader = WireReader(value);
    final int version;
    final int inputCount;
    try {
      version = reader.readInt32();

      // Old serialization only: the byte after the version is the input
      // count, never a 0x00 segwit marker. A witness-serialized unsigned tx
      // (marker 0x00, flag 0x01) is rejected by BIP-174.
      // (BIP-174 invalid vector: "unsigned tx serialized with witness
      // serialization format".)
      inputCount = reader.readVarInt().toInt();
    } on FormatException {
      rethrow;
    } catch (_) {
      throw FormatException('Invalid PSBT: malformed unsigned transaction');
    }

    final inputs = <TxInput>[];
    try {
      for (var i = 0; i < inputCount; i++) {
        final prevOut = Outpoint.fromReader(reader);
        final scriptSig = reader.readVarSlice();
        final sequence = reader.readUInt32();
        // BIP-174: scriptSigs of the unsigned tx inputs must be empty.
        if (scriptSig.isNotEmpty) {
          throw FormatException(
              'Invalid PSBT: unsigned tx input $i has a non-empty scriptSig');
        }
        inputs.add(RawInput(prevOut: prevOut, sequence: sequence));
      }

      final outputCount = reader.readVarInt().toInt();
      final outputs = <TxOutput>[];
      for (var i = 0; i < outputCount; i++) {
        outputs.add(TxOutput.fromReader(reader));
      }

      final locktime = reader.readUInt32();

      // The unsigned tx must consume the entire field. Any trailing bytes
      // imply witness data or a malformed transaction.
      if (!reader.atEnd) {
        throw FormatException(
            'Invalid PSBT: unsigned transaction has trailing bytes '
            '(witness data is not allowed)');
      }

      return Tx(
        version: version,
        inputs: inputs,
        outputs: outputs,
        locktime: locktime,
      );
    } on FormatException {
      rethrow;
    } catch (_) {
      throw FormatException('Invalid PSBT: malformed unsigned transaction');
    }
  }

  @override
  int get version => 0;

  @override
  Tx? get unsignedTx => _unsignedTx;

  @override
  int get inputCount => _unsignedTx?.inputs.length ?? 0;

  @override
  int get outputCount => _unsignedTx?.outputs.length ?? 0;

  @override
  void addInput({
    required Outpoint outpoint,
    Uint8List? witnessUtxoScript,
    BigInt? witnessUtxoValue,
    Tx? nonWitnessUtxo,
    int sequence = 0xffffffff,
  }) {
    final newInput = RawInput(prevOut: outpoint, sequence: sequence);
    final inputs = _unsignedTx?.inputs ?? [];
    final outputs = _unsignedTx?.outputs ?? [];
    _unsignedTx = Tx(
      version: _unsignedTx?.version ?? Tx.currentVersion,
      inputs: [...inputs, newInput],
      outputs: outputs,
      locktime: _unsignedTx?.locktime ?? 0,
    );

    final inputKvs = <PsbtKeyValue>[];
    if (nonWitnessUtxo != null) {
      inputKvs.add(PsbtKeyValue(
        key: Uint8List.fromList([PsbtInputEntry.nonWitnessUtxo.keyType]),
        value: nonWitnessUtxo.toBytes(),
      ));
    }
    if (witnessUtxoScript != null && witnessUtxoValue != null) {
      final out = TxOutput(value: witnessUtxoValue, scriptPubKey: witnessUtxoScript);
      inputKvs.add(PsbtKeyValue(
        key: Uint8List.fromList([PsbtInputEntry.witnessUtxo.keyType]),
        value: out.toBytes(),
      ));
    }

    _ensureSections();
    final insertIndex = 1 + (inputCount - 1);

    _sections.insert(insertIndex, inputKvs);
  }

  @override
  void addOutput({
    required Uint8List scriptPubKey,
    required BigInt value,
  }) {
    final newOutput = TxOutput(value: value, scriptPubKey: scriptPubKey);
    final inputs = _unsignedTx?.inputs ?? [];
    final outputs = _unsignedTx?.outputs ?? [];
    _unsignedTx = Tx(
      version: _unsignedTx?.version ?? Tx.currentVersion,
      inputs: inputs,
      outputs: [...outputs, newOutput],
      locktime: _unsignedTx?.locktime ?? 0,
    );

    _ensureSections();
    _sections.add(<PsbtKeyValue>[]);
  }

  @override
  Tx finalize() {
    final tx = _unsignedTx;
    if (tx == null) {
      throw StateError('No unsigned transaction to finalize');
    }

    final newInputs = <TxInput>[];
    for (var i = 0; i < tx.inputs.length; i++) {
      final inputSection = getInputSection(i);
      Uint8List? finalScriptSig;
      for (final kv in inputSection) {
        if (kv.key.isNotEmpty &&
            kv.key[0] == PsbtInputEntry.finalScriptSig.keyType) {
          finalScriptSig = kv.value;
          break;
        }
      }
      final prevOut = tx.inputs[i].prevOut;
      final seq = tx.inputs[i].sequence;
      newInputs.add(RawInput(
        prevOut: prevOut,
        scriptSig: finalScriptSig,
        sequence: seq,
      ));
    }

    return Tx(
      version: tx.version,
      inputs: newInputs,
      outputs: tx.outputs,
      locktime: tx.locktime,
    );
  }

  @override
  String toBase64() => base64Encode(toBytes());

  @override
  Uint8List toBytes() {
    _ensureSections();

    final globalKvs = <PsbtKeyValue>[];
    if (_unsignedTx != null) {
      globalKvs.add(PsbtKeyValue(
        key: Uint8List.fromList([PsbtGlobal.unsignedTx.keyType]),
        value: _unsignedTx!.toBytes(),
      ));
    }
    if (_sections.isNotEmpty) {
      for (final kv in _sections[0]) {
        if (kv.key.isNotEmpty &&
            kv.key[0] != PsbtGlobal.unsignedTx.keyType) {
          globalKvs.add(kv);
        }
      }
    }
    _sections[0] = globalKvs;

    return PsbtCodec.encode(_sections);
  }

  List<PsbtKeyValue> getInputSection(int index) {
    final sectionIndex = 1 + index;
    if (sectionIndex < _sections.length) {
      return _sections[sectionIndex];
    }
    return const [];
  }

  void addInputEntry(int index, PsbtKeyValue entry) {
    _ensureSections();
    final sectionIndex = 1 + index;
    if (sectionIndex < _sections.length) {
      _sections[sectionIndex].add(entry);
    }
  }

  void _ensureSections() {
    if (_sections.isEmpty) {
      _sections.add(<PsbtKeyValue>[]);
    }
  }
}
