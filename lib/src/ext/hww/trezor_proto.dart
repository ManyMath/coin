import 'dart:convert';
import 'dart:typed_data';
import 'trezor_features.dart';

// Message type constants for Trezor wire protocol.
// Kept as static const int (not enum) so callers pass raw ints to TrezorDevice.call().
final class TrezorMsgType {
  static const int initialize = 0;
  static const int failure = 3;
  static const int getPublicKey = 11;
  static const int publicKey = 12;
  static const int features = 17;
  static const int pinMatrixRequest = 18;
  static const int pinMatrixAck = 19;
  static const int buttonRequest = 26;
  static const int buttonAck = 27;
  static const int passphraseRequest = 41;
  static const int passphraseAck = 42;
}

class ProtoWriter {
  final List<int> _buf = [];

  void writeVarint(int value) {
    do {
      _buf.add((value & 0x7F) | (value >= 0x80 ? 0x80 : 0));
      value >>>= 7;
    } while (value != 0);
  }

  void _writeTag(int fieldNum, int wireType) =>
      writeVarint((fieldNum << 3) | wireType);

  void writeBool(int fieldNum, bool value) {
    _writeTag(fieldNum, 0);
    writeVarint(value ? 1 : 0);
  }

  void writeString(int fieldNum, String value) {
    _writeTag(fieldNum, 2);
    final b = utf8.encode(value);
    writeVarint(b.length);
    _buf.addAll(b);
  }

  // Unpacked repeated uint32 - each element gets its own tag+varint pair.
  // Trezor Model One rejects packed encoding (single tag+length+varints).
  void writeRepeatedUint32(int fieldNum, List<int> values) {
    for (final v in values) {
      _writeTag(fieldNum, 0);
      writeVarint(v);
    }
  }

  Uint8List toBytes() => Uint8List.fromList(_buf);
}

class ProtoReader {
  final Uint8List _buf;
  int _pos = 0;

  ProtoReader(this._buf);

  bool get hasMore => _pos < _buf.length;

  int readRawVarint() {
    int result = 0;
    int shift = 0;
    int b;
    do {
      b = _buf[_pos++];
      result |= (b & 0x7F) << shift;
      shift += 7;
    } while ((b & 0x80) != 0);
    return result;
  }

  (int, int) readTag() {
    final raw = readRawVarint();
    return (raw >> 3, raw & 0x07);
  }

  Uint8List readLenDelim() {
    final len = readRawVarint();
    final sub = _buf.sublist(_pos, _pos + len);
    _pos += len;
    return sub;
  }

  String readString() => utf8.decode(readLenDelim());

  void skip(int wireType) {
    switch (wireType) {
      case 0:
        readRawVarint();
      case 1:
        _pos += 8;
      case 2:
        final len = readRawVarint();
        _pos += len;
      case 5:
        _pos += 4;
    }
  }
}

class TrezorPublicKey {
  final String xpub;
  const TrezorPublicKey({required this.xpub});
}

class TrezorFailure {
  final int? code;
  final String? message;
  const TrezorFailure({this.code, this.message});
}

Uint8List buildInitialize() => Uint8List(0);

Uint8List buildButtonAck() => Uint8List(0);

Uint8List buildGetPublicKey({
  required List<int> addressN,
  bool showDisplay = false,
}) {
  final writer = ProtoWriter();
  writer.writeRepeatedUint32(1, addressN);
  // Field 4 (script_type) deliberately omitted - Model One firmware 1.12-1.13 rejects it.
  if (showDisplay) writer.writeBool(3, true);
  return writer.toBytes();
}

Uint8List buildPinMatrixAck(String pin) =>
    (ProtoWriter()..writeString(1, pin)).toBytes();

Uint8List buildPassphraseAck({String passphrase = ''}) =>
    (ProtoWriter()..writeString(1, passphrase)).toBytes();

TrezorFeatures parseFeatures(Uint8List bytes) {
  final reader = ProtoReader(bytes);
  String? label, model;
  int? fwMajor, fwMinor, fwPatch;
  bool? initialized;
  while (reader.hasMore) {
    final (fieldNum, wireType) = reader.readTag();
    switch (fieldNum) {
      case 2:
        fwMajor = reader.readRawVarint();
      case 3:
        fwMinor = reader.readRawVarint();
      case 4:
        fwPatch = reader.readRawVarint();
      case 10:
        label = reader.readString();
      case 12:
        initialized = reader.readRawVarint() != 0;
      case 21:
        model = reader.readString();
      default:
        reader.skip(wireType);
    }
  }
  return TrezorFeatures(
    label: label,
    model: model,
    firmwareVersion:
        '${fwMajor ?? 0}.${fwMinor ?? 0}.${fwPatch ?? 0}',
    initialized: initialized,
  );
}

TrezorPublicKey parsePublicKey(Uint8List bytes) {
  final reader = ProtoReader(bytes);
  String? xpub;
  while (reader.hasMore) {
    final (fieldNum, wireType) = reader.readTag();
    switch (fieldNum) {
      case 1:
        reader.readLenDelim(); // HDNode - skip payload
      case 2:
        xpub = reader.readString();
      default:
        reader.skip(wireType);
    }
  }
  if (xpub == null) throw StateError('parsePublicKey: field 2 (xpub) missing');
  return TrezorPublicKey(xpub: xpub);
}

TrezorFailure parseFailure(Uint8List bytes) {
  final reader = ProtoReader(bytes);
  int? code;
  String? message;
  while (reader.hasMore) {
    final (fieldNum, wireType) = reader.readTag();
    switch (fieldNum) {
      case 1:
        code = reader.readRawVarint();
      case 2:
        message = reader.readString();
      default:
        reader.skip(wireType);
    }
  }
  return TrezorFailure(code: code, message: message);
}
