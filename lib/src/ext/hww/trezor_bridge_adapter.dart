import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;

import 'hardware_device.dart';
import 'trezor_device.dart';
import 'trezor_features.dart';
import 'trezor_proto.dart';

String toHex(Uint8List bytes) {
  final sb = StringBuffer();
  for (final b in bytes) {
    sb.write(b.toRadixString(16).padLeft(2, '0'));
  }
  return sb.toString();
}

Uint8List fromHex(String hex) {
  final length = hex.length ~/ 2;
  final bytes = Uint8List(length);
  for (var i = 0; i < length; i++) {
    bytes[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return bytes;
}

String encodeFrame(int msgType, Uint8List payload) {
  final header = ByteData(6);
  header.setUint16(0, msgType, Endian.big);
  header.setUint32(2, payload.length, Endian.big);
  final frame = Uint8List(6 + payload.length);
  frame.setAll(0, header.buffer.asUint8List());
  frame.setAll(6, payload);
  return toHex(frame);
}

(int, Uint8List) decodeFrame(String hex) {
  if (hex.length < 12) {
    throw FormatException(
      'Frame hex must be at least 12 characters (6 header bytes), '
      'got ${hex.length}',
    );
  }
  final bytes = fromHex(hex);
  final bd = ByteData.sublistView(bytes);
  final msgType = bd.getUint16(0, Endian.big);
  final payloadLength = bd.getUint32(2, Endian.big);
  final payload = Uint8List.sublistView(bytes, 6, 6 + payloadLength);
  return (msgType, payload);
}

class TrezorBridgeAdapter extends TrezorDevice {
  final String _baseUrl;
  final http.Client _client;
  String? _session;
  TrezorHardwareWalletDevice? _connectedDevice;

  TrezorHardwareWalletDevice? get connectedDevice => _connectedDevice;

  TrezorBridgeAdapter({
    String baseUrl = 'http://127.0.0.1:21325',
    http.Client? client,
  })  : _baseUrl = baseUrl,
        _client = client ?? http.Client();

  @override
  bool get isConnected => _session != null;

  Future<String> _post(String path, {String body = ''}) async {
    final response = await _client.post(
      Uri.parse('$_baseUrl$path'),
      headers: {'Origin': 'http://localhost'},
      body: body,
    );
    if (response.statusCode != 200) {
      throw StateError(
        'Bridge returned ${response.statusCode}: ${response.body}',
      );
    }
    return response.body;
  }

  static String _modelFromPid(int productId) {
    switch (productId) {
      case 0x53C1:
        return '1';
      case 0x53C2:
        return 'T';
      default:
        return 'unknown';
    }
  }

  @override
  Future<List<HardwareDevice>> scanForDevices() async {
    final body = await _post('/enumerate');
    final entries = jsonDecode(body) as List<dynamic>;
    return entries.map((entry) {
      final device = TrezorHardwareWalletDevice(
        hidPath: entry['path'] as String,
      );
      device.features = TrezorFeatures(
        model: _modelFromPid(entry['product'] as int),
      );
      return device;
    }).toList();
  }

  @override
  Future<void> connectDevice() async {
    final body = await _post('/enumerate');
    final entries = jsonDecode(body) as List<dynamic>;
    if (entries.isEmpty) {
      throw StateError('No devices found');
    }

    final entry = _connectedDevice != null
        ? entries.firstWhere(
            (e) => e['path'] == _connectedDevice!.hidPath,
            orElse: () => entries.first,
          )
        : entries.first;

    final path = entry['path'] as String;
    final existingSession = entry['session'];

    // Atomic session steal: /acquire/<path>/<prev> hands ownership in one call.
    // Using separate release + acquire/null leaves a race window where another
    // client (Trezor Suite) can acquire between the two requests.
    final encodedPath = Uri.encodeComponent(path);
    final prev = (existingSession is String) ? existingSession : 'null';
    final acquireBody = await _post('/acquire/$encodedPath/$prev');
    final acquireJson = jsonDecode(acquireBody) as Map<String, dynamic>;
    _session = acquireJson['session'] as String;
    try {
      final (respType, respPayload) = await call(
        TrezorMsgType.initialize,
        buildInitialize(),
      );
      if (respType == TrezorMsgType.failure) {
        final failure = parseFailure(respPayload);
        throw StateError(
          'Initialize failed: ${failure.message ?? "unknown error"}',
        );
      }
      if (respType != TrezorMsgType.features) {
        throw StateError(
          'Expected Features (${TrezorMsgType.features}), got message type $respType',
        );
      }
      final features = parseFeatures(respPayload);
      _connectedDevice = TrezorDevice.forFirmware(features, hidPath: path);
    } catch (_) {
      _session = null;
      rethrow;
    }
  }

  @override
  Future<void> disconnect() async {
    if (_session == null) return;
    try {
      await _post('/release/${Uri.encodeComponent(_session!)}');
    } catch (_) {}
    _session = null;
    _connectedDevice = null;
  }

  Future<TrezorPublicKey> getPublicKey({
    required List<int> addressN,
    Future<String> Function()? onPinRequest,
    Future<String> Function()? onPassphraseRequest,
  }) async {
    if (_session == null) {
      throw StateError('Not connected - call connectDevice() first');
    }
    var (msgType, payload) = await call(
      TrezorMsgType.getPublicKey,
      buildGetPublicKey(addressN: addressN),
    );
    while (true) {
      if (msgType == TrezorMsgType.pinMatrixRequest) {
        if (onPinRequest == null) {
          throw StateError(
            'PIN requested but no onPinRequest callback provided',
          );
        }
        final pin = await onPinRequest();
        (msgType, payload) = await call(
          TrezorMsgType.pinMatrixAck,
          buildPinMatrixAck(pin),
        );
      } else if (msgType == TrezorMsgType.passphraseRequest) {
        final passphrase =
            onPassphraseRequest != null ? await onPassphraseRequest() : '';
        (msgType, payload) = await call(
          TrezorMsgType.passphraseAck,
          buildPassphraseAck(passphrase: passphrase),
        );
      } else if (msgType == TrezorMsgType.buttonRequest) {
        (msgType, payload) = await call(
          TrezorMsgType.buttonAck,
          buildButtonAck(),
        );
      } else if (msgType == TrezorMsgType.publicKey) {
        return parsePublicKey(payload);
      } else if (msgType == TrezorMsgType.failure) {
        final failure = parseFailure(payload);
        throw StateError(
          'Device returned failure (code ${failure.code}): ${failure.message}',
        );
      } else {
        throw StateError('Unexpected message type: $msgType');
      }
    }
  }

  Future<void> _reacquireSession() async {
    final body = await _post('/enumerate');
    final entries = jsonDecode(body) as List<dynamic>;
    if (entries.isEmpty) throw StateError('Device disappeared during retry');
    final entry = _connectedDevice != null
        ? entries.firstWhere(
            (e) => e['path'] == _connectedDevice!.hidPath,
            orElse: () => entries.first,
          )
        : entries.first;
    final path = entry['path'] as String;
    final prev = entry['session'];
    final encodedPath = Uri.encodeComponent(path);
    final prevStr = (prev is String) ? prev : 'null';
    final acquireBody = await _post('/acquire/$encodedPath/$prevStr');
    final acquireJson = jsonDecode(acquireBody) as Map<String, dynamic>;
    _session = acquireJson['session'] as String;
  }

  @override
  Future<(int, Uint8List)> call(int msgType, Uint8List payload) async {
    if (_session == null) {
      throw StateError('Not connected - call connectDevice() first');
    }
    final encoded = encodeFrame(msgType, payload);
    try {
      final responseBody = await _post(
        '/call/${Uri.encodeComponent(_session!)}',
        body: encoded,
      );
      return decodeFrame(responseBody);
    } on Exception {
      // Session may have been stolen by another client (e.g. Trezor Suite).
      // Re-acquire and retry once.
      await _reacquireSession();
      final responseBody = await _post(
        '/call/${Uri.encodeComponent(_session!)}',
        body: encoded,
      );
      return decodeFrame(responseBody);
    }
  }
}
