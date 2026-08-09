import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';
import 'package:coin/src/ext/hww/trezor_bridge_adapter.dart';
import 'package:coin/src/ext/hww/trezor_device.dart';
import 'package:coin/src/ext/hww/trezor_features.dart';
import 'package:coin/src/ext/hww/trezor_proto.dart';

void main() {
  group('toHex', () {
    test('converts bytes to lowercase hex string', () {
      expect(toHex(Uint8List.fromList([0xDE, 0xAD])), equals('dead'));
    });

    test('handles empty list', () {
      expect(toHex(Uint8List(0)), equals(''));
    });

    test('pads single-digit hex values with leading zero', () {
      expect(toHex(Uint8List.fromList([0x01, 0x0F])), equals('010f'));
    });
  });

  group('fromHex', () {
    test('parses hex string to bytes', () {
      expect(fromHex('dead'), equals([0xDE, 0xAD]));
    });

    test('handles empty string', () {
      expect(fromHex(''), equals(Uint8List(0)));
    });

    test('handles odd-length string by truncating last nibble', () {
      // fromHex('abc') parses 'ab' (1 byte), the trailing 'c' is ignored
      expect(fromHex('abc'), equals([0xAB]));
    });
  });

  group('toHex/fromHex round-trip', () {
    test('round-trips arbitrary bytes', () {
      final original = Uint8List.fromList(
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA,
         0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
      );
      expect(fromHex(toHex(original)), equals(original));
    });
  });

  group('encodeFrame', () {
    test('encodes empty payload with correct header', () {
      // type 17 (0x0011), length 0 (0x00000000), no payload
      expect(encodeFrame(17, Uint8List(0)), equals('001100000000'));
    });

    test('encodes payload with correct header and body', () {
      // type 17 (0x0011), length 3 (0x00000003), payload [1,2,3]
      expect(
        encodeFrame(17, Uint8List.fromList([1, 2, 3])),
        equals('001100000003010203'),
      );
    });

    test('uses big-endian byte order for type and length', () {
      // type 256 (0x0100), length 0
      expect(encodeFrame(256, Uint8List(0)), equals('010000000000'));
    });
  });

  group('decodeFrame', () {
    test('decodes known hex string', () {
      final (msgType, payload) = decodeFrame('001100000003010203');
      expect(msgType, equals(17));
      expect(payload, equals([1, 2, 3]));
    });

    test('decodes empty payload', () {
      final (msgType, payload) = decodeFrame('001100000000');
      expect(msgType, equals(17));
      expect(payload, isEmpty);
    });

    test('throws FormatException on truncated hex', () {
      // fewer than 12 hex chars = fewer than 6 header bytes
      expect(() => decodeFrame('0011'), throwsFormatException);
      expect(() => decodeFrame(''), throwsFormatException);
    });
  });

  group('encodeFrame/decodeFrame round-trip', () {
    test('round-trips with empty payload', () {
      final (msgType, payload) = decodeFrame(encodeFrame(42, Uint8List(0)));
      expect(msgType, equals(42));
      expect(payload, isEmpty);
    });

    test('round-trips with non-empty payload', () {
      final original = Uint8List.fromList([10, 20, 30, 40, 50]);
      final (msgType, payload) = decodeFrame(encodeFrame(999, original));
      expect(msgType, equals(999));
      expect(payload, equals(original));
    });
  });

  group('TrezorBridgeAdapter with MockClient', () {
    late List<http.Request> capturedRequests;

    MockClient mockClient(
      Future<http.Response> Function(http.Request) handler,
    ) {
      capturedRequests = [];
      return MockClient((request) {
        capturedRequests.add(request);
        return handler(request);
      });
    }

    Uint8List buildFeaturesPayload({
      String label = 'TestDevice',
      String model = '1',
      bool initialized = true,
      int? fwMajor,
      int? fwMinor,
      int? fwPatch,
    }) {
      final w = ProtoWriter();
      w.writeString(10, label);
      w.writeBool(12, initialized);
      w.writeString(21, model);
      final base = w.toBytes().toList();
      // Firmware version fields 2/3/4 are varints - write tag+value manually
      // since ProtoWriter only has writeBool/writeString/writeRepeatedUint32.
      void addVarintField(int fieldNum, int value) {
        base.add((fieldNum << 3) | 0); // tag: fieldNum, wire type 0
        var v = value;
        do {
          base.add((v & 0x7F) | (v >= 0x80 ? 0x80 : 0));
          v >>>= 7;
        } while (v != 0);
      }
      if (fwMajor != null) addVarintField(2, fwMajor);
      if (fwMinor != null) addVarintField(3, fwMinor);
      if (fwPatch != null) addVarintField(4, fwPatch);
      return Uint8List.fromList(base);
    }

    String syntheticFeaturesHex({
      String label = 'TestDevice',
      String model = '1',
      bool initialized = true,
      int? fwMajor,
      int? fwMinor,
      int? fwPatch,
    }) {
      return encodeFrame(
        TrezorMsgType.features,
        buildFeaturesPayload(
          label: label,
          model: model,
          initialized: initialized,
          fwMajor: fwMajor,
          fwMinor: fwMinor,
          fwPatch: fwPatch,
        ),
      );
    }

    group('scanForDevices', () {
      test('parses enumerate response into devices', () async {
        final client = mockClient((req) async {
          expect(req.url.path, equals('/enumerate'));
          expect(req.headers['Origin'], equals('http://localhost'));
          return http.Response(
            jsonEncode([
              {'path': 'usb0001', 'vendor': 0x534C, 'product': 0x53C1, 'session': null},
              {'path': 'usb0002', 'vendor': 0x534C, 'product': 0x53C2, 'session': 'abc'},
            ]),
            200,
          );
        });

        final adapter = TrezorBridgeAdapter(client: client);
        final devices = await adapter.scanForDevices();

        expect(devices.length, equals(2));
        final d0 = devices[0] as TrezorHardwareWalletDevice;
        expect(d0.hidPath, equals('usb0001'));
        expect(d0.features?.model, equals('1'));
        final d1 = devices[1] as TrezorHardwareWalletDevice;
        expect(d1.hidPath, equals('usb0002'));
        expect(d1.features?.model, equals('T'));
      });

      test('returns empty list when no devices', () async {
        final client = mockClient((req) async {
          return http.Response('[]', 200);
        });

        final adapter = TrezorBridgeAdapter(client: client);
        final devices = await adapter.scanForDevices();
        expect(devices, isEmpty);
      });
    });

    group('connectDevice', () {
      test('acquires session from first device', () async {
        final client = mockClient((req) async {
          if (req.url.path == '/enumerate') {
            return http.Response(
              jsonEncode([
                {'path': 'usb0001', 'vendor': 0x534C, 'product': 0x53C1, 'session': null},
              ]),
              200,
            );
          }
          if (req.url.path == '/acquire/usb0001/null') {
            return http.Response('{"session":"sess42"}', 200);
          }
          if (req.url.path.startsWith('/call/')) {
            return http.Response(syntheticFeaturesHex(), 200);
          }
          return http.Response('unexpected: ${req.url.path}', 500);
        });

        final adapter = TrezorBridgeAdapter(client: client);
        expect(adapter.isConnected, isFalse);
        await adapter.connectDevice();
        expect(adapter.isConnected, isTrue);
        expect(adapter.connectedDevice?.features?.label, equals('TestDevice'));
        expect(adapter.connectedDevice?.features?.initialized, isTrue);
      });

      test('populates connectedDevice.features with firmware version', () async {
        final client = mockClient((req) async {
          if (req.url.path == '/enumerate') {
            return http.Response(
              jsonEncode([
                {'path': 'usb0001', 'vendor': 0x534C, 'product': 0x53C1, 'session': null},
              ]),
              200,
            );
          }
          if (req.url.path == '/acquire/usb0001/null') {
            return http.Response('{"session":"s1"}', 200);
          }
          if (req.url.path.startsWith('/call/')) {
            return http.Response(
              syntheticFeaturesHex(
                label: 'MyTrezor',
                model: '1',
                initialized: true,
                fwMajor: 1,
                fwMinor: 13,
                fwPatch: 1,
              ),
              200,
            );
          }
          return http.Response('unexpected: ${req.url.path}', 500);
        });

        final adapter = TrezorBridgeAdapter(client: client);
        await adapter.connectDevice();
        final dev = adapter.connectedDevice;
        expect(dev, isNotNull);
        expect(dev!.hidPath, equals('usb0001'));
        expect(dev.features?.label, equals('MyTrezor'));
        expect(dev.features?.model, equals('1'));
        expect(dev.features?.initialized, isTrue);
        expect(dev.features?.firmwareVersion, equals('1.13.1'));
      });

      test('steals existing session before acquiring', () async {
        var acquireWithPrev = false;
        final client = mockClient((req) async {
          if (req.url.path == '/enumerate') {
            return http.Response(
              jsonEncode([
                {'path': 'usb0001', 'vendor': 0x534C, 'product': 0x53C1, 'session': 'old-sess'},
              ]),
              200,
            );
          }
          if (req.url.path == '/acquire/usb0001/old-sess') {
            acquireWithPrev = true;
            return http.Response('{"session":"new-sess"}', 200);
          }
          if (req.url.path.startsWith('/call/')) {
            return http.Response(syntheticFeaturesHex(), 200);
          }
          return http.Response('unexpected: ${req.url.path}', 500);
        });

        final adapter = TrezorBridgeAdapter(client: client);
        await adapter.connectDevice();
        expect(acquireWithPrev, isTrue);
        expect(adapter.isConnected, isTrue);
      });

      test('throws StateError when no devices found', () async {
        final client = mockClient((req) async {
          return http.Response('[]', 200);
        });

        final adapter = TrezorBridgeAdapter(client: client);
        expect(
          () => adapter.connectDevice(),
          throwsA(
            isA<StateError>().having(
              (e) => e.message,
              'message',
              contains('No devices found'),
            ),
          ),
        );
      });

      test('clears session on Failure response', () async {
        final failurePayload = (ProtoWriter()
              ..writeString(2, 'device locked'))
            .toBytes();
        final client = mockClient((req) async {
          if (req.url.path == '/enumerate') {
            return http.Response(
              jsonEncode([
                {'path': 'usb0001', 'vendor': 0x534C, 'product': 0x53C1, 'session': null},
              ]),
              200,
            );
          }
          if (req.url.path == '/acquire/usb0001/null') {
            return http.Response('{"session":"sess-fail"}', 200);
          }
          if (req.url.path.startsWith('/call/')) {
            return http.Response(
              encodeFrame(TrezorMsgType.failure, failurePayload),
              200,
            );
          }
          return http.Response('unexpected', 500);
        });

        final adapter = TrezorBridgeAdapter(client: client);
        expect(
          () => adapter.connectDevice(),
          throwsA(
            isA<StateError>().having(
              (e) => e.message,
              'message',
              contains('Initialize failed'),
            ),
          ),
        );
        expect(adapter.isConnected, isFalse);
      });

      test('clears session on unexpected message type', () async {
        final client = mockClient((req) async {
          if (req.url.path == '/enumerate') {
            return http.Response(
              jsonEncode([
                {'path': 'usb0001', 'vendor': 0x534C, 'product': 0x53C1, 'session': null},
              ]),
              200,
            );
          }
          if (req.url.path == '/acquire/usb0001/null') {
            return http.Response('{"session":"sess-bad"}', 200);
          }
          if (req.url.path.startsWith('/call/')) {
            return http.Response(
              encodeFrame(99, Uint8List(0)),
              200,
            );
          }
          return http.Response('unexpected', 500);
        });

        final adapter = TrezorBridgeAdapter(client: client);
        expect(
          () => adapter.connectDevice(),
          throwsA(
            isA<StateError>().having(
              (e) => e.message,
              'message',
              contains('Expected Features'),
            ),
          ),
        );
        expect(adapter.isConnected, isFalse);
      });
    });

    group('disconnect', () {
      test('is safe no-op when already disconnected', () async {
        final client = mockClient((req) async {
          fail('No HTTP calls expected');
          return http.Response('', 500);
        });

        final adapter = TrezorBridgeAdapter(client: client);
        await adapter.disconnect();
        expect(adapter.isConnected, isFalse);
      });

      test('releases session and clears state', () async {
        var releaseCalled = false;
        final client = mockClient((req) async {
          if (req.url.path == '/enumerate') {
            return http.Response(
              jsonEncode([
                {'path': 'usb0001', 'vendor': 0x534C, 'product': 0x53C1, 'session': null},
              ]),
              200,
            );
          }
          if (req.url.path == '/acquire/usb0001/null') {
            return http.Response('{"session":"sess1"}', 200);
          }
          if (req.url.path.startsWith('/call/')) {
            return http.Response(syntheticFeaturesHex(), 200);
          }
          if (req.url.path == '/release/sess1') {
            releaseCalled = true;
            return http.Response('{}', 200);
          }
          return http.Response('unexpected: ${req.url.path}', 500);
        });

        final adapter = TrezorBridgeAdapter(client: client);
        await adapter.connectDevice();
        expect(adapter.isConnected, isTrue);
        await adapter.disconnect();
        expect(adapter.isConnected, isFalse);
        expect(releaseCalled, isTrue);
      });
    });

    group('call', () {
      test('throws StateError when not connected', () {
        final client = mockClient((req) async {
          fail('No HTTP calls expected');
          return http.Response('', 500);
        });

        final adapter = TrezorBridgeAdapter(client: client);
        expect(
          () => adapter.call(17, Uint8List(0)),
          throwsA(
            isA<StateError>().having(
              (e) => e.message,
              'message',
              contains('Not connected'),
            ),
          ),
        );
      });

      test('encodes request and decodes response frame', () async {
        var initCallDone = false;
        final client = mockClient((req) async {
          if (req.url.path == '/enumerate') {
            return http.Response(
              jsonEncode([
                {'path': 'usb0001', 'vendor': 0x534C, 'product': 0x53C1, 'session': null},
              ]),
              200,
            );
          }
          if (req.url.path == '/acquire/usb0001/null') {
            return http.Response('{"session":"sess1"}', 200);
          }
          if (req.url.path == '/call/sess1') {
            if (!initCallDone) {
              initCallDone = true;
              return http.Response(syntheticFeaturesHex(), 200);
            }
            final requestFrame = req.body;
            final (reqType, reqPayload) = decodeFrame(requestFrame);
            expect(reqType, equals(17));
            expect(reqPayload, equals([0x0A, 0x05]));
            return http.Response(
              encodeFrame(18, Uint8List.fromList([0xFF])),
              200,
            );
          }
          return http.Response('unexpected: ${req.url.path}', 500);
        });

        final adapter = TrezorBridgeAdapter(client: client);
        await adapter.connectDevice();
        final (respType, respPayload) = await adapter.call(
          17,
          Uint8List.fromList([0x0A, 0x05]),
        );
        expect(respType, equals(18));
        expect(respPayload, equals([0xFF]));
      });

      test('retries with re-acquired session on call failure', () async {
        var initCount = 0;
        var callFailedOnce = false;
        final client = mockClient((req) async {
          if (req.url.path == '/enumerate') {
            return http.Response(
              jsonEncode([
                {'path': 'usb0001', 'vendor': 0x534C, 'product': 0x53C1, 'session': null},
              ]),
              200,
            );
          }
          if (req.url.path == '/acquire/usb0001/null') {
            return http.Response('{"session":"sess-retry"}', 200);
          }
          if (req.url.path == '/call/sess-retry') {
            if (initCount == 0) {
              initCount++;
              return http.Response(syntheticFeaturesHex(), 200);
            }
            if (!callFailedOnce) {
              callFailedOnce = true;
              throw Exception('Connection lost');
            }
            return http.Response(
              encodeFrame(18, Uint8List.fromList([0xAA])),
              200,
            );
          }
          return http.Response('unexpected: ${req.url.path}', 500);
        });

        final adapter = TrezorBridgeAdapter(client: client);
        await adapter.connectDevice();
        final (respType, respPayload) = await adapter.call(
          17,
          Uint8List.fromList([0x01]),
        );
        expect(callFailedOnce, isTrue);
        expect(respType, equals(18));
        expect(respPayload, equals([0xAA]));
      });
    });

    group('_post error handling', () {
      test('throws StateError on non-200 response', () async {
        final client = mockClient((req) async {
          return http.Response('Bridge error details', 503);
        });

        final adapter = TrezorBridgeAdapter(client: client);
        expect(
          () => adapter.scanForDevices(),
          throwsA(
            isA<StateError>().having(
              (e) => e.message,
              'message',
              allOf(contains('503'), contains('Bridge error details')),
            ),
          ),
        );
      });
    });

    String syntheticPinMatrixRequestHex() {
      return encodeFrame(TrezorMsgType.pinMatrixRequest, Uint8List(0));
    }

    String syntheticPublicKeyHex(String xpub) {
      final w = ProtoWriter();
      w.writeString(2, xpub);
      return encodeFrame(TrezorMsgType.publicKey, w.toBytes());
    }

    String syntheticFailureHex({int? code, String? message}) {
      final w = ProtoWriter();
      if (code != null) {
        // varint field 1
        final raw = <int>[(1 << 3) | 0];
        var v = code;
        do {
          raw.add((v & 0x7F) | (v >= 0x80 ? 0x80 : 0));
          v >>>= 7;
        } while (v != 0);
        // Append to writer output via writeString workaround not needed;
        // build manually and concat.
        final wCode = ProtoWriter();
        if (message != null) wCode.writeString(2, message);
        final codeBytes = raw;
        final msgBytes = wCode.toBytes();
        final all = Uint8List.fromList([...codeBytes, ...msgBytes]);
        return encodeFrame(TrezorMsgType.failure, all);
      }
      if (message != null) w.writeString(2, message);
      return encodeFrame(TrezorMsgType.failure, w.toBytes());
    }

    group('getPublicKey', () {
      test('throws StateError when not connected', () {
        final client = mockClient((req) async {
          fail('No HTTP calls expected');
          return http.Response('', 500);
        });
        final adapter = TrezorBridgeAdapter(client: client);
        expect(
          () => adapter.getPublicKey(addressN: [0x80000054]),
          throwsA(
            isA<StateError>().having(
              (e) => e.message,
              'message',
              contains('Not connected'),
            ),
          ),
        );
      });

      test('sends GetPublicKey, handles PinMatrixRequest, returns PublicKey',
          () async {
        var callIndex = 0;
        final client = mockClient((req) async {
          if (req.url.path == '/enumerate') {
            return http.Response(
              jsonEncode([
                {
                  'path': 'usb0001',
                  'vendor': 0x534C,
                  'product': 0x53C1,
                  'session': null,
                },
              ]),
              200,
            );
          }
          if (req.url.path == '/acquire/usb0001/null') {
            return http.Response('{"session":"sess1"}', 200);
          }
          if (req.url.path == '/call/sess1') {
            final response = switch (callIndex) {
              0 => syntheticFeaturesHex(),
              1 => syntheticPinMatrixRequestHex(),
              2 => syntheticPublicKeyHex(
                  'xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5'),
              _ => throw StateError('Unexpected call index: $callIndex'),
            };
            callIndex++;
            return http.Response(response, 200);
          }
          return http.Response('unexpected: ${req.url.path}', 500);
        });

        final adapter = TrezorBridgeAdapter(client: client);
        await adapter.connectDevice();
        final pubKey = await adapter.getPublicKey(
          addressN: [0x80000054, 0x80000000, 0x80000000],
          onPinRequest: () async => '159',
        );
        expect(
          pubKey.xpub,
          equals(
            'xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5',
          ),
        );
      });

      test('handles PassphraseRequest after PinMatrixRequest', () async {
        var callIndex = 0;
        var pinCalled = false;
        var passphraseCalled = false;
        final client = mockClient((req) async {
          if (req.url.path == '/enumerate') {
            return http.Response(
              jsonEncode([
                {
                  'path': 'usb0001',
                  'vendor': 0x534C,
                  'product': 0x53C1,
                  'session': null,
                },
              ]),
              200,
            );
          }
          if (req.url.path == '/acquire/usb0001/null') {
            return http.Response('{"session":"sess1"}', 200);
          }
          if (req.url.path == '/call/sess1') {
            final response = switch (callIndex) {
              0 => syntheticFeaturesHex(),
              1 => syntheticPinMatrixRequestHex(),
              2 => encodeFrame(
                  TrezorMsgType.passphraseRequest, Uint8List(0)),
              3 => syntheticPublicKeyHex('xpub6passphrase...'),
              _ => throw StateError('Unexpected call index: $callIndex'),
            };
            callIndex++;
            return http.Response(response, 200);
          }
          return http.Response('unexpected: ${req.url.path}', 500);
        });

        final adapter = TrezorBridgeAdapter(client: client);
        await adapter.connectDevice();
        final pubKey = await adapter.getPublicKey(
          addressN: [0x80000054, 0x80000000, 0x80000000],
          onPinRequest: () async {
            pinCalled = true;
            return '159';
          },
          onPassphraseRequest: () async {
            passphraseCalled = true;
            return 'my secret';
          },
        );
        expect(pubKey.xpub, equals('xpub6passphrase...'));
        expect(pinCalled, isTrue);
        expect(passphraseCalled, isTrue);
      });

      test('throws on Failure response after PIN', () async {
        var callIndex = 0;
        final client = mockClient((req) async {
          if (req.url.path == '/enumerate') {
            return http.Response(
              jsonEncode([
                {
                  'path': 'usb0001',
                  'vendor': 0x534C,
                  'product': 0x53C1,
                  'session': null,
                },
              ]),
              200,
            );
          }
          if (req.url.path == '/acquire/usb0001/null') {
            return http.Response('{"session":"sess1"}', 200);
          }
          if (req.url.path == '/call/sess1') {
            final response = switch (callIndex) {
              0 => syntheticFeaturesHex(),
              1 => syntheticPinMatrixRequestHex(),
              2 => syntheticFailureHex(code: 6, message: 'PIN invalid'),
              _ => throw StateError('Unexpected call index: $callIndex'),
            };
            callIndex++;
            return http.Response(response, 200);
          }
          return http.Response('unexpected: ${req.url.path}', 500);
        });

        final adapter = TrezorBridgeAdapter(client: client);
        await adapter.connectDevice();
        expect(
          () => adapter.getPublicKey(
            addressN: [0x80000054, 0x80000000, 0x80000000],
            onPinRequest: () async => '159',
          ),
          throwsA(
            isA<StateError>().having(
              (e) => e.message,
              'message',
              allOf(contains('code 6'), contains('PIN invalid')),
            ),
          ),
        );
      });

      test('returns PublicKey directly when no PIN requested', () async {
        var callIndex = 0;
        final client = mockClient((req) async {
          if (req.url.path == '/enumerate') {
            return http.Response(
              jsonEncode([
                {
                  'path': 'usb0001',
                  'vendor': 0x534C,
                  'product': 0x53C1,
                  'session': null,
                },
              ]),
              200,
            );
          }
          if (req.url.path == '/acquire/usb0001/null') {
            return http.Response('{"session":"sess1"}', 200);
          }
          if (req.url.path == '/call/sess1') {
            final response = switch (callIndex) {
              0 => syntheticFeaturesHex(),
              1 => syntheticPublicKeyHex('xpub6direct...'),
              _ => throw StateError('Unexpected call index: $callIndex'),
            };
            callIndex++;
            return http.Response(response, 200);
          }
          return http.Response('unexpected: ${req.url.path}', 500);
        });

        final adapter = TrezorBridgeAdapter(client: client);
        await adapter.connectDevice();
        final pubKey = await adapter.getPublicKey(
          addressN: [0x80000054, 0x80000000, 0x80000000],
        );
        expect(pubKey.xpub, equals('xpub6direct...'));
      });

      test('throws StateError when PIN requested but no callback', () async {
        var callIndex = 0;
        final client = mockClient((req) async {
          if (req.url.path == '/enumerate') {
            return http.Response(
              jsonEncode([
                {
                  'path': 'usb0001',
                  'vendor': 0x534C,
                  'product': 0x53C1,
                  'session': null,
                },
              ]),
              200,
            );
          }
          if (req.url.path == '/acquire/usb0001/null') {
            return http.Response('{"session":"sess1"}', 200);
          }
          if (req.url.path == '/call/sess1') {
            final response = switch (callIndex) {
              0 => syntheticFeaturesHex(),
              1 => syntheticPinMatrixRequestHex(),
              _ => throw StateError('Unexpected call index: $callIndex'),
            };
            callIndex++;
            return http.Response(response, 200);
          }
          return http.Response('unexpected: ${req.url.path}', 500);
        });

        final adapter = TrezorBridgeAdapter(client: client);
        await adapter.connectDevice();
        expect(
          () => adapter.getPublicKey(
            addressN: [0x80000054, 0x80000000, 0x80000000],
          ),
          throwsA(
            isA<StateError>().having(
              (e) => e.message,
              'message',
              contains('no onPinRequest callback'),
            ),
          ),
        );
      });

      test('throws StateError with failure code and message on Failure',
          () async {
        var callIndex = 0;
        final client = mockClient((req) async {
          if (req.url.path == '/enumerate') {
            return http.Response(
              jsonEncode([
                {
                  'path': 'usb0001',
                  'vendor': 0x534C,
                  'product': 0x53C1,
                  'session': null,
                },
              ]),
              200,
            );
          }
          if (req.url.path == '/acquire/usb0001/null') {
            return http.Response('{"session":"sess1"}', 200);
          }
          if (req.url.path == '/call/sess1') {
            final response = switch (callIndex) {
              0 => syntheticFeaturesHex(),
              1 => syntheticFailureHex(code: 9, message: 'PIN cancelled'),
              _ => throw StateError('Unexpected call index: $callIndex'),
            };
            callIndex++;
            return http.Response(response, 200);
          }
          return http.Response('unexpected: ${req.url.path}', 500);
        });

        final adapter = TrezorBridgeAdapter(client: client);
        await adapter.connectDevice();
        expect(
          () => adapter.getPublicKey(
            addressN: [0x80000054, 0x80000000, 0x80000000],
            onPinRequest: () async => '159',
          ),
          throwsA(
            isA<StateError>().having(
              (e) => e.message,
              'message',
              allOf(contains('code 9'), contains('PIN cancelled')),
            ),
          ),
        );
      });

      test('handles ButtonRequest in loop', () async {
        var callIndex = 0;
        final client = mockClient((req) async {
          if (req.url.path == '/enumerate') {
            return http.Response(
              jsonEncode([
                {
                  'path': 'usb0001',
                  'vendor': 0x534C,
                  'product': 0x53C1,
                  'session': null,
                },
              ]),
              200,
            );
          }
          if (req.url.path == '/acquire/usb0001/null') {
            return http.Response('{"session":"sess1"}', 200);
          }
          if (req.url.path == '/call/sess1') {
            final response = switch (callIndex) {
              0 => syntheticFeaturesHex(),
              1 =>
                encodeFrame(TrezorMsgType.buttonRequest, Uint8List(0)),
              2 => syntheticPublicKeyHex('xpub_btn'),
              _ => throw StateError('Unexpected call index: $callIndex'),
            };
            callIndex++;
            return http.Response(response, 200);
          }
          return http.Response('unexpected: ${req.url.path}', 500);
        });

        final adapter = TrezorBridgeAdapter(client: client);
        await adapter.connectDevice();
        final pubKey = await adapter.getPublicKey(
          addressN: [0x80000054, 0x80000000, 0x80000000],
        );
        expect(pubKey.xpub, equals('xpub_btn'));
      });

      test('handles PassphraseRequest with default empty passphrase',
          () async {
        var callIndex = 0;
        final client = mockClient((req) async {
          if (req.url.path == '/enumerate') {
            return http.Response(
              jsonEncode([
                {
                  'path': 'usb0001',
                  'vendor': 0x534C,
                  'product': 0x53C1,
                  'session': null,
                },
              ]),
              200,
            );
          }
          if (req.url.path == '/acquire/usb0001/null') {
            return http.Response('{"session":"sess1"}', 200);
          }
          if (req.url.path == '/call/sess1') {
            final response = switch (callIndex) {
              0 => syntheticFeaturesHex(),
              1 => encodeFrame(
                  TrezorMsgType.passphraseRequest, Uint8List(0)),
              2 => syntheticPublicKeyHex('xpub_pp'),
              _ => throw StateError('Unexpected call index: $callIndex'),
            };
            callIndex++;
            return http.Response(response, 200);
          }
          return http.Response('unexpected: ${req.url.path}', 500);
        });

        final adapter = TrezorBridgeAdapter(client: client);
        await adapter.connectDevice();
        final pubKey = await adapter.getPublicKey(
          addressN: [0x80000054, 0x80000000, 0x80000000],
        );
        expect(pubKey.xpub, equals('xpub_pp'));
      });

      test('throws on unexpected message type', () async {
        var callIndex = 0;
        final client = mockClient((req) async {
          if (req.url.path == '/enumerate') {
            return http.Response(
              jsonEncode([
                {
                  'path': 'usb0001',
                  'vendor': 0x534C,
                  'product': 0x53C1,
                  'session': null,
                },
              ]),
              200,
            );
          }
          if (req.url.path == '/acquire/usb0001/null') {
            return http.Response('{"session":"sess1"}', 200);
          }
          if (req.url.path == '/call/sess1') {
            final response = switch (callIndex) {
              0 => syntheticFeaturesHex(),
              1 => encodeFrame(999, Uint8List(0)),
              _ => throw StateError('Unexpected call index: $callIndex'),
            };
            callIndex++;
            return http.Response(response, 200);
          }
          return http.Response('unexpected: ${req.url.path}', 500);
        });

        final adapter = TrezorBridgeAdapter(client: client);
        await adapter.connectDevice();
        expect(
          () => adapter.getPublicKey(
            addressN: [0x80000054, 0x80000000, 0x80000000],
          ),
          throwsA(
            isA<StateError>().having(
              (e) => e.message,
              'message',
              contains('Unexpected message type: 999'),
            ),
          ),
        );
      });
    });
  });

  group('TrezorDevice.forFirmware', () {
    test('creates device with features populated', () {
      final features = TrezorFeatures(
        label: 'Test',
        model: '1',
        firmwareVersion: '1.13.1',
        initialized: true,
      );
      final device = TrezorDevice.forFirmware(features, hidPath: 'usb0001');
      expect(device.hidPath, equals('usb0001'));
      expect(device.features?.label, equals('Test'));
      expect(device.features?.model, equals('1'));
      expect(device.features?.firmwareVersion, equals('1.13.1'));
      expect(device.features?.initialized, isTrue);
    });
  });
}
