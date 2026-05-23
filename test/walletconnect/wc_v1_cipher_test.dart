import 'dart:typed_data';

import 'package:coin/coin_walletconnect.dart';
import 'package:test/test.dart';

/// WalletConnect v1 transport-crypto vectors (AES-256-CBC + HMAC-SHA256).
///
/// Key/iv/plaintext inputs and expected `data`+`hmac` outputs captured from
/// walletconnect_dart@0.0.11, repo
/// https://github.com/RootSoft/walletconnect-dart-sdk
/// (goldens/wcdart.out). See test/walletconnect/goldens/README.md for the
/// goldens index.
void main() {
  setUpAll(() async {
    await VaultKeeper.initialize();
  });

  final key = Uint8List.fromList(hexDecode(
      '41791102999c339c844880b23950704cc43aa840f3739e365323cda4dfa89e7a'));
  final iv = Uint8List.fromList(hexDecode('000102030405060708090a0b0c0d0e0f'));
  const plaintext =
      '{"id":1,"jsonrpc":"2.0","method":"personal_sign","params":[]}';

  const expectedData =
      '87b911e5e0bfc8fd1a0fb7cb57bed8024f80176fc685e830a9d14a639a4a22c830dc7edc654a6141b3c3510402ccb096a67481f6d5abb49f3a9e747512211bf0';
  const expectedHmac =
      '16683eee7e05586f1538044157303e5ea73592ad259a51615e3f69adb24594cc';

  test('encrypt reproduces canonical data + hmac', () {
    final payload = wcV1Encrypt(key32: key, iv16: iv, plaintext: plaintext);
    expect(payload.data, expectedData);
    expect(payload.hmac, expectedHmac);
    expect(payload.iv, '000102030405060708090a0b0c0d0e0f');
  });

  test('decrypt verifies hmac and recovers plaintext', () {
    const payload = WcV1Payload(
      data: expectedData,
      hmac: expectedHmac,
      iv: '000102030405060708090a0b0c0d0e0f',
    );
    expect(wcV1VerifyHmac(payload, key), isTrue);
    expect(wcV1Decrypt(payload, key), plaintext);
  });

  test('tampered ciphertext fails HMAC before decryption', () {
    final tampered = WcV1Payload(
      data: '00${expectedData.substring(2)}',
      hmac: expectedHmac,
      iv: '000102030405060708090a0b0c0d0e0f',
    );
    expect(wcV1VerifyHmac(tampered, key), isFalse);
    expect(() => wcV1Decrypt(tampered, key), throwsFormatException);
  });

  test('round-trip an arbitrary message', () {
    const msg = '{"hello":"world","n":42}';
    final p = wcV1Encrypt(key32: key, iv16: iv, plaintext: msg);
    expect(wcV1Decrypt(p, key), msg);
  });
}
