// ignore_for_file: avoid_print
import 'dart:io';

import 'package:coin/coin_hww.dart';

Future<void> main() async {
  final adapter = TrezorBridgeAdapter();
  try {
    final devices = await adapter.scanForDevices();
    print('Found ${devices.length} device(s)');
    if (devices.isEmpty) {
      print('No Trezor devices found. Is Trezor Suite / Bridge running?');
      return;
    }

    print('Connecting (session steal + Initialize handshake)...');
    await adapter.connectDevice();
    final features = adapter.connectedDevice?.features;
    print('Connected: ${features?.label ?? "unlabeled"} '
        '(fw ${features?.firmwareVersion}, model ${features?.model})');

    // BIP84 native segwit, Bitcoin mainnet, account 0: m/84'/0'/0'
    final addressN = [0x80000054, 0x80000000, 0x80000000];
    print("Requesting xpub for m/84'/0'/0'...");

    final publicKey = await adapter.getPublicKey(
      addressN: addressN,
      onPinRequest: () async {
        print('');
        print('PIN entry: look at the Trezor screen for the 3x3 grid.');
        print('Each position is numbered:');
        print('  7 8 9');
        print('  4 5 6');
        print('  1 2 3');
        print('Enter the POSITIONS matching your PIN digits (e.g. "5739"):');
        stdout.write('PIN> ');
        return stdin.readLineSync() ?? '';
      },
      onPassphraseRequest: () async {
        stdout.write('Enter passphrase (empty for none): ');
        return stdin.readLineSync() ?? '';
      },
    );

    print('xpub: ${publicKey.xpub}');

    await adapter.disconnect();
    print('Disconnected.');
  } on Exception catch (e) {
    print('Error: $e');
    print('Make sure Trezor Bridge is running at http://127.0.0.1:21325');
  }
}
