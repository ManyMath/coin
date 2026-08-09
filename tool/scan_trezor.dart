// ignore_for_file: avoid_print
import 'package:coin/coin_hww.dart';

Future<void> main() async {
  final adapter = TrezorBridgeAdapter();
  print('Scanning for Trezor devices...');
  try {
    final devices = await adapter.scanForDevices();
    print('Found ${devices.length} device(s):');
    for (final d in devices) {
      final dev = d as TrezorHardwareWalletDevice;
      print('  path: ${dev.hidPath}, model: ${dev.features?.model}');
    }
    if (devices.isEmpty) {
      print('No devices found.');
      return;
    }
    print('Connecting (session steal)...');
    await adapter.connectDevice();
    print('Connected! Session acquired. isConnected: ${adapter.isConnected}');
    print('Disconnecting...');
    await adapter.disconnect();
    print('Disconnected. isConnected: ${adapter.isConnected}');
  } on Exception catch (e) {
    print('Bridge error: $e');
    print('Make sure Trezor Bridge is running at http://127.0.0.1:21325');
  }
}
