// ignore_for_file: avoid_print
import 'package:coin/coin_hww.dart';

Future<void> main() async {
  final adapter = TrezorBridgeAdapter();
  print('Scanning for Trezor devices...');
  try {
    final devices = await adapter.scanForDevices();
    print('Found ${devices.length} device(s)');
    if (devices.isEmpty) {
      print('No devices found.');
      return;
    }
    print('Connecting (session steal + Initialize handshake)...');
    await adapter.connectDevice();
    print('Connected! isConnected: ${adapter.isConnected}');
    final dev = adapter.connectedDevice;
    if (dev?.features != null) {
      final f = dev!.features!;
      print('Features:');
      print('  label: ${f.label}');
      print('  firmware: ${f.firmwareVersion}');
      print('  model: ${f.model}');
      print('  initialized: ${f.initialized}');
    } else {
      print('Warning: no features available after connect');
    }
    print('Disconnecting...');
    await adapter.disconnect();
    print('Disconnected. isConnected: ${adapter.isConnected}');
  } on Exception catch (e) {
    print('Error: $e');
    print('Make sure Trezor Bridge is running at http://127.0.0.1:21325');
  }
}
