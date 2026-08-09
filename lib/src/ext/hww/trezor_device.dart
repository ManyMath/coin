import 'dart:typed_data';
import 'hardware_device.dart';
import 'trezor_features.dart';

abstract class TrezorDevice extends HardwareDevice {
  Future<(int, Uint8List)> call(int msgType, Uint8List payload);

  static TrezorHardwareWalletDevice forFirmware(
    TrezorFeatures features, {
    required String hidPath,
  }) {
    final device = TrezorHardwareWalletDevice(hidPath: hidPath);
    device.features = features;
    return device;
  }
}

class TrezorHardwareWalletDevice extends TrezorDevice {
  final String hidPath;
  TrezorFeatures? features;

  TrezorHardwareWalletDevice({required this.hidPath});

  @override
  bool get isConnected => throw UnimplementedError();

  @override
  Future<List<HardwareDevice>> scanForDevices() => throw UnimplementedError();

  @override
  Future<void> connectDevice() => throw UnimplementedError();

  @override
  Future<void> disconnect() => throw UnimplementedError();

  @override
  Future<(int, Uint8List)> call(int msgType, Uint8List payload) =>
      throw UnimplementedError();
}
