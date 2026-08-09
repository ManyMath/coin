abstract class HardwareDevice {
  bool get isConnected;
  Future<List<HardwareDevice>> scanForDevices();
  Future<void> connectDevice();
  Future<void> disconnect();
}
