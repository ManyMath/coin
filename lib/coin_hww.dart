/// Hardware-wallet support.
///
/// A Trezor stack: a protobuf wire codec, device/features models, a
/// HardwareDevice abstraction, and a Trezor Bridge HTTP adapter
/// (127.0.0.1:21325). Kept in its own barrel, separate from the core, since it
/// targets a live device. Pulls in `package:http` (native I/O).
library;

export 'coin.dart';

export 'src/ext/hww/hardware_wallet_enums.dart';
export 'src/ext/hww/hardware_device.dart';
export 'src/ext/hww/trezor_features.dart';
export 'src/ext/hww/trezor_device.dart';
export 'src/ext/hww/trezor_proto.dart';
export 'src/ext/hww/trezor_bridge_adapter.dart';
