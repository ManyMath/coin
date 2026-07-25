/// Hardware-wallet support.
///
/// Currently a Trezor stack: a protobuf wire codec, device/features models,
/// and a Trezor Bridge HTTP adapter. Kept in its own barrel, separate from
/// the core, since it targets a live device.
library;

export 'coin.dart';

export 'src/ext/hww/trezor_features.dart';
export 'src/ext/hww/trezor_proto.dart';
