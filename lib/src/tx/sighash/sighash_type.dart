class SigHashType {
  final int flag;
  const SigHashType._(this.flag);

  /// BIP-341 SIGHASH_DEFAULT (flag 0x00). Taproot key-path only.
  ///
  /// A 0x00 flag commits to all inputs and outputs (semantically identical to
  /// SIGHASH_ALL) but is encoded as a bare 64-byte Schnorr witness with no
  /// trailing sighash byte. Legacy/SegWit signatures never use 0x00.
  static const taprootDefault = SigHashType._(0x00);

  static const all = SigHashType._(0x01);
  static const none = SigHashType._(0x02);
  static const single = SigHashType._(0x03);

  /// True for the BIP-341 SIGHASH_DEFAULT (0x00) flag. When set, a taproot
  /// key-path witness is the bare 64-byte signature with no appended flag.
  bool get isTaprootDefault => flag == 0x00;

  bool get anyoneCanPay => (flag & 0x80) != 0;

  SigHashType withAnyoneCanPay() => SigHashType._(flag | 0x80);

  static const allAnyoneCanPay = SigHashType._(0x81);
  static const noneAnyoneCanPay = SigHashType._(0x82);
  static const singleAnyoneCanPay = SigHashType._(0x83);

  factory SigHashType.fromFlag(int flag) => SigHashType._(flag);

  int get baseType => flag & 0x1f;

  @override
  bool operator ==(Object other) =>
      other is SigHashType && flag == other.flag;

  @override
  int get hashCode => flag;
}
