class PolyseedBirthday {
  /// 1st November 2021 12:00 UTC (matches C reference epoch).
  static const int epoch = 1635768000;

  /// 1/12 of the Gregorian year in seconds (matches C reference time_step).
  static const int timeStep = 2629746;

  static const int dateBits = 10;
  static const int dateBitMask = (1 << dateBits) - 1; // 1023

  /// Encode a Unix timestamp as a 10-bit birthday index.
  static int encode(int unixSecs) {
    if (unixSecs == -1 || unixSecs < epoch) return 0;
    return ((unixSecs - epoch) / timeStep).floor() & dateBitMask;
  }

  /// Decode a 10-bit birthday index back to a Unix timestamp.
  static int decode(int birthday) => epoch + birthday * timeStep;
}
