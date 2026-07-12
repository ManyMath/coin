class PolyseedFeatures {
  static const int featureBits = 5;
  static const int featuresBitMask = (1 << featureBits) - 1; // 0x1f = 31
  static const int encryptedBitMask = 16; // bit 4

  // Bits 0-3 are reserved (bits 0-2 are user features, bit 3 is reserved).
  // Bit 4 is the encryption flag (not reserved  -  an encrypted seed is supported).
  // This matches the C reference: reserved = featuresBitMask ^ encryptedBitMask.
  static const int _reservedMask = featuresBitMask ^ encryptedBitMask; // 0x0f

  static bool isSupported(int features) => (features & _reservedMask) == 0;
  static bool isEncrypted(int features) => (features & encryptedBitMask) != 0;
}
