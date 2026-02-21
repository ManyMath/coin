import 'package:coin/coin.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(() async {
    await VaultKeeper.initialize();
  });

  // Seed 000102..0e0f is the BIP-32 Test Vector 1 seed:
  // https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vector-1
  // The groups below (fromSeed, Public key derivation, derivePath, DerivedKey
  // properties) reuse it but assert structural/round-trip facts (depth, chain-
  // code length, fingerprint=hash160[0:4], neuter consistency); the xprv/xpub
  // strings are in the "BIP-32 Test Vector 1/2/3" groups.
  group('DerivedKey.fromSeed', () {
    test('produces DerivedSecretKey at depth 0', () {
      final seed = hexDecode('000102030405060708090a0b0c0d0e0f');
      final master = DerivedKey.fromSeed(seed);
      expect(master, isA<DerivedSecretKey>());
      expect(master.depth, 0);
      expect(master.index, 0);
      expect(master.parentFingerprint, 0);
    });

    test('chain code is 32 bytes', () {
      final seed = hexDecode('000102030405060708090a0b0c0d0e0f');
      final master = DerivedKey.fromSeed(seed);
      expect(master.chainCode.length, 32);
    });
  });

  // BIP-32 Test Vectors 1-3, from the BIP-32 spec test-vector tables.
  // https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vectors
  group('BIP-32 Test Vector 1', () {
    late DerivedSecretKey master;

    setUp(() {
      final seed = hexDecode('000102030405060708090a0b0c0d0e0f');
      master = DerivedKey.fromSeed(seed) as DerivedSecretKey;
    });

    test('Chain m - xpub', () {
      expect(
        _xpub(master),
        'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8',
      );
    });

    test('Chain m - xprv', () {
      expect(
        master.encode(),
        'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi',
      );
    });

    test("Chain m/0' - xpub", () {
      final child = master.derivePath("m/0'");
      expect(
        _xpub(child as DerivedSecretKey),
        'xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw',
      );
    });

    test("Chain m/0' - xprv", () {
      final child = master.derivePath("m/0'") as DerivedSecretKey;
      expect(
        child.encode(),
        'xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7',
      );
    });

    test("Chain m/0'/1 - xpub", () {
      final child = master.derivePath("m/0'/1");
      expect(
        _xpub(child as DerivedSecretKey),
        'xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ',
      );
    });

    test("Chain m/0'/1 - xprv", () {
      final child = master.derivePath("m/0'/1") as DerivedSecretKey;
      expect(
        child.encode(),
        'xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs',
      );
    });

    test("Chain m/0'/1/2' - xpub", () {
      final child = master.derivePath("m/0'/1/2'");
      expect(
        _xpub(child as DerivedSecretKey),
        'xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5',
      );
    });

    test("Chain m/0'/1/2' - xprv", () {
      final child = master.derivePath("m/0'/1/2'") as DerivedSecretKey;
      expect(
        child.encode(),
        'xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM',
      );
    });

    test("Chain m/0'/1/2'/2 - xpub", () {
      final child = master.derivePath("m/0'/1/2'/2");
      expect(
        _xpub(child as DerivedSecretKey),
        'xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV',
      );
    });

    test("Chain m/0'/1/2'/2 - xprv", () {
      final child = master.derivePath("m/0'/1/2'/2") as DerivedSecretKey;
      expect(
        child.encode(),
        'xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334',
      );
    });

    test("Chain m/0'/1/2'/2/1000000000 - xpub", () {
      final child = master.derivePath("m/0'/1/2'/2/1000000000");
      expect(
        _xpub(child as DerivedSecretKey),
        'xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy',
      );
    });

    test("Chain m/0'/1/2'/2/1000000000 - xprv", () {
      final child =
          master.derivePath("m/0'/1/2'/2/1000000000") as DerivedSecretKey;
      expect(
        child.encode(),
        'xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76',
      );
    });
  });

  group('BIP-32 Test Vector 2', () {
    late DerivedSecretKey master;

    setUp(() {
      final seed = hexDecode(
        'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a2'
        '9f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542',
      );
      master = DerivedKey.fromSeed(seed) as DerivedSecretKey;
    });

    test('Chain m - xpub', () {
      expect(
        _xpub(master),
        'xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB',
      );
    });

    test('Chain m - xprv', () {
      expect(
        master.encode(),
        'xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U',
      );
    });

    test('Chain m/0 - xpub', () {
      final child = master.derivePath('m/0');
      expect(
        _xpub(child as DerivedSecretKey),
        'xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH',
      );
    });

    test('Chain m/0 - xprv', () {
      final child = master.derivePath('m/0') as DerivedSecretKey;
      expect(
        child.encode(),
        'xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt',
      );
    });

    test("Chain m/0/2147483647' - xpub", () {
      final child = master.derivePath("m/0/2147483647'");
      expect(
        _xpub(child as DerivedSecretKey),
        'xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a',
      );
    });

    test("Chain m/0/2147483647' - xprv", () {
      final child = master.derivePath("m/0/2147483647'") as DerivedSecretKey;
      expect(
        child.encode(),
        'xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9',
      );
    });

    test("Chain m/0/2147483647'/1 - xpub", () {
      final child = master.derivePath("m/0/2147483647'/1");
      expect(
        _xpub(child as DerivedSecretKey),
        'xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon',
      );
    });

    test("Chain m/0/2147483647'/1 - xprv", () {
      final child =
          master.derivePath("m/0/2147483647'/1") as DerivedSecretKey;
      expect(
        child.encode(),
        'xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef',
      );
    });

    test("Chain m/0/2147483647'/1/2147483646' - xpub", () {
      final child = master.derivePath("m/0/2147483647'/1/2147483646'");
      expect(
        _xpub(child as DerivedSecretKey),
        'xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL',
      );
    });

    test("Chain m/0/2147483647'/1/2147483646' - xprv", () {
      final child =
          master.derivePath("m/0/2147483647'/1/2147483646'") as DerivedSecretKey;
      expect(
        child.encode(),
        'xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc',
      );
    });

    test("Chain m/0/2147483647'/1/2147483646'/2 - xpub", () {
      final child = master.derivePath("m/0/2147483647'/1/2147483646'/2");
      expect(
        _xpub(child as DerivedSecretKey),
        'xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt',
      );
    });

    test("Chain m/0/2147483647'/1/2147483646'/2 - xprv", () {
      final child =
          master.derivePath("m/0/2147483647'/1/2147483646'/2") as DerivedSecretKey;
      expect(
        child.encode(),
        'xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j',
      );
    });
  });

  group('BIP-32 Test Vector 3', () {
    late DerivedSecretKey master;

    setUp(() {
      final seed = hexDecode(
        '4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4ac'
        'ba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be',
      );
      master = DerivedKey.fromSeed(seed) as DerivedSecretKey;
    });

    test('Chain m - xpub', () {
      expect(
        _xpub(master),
        'xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13',
      );
    });

    test('Chain m - xprv', () {
      expect(
        master.encode(),
        'xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6',
      );
    });

    test("Chain m/0' - xpub", () {
      final child = master.derivePath("m/0'");
      expect(
        _xpub(child as DerivedSecretKey),
        'xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y',
      );
    });

    test("Chain m/0' - xprv", () {
      final child = master.derivePath("m/0'") as DerivedSecretKey;
      expect(
        child.encode(),
        'xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L',
      );
    });
  });

  group('Public key derivation', () {
    test('public-only derivation matches private derivation for normal child',
        () {
      final seed = hexDecode('000102030405060708090a0b0c0d0e0f');
      final master = DerivedKey.fromSeed(seed) as DerivedSecretKey;

      final privChild = master.derivePath("m/0'/1") as DerivedSecretKey;

      final privAt0h = master.derivePath("m/0'") as DerivedSecretKey;
      final pubAt0h = _toPubOnly(privAt0h);
      final pubChild = pubAt0h.derive(1);

      expect(pubChild.publicKey, equals(privChild.publicKey));
    });

    test('hardened derivation from public key throws', () {
      final seed = hexDecode('000102030405060708090a0b0c0d0e0f');
      final master = DerivedKey.fromSeed(seed) as DerivedSecretKey;
      final masterPub = _toPubOnly(master);

      expect(
        () => masterPub.deriveHardened(0),
        throwsArgumentError,
      );
    });
  });

  group('derivePath', () {
    test('path "m" returns master key', () {
      final seed = hexDecode('000102030405060708090a0b0c0d0e0f');
      final master = DerivedKey.fromSeed(seed) as DerivedSecretKey;
      final same = master.derivePath('m') as DerivedSecretKey;
      expect(same.encode(), master.encode());
    });

    test('hardened with h suffix works like apostrophe', () {
      final seed = hexDecode('000102030405060708090a0b0c0d0e0f');
      final master = DerivedKey.fromSeed(seed) as DerivedSecretKey;
      final a = master.derivePath("m/0'") as DerivedSecretKey;
      final b = master.derivePath('m/0h') as DerivedSecretKey;
      expect(a.encode(), b.encode());
    });
  });

  group('DerivedKey properties', () {
    test('depth increments with each derivation', () {
      final seed = hexDecode('000102030405060708090a0b0c0d0e0f');
      final master = DerivedKey.fromSeed(seed);
      expect(master.depth, 0);

      final child1 = master.deriveHardened(0);
      expect(child1.depth, 1);

      final child2 = child1.derive(1);
      expect(child2.depth, 2);
    });

    test('fingerprint is first 4 bytes of hash160 of public key', () {
      final seed = hexDecode('000102030405060708090a0b0c0d0e0f');
      final master = DerivedKey.fromSeed(seed);
      final id = hash160(master.publicKey.bytes);
      final expected =
          (id[0] << 24) | (id[1] << 16) | (id[2] << 8) | id[3];
      expect(master.fingerprint, expected);
    });

    test('child parentFingerprint equals parent fingerprint', () {
      final seed = hexDecode('000102030405060708090a0b0c0d0e0f');
      final master = DerivedKey.fromSeed(seed);
      final child = master.deriveHardened(0);
      expect(child.parentFingerprint, master.fingerprint);
    });

    test('identifier is 20 bytes', () {
      final seed = hexDecode('000102030405060708090a0b0c0d0e0f');
      final master = DerivedKey.fromSeed(seed);
      expect(master.identifier.length, 20);
    });
  });
}

/// Encode a DerivedSecretKey as an xpub (public key serialization).
String _xpub(DerivedSecretKey key) {
  final pub = DerivedPublicKey(
    publicKey: key.publicKey,
    chainCode: key.chainCode,
    depth: key.depth,
    index: key.index,
    parentFingerprint: key.parentFingerprint,
  );
  return pub.encode();
}

/// Create a DerivedPublicKey from a DerivedSecretKey (neuter).
DerivedPublicKey _toPubOnly(DerivedSecretKey key) {
  return DerivedPublicKey(
    publicKey: key.publicKey,
    chainCode: key.chainCode,
    depth: key.depth,
    index: key.index,
    parentFingerprint: key.parentFingerprint,
  );
}
