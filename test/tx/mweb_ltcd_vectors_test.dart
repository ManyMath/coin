import 'package:coin/coin.dart';
import 'package:test/test.dart';

/// MWEB transaction vectors from `ltcsuite/ltcd` (the Go Litecoin node)
/// `wire/testdata/*.dat` fixtures, per `TestMwebTxDeserialize` in
/// `wire/msgtx_test.go`.
///
/// Assertion regimes. The model stores MWEB as an opaque blob and `RawInput`
/// discards witness data on read (pre-existing design). Litecoin Core
/// computes an MWEB-only tx's txid as a kernel hash, not a serialization
/// hash:
///
///  1. HogEx (flag 0x08, has real vin/vout, NOT mweb-only): exact round-trip
///     and txid match (txid is a NO_WITNESS|NO_MWEB serialization hash).
///  2. Peg-in stripped (flag 0x01, witness, no mweb): witness dropped on
///     read, so the round-trip differs; txid still matches (txid excludes
///     witness).
///  3. Peg-in mempool (flag 0x09, witness + mweb): witness dropped; the
///     mweb tail is captured; txid matches the stripped in-block form's
///     txid (txid excludes both witness and mweb).
///  4. MWEB-only (flag 0x08, no canonical vin/vout): exact round-trip (no
///     witness, opaque mweb blob written back unchanged) but txid is not
///     asserted - Litecoin Core derives it from a kernel hash, which the
///     opaque model does not reproduce (Slice B / mwebd territory).
///
/// Sources:
///  - github.com/ltcsuite/ltcd wire/testdata/
///    tx...de22f4d....dat            (HogEx, block 2269979)
///    tx...8b8343978....dat          (peg-in, in-block / stripped)
///    tx...8b8343978..._mp.dat       (peg-in, mempool / full MWEB tail)
///    tx...e6f8fdb15..._mp.dat       (MWEB-only, mempool)
///  - txids/locktimes from wire/msgtx_test.go TestMwebTxDeserialize.

// HogEx, block 2269979, flag 0x08, 169 bytes. Has 2 real inputs + 2 real
// outputs and a 1-byte "null mw" extension block before the locktime.
const _hogex =
    '02000000000802b53383f142a28e74d72007b42725262cd90d7056e2ce2af186'
    '2a37a5032600a60000000000ffffffff03defc47752611917d9154cec90d5c56'
    '54a2e9776979da545df9be8d9743838b0000000000ffffffff02562929c41200'
    '00002258206ff2ee1047b7e028f6b057b3c7df6224327d507e4c513002dbf2d9'
    '81bcaa7fc8006a180000000000160014d11a7dfea8f1bc58aafc563e6d9feea3'
    '92cdae930000000000';

// Peg-in 8b8343978..., IN BLOCK, flag 0x01 (mw bit unset, mw tx stripped),
// 203 bytes, version 2, 1 regular input / 1 regular output. Witness present.
const _peginBlock =
    '020000000001015fd2189034093b720c4b9aef085494a6b0308f9c160687c1ae'
    '8c460063f3e4bd0000000000feffffff01a28d357700000000225920e933ba73'
    '7012a3fdcb6b02ee1453f49c940b7e0ee59df9905a00c9603a2facbb02473044'
    '02207c2261c46d390172d75be4f6f3edd9eefb442ff6e5fa36330d468c3d5f66'
    'ba2b022005bcae3c36cbc0df72239d0df36ca9b53949e09888c9a23579787373'
    '612eda500121021d51ab179db58724222743d3b5911f71944171ef3c7ba082b2'
    '6dad391f4259cf1aa32200';

// Peg-in 8b8343978..., MEMPOOL, flag 0x09 (witness + mweb), 2203 bytes,
// version 2, same 1 input / 1 output, but with the full MWEB tail. SAME txid
// as the stripped in-block form above.
const _peginMempool =
    '020000000009015fd2189034093b720c4b9aef085494a6b0308f9c160687c1ae'
    '8c460063f3e4bd0000000000feffffff01a28d357700000000225920e933ba73'
    '7012a3fdcb6b02ee1453f49c940b7e0ee59df9905a00c9603a2facbb02473044'
    '02207c2261c46d390172d75be4f6f3edd9eefb442ff6e5fa36330d468c3d5f66'
    'ba2b022005bcae3c36cbc0df72239d0df36ca9b53949e09888c9a23579787373'
    '612eda500121021d51ab179db58724222743d3b5911f71944171ef3c7ba082b2'
    '6dad391f4259cf0180d3c6642cff373fad27fb93cf340dbb01a75dfa4645d3ac'
    '39a9affbb115c013ea2d1f23a0390537cd15d7b7ae4ac16762a734fef9464344'
    '1d0b108e175ffd0100020951306d4df7ab8f4e6c8b2a549b6766a5fcab15c0fa'
    '30d08a7e85fa2bee218a1f031ae80313197aaa8a20fff310355f1423bf61c101'
    '6ccfb45aece95c25618d5d580334017271f54800acf5d0f4a5aefa057b37384d'
    'bd403bc188d613b76ddca450830102317f2d059f2021115d80f8310384a1e7c9'
    'a1fe6ba6c1207be14f1a9b8663fbac9fa464e8720f6011e85646d08c8f60e0b5'
    '95699b547052ad62d992aa98070f18c15b3bdf4cea05717500c244c496295b1f'
    'e2fb41600cacfec1f257800188ebfc3e7da615626e04370ccdb937028079b649'
    '26383c90271db7f10a802f4933de8977d8524cccd607733beca37a9a6de018b1'
    'f6bd597e68b1e7d28dd7b3d1285b0b817d8e02d4cc93754140a002c7867dcb8d'
    'b6163bdfd29d2b8fdd45cb2e3db2e56cec69cd6e179e33ebb12e201d289ff015'
    '67c0e485f8e0e66e5cb7e6b08a9d2fe5c2ff4d658df22596655ca86cac1ee30b'
    'ff49232737300b8eebccdc23ece84b86bec78e45f8f56716f1a60b883ca20818'
    'be43b38b2fbbb707a847be5fa111dcf4dfc74a15d0fde3f81889ed5655824804'
    '251364fa5e6ab8617c8fcbd5dba45dae1d7c4e55187bfeb2d7db9496484c7d93'
    '183f6e1627219bd175ef21f855be3aad17055bb82ae030689da31a6a41a406d2'
    '925c348d9e9f0784e4314277d2d4c106c0b2395fc122c02a161145023a6ca00e'
    'ed15fff53029b1217945007cce5fa567b9767dd4a369875738f056ff915fa291'
    '778ad80c1f4054bc6d968fff9b20771d23d16391eaf3a42a46702e424c21c0f3'
    '0425d8e7175f93819f3f11355aeae3737beec3a33ade3532f8c3248d53c2d023'
    '3547684822fb60af320b72875cc585b388c5b5d4024e626e91ef1d2e31581b70'
    '30559aa393e628a098c7c65e6c8bf10c82c77dd641d3cc8b6204fd561f549ea5'
    '256d840f2aaf263349314a4cfe4b43b268412b75b2877ce6c69996c82e459712'
    'ba406ba643d5dedd3e5e734b47662b048fa8ac0937a23cc118bb35fb69f9f43a'
    'e4b765dec04e9173bc0b93e9d69a882b999e29f6627c6342cffb9b8bdbffca5a'
    'e8eaaf6021378800d4ebd17c9e9e97c26a58f2c59af64a9fad7cd3f8222811ef'
    'db3b2e5ee093d2b9470e0c97b484a234ff4c01115623ae95ed29dc82398e6b5f'
    '1b72191bfd7201b48ee2f1a6f81ccbfad6ebe817fad29543a25bc2a454709945'
    'f78d09625e24f04f34e990ca17356191a768acbcd0687f14fb8e87b1a4dd0707'
    '341f413c09c1dc43cd1d8c09f5b3e76b9a386d07e101841670a29083a11c17ec'
    '9ab1aa5222bc3e475c0cb8b002b4f8a04293f6bcb8a5e0a54a7f720e9652b70c'
    '0523774ff5183c8460440933c403a5167e06e7afe55623514c0b99197823ce63'
    '2296a0b2a38fbe15fca08616d200010253766df46c32c658d6683fcf58a87be1'
    '22bdb663d73f217702ca59d4d62978a304da9cc31d9124289fb087d7f8f9035b'
    '7f9999605279c60cb1f6acdc6c0b7332c633375206da193a08a5825e133be7f4'
    '661d1237f2acccde779fb26f53de7aba3b1136ae8b7a418f27973fb0b4a5a52e'
    '391ea62b0542d4705e04ead47d1da3f777fdf295828bf0dfef3316e6daf53fb0'
    '94bd0234105f3a551ddf4d30d3920a71d5d24ce143fe1eeef9b011ef6541e96c'
    '0910cf4bdcd269873404a734c138cf50c2924e7755755857d55e1814eb3b5b44'
    'd5393f618ed2992561a936695b2707c05d381cf54bffd6b377f176f93d0fdbc0'
    '52599ee62ed835f9997408d2aa3015a1f056efa3e3fc64ff994ca1ca4d6069b3'
    'f1811437da713adab88a662c2cbd5b15d1be7501beb7079421ce6239457094cb'
    'bd70899cb57f1ed61c0d8b39638ae73ceec54219bfb0376ef2b7925e25400ec7'
    'f49b141cd8e2af37ad0578582e08d3a1e21da570aa8e6af8b09d9176d57015bd'
    '8859dcf6b2f53321dd5a876d1cc854f0c7833271e648993a1058c30d8e994cf0'
    '78633043f05877ebcc6a01023d777c7806aca72c2af357e49a463457f1e55793'
    '2da333fdd9ab4c30546ab9f166c72e1f68fced3f2af62d4a805005e034b80766'
    '6512cc4fbacda519264838e6c575aa3bf72894d6320262da910506384d44ab6e'
    '3a2b77037ba7bcb83e5f6dd89a620372fdbba42a98c1b0c6322c95cb1850fd9b'
    '5ea4139e8f8c5e23765fd0a2e0b3851798398de2342c212db72e23f06959ff4e'
    '75a952b0686c0f4b0d034c0781fc4e9c58a43551adc5582888152165b56d20b3'
    'db98e77e0a5cdeb08034207a97ef0bae8a6b5199e20b76bd6d191888626847e1'
    '3605ba69a9b1705dc6466700a334f9cdfeac74e4e754b2aec10f2e63b9da6034'
    '7fbdee211c06e29aace74c990fb0dc447ac0bf1574171d9e6cf5c308ee4b9bc6'
    '0d911eab70712cc67c4479a33af2916fc46b1b8447ee4f4fbd0ce1fb30cde7b4'
    '979d06c599b4a4e482cc395cb380a0ff0434ced21d671fc21d17b9cb57c8e5d9'
    'ea37b4865533b6e7fe7bcd167dcee74922e8386f9f0c70ff9ce799e11c79c34d'
    '0d250c647756cf434b5803d001139d3c86b8d59a22034b86d76154f2dc80fe0a'
    'b180cad8d53ebb6afef4f546d29c28dcd754e8c61c6908bd3ffaae4171170f47'
    'b69eb4e75274aad37940199c994c13b55c4064dbe969c03babc71c3573ba6c73'
    '338a282cbf4c102c8c69bf53ef3ca43649896e1b1ce52e4704748384e3339bac'
    'de1dfd2eee3c01f1f61013e051ca13e8a7901c8ac465a51aa32200';

// MEMPOOL MWEB-only tx e6f8fdb15..., flag 0x08, 2203 bytes, version 2,
// 0 regular inputs / 0 regular outputs, 1 mw input / 2 mw outputs, 1 kernel.
// Pure MWEB.
const _mwebOnly =
    '020000000008000001ef12836c5077958f705acdbfc63807318e8892b715d251'
    '46313356f98c99f76fd57c8b0a35beab5f4c12695a4c86dc5757dc893636d590'
    '2c2050ec930a5a51df0101376e9047086d74321f49f7968ce6e8ee974c1935da'
    '132be6c5fbd284624a203f092c41fad8927f4ddaa261f6a3935518fea2bafd57'
    '158ff5abe1f82e9b1813425603aa62a2b1f7e91b7db89172f658641ee1ff4541'
    '09e4ca5c68ef71c87f9bacee6b0214bb27c4c5c43d11e43b2f3b9e1c4308b3ec'
    'b7ee2069ed9449cc702923e49420b86b71339adc29a6cff59a66848ca4d98ae7'
    '7d5080042bd659db137e18e06d25cf85d756362f45757151a9315a6e3475701a'
    'da04707a2251dad0e60f0aed1ab70208b95767242302c3fcf39027378f3e14d8'
    '4fc6648e630024cff9201d8c77bee80602a59498817429eae77f39fd318fdaef'
    'c2942783254356647fe644c3e1c0055dc402ba4a4cc8d108f4bbb9a586731ba2'
    'ddcb05f71e3e6041f9fbef7575552061675b0102fbf91f61620be900fd406586'
    '3eed964e874da1b292e84e2c4037e29317efa89d65ea6534e58a6f1e4a3bb94b'
    '2e66297db3d47ed3c2818de5b8a87531644c37113445496b16737985f4b4c0d3'
    '1e5bbc01b136b796b5253b391cff919bfb684524ce29ef32f1bdd3359b3f78b0'
    'a250cc1c7620d0f20227f0699201d1bca25d05ba570af146371e21b0c69462c3'
    '6fb85438c38e54398481fe912d635cc285a65dd261b85e1fc348f8e8e0cc62d4'
    '1f5dbf171e7e03430e7fecfd804ba18964141a199e53698d9adc79ccb1f7abb9'
    '5fc0083791c2e5c9f6bdc3d05fe98752610558ce44f3583894a9a4928fcd28fe'
    '224e99f8e76eb03347d1ab9e630cce0337de7b17aca4f7bc8c6de3689fd9e80c'
    '63c43c521dd44604a573cfb835d9689bc41e7d2420273e3588b9c4647fdaf70c'
    '5239e0728609c61f8c69d6093409a81c16966f3c47126c746bac42e56af0687b'
    'caccfbedf025b2f711053f848e37f5be778d8d96deb122c101c97a54a2203912'
    'd619e9b3efed31efc843bb25724dd3e279dfbe786477ac85d34945d182dd705f'
    'bdea6beedfa80b8038e6ad7e02dd5f0314cea9860edb7637337dcfaa323ea72f'
    'c160ad8bdaed04d1b82fd29b04b4d7a3700a0937568b3c43f44b04ffe74c54df'
    '19c205030c4b297f6db3def168ac98db3cc40824b0f725f7d0261d9d4667d487'
    '4df33dcd0221d6b9664dc7a902a77136845ba98ece507e377647ef5fdcbb2f0b'
    'a022399c1658b623e7b0e0cd8a85d88e8ad3a3e51ec2f7c044be2ca3e9648859'
    '01c35a91457a1b05a4c1576220c7659e88a30e56ff45fd3add0e9cac32bf9350'
    '1ee96e8dd8e8750ebedac87a91155b26b237d554fa091e8b05504b308c680523'
    '10e931bcef07b1ec8fac7d6763ff3903cb9af9c45f7aa483bcd81ffe23d335ea'
    '1f43c33c207f0e6f94d2628015fd6d75e775dd925024f180d1356c4746f21783'
    '4fbdbda2375c9a570dd3b5342023ef1236c224917ffcf8a351e5be8566d6458e'
    '0dfe4c45d6a8c116bd05d822b1b146fa0e2d9562f66411e04be6514af5b8699c'
    '68d549bcad90895ae5f089e291669e8d57fcc0da620771f9f8be50cb187955cb'
    '4296f79d18a47fcd944ea6e32c008d6c09f944ca24090e82a0ac17ab24ec03ad'
    'ffc5a80969d92d94464d3433d4b7b0e57803a3785bf87d74de898c703b0c08d6'
    '7a542bd70c58bcaa6713c1452c2f124fa97b02913a1fc628378ce10a59dd053f'
    'b3c24a9228bec790330f062c020ed111b3b52701023896aea373d7b26f7f5b69'
    'adf644685b47902936f4a90bd9c5d64e8ab08a338aa623d2bd1d813345c6e1ce'
    'd3dd4fc7ffc04ded0d68b534a3a92ae20817937d4c8edff4644afb5c82a81f75'
    '158c55f97f222fb9c8c72baa06999f159265a459b679755e617bb2a55a67d054'
    '7f32f0f8c3e637db1ecfa66be06a09c79ab3484ae2abe743eb990c0759646377'
    'd3fcfad92fcf6fc509b00408be381d89f316afeab4812640ade390c7a5f2960e'
    'a846aa3828e456a45be9fbf6a0ea16980df2289e946b5abf41ea699d9311786b'
    '233ccfe5d2a12e8acaf933a35e0405cd2e173088868dfbde9d9106eae895a8ff'
    '750025ade7b6a081f7e018ce4988da64fa719ca3532493c1ba56c8b06d2a25a8'
    'bd689bc3f13dba287dda0994c8859771ac6f8d0de30beffdf390a4f9741bcd48'
    'c1e08dc976d7d587e361f5378d11365f4f284fa1fdd40df7f581d93f42f03921'
    '17ab7e4cd2c1ad4a622428125e91121a3a0849ee4540e7dea96efd7165236237'
    'f923692b76608b3c97a47167cf2f700b5e1bea21d8faea16ebc4117d178f9085'
    '65bfe3687ff7724374bec2aaf66f14a002d8c5b96f3776f6de7fd6fa106a69c0'
    '0c29000c77e9f868b0e0a482d1805a4f62e5619bae2bd17a65c62fa2b06b0367'
    'd56041082bb4832089df39801eb8731ed9ef78fd615cbf2338fec3087ce21a24'
    '65f41b954a561895a7bce22ec2456f93b62086330ec4b763b88117960152145f'
    '6c906df9594277051fd187157f478fa2faa02ec62b1f2262d37aa441295f94ab'
    '619ff885ad1edd2f867f3573c00eacab6a0c5d30401eb7da428705bf0de2775e'
    '203b5ba67806b0303e7a9edc18b90e5b9a1fd9edddd7197c95d2f9fc0729def2'
    '7b548032285824182d00afa4e9aa6f0f4bc79a0144ad5a0398e7dd95451a315d'
    '4f426eb8a61cedb3dbe72d7c12f7cb70b45fe68ec993012e5f96010cdc1b7cbe'
    '697641efb8ed693ada468c1e344c6e89f3ac71b5de579b9548d7e93640ae8874'
    '0d4f878f6500d3d368aa8feb8759601ccff3043d2f5a5d7e4d9fcc262f1a9ec8'
    'a38a8bb047afab7d0e1118162c91a0a03c4e9920063f8339aa6c1abaeb0a7d25'
    'bce628bd836a15c7b09cb208c3a099824b01119d3c03a4d19b6f6d1dddd4449b'
    'ec13aa8a47c3a5f27fe911e758cd44cdd1ff7993ac8909125bb52895de1063a7'
    'bdbd93ab9c1c49b4d2e226dd2d17a1abd286470f267ff29444bfad91bcfb97e4'
    '766cf4893577770aa648ea04d249845f9b6f8270b2605be024d15f8369699093'
    'e9be42eeda86e40cf7c5e390ffc967fc5616bde3c1d370dda22200';

void main() {
  setUpAll(() async {
    await VaultKeeper.initialize();
  });

  group('MWEB ltcd wire/testdata vectors', () {
    // Regime 1: HogEx - exact round-trip + txid match.
    test('HogEx (flag 0x08, real vin/vout) round-trips and matches txid', () {
      final tx = Tx.fromHex(_hogex);

      expect(tx.inputs.length, 2);
      expect(tx.outputs.length, 2);
      expect(tx.locktime, 0);
      expect(tx.mwebBytes, isNotNull);
      expect(tx.mwebBytes!.length, greaterThan(0));

      // Re-serialized flag bit is MWEB-only (0x08).
      final bytes = tx.toBytes();
      expect(bytes[4], 0x00, reason: 'marker');
      expect(bytes[5], 0x08, reason: 'flag: MWEB bit only');

      // No witness to drop -> exact round-trip.
      expect(tx.toHex(), _hogex);
      // txid is a NO_WITNESS|NO_MWEB serialization hash.
      expect(tx.txid,
          'de22f4de7116b8482a691cc5e552c4212f0ae77e3c8d92c9cb85c29f4dc1f47c');
    });

    // Regime 2: in-block peg-in - witness dropped, round-trip differs, but
    // txid (which excludes witness) still matches.
    test('Peg-in stripped (flag 0x01, witness, no mweb) matches txid', () {
      final tx = Tx.fromHex(_peginBlock);

      expect(tx.inputs.length, 1);
      expect(tx.outputs.length, 1);
      expect(tx.locktime, 2269978);
      // No MWEB extension block in the stripped in-block form.
      expect(tx.mwebBytes, isNull);

      // Witness is discarded on read (pre-existing RawInput design), so the
      // re-serialization differs from the witness-bearing input.
      expect(tx.toHex(), isNot(_peginBlock));

      // txid excludes witness -> still matches.
      expect(tx.txid,
          '8b8343978dbef95d54da796977e9a254565c0dc9ce54917d9111267547fcde03');
    });

    // Regime 3: mempool peg-in - witness + mweb. Witness dropped, mweb tail
    // captured, txid matches the in-block stripped form (excludes BOTH).
    test('Peg-in mempool (flag 0x09, witness + mweb) captures mweb + matches '
        'in-block txid', () {
      final tx = Tx.fromHex(_peginMempool);

      expect(tx.inputs.length, 1);
      expect(tx.outputs.length, 1);
      expect(tx.locktime, 2269978);

      // The ~2KB MWEB tail is captured as an opaque blob.
      expect(tx.mwebBytes, isNotNull);
      expect(tx.mwebBytes!.length, greaterThan(0));

      // Both flag bits (0x01 witness, 0x08 mweb) were present in the source
      // (flag byte at offset 5 of the hex string == "09").
      expect(_peginMempool.substring(10, 12), '09');

      // Witness dropped -> round-trip differs.
      expect(tx.toHex(), isNot(_peginMempool));

      // The 0x09 mempool form and the 0x01 in-block form share a txid because
      // the txid excludes both witness and MWEB data.
      expect(tx.txid,
          '8b8343978dbef95d54da796977e9a254565c0dc9ce54917d9111267547fcde03');
    });

    // Regime 4: pure MWEB-only - exact round-trip, but txid is a kernel hash
    // and is not asserted.
    test('MWEB-only (flag 0x08, no canonical vin/vout) round-trips '
        'unchanged; txid intentionally not asserted', () {
      final tx = Tx.fromHex(_mwebOnly);

      // MWEB-only: no canonical inputs or outputs.
      expect(tx.inputs.length, 0);
      expect(tx.outputs.length, 0);
      expect(tx.locktime, 2269917);

      expect(tx.mwebBytes, isNotNull);
      // Large MWEB blob (whole tx is 2203 bytes; mweb is the bulk of it).
      expect(tx.mwebBytes!.length, greaterThan(2000));

      // Re-serialized flag is MWEB-only (0x08).
      final bytes = tx.toBytes();
      expect(bytes[4], 0x00, reason: 'marker');
      expect(bytes[5], 0x08, reason: 'flag: MWEB bit only');

      // No witness; the opaque MWEB blob is written back unchanged before the
      // locktime.
      expect(tx.toHex(), _mwebOnly);

      // Litecoin Core computes a pure MWEB-only tx's txid as a kernel hash,
      // not a serialization hash. The opaque-blob model does not reproduce
      // kernel hashing (Slice B / mwebd territory), so tx.txid is not
      // asserted here. The ltcd value is
      //   e6f8fdb15b27e603adcfa5aa4107a0e7a7b07e6dc76d2ba95a33710db02a0049
      // (wire/msgtx_test.go).
    });
  });
}
