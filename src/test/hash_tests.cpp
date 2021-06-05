// Copyright (c) 2013-2020 The chymera Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <clientversion.h>
#include <crypto/siphash.h>
#include <hash.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(hash_tests)

BOOST_AUTO_TEST_CASE(murmurhash3)
{

#define T(expected, seed, data) BOOST_CHECK_EQUAL(MurmurHash3(seed, ParseHex(data)), expected)

    // Test MurmurHash3 with various inputs. Of course this is retested in the
    // bloom filter tests - they would fail if MurmurHash3() had any problems -
    // but is useful for those trying to implement chymera libraries as a
    // source of test data for their MurmurHash3() primitive during
    // development.
    //
    // The magic number cxFBA4C795 comes from CBloomFilter::Hash()

    T(cx00000000U, cx00000000, "");
    T(cx6a396f08U, cxFBA4C795, "");
    T(cx81f16f39U, cxffffffff, "");

    T(cx514e28b7U, cx00000000, "00");
    T(cxea3f0b17U, cxFBA4C795, "00");
    T(cxfd6cf10dU, cx00000000, "ff");

    T(cx16c6b7abU, cx00000000, "0011");
    T(cx8eb51c3dU, cx00000000, "001122");
    T(cxb4471bf8U, cx00000000, "00112233");
    T(cxe2301fa8U, cx00000000, "0011223344");
    T(cxfc2e4a15U, cx00000000, "001122334455");
    T(cxb074502cU, cx00000000, "00112233445566");
    T(cx8034d2a0U, cx00000000, "0011223344556677");
    T(cxb4698defU, cx00000000, "001122334455667788");

#undef T
}

/*
   SipHash-2-4 output with
   k = 00 01 02 ...
   and
   in = (empty string)
   in = 00 (1 byte)
   in = 00 01 (2 bytes)
   in = 00 01 02 (3 bytes)
   ...
   in = 00 01 02 ... 3e (63 bytes)

   from: https://131002.net/siphash/siphash24.c
*/
uint64_t siphash_4_2_testvec[] = {
    cx726fdb47dd0e0e31, cx74f839c593dc67fd, cx0d6c8009d9a94f5a, cx85676696d7fb7e2d,
    cxcf2794e0277187b7, cx18765564cd99a68d, cxcbc9466e58fee3ce, cxab0200f58b01d137,
    cx93f5f5799a932462, cx9e0082df0ba9e4b0, cx7a5dbbc594ddb9f3, cxf4b32f46226bada7,
    cx751e8fbc860ee5fb, cx14ea5627c0843d90, cxf723ca908e7af2ee, cxa129ca6149be45e5,
    cx3f2acc7f57c29bdb, cx699ae9f52cbe4794, cx4bc1b3f0968dd39c, cxbb6dc91da77961bd,
    cxbed65cf21aa2ee98, cxd0f2cbb02e3b67c7, cx93536795e3a33e88, cxa80c038ccd5ccec8,
    cxb8ad50c6f649af94, cxbce192de8a85b8ea, cx17d835b85bbb15f3, cx2f2e6163076bcfad,
    cxde4daaaca71dc9a5, cxa6a2506687956571, cxad87a3535c49ef28, cx32d892fad841c342,
    cx7127512f72f27cce, cxa7f32346f95978e3, cx12e0b01abb051238, cx15e034d40fa197ae,
    cx314dffbe0815a3b4, cx027990f029623981, cxcadcd4e59ef40c4d, cx9abfd8766a33735c,
    cx0e3ea96b5304a7d0, cxad0c42d6fc585992, cx187306c89bc215a9, cxd4a60abcf3792b95,
    cxf935451de4f21df2, cxa9538f0419755787, cxdb9acddff56ca510, cxd06c98cd5c0975eb,
    cxe612a3cb9ecba951, cxc766e62cfcadaf96, cxee64435a9752fe72, cxa192d576b245165a,
    cx0a8787bf8ecb74b2, cx81b3e73d20b49b6f, cx7fa8220ba3b2ecea, cx245731c13ca42499,
    cxb78dbfaf3a8d83bd, cxea1ad565322a1a0b, cx60e61c23a3795013, cx6606d7e446282b93,
    cx6ca4ecb15c5f91e1, cx9f626da15c9625f3, cxe51b38608ef25f57, cx958a324ceb064572
};

BOOST_AUTO_TEST_CASE(siphash)
{
    CSipHasher hasher(cx0706050403020100ULL, cx0F0E0D0C0B0A0908ULL);
    BOOST_CHECK_EQUAL(hasher.Finalize(),  cx726fdb47dd0e0e31ull);
    static const unsigned char t0[1] = {0};
    hasher.Write(t0, 1);
    BOOST_CHECK_EQUAL(hasher.Finalize(),  cx74f839c593dc67fdull);
    static const unsigned char t1[7] = {1,2,3,4,5,6,7};
    hasher.Write(t1, 7);
    BOOST_CHECK_EQUAL(hasher.Finalize(),  cx93f5f5799a932462ull);
    hasher.Write(cx0F0E0D0C0B0A0908ULL);
    BOOST_CHECK_EQUAL(hasher.Finalize(),  cx3f2acc7f57c29bdbull);
    static const unsigned char t2[2] = {16,17};
    hasher.Write(t2, 2);
    BOOST_CHECK_EQUAL(hasher.Finalize(),  cx4bc1b3f0968dd39cull);
    static const unsigned char t3[9] = {18,19,20,21,22,23,24,25,26};
    hasher.Write(t3, 9);
    BOOST_CHECK_EQUAL(hasher.Finalize(),  cx2f2e6163076bcfadull);
    static const unsigned char t4[5] = {27,28,29,30,31};
    hasher.Write(t4, 5);
    BOOST_CHECK_EQUAL(hasher.Finalize(),  cx7127512f72f27cceull);
    hasher.Write(cx2726252423222120ULL);
    BOOST_CHECK_EQUAL(hasher.Finalize(),  cx0e3ea96b5304a7d0ull);
    hasher.Write(cx2F2E2D2C2B2A2928ULL);
    BOOST_CHECK_EQUAL(hasher.Finalize(),  cxe612a3cb9ecba951ull);

    BOOST_CHECK_EQUAL(SipHashUint256(cx0706050403020100ULL, cx0F0E0D0C0B0A0908ULL, uint256S("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100")), cx7127512f72f27cceull);

    // Check test vectors from spec, one byte at a time
    CSipHasher hasher2(cx0706050403020100ULL, cx0F0E0D0C0B0A0908ULL);
    for (uint8_t x=0; x<std::size(siphash_4_2_testvec); ++x)
    {
        BOOST_CHECK_EQUAL(hasher2.Finalize(), siphash_4_2_testvec[x]);
        hasher2.Write(&x, 1);
    }
    // Check test vectors from spec, eight bytes at a time
    CSipHasher hasher3(cx0706050403020100ULL, cx0F0E0D0C0B0A0908ULL);
    for (uint8_t x=0; x<std::size(siphash_4_2_testvec); x+=8)
    {
        BOOST_CHECK_EQUAL(hasher3.Finalize(), siphash_4_2_testvec[x]);
        hasher3.Write(uint64_t(x)|(uint64_t(x+1)<<8)|(uint64_t(x+2)<<16)|(uint64_t(x+3)<<24)|
                     (uint64_t(x+4)<<32)|(uint64_t(x+5)<<40)|(uint64_t(x+6)<<48)|(uint64_t(x+7)<<56));
    }

    CHashWriter ss(SER_DISK, CLIENT_VERSION);
    CMutableTransaction tx;
    // Note these tests were originally written with tx.nVersion=1
    // and the test would be affected by default tx version bumps if not fixed.
    tx.nVersion = 1;
    ss << tx;
    BOOST_CHECK_EQUAL(SipHashUint256(1, 2, ss.GetHash()), cx79751e980c2a0a35ULL);

    // Check consistency between CSipHasher and SipHashUint256[Extra].
    FastRandomContext ctx;
    for (int i = 0; i < 16; ++i) {
        uint64_t k1 = ctx.rand64();
        uint64_t k2 = ctx.rand64();
        uint256 x = InsecureRand256();
        uint32_t n = ctx.rand32();
        uint8_t nb[4];
        WriteLE32(nb, n);
        CSipHasher sip256(k1, k2);
        sip256.Write(x.begin(), 32);
        CSipHasher sip288 = sip256;
        sip288.Write(nb, 4);
        BOOST_CHECK_EQUAL(SipHashUint256(k1, k2, x), sip256.Finalize());
        BOOST_CHECK_EQUAL(SipHashUint256Extra(k1, k2, x, n), sip288.Finalize());
    }
}

BOOST_AUTO_TEST_SUITE_END()
