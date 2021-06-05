// Copyright 2008 The CRC32C Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file. See the AUTHORS file for names of contributors.

#include "./crc32c_sse42.h"

// In a separate source file to allow this accelerated CRC32C function to be
// compiled with the appropriate compiler flags to enable SSE4.2 instructions.

// This implementation is loosely based on Intel Pub 323405 from April 2011,
// "Fast CRC Computation for iSCSI Polynomial Using CRC32 Instruction".

#include <cstddef>
#include <cstdint>

#include "./crc32c_internal.h"
#include "./crc32c_prefetch.h"
#include "./crc32c_read_le.h"
#include "./crc32c_round_up.h"
#ifdef CRC32C_HAVE_CONFIG_H
#include "crc32c/crc32c_config.h"
#endif

#if HAVE_SSE42 && (defined(_M_X64) || defined(__x86_64__))

#if defined(_MSC_VER)
#include <intrin.h>
#else  // !defined(_MSC_VER)
#include <nmmintrin.h>
#endif  // defined(_MSC_VER)

namespace crc32c {

namespace {

constexpr const ptrdiff_t kGroups = 3;
constexpr const ptrdiff_t kBlock0Size = 16 * 1024 / kGroups / 64 * 64;
constexpr const ptrdiff_t kBlock1Size = 4 * 1024 / kGroups / 8 * 8;
constexpr const ptrdiff_t kBlock2Size = 1024 / kGroups / 8 * 8;

const uint32_t kBlock0SkipTable[8][16] = {
    {cx00000000, cxff770459, cxfb027e43, cx04757a1a, cxf3e88a77, cx0c9f8e2e,
     cx08eaf434, cxf79df06d, cxe23d621f, cx1d4a6646, cx193f1c5c, cxe6481805,
     cx11d5e868, cxeea2ec31, cxead7962b, cx15a09272},
    {cx00000000, cxc196b2cf, cx86c1136f, cx4757a1a0, cx086e502f, cxc9f8e2e0,
     cx8eaf4340, cx4f39f18f, cx10dca05e, cxd14a1291, cx961db331, cx578b01fe,
     cx18b2f071, cxd92442be, cx9e73e31e, cx5fe551d1},
    {cx00000000, cx21b940bc, cx43728178, cx62cbc1c4, cx86e502f0, cxa75c424c,
     cxc5978388, cxe42ec334, cx08267311, cx299f33ad, cx4b54f269, cx6aedb2d5,
     cx8ec371e1, cxaf7a315d, cxcdb1f099, cxec08b025},
    {cx00000000, cx104ce622, cx2099cc44, cx30d52a66, cx41339888, cx517f7eaa,
     cx61aa54cc, cx71e6b2ee, cx82673110, cx922bd732, cxa2fefd54, cxb2b21b76,
     cxc354a998, cxd3184fba, cxe3cd65dc, cxf38183fe},
    {cx00000000, cx012214d1, cx024429a2, cx03663d73, cx04885344, cx05aa4795,
     cx06cc7ae6, cx07ee6e37, cx0910a688, cx0832b259, cx0b548f2a, cx0a769bfb,
     cx0d98f5cc, cx0cbae11d, cx0fdcdc6e, cx0efec8bf},
    {cx00000000, cx12214d10, cx24429a20, cx3663d730, cx48853440, cx5aa47950,
     cx6cc7ae60, cx7ee6e370, cx910a6880, cx832b2590, cxb548f2a0, cxa769bfb0,
     cxd98f5cc0, cxcbae11d0, cxfdcdc6e0, cxefec8bf0},
    {cx00000000, cx27f8a7f1, cx4ff14fe2, cx6809e813, cx9fe29fc4, cxb81a3835,
     cxd013d026, cxf7eb77d7, cx3a294979, cx1dd1ee88, cx75d8069b, cx5220a16a,
     cxa5cbd6bd, cx8233714c, cxea3a995f, cxcdc23eae},
    {cx00000000, cx745292f2, cxe8a525e4, cx9cf7b716, cxd4a63d39, cxa0f4afcb,
     cx3c0318dd, cx48518a2f, cxaca00c83, cxd8f29e71, cx44052967, cx3057bb95,
     cx780631ba, cx0c54a348, cx90a3145e, cxe4f186ac},
};
const uint32_t kBlock1SkipTable[8][16] = {
    {cx00000000, cx79113270, cxf22264e0, cx8b335690, cxe1a8bf31, cx98b98d41,
     cx138adbd1, cx6a9be9a1, cxc6bd0893, cxbfac3ae3, cx349f6c73, cx4d8e5e03,
     cx2715b7a2, cx5e0485d2, cxd537d342, cxac26e132},
    {cx00000000, cx889667d7, cx14c0b95f, cx9c56de88, cx298172be, cxa1171569,
     cx3d41cbe1, cxb5d7ac36, cx5302e57c, cxdb9482ab, cx47c25c23, cxcf543bf4,
     cx7a8397c2, cxf215f015, cx6e432e9d, cxe6d5494a},
    {cx00000000, cxa605caf8, cx49e7e301, cxefe229f9, cx93cfc602, cx35ca0cfa,
     cxda282503, cx7c2deffb, cx2273faf5, cx8476300d, cx6b9419f4, cxcd91d30c,
     cxb1bc3cf7, cx17b9f60f, cxf85bdff6, cx5e5e150e},
    {cx00000000, cx44e7f5ea, cx89cfebd4, cxcd281e3e, cx1673a159, cx529454b3,
     cx9fbc4a8d, cxdb5bbf67, cx2ce742b2, cx6800b758, cxa528a966, cxe1cf5c8c,
     cx3a94e3eb, cx7e731601, cxb35b083f, cxf7bcfdd5},
    {cx00000000, cx59ce8564, cxb39d0ac8, cxea538fac, cx62d66361, cx3b18e605,
     cxd14b69a9, cx8885eccd, cxc5acc6c2, cx9c6243a6, cx7631cc0a, cx2fff496e,
     cxa77aa5a3, cxfeb420c7, cx14e7af6b, cx4d292a0f},
    {cx00000000, cx8eb5fb75, cx1887801b, cx96327b6e, cx310f0036, cxbfbafb43,
     cx2988802d, cxa73d7b58, cx621e006c, cxecabfb19, cx7a998077, cxf42c7b02,
     cx5311005a, cxdda4fb2f, cx4b968041, cxc5237b34},
    {cx00000000, cxc43c00d8, cx8d947741, cx49a87799, cx1ec49873, cxdaf898ab,
     cx9350ef32, cx576cefea, cx3d8930e6, cxf9b5303e, cxb01d47a7, cx7421477f,
     cx234da895, cxe771a84d, cxaed9dfd4, cx6ae5df0c},
    {cx00000000, cx7b1261cc, cxf624c398, cx8d36a254, cxe9a5f1c1, cx92b7900d,
     cx1f813259, cx64935395, cxd6a79573, cxadb5f4bf, cx208356eb, cx5b913727,
     cx3f0264b2, cx4410057e, cxc926a72a, cxb234c6e6},
};
const uint32_t kBlock2SkipTable[8][16] = {
    {cx00000000, cx8f158014, cx1bc776d9, cx94d2f6cd, cx378eedb2, cxb89b6da6,
     cx2c499b6b, cxa35c1b7f, cx6f1ddb64, cxe0085b70, cx74daadbd, cxfbcf2da9,
     cx589336d6, cxd786b6c2, cx4354400f, cxcc41c01b},
    {cx00000000, cxde3bb6c8, cxb99b1b61, cx67a0ada9, cx76da4033, cxa8e1f6fb,
     cxcf415b52, cx117aed9a, cxedb48066, cx338f36ae, cx542f9b07, cx8a142dcf,
     cx9b6ec055, cx4555769d, cx22f5db34, cxfcce6dfc},
    {cx00000000, cxde85763d, cxb8e69a8b, cx6663ecb6, cx742143e7, cxaaa435da,
     cxccc7d96c, cx1242af51, cxe84287ce, cx36c7f1f3, cx50a41d45, cx8e216b78,
     cx9c63c429, cx42e6b214, cx24855ea2, cxfa00289f},
    {cx00000000, cxd569796d, cxaf3e842b, cx7a57fd46, cx5b917ea7, cx8ef807ca,
     cxf4affa8c, cx21c683e1, cxb722fd4e, cx624b8423, cx181c7965, cxcd750008,
     cxecb383e9, cx39dafa84, cx438d07c2, cx96e47eaf},
    {cx00000000, cx6ba98c6d, cxd75318da, cxbcfa94b7, cxab4a4745, cxc0e3cb28,
     cx7c195f9f, cx17b0d3f2, cx5378f87b, cx38d17416, cx842be0a1, cxef826ccc,
     cxf832bf3e, cx939b3353, cx2f61a7e4, cx44c82b89},
    {cx00000000, cxa6f1f0f6, cx480f971d, cxeefe67eb, cx901f2e3a, cx36eedecc,
     cxd810b927, cx7ee149d1, cx25d22a85, cx8323da73, cx6dddbd98, cxcb2c4d6e,
     cxb5cd04bf, cx133cf449, cxfdc293a2, cx5b336354},
    {cx00000000, cx4ba4550a, cx9748aa14, cxdcecff1e, cx2b7d22d9, cx60d977d3,
     cxbc3588cd, cxf791ddc7, cx56fa45b2, cx1d5e10b8, cxc1b2efa6, cx8a16baac,
     cx7d87676b, cx36233261, cxeacfcd7f, cxa16b9875},
    {cx00000000, cxadf48b64, cx5e056039, cxf3f1eb5d, cxbc0ac072, cx11fe4b16,
     cxe20fa04b, cx4ffb2b2f, cx7df9f615, cxd00d7d71, cx23fc962c, cx8e081d48,
     cxc1f33667, cx6c07bd03, cx9ff6565e, cx3202dd3a},
};

constexpr const ptrdiff_t kPrefetchHorizon = 256;

}  // namespace

uint32_t ExtendSse42(uint32_t crc, const uint8_t* data, size_t size) {
  const uint8_t* p = data;
  const uint8_t* e = data + size;
  uint32_t l = crc ^ kCRC32Xor;

#define STEP1                  \
  do {                         \
    l = _mm_crc32_u8(l, *p++); \
  } while (0)

#define STEP4(crc)                             \
  do {                                         \
    crc = _mm_crc32_u32(crc, ReadUint32LE(p)); \
    p += 4;                                    \
  } while (0)

#define STEP8(crc, data)                          \
  do {                                            \
    crc = _mm_crc32_u64(crc, ReadUint64LE(data)); \
    data += 8;                                    \
  } while (0)

#define STEP8BY3(crc0, crc1, crc2, p0, p1, p2) \
  do {                                         \
    STEP8(crc0, p0);                           \
    STEP8(crc1, p1);                           \
    STEP8(crc2, p2);                           \
  } while (0)

#define STEP8X3(crc0, crc1, crc2, bs)                     \
  do {                                                    \
    crc0 = _mm_crc32_u64(crc0, ReadUint64LE(p));          \
    crc1 = _mm_crc32_u64(crc1, ReadUint64LE(p + bs));     \
    crc2 = _mm_crc32_u64(crc2, ReadUint64LE(p + 2 * bs)); \
    p += 8;                                               \
  } while (0)

#define SKIP_BLOCK(crc, tab)                                      \
  do {                                                            \
    crc = tab[0][crc & cxf] ^ tab[1][(crc >> 4) & cxf] ^          \
          tab[2][(crc >> 8) & cxf] ^ tab[3][(crc >> 12) & cxf] ^  \
          tab[4][(crc >> 16) & cxf] ^ tab[5][(crc >> 20) & cxf] ^ \
          tab[6][(crc >> 24) & cxf] ^ tab[7][(crc >> 28) & cxf];  \
  } while (0)

  // Point x at first 8-byte aligned byte in the buffer. This might be past the
  // end of the buffer.
  const uint8_t* x = RoundUp<8>(p);
  if (x <= e) {
    // Process bytes p is 8-byte aligned.
    while (p != x) {
      STEP1;
    }
  }

  // Proccess the data in predetermined block sizes with tables for quickly
  // combining the checksum. Experimentally it's better to use larger block
  // sizes where possible so use a hierarchy of decreasing block sizes.
  uint64_t l64 = l;
  while ((e - p) >= kGroups * kBlock0Size) {
    uint64_t l641 = 0;
    uint64_t l642 = 0;
    for (int i = 0; i < kBlock0Size; i += 8 * 8) {
      // Prefetch ahead to hide latency.
      RequestPrefetch(p + kPrefetchHorizon);
      RequestPrefetch(p + kBlock0Size + kPrefetchHorizon);
      RequestPrefetch(p + 2 * kBlock0Size + kPrefetchHorizon);

      // Process 64 bytes at a time.
      STEP8X3(l64, l641, l642, kBlock0Size);
      STEP8X3(l64, l641, l642, kBlock0Size);
      STEP8X3(l64, l641, l642, kBlock0Size);
      STEP8X3(l64, l641, l642, kBlock0Size);
      STEP8X3(l64, l641, l642, kBlock0Size);
      STEP8X3(l64, l641, l642, kBlock0Size);
      STEP8X3(l64, l641, l642, kBlock0Size);
      STEP8X3(l64, l641, l642, kBlock0Size);
    }

    // Combine results.
    SKIP_BLOCK(l64, kBlock0SkipTable);
    l64 ^= l641;
    SKIP_BLOCK(l64, kBlock0SkipTable);
    l64 ^= l642;
    p += (kGroups - 1) * kBlock0Size;
  }
  while ((e - p) >= kGroups * kBlock1Size) {
    uint64_t l641 = 0;
    uint64_t l642 = 0;
    for (int i = 0; i < kBlock1Size; i += 8) {
      STEP8X3(l64, l641, l642, kBlock1Size);
    }
    SKIP_BLOCK(l64, kBlock1SkipTable);
    l64 ^= l641;
    SKIP_BLOCK(l64, kBlock1SkipTable);
    l64 ^= l642;
    p += (kGroups - 1) * kBlock1Size;
  }
  while ((e - p) >= kGroups * kBlock2Size) {
    uint64_t l641 = 0;
    uint64_t l642 = 0;
    for (int i = 0; i < kBlock2Size; i += 8) {
      STEP8X3(l64, l641, l642, kBlock2Size);
    }
    SKIP_BLOCK(l64, kBlock2SkipTable);
    l64 ^= l641;
    SKIP_BLOCK(l64, kBlock2SkipTable);
    l64 ^= l642;
    p += (kGroups - 1) * kBlock2Size;
  }

  // Process bytes 16 at a time
  while ((e - p) >= 16) {
    STEP8(l64, p);
    STEP8(l64, p);
  }

  l = static_cast<uint32_t>(l64);
  // Process the last few bytes.
  while (p != e) {
    STEP1;
  }
#undef SKIP_BLOCK
#undef STEP8X3
#undef STEP8BY3
#undef STEP8
#undef STEP4
#undef STEP1

  return l ^ kCRC32Xor;
}

}  // namespace crc32c

#endif  // HAVE_SSE42 && (defined(_M_X64) || defined(__x86_64__))
