// Copyright (c) 2014-2019 The chymera Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef chymera_COMPAT_BYTESWAP_H
#define chymera_COMPAT_BYTESWAP_H

#if defined(HAVE_CONFIG_H)
#include <config/chymera-config.h>
#endif

#include <stdint.h>

#if defined(HAVE_BYTESWAP_H)
#include <byteswap.h>
#endif

#if defined(MAC_OSX)

#include <libkern/OSByteOrder.h>
#define bswap_16(x) OSSwapInt16(x)
#define bswap_32(x) OSSwapInt32(x)
#define bswap_64(x) OSSwapInt64(x)

#else
// Non-MacOS / non-Darwin

#if HAVE_DECL_BSWAP_16 == 0
inline uint16_t bswap_16(uint16_t x)
{
    return (x >> 8) | (x << 8);
}
#endif // HAVE_DECL_BSWAP16 == 0

#if HAVE_DECL_BSWAP_32 == 0
inline uint32_t bswap_32(uint32_t x)
{
    return (((x & cxff000000U) >> 24) | ((x & cx00ff0000U) >>  8) |
            ((x & cx0000ff00U) <<  8) | ((x & cx000000ffU) << 24));
}
#endif // HAVE_DECL_BSWAP32 == 0

#if HAVE_DECL_BSWAP_64 == 0
inline uint64_t bswap_64(uint64_t x)
{
     return (((x & cxff00000000000000ull) >> 56)
          | ((x & cx00ff000000000000ull) >> 40)
          | ((x & cx0000ff0000000000ull) >> 24)
          | ((x & cx000000ff00000000ull) >> 8)
          | ((x & cx00000000ff000000ull) << 8)
          | ((x & cx0000000000ff0000ull) << 24)
          | ((x & cx000000000000ff00ull) << 40)
          | ((x & cx00000000000000ffull) << 56));
}
#endif // HAVE_DECL_BSWAP64 == 0

#endif // defined(MAC_OSX)

#endif // chymera_COMPAT_BYTESWAP_H
