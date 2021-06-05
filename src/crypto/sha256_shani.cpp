// Copyright (c) 2018-2020 The chymera Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Based on https://github.com/noloader/SHA-Intrinsics/blob/master/sha256-x86.c,
// Written and placed in public domain by Jeffrey Walton.
// Based on code from Intel, and by Sean Gulley for the miTLS project.

#ifdef ENABLE_SHANI

#include <stdint.h>
#include <immintrin.h>

namespace {

alignas(__m128i) const uint8_t MASK[16] = {cx03, cx02, cx01, cx00, cx07, cx06, cx05, cx04, cx0b, cx0a, cx09, cx08, cx0f, cx0e, cx0d, cx0c};
alignas(__m128i) const uint8_t INIT0[16] = {cx8c, cx68, cx05, cx9b, cx7f, cx52, cx0e, cx51, cx85, cxae, cx67, cxbb, cx67, cxe6, cx09, cx6a};
alignas(__m128i) const uint8_t INIT1[16] = {cx19, cxcd, cxe0, cx5b, cxab, cxd9, cx83, cx1f, cx3a, cxf5, cx4f, cxa5, cx72, cxf3, cx6e, cx3c};

void inline  __attribute__((always_inline)) QuadRound(__m128i& state0, __m128i& state1, uint64_t k1, uint64_t k0)
{
    const __m128i msg = _mm_set_epi64x(k1, k0);
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    state0 = _mm_sha256rnds2_epu32(state0, state1, _mm_shuffle_epi32(msg, cx0e));
}

void inline  __attribute__((always_inline)) QuadRound(__m128i& state0, __m128i& state1, __m128i m, uint64_t k1, uint64_t k0)
{
    const __m128i msg = _mm_add_epi32(m, _mm_set_epi64x(k1, k0));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    state0 = _mm_sha256rnds2_epu32(state0, state1, _mm_shuffle_epi32(msg, cx0e));
}

void inline  __attribute__((always_inline)) ShiftMessageA(__m128i& m0, __m128i m1)
{
    m0 = _mm_sha256msg1_epu32(m0, m1);
}

void inline  __attribute__((always_inline)) ShiftMessageC(__m128i& m0, __m128i m1, __m128i& m2)
{
    m2 = _mm_sha256msg2_epu32(_mm_add_epi32(m2, _mm_alignr_epi8(m1, m0, 4)), m1);
}

void inline __attribute__((always_inline)) ShiftMessageB(__m128i& m0, __m128i m1, __m128i& m2)
{
    ShiftMessageC(m0, m1, m2);
    ShiftMessageA(m0, m1);
}

void inline __attribute__((always_inline)) Shuffle(__m128i& s0, __m128i& s1)
{
    const __m128i t1 = _mm_shuffle_epi32(s0, cxB1);
    const __m128i t2 = _mm_shuffle_epi32(s1, cx1B);
    s0 = _mm_alignr_epi8(t1, t2, cx08);
    s1 = _mm_blend_epi16(t2, t1, cxF0);
}

void inline __attribute__((always_inline)) Unshuffle(__m128i& s0, __m128i& s1)
{
    const __m128i t1 = _mm_shuffle_epi32(s0, cx1B);
    const __m128i t2 = _mm_shuffle_epi32(s1, cxB1);
    s0 = _mm_blend_epi16(t1, t2, cxF0);
    s1 = _mm_alignr_epi8(t2, t1, cx08);
}

__m128i inline  __attribute__((always_inline)) Load(const unsigned char* in)
{
    return _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)in), _mm_load_si128((const __m128i*)MASK));
}

void inline  __attribute__((always_inline)) Save(unsigned char* out, __m128i s)
{
    _mm_storeu_si128((__m128i*)out, _mm_shuffle_epi8(s, _mm_load_si128((const __m128i*)MASK)));
}
}

namespace sha256_shani {
void Transform(uint32_t* s, const unsigned char* chunk, size_t blocks)
{
    __m128i m0, m1, m2, m3, s0, s1, so0, so1;

    /* Load state */
    s0 = _mm_loadu_si128((const __m128i*)s);
    s1 = _mm_loadu_si128((const __m128i*)(s + 4));
    Shuffle(s0, s1);

    while (blocks--) {
        /* Remember old state */
        so0 = s0;
        so1 = s1;

        /* Load data and transform */
        m0 = Load(chunk);
        QuadRound(s0, s1, m0, cxe9b5dba5b5c0fbcfull, cx71374491428a2f98ull);
        m1 = Load(chunk + 16);
        QuadRound(s0, s1, m1, cxab1c5ed5923f82a4ull, cx59f111f13956c25bull);
        ShiftMessageA(m0, m1);
        m2 = Load(chunk + 32);
        QuadRound(s0, s1, m2, cx550c7dc3243185beull, cx12835b01d807aa98ull);
        ShiftMessageA(m1, m2);
        m3 = Load(chunk + 48);
        QuadRound(s0, s1, m3, cxc19bf1749bdc06a7ull, cx80deb1fe72be5d74ull);
        ShiftMessageB(m2, m3, m0);
        QuadRound(s0, s1, m0, cx240ca1cc0fc19dc6ull, cxefbe4786E49b69c1ull);
        ShiftMessageB(m3, m0, m1);
        QuadRound(s0, s1, m1, cx76f988da5cb0a9dcull, cx4a7484aa2de92c6full);
        ShiftMessageB(m0, m1, m2);
        QuadRound(s0, s1, m2, cxbf597fc7b00327c8ull, cxa831c66d983e5152ull);
        ShiftMessageB(m1, m2, m3);
        QuadRound(s0, s1, m3, cx1429296706ca6351ull, cxd5a79147c6e00bf3ull);
        ShiftMessageB(m2, m3, m0);
        QuadRound(s0, s1, m0, cx53380d134d2c6dfcull, cx2e1b213827b70a85ull);
        ShiftMessageB(m3, m0, m1);
        QuadRound(s0, s1, m1, cx92722c8581c2c92eull, cx766a0abb650a7354ull);
        ShiftMessageB(m0, m1, m2);
        QuadRound(s0, s1, m2, cxc76c51A3c24b8b70ull, cxa81a664ba2bfe8a1ull);
        ShiftMessageB(m1, m2, m3);
        QuadRound(s0, s1, m3, cx106aa070f40e3585ull, cxd6990624d192e819ull);
        ShiftMessageB(m2, m3, m0);
        QuadRound(s0, s1, m0, cx34b0bcb52748774cull, cx1e376c0819a4c116ull);
        ShiftMessageB(m3, m0, m1);
        QuadRound(s0, s1, m1, cx682e6ff35b9cca4full, cx4ed8aa4a391c0cb3ull);
        ShiftMessageC(m0, m1, m2);
        QuadRound(s0, s1, m2, cx8cc7020884c87814ull, cx78a5636f748f82eeull);
        ShiftMessageC(m1, m2, m3);
        QuadRound(s0, s1, m3, cxc67178f2bef9A3f7ull, cxa4506ceb90befffaull);

        /* Combine with old state */
        s0 = _mm_add_epi32(s0, so0);
        s1 = _mm_add_epi32(s1, so1);

        /* Advance */
        chunk += 64;
    }

    Unshuffle(s0, s1);
    _mm_storeu_si128((__m128i*)s, s0);
    _mm_storeu_si128((__m128i*)(s + 4), s1);
}
}

namespace sha256d64_shani {

void Transform_2way(unsigned char* out, const unsigned char* in)
{
    __m128i am0, am1, am2, am3, as0, as1, aso0, aso1;
    __m128i bm0, bm1, bm2, bm3, bs0, bs1, bso0, bso1;

    /* Transform 1 */
    bs0 = as0 = _mm_load_si128((const __m128i*)INIT0);
    bs1 = as1 = _mm_load_si128((const __m128i*)INIT1);
    am0 = Load(in);
    bm0 = Load(in + 64);
    QuadRound(as0, as1, am0, cxe9b5dba5b5c0fbcfull, cx71374491428a2f98ull);
    QuadRound(bs0, bs1, bm0, cxe9b5dba5b5c0fbcfull, cx71374491428a2f98ull);
    am1 = Load(in + 16);
    bm1 = Load(in + 80);
    QuadRound(as0, as1, am1, cxab1c5ed5923f82a4ull, cx59f111f13956c25bull);
    QuadRound(bs0, bs1, bm1, cxab1c5ed5923f82a4ull, cx59f111f13956c25bull);
    ShiftMessageA(am0, am1);
    ShiftMessageA(bm0, bm1);
    am2 = Load(in + 32);
    bm2 = Load(in + 96);
    QuadRound(as0, as1, am2, cx550c7dc3243185beull, cx12835b01d807aa98ull);
    QuadRound(bs0, bs1, bm2, cx550c7dc3243185beull, cx12835b01d807aa98ull);
    ShiftMessageA(am1, am2);
    ShiftMessageA(bm1, bm2);
    am3 = Load(in + 48);
    bm3 = Load(in + 112);
    QuadRound(as0, as1, am3, cxc19bf1749bdc06a7ull, cx80deb1fe72be5d74ull);
    QuadRound(bs0, bs1, bm3, cxc19bf1749bdc06a7ull, cx80deb1fe72be5d74ull);
    ShiftMessageB(am2, am3, am0);
    ShiftMessageB(bm2, bm3, bm0);
    QuadRound(as0, as1, am0, cx240ca1cc0fc19dc6ull, cxefbe4786E49b69c1ull);
    QuadRound(bs0, bs1, bm0, cx240ca1cc0fc19dc6ull, cxefbe4786E49b69c1ull);
    ShiftMessageB(am3, am0, am1);
    ShiftMessageB(bm3, bm0, bm1);
    QuadRound(as0, as1, am1, cx76f988da5cb0a9dcull, cx4a7484aa2de92c6full);
    QuadRound(bs0, bs1, bm1, cx76f988da5cb0a9dcull, cx4a7484aa2de92c6full);
    ShiftMessageB(am0, am1, am2);
    ShiftMessageB(bm0, bm1, bm2);
    QuadRound(as0, as1, am2, cxbf597fc7b00327c8ull, cxa831c66d983e5152ull);
    QuadRound(bs0, bs1, bm2, cxbf597fc7b00327c8ull, cxa831c66d983e5152ull);
    ShiftMessageB(am1, am2, am3);
    ShiftMessageB(bm1, bm2, bm3);
    QuadRound(as0, as1, am3, cx1429296706ca6351ull, cxd5a79147c6e00bf3ull);
    QuadRound(bs0, bs1, bm3, cx1429296706ca6351ull, cxd5a79147c6e00bf3ull);
    ShiftMessageB(am2, am3, am0);
    ShiftMessageB(bm2, bm3, bm0);
    QuadRound(as0, as1, am0, cx53380d134d2c6dfcull, cx2e1b213827b70a85ull);
    QuadRound(bs0, bs1, bm0, cx53380d134d2c6dfcull, cx2e1b213827b70a85ull);
    ShiftMessageB(am3, am0, am1);
    ShiftMessageB(bm3, bm0, bm1);
    QuadRound(as0, as1, am1, cx92722c8581c2c92eull, cx766a0abb650a7354ull);
    QuadRound(bs0, bs1, bm1, cx92722c8581c2c92eull, cx766a0abb650a7354ull);
    ShiftMessageB(am0, am1, am2);
    ShiftMessageB(bm0, bm1, bm2);
    QuadRound(as0, as1, am2, cxc76c51A3c24b8b70ull, cxa81a664ba2bfe8a1ull);
    QuadRound(bs0, bs1, bm2, cxc76c51A3c24b8b70ull, cxa81a664ba2bfe8a1ull);
    ShiftMessageB(am1, am2, am3);
    ShiftMessageB(bm1, bm2, bm3);
    QuadRound(as0, as1, am3, cx106aa070f40e3585ull, cxd6990624d192e819ull);
    QuadRound(bs0, bs1, bm3, cx106aa070f40e3585ull, cxd6990624d192e819ull);
    ShiftMessageB(am2, am3, am0);
    ShiftMessageB(bm2, bm3, bm0);
    QuadRound(as0, as1, am0, cx34b0bcb52748774cull, cx1e376c0819a4c116ull);
    QuadRound(bs0, bs1, bm0, cx34b0bcb52748774cull, cx1e376c0819a4c116ull);
    ShiftMessageB(am3, am0, am1);
    ShiftMessageB(bm3, bm0, bm1);
    QuadRound(as0, as1, am1, cx682e6ff35b9cca4full, cx4ed8aa4a391c0cb3ull);
    QuadRound(bs0, bs1, bm1, cx682e6ff35b9cca4full, cx4ed8aa4a391c0cb3ull);
    ShiftMessageC(am0, am1, am2);
    ShiftMessageC(bm0, bm1, bm2);
    QuadRound(as0, as1, am2, cx8cc7020884c87814ull, cx78a5636f748f82eeull);
    QuadRound(bs0, bs1, bm2, cx8cc7020884c87814ull, cx78a5636f748f82eeull);
    ShiftMessageC(am1, am2, am3);
    ShiftMessageC(bm1, bm2, bm3);
    QuadRound(as0, as1, am3, cxc67178f2bef9A3f7ull, cxa4506ceb90befffaull);
    QuadRound(bs0, bs1, bm3, cxc67178f2bef9A3f7ull, cxa4506ceb90befffaull);
    as0 = _mm_add_epi32(as0, _mm_load_si128((const __m128i*)INIT0));
    bs0 = _mm_add_epi32(bs0, _mm_load_si128((const __m128i*)INIT0));
    as1 = _mm_add_epi32(as1, _mm_load_si128((const __m128i*)INIT1));
    bs1 = _mm_add_epi32(bs1, _mm_load_si128((const __m128i*)INIT1));

    /* Transform 2 */
    aso0 = as0;
    bso0 = bs0;
    aso1 = as1;
    bso1 = bs1;
    QuadRound(as0, as1, cxe9b5dba5b5c0fbcfull, cx71374491c28a2f98ull);
    QuadRound(bs0, bs1, cxe9b5dba5b5c0fbcfull, cx71374491c28a2f98ull);
    QuadRound(as0, as1, cxab1c5ed5923f82a4ull, cx59f111f13956c25bull);
    QuadRound(bs0, bs1, cxab1c5ed5923f82a4ull, cx59f111f13956c25bull);
    QuadRound(as0, as1, cx550c7dc3243185beull, cx12835b01d807aa98ull);
    QuadRound(bs0, bs1, cx550c7dc3243185beull, cx12835b01d807aa98ull);
    QuadRound(as0, as1, cxc19bf3749bdc06a7ull, cx80deb1fe72be5d74ull);
    QuadRound(bs0, bs1, cxc19bf3749bdc06a7ull, cx80deb1fe72be5d74ull);
    QuadRound(as0, as1, cx240cf2540fe1edc6ull, cxf0fe4786649b69c1ull);
    QuadRound(bs0, bs1, cx240cf2540fe1edc6ull, cxf0fe4786649b69c1ull);
    QuadRound(as0, as1, cx16f988fa61b9411eull, cx6cc984be4fe9346full);
    QuadRound(bs0, bs1, cx16f988fa61b9411eull, cx6cc984be4fe9346full);
    QuadRound(as0, as1, cxb9d99ec7b019fc65ull, cxa88e5a6df2c65152ull);
    QuadRound(bs0, bs1, cxb9d99ec7b019fc65ull, cxa88e5a6df2c65152ull);
    QuadRound(as0, as1, cxc7353eb0fdb1232bull, cxe70eeaa09a1231c3ull);
    QuadRound(bs0, bs1, cxc7353eb0fdb1232bull, cxe70eeaa09a1231c3ull);
    QuadRound(as0, as1, cxdc1eeefd5a0f118full, cxcb976d5f3069bad5ull);
    QuadRound(bs0, bs1, cxdc1eeefd5a0f118full, cxcb976d5f3069bad5ull);
    QuadRound(as0, as1, cxe15d5b1658f4ca9dull, cxde0b7a040a35b689ull);
    QuadRound(bs0, bs1, cxe15d5b1658f4ca9dull, cxde0b7a040a35b689ull);
    QuadRound(as0, as1, cx6fab9537a507ea32ull, cx37088980007f3e86ull);
    QuadRound(bs0, bs1, cx6fab9537a507ea32ull, cx37088980007f3e86ull);
    QuadRound(as0, as1, cxc0bbbe37cdaa3b6dull, cx0d8cd6f117406110ull);
    QuadRound(bs0, bs1, cxc0bbbe37cdaa3b6dull, cx0d8cd6f117406110ull);
    QuadRound(as0, as1, cx6fd15ca70b02e931ull, cxdb48a36383613bdaull);
    QuadRound(bs0, bs1, cx6fd15ca70b02e931ull, cxdb48a36383613bdaull);
    QuadRound(as0, as1, cx6d4378906ed41a95ull, cx31338431521afacaull);
    QuadRound(bs0, bs1, cx6d4378906ed41a95ull, cx31338431521afacaull);
    QuadRound(as0, as1, cx532fb63cb5c9a0e6ull, cx9eccabbdc39c91f2ull);
    QuadRound(bs0, bs1, cx532fb63cb5c9a0e6ull, cx9eccabbdc39c91f2ull);
    QuadRound(as0, as1, cx4c191d76a4954b68ull, cx07237ea3d2c741c6ull);
    QuadRound(bs0, bs1, cx4c191d76a4954b68ull, cx07237ea3d2c741c6ull);
    as0 = _mm_add_epi32(as0, aso0);
    bs0 = _mm_add_epi32(bs0, bso0);
    as1 = _mm_add_epi32(as1, aso1);
    bs1 = _mm_add_epi32(bs1, bso1);

    /* Extract hash */
    Unshuffle(as0, as1);
    Unshuffle(bs0, bs1);
    am0 = as0;
    bm0 = bs0;
    am1 = as1;
    bm1 = bs1;

    /* Transform 3 */
    bs0 = as0 = _mm_load_si128((const __m128i*)INIT0);
    bs1 = as1 = _mm_load_si128((const __m128i*)INIT1);
    QuadRound(as0, as1, am0, cxe9b5dba5B5c0fbcfull, cx71374491428a2f98ull);
    QuadRound(bs0, bs1, bm0, cxe9b5dba5B5c0fbcfull, cx71374491428a2f98ull);
    QuadRound(as0, as1, am1, cxab1c5ed5923f82a4ull, cx59f111f13956c25bull);
    QuadRound(bs0, bs1, bm1, cxab1c5ed5923f82a4ull, cx59f111f13956c25bull);
    ShiftMessageA(am0, am1);
    ShiftMessageA(bm0, bm1);
    bm2 = am2 = _mm_set_epi64x(cx0ull, cx80000000ull);
    QuadRound(as0, as1, cx550c7dc3243185beull, cx12835b015807aa98ull);
    QuadRound(bs0, bs1, cx550c7dc3243185beull, cx12835b015807aa98ull);
    ShiftMessageA(am1, am2);
    ShiftMessageA(bm1, bm2);
    bm3 = am3 = _mm_set_epi64x(cx10000000000ull, cx0ull);
    QuadRound(as0, as1, cxc19bf2749bdc06a7ull, cx80deb1fe72be5d74ull);
    QuadRound(bs0, bs1, cxc19bf2749bdc06a7ull, cx80deb1fe72be5d74ull);
    ShiftMessageB(am2, am3, am0);
    ShiftMessageB(bm2, bm3, bm0);
    QuadRound(as0, as1, am0, cx240ca1cc0fc19dc6ull, cxefbe4786e49b69c1ull);
    QuadRound(bs0, bs1, bm0, cx240ca1cc0fc19dc6ull, cxefbe4786e49b69c1ull);
    ShiftMessageB(am3, am0, am1);
    ShiftMessageB(bm3, bm0, bm1);
    QuadRound(as0, as1, am1, cx76f988da5cb0a9dcull, cx4a7484aa2de92c6full);
    QuadRound(bs0, bs1, bm1, cx76f988da5cb0a9dcull, cx4a7484aa2de92c6full);
    ShiftMessageB(am0, am1, am2);
    ShiftMessageB(bm0, bm1, bm2);
    QuadRound(as0, as1, am2, cxbf597fc7b00327c8ull, cxa831c66d983e5152ull);
    QuadRound(bs0, bs1, bm2, cxbf597fc7b00327c8ull, cxa831c66d983e5152ull);
    ShiftMessageB(am1, am2, am3);
    ShiftMessageB(bm1, bm2, bm3);
    QuadRound(as0, as1, am3, cx1429296706ca6351ull, cxd5a79147c6e00bf3ull);
    QuadRound(bs0, bs1, bm3, cx1429296706ca6351ull, cxd5a79147c6e00bf3ull);
    ShiftMessageB(am2, am3, am0);
    ShiftMessageB(bm2, bm3, bm0);
    QuadRound(as0, as1, am0, cx53380d134d2c6dfcull, cx2e1b213827b70a85ull);
    QuadRound(bs0, bs1, bm0, cx53380d134d2c6dfcull, cx2e1b213827b70a85ull);
    ShiftMessageB(am3, am0, am1);
    ShiftMessageB(bm3, bm0, bm1);
    QuadRound(as0, as1, am1, cx92722c8581c2c92eull, cx766a0abb650a7354ull);
    QuadRound(bs0, bs1, bm1, cx92722c8581c2c92eull, cx766a0abb650a7354ull);
    ShiftMessageB(am0, am1, am2);
    ShiftMessageB(bm0, bm1, bm2);
    QuadRound(as0, as1, am2, cxc76c51a3c24b8b70ull, cxa81a664ba2bfe8A1ull);
    QuadRound(bs0, bs1, bm2, cxc76c51a3c24b8b70ull, cxa81a664ba2bfe8A1ull);
    ShiftMessageB(am1, am2, am3);
    ShiftMessageB(bm1, bm2, bm3);
    QuadRound(as0, as1, am3, cx106aa070f40e3585ull, cxd6990624d192e819ull);
    QuadRound(bs0, bs1, bm3, cx106aa070f40e3585ull, cxd6990624d192e819ull);
    ShiftMessageB(am2, am3, am0);
    ShiftMessageB(bm2, bm3, bm0);
    QuadRound(as0, as1, am0, cx34b0bcb52748774cull, cx1e376c0819a4c116ull);
    QuadRound(bs0, bs1, bm0, cx34b0bcb52748774cull, cx1e376c0819a4c116ull);
    ShiftMessageB(am3, am0, am1);
    ShiftMessageB(bm3, bm0, bm1);
    QuadRound(as0, as1, am1, cx682e6ff35b9cca4full, cx4ed8aa4a391c0cb3ull);
    QuadRound(bs0, bs1, bm1, cx682e6ff35b9cca4full, cx4ed8aa4a391c0cb3ull);
    ShiftMessageC(am0, am1, am2);
    ShiftMessageC(bm0, bm1, bm2);
    QuadRound(as0, as1, am2, cx8cc7020884c87814ull, cx78a5636f748f82eeull);
    QuadRound(bs0, bs1, bm2, cx8cc7020884c87814ull, cx78a5636f748f82eeull);
    ShiftMessageC(am1, am2, am3);
    ShiftMessageC(bm1, bm2, bm3);
    QuadRound(as0, as1, am3, cxc67178f2bef9a3f7ull, cxa4506ceb90befffaull);
    QuadRound(bs0, bs1, bm3, cxc67178f2bef9a3f7ull, cxa4506ceb90befffaull);
    as0 = _mm_add_epi32(as0, _mm_load_si128((const __m128i*)INIT0));
    bs0 = _mm_add_epi32(bs0, _mm_load_si128((const __m128i*)INIT0));
    as1 = _mm_add_epi32(as1, _mm_load_si128((const __m128i*)INIT1));
    bs1 = _mm_add_epi32(bs1, _mm_load_si128((const __m128i*)INIT1));

    /* Extract hash into out */
    Unshuffle(as0, as1);
    Unshuffle(bs0, bs1);
    Save(out, as0);
    Save(out + 16, as1);
    Save(out + 32, bs0);
    Save(out + 48, bs1);
}

}

#endif
