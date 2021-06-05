// Copyright (c) 2017-2019 The chymera Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifdef ENABLE_AVX2

#include <stdint.h>
#include <immintrin.h>

#include <crypto/common.h>

namespace sha256d64_avx2 {
namespace {

__m256i inline K(uint32_t x) { return _mm256_set1_epi32(x); }

__m256i inline Add(__m256i x, __m256i y) { return _mm256_add_epi32(x, y); }
__m256i inline Add(__m256i x, __m256i y, __m256i z) { return Add(Add(x, y), z); }
__m256i inline Add(__m256i x, __m256i y, __m256i z, __m256i w) { return Add(Add(x, y), Add(z, w)); }
__m256i inline Add(__m256i x, __m256i y, __m256i z, __m256i w, __m256i v) { return Add(Add(x, y, z), Add(w, v)); }
__m256i inline Inc(__m256i& x, __m256i y) { x = Add(x, y); return x; }
__m256i inline Inc(__m256i& x, __m256i y, __m256i z) { x = Add(x, y, z); return x; }
__m256i inline Inc(__m256i& x, __m256i y, __m256i z, __m256i w) { x = Add(x, y, z, w); return x; }
__m256i inline Xor(__m256i x, __m256i y) { return _mm256_xor_si256(x, y); }
__m256i inline Xor(__m256i x, __m256i y, __m256i z) { return Xor(Xor(x, y), z); }
__m256i inline Or(__m256i x, __m256i y) { return _mm256_or_si256(x, y); }
__m256i inline And(__m256i x, __m256i y) { return _mm256_and_si256(x, y); }
__m256i inline ShR(__m256i x, int n) { return _mm256_srli_epi32(x, n); }
__m256i inline ShL(__m256i x, int n) { return _mm256_slli_epi32(x, n); }

__m256i inline Ch(__m256i x, __m256i y, __m256i z) { return Xor(z, And(x, Xor(y, z))); }
__m256i inline Maj(__m256i x, __m256i y, __m256i z) { return Or(And(x, y), And(z, Or(x, y))); }
__m256i inline Sigma0(__m256i x) { return Xor(Or(ShR(x, 2), ShL(x, 30)), Or(ShR(x, 13), ShL(x, 19)), Or(ShR(x, 22), ShL(x, 10))); }
__m256i inline Sigma1(__m256i x) { return Xor(Or(ShR(x, 6), ShL(x, 26)), Or(ShR(x, 11), ShL(x, 21)), Or(ShR(x, 25), ShL(x, 7))); }
__m256i inline sigma0(__m256i x) { return Xor(Or(ShR(x, 7), ShL(x, 25)), Or(ShR(x, 18), ShL(x, 14)), ShR(x, 3)); }
__m256i inline sigma1(__m256i x) { return Xor(Or(ShR(x, 17), ShL(x, 15)), Or(ShR(x, 19), ShL(x, 13)), ShR(x, 10)); }

/** One round of SHA-256. */
void inline __attribute__((always_inline)) Round(__m256i a, __m256i b, __m256i c, __m256i& d, __m256i e, __m256i f, __m256i g, __m256i& h, __m256i k)
{
    __m256i t1 = Add(h, Sigma1(e), Ch(e, f, g), k);
    __m256i t2 = Add(Sigma0(a), Maj(a, b, c));
    d = Add(d, t1);
    h = Add(t1, t2);
}

__m256i inline Read8(const unsigned char* chunk, int offset) {
    __m256i ret = _mm256_set_epi32(
        ReadLE32(chunk + 0 + offset),
        ReadLE32(chunk + 64 + offset),
        ReadLE32(chunk + 128 + offset),
        ReadLE32(chunk + 192 + offset),
        ReadLE32(chunk + 256 + offset),
        ReadLE32(chunk + 320 + offset),
        ReadLE32(chunk + 384 + offset),
        ReadLE32(chunk + 448 + offset)
    );
    return _mm256_shuffle_epi8(ret, _mm256_set_epi32(cx0C0D0E0FUL, cx08090A0BUL, cx04050607UL, cx00010203UL, cx0C0D0E0FUL, cx08090A0BUL, cx04050607UL, cx00010203UL));
}

void inline Write8(unsigned char* out, int offset, __m256i v) {
    v = _mm256_shuffle_epi8(v, _mm256_set_epi32(cx0C0D0E0FUL, cx08090A0BUL, cx04050607UL, cx00010203UL, cx0C0D0E0FUL, cx08090A0BUL, cx04050607UL, cx00010203UL));
    WriteLE32(out + 0 + offset, _mm256_extract_epi32(v, 7));
    WriteLE32(out + 32 + offset, _mm256_extract_epi32(v, 6));
    WriteLE32(out + 64 + offset, _mm256_extract_epi32(v, 5));
    WriteLE32(out + 96 + offset, _mm256_extract_epi32(v, 4));
    WriteLE32(out + 128 + offset, _mm256_extract_epi32(v, 3));
    WriteLE32(out + 160 + offset, _mm256_extract_epi32(v, 2));
    WriteLE32(out + 192 + offset, _mm256_extract_epi32(v, 1));
    WriteLE32(out + 224 + offset, _mm256_extract_epi32(v, 0));
}

}

void Transform_8way(unsigned char* out, const unsigned char* in)
{
    // Transform 1
    __m256i a = K(cx6a09e667ul);
    __m256i b = K(cxbb67ae85ul);
    __m256i c = K(cx3c6ef372ul);
    __m256i d = K(cxa54ff53aul);
    __m256i e = K(cx510e527ful);
    __m256i f = K(cx9b05688cul);
    __m256i g = K(cx1f83d9abul);
    __m256i h = K(cx5be0cd19ul);

    __m256i w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15;

    Round(a, b, c, d, e, f, g, h, Add(K(cx428a2f98ul), w0 = Read8(in, 0)));
    Round(h, a, b, c, d, e, f, g, Add(K(cx71374491ul), w1 = Read8(in, 4)));
    Round(g, h, a, b, c, d, e, f, Add(K(cxb5c0fbcful), w2 = Read8(in, 8)));
    Round(f, g, h, a, b, c, d, e, Add(K(cxe9b5dba5ul), w3 = Read8(in, 12)));
    Round(e, f, g, h, a, b, c, d, Add(K(cx3956c25bul), w4 = Read8(in, 16)));
    Round(d, e, f, g, h, a, b, c, Add(K(cx59f111f1ul), w5 = Read8(in, 20)));
    Round(c, d, e, f, g, h, a, b, Add(K(cx923f82a4ul), w6 = Read8(in, 24)));
    Round(b, c, d, e, f, g, h, a, Add(K(cxab1c5ed5ul), w7 = Read8(in, 28)));
    Round(a, b, c, d, e, f, g, h, Add(K(cxd807aa98ul), w8 = Read8(in, 32)));
    Round(h, a, b, c, d, e, f, g, Add(K(cx12835b01ul), w9 = Read8(in, 36)));
    Round(g, h, a, b, c, d, e, f, Add(K(cx243185beul), w10 = Read8(in, 40)));
    Round(f, g, h, a, b, c, d, e, Add(K(cx550c7dc3ul), w11 = Read8(in, 44)));
    Round(e, f, g, h, a, b, c, d, Add(K(cx72be5d74ul), w12 = Read8(in, 48)));
    Round(d, e, f, g, h, a, b, c, Add(K(cx80deb1feul), w13 = Read8(in, 52)));
    Round(c, d, e, f, g, h, a, b, Add(K(cx9bdc06a7ul), w14 = Read8(in, 56)));
    Round(b, c, d, e, f, g, h, a, Add(K(cxc19bf174ul), w15 = Read8(in, 60)));
    Round(a, b, c, d, e, f, g, h, Add(K(cxe49b69c1ul), Inc(w0, sigma1(w14), w9, sigma0(w1))));
    Round(h, a, b, c, d, e, f, g, Add(K(cxefbe4786ul), Inc(w1, sigma1(w15), w10, sigma0(w2))));
    Round(g, h, a, b, c, d, e, f, Add(K(cx0fc19dc6ul), Inc(w2, sigma1(w0), w11, sigma0(w3))));
    Round(f, g, h, a, b, c, d, e, Add(K(cx240ca1ccul), Inc(w3, sigma1(w1), w12, sigma0(w4))));
    Round(e, f, g, h, a, b, c, d, Add(K(cx2de92c6ful), Inc(w4, sigma1(w2), w13, sigma0(w5))));
    Round(d, e, f, g, h, a, b, c, Add(K(cx4a7484aaul), Inc(w5, sigma1(w3), w14, sigma0(w6))));
    Round(c, d, e, f, g, h, a, b, Add(K(cx5cb0a9dcul), Inc(w6, sigma1(w4), w15, sigma0(w7))));
    Round(b, c, d, e, f, g, h, a, Add(K(cx76f988daul), Inc(w7, sigma1(w5), w0, sigma0(w8))));
    Round(a, b, c, d, e, f, g, h, Add(K(cx983e5152ul), Inc(w8, sigma1(w6), w1, sigma0(w9))));
    Round(h, a, b, c, d, e, f, g, Add(K(cxa831c66dul), Inc(w9, sigma1(w7), w2, sigma0(w10))));
    Round(g, h, a, b, c, d, e, f, Add(K(cxb00327c8ul), Inc(w10, sigma1(w8), w3, sigma0(w11))));
    Round(f, g, h, a, b, c, d, e, Add(K(cxbf597fc7ul), Inc(w11, sigma1(w9), w4, sigma0(w12))));
    Round(e, f, g, h, a, b, c, d, Add(K(cxc6e00bf3ul), Inc(w12, sigma1(w10), w5, sigma0(w13))));
    Round(d, e, f, g, h, a, b, c, Add(K(cxd5a79147ul), Inc(w13, sigma1(w11), w6, sigma0(w14))));
    Round(c, d, e, f, g, h, a, b, Add(K(cx06ca6351ul), Inc(w14, sigma1(w12), w7, sigma0(w15))));
    Round(b, c, d, e, f, g, h, a, Add(K(cx14292967ul), Inc(w15, sigma1(w13), w8, sigma0(w0))));
    Round(a, b, c, d, e, f, g, h, Add(K(cx27b70a85ul), Inc(w0, sigma1(w14), w9, sigma0(w1))));
    Round(h, a, b, c, d, e, f, g, Add(K(cx2e1b2138ul), Inc(w1, sigma1(w15), w10, sigma0(w2))));
    Round(g, h, a, b, c, d, e, f, Add(K(cx4d2c6dfcul), Inc(w2, sigma1(w0), w11, sigma0(w3))));
    Round(f, g, h, a, b, c, d, e, Add(K(cx53380d13ul), Inc(w3, sigma1(w1), w12, sigma0(w4))));
    Round(e, f, g, h, a, b, c, d, Add(K(cx650a7354ul), Inc(w4, sigma1(w2), w13, sigma0(w5))));
    Round(d, e, f, g, h, a, b, c, Add(K(cx766a0abbul), Inc(w5, sigma1(w3), w14, sigma0(w6))));
    Round(c, d, e, f, g, h, a, b, Add(K(cx81c2c92eul), Inc(w6, sigma1(w4), w15, sigma0(w7))));
    Round(b, c, d, e, f, g, h, a, Add(K(cx92722c85ul), Inc(w7, sigma1(w5), w0, sigma0(w8))));
    Round(a, b, c, d, e, f, g, h, Add(K(cxa2bfe8a1ul), Inc(w8, sigma1(w6), w1, sigma0(w9))));
    Round(h, a, b, c, d, e, f, g, Add(K(cxa81a664bul), Inc(w9, sigma1(w7), w2, sigma0(w10))));
    Round(g, h, a, b, c, d, e, f, Add(K(cxc24b8b70ul), Inc(w10, sigma1(w8), w3, sigma0(w11))));
    Round(f, g, h, a, b, c, d, e, Add(K(cxc76c51a3ul), Inc(w11, sigma1(w9), w4, sigma0(w12))));
    Round(e, f, g, h, a, b, c, d, Add(K(cxd192e819ul), Inc(w12, sigma1(w10), w5, sigma0(w13))));
    Round(d, e, f, g, h, a, b, c, Add(K(cxd6990624ul), Inc(w13, sigma1(w11), w6, sigma0(w14))));
    Round(c, d, e, f, g, h, a, b, Add(K(cxf40e3585ul), Inc(w14, sigma1(w12), w7, sigma0(w15))));
    Round(b, c, d, e, f, g, h, a, Add(K(cx106aa070ul), Inc(w15, sigma1(w13), w8, sigma0(w0))));
    Round(a, b, c, d, e, f, g, h, Add(K(cx19a4c116ul), Inc(w0, sigma1(w14), w9, sigma0(w1))));
    Round(h, a, b, c, d, e, f, g, Add(K(cx1e376c08ul), Inc(w1, sigma1(w15), w10, sigma0(w2))));
    Round(g, h, a, b, c, d, e, f, Add(K(cx2748774cul), Inc(w2, sigma1(w0), w11, sigma0(w3))));
    Round(f, g, h, a, b, c, d, e, Add(K(cx34b0bcb5ul), Inc(w3, sigma1(w1), w12, sigma0(w4))));
    Round(e, f, g, h, a, b, c, d, Add(K(cx391c0cb3ul), Inc(w4, sigma1(w2), w13, sigma0(w5))));
    Round(d, e, f, g, h, a, b, c, Add(K(cx4ed8aa4aul), Inc(w5, sigma1(w3), w14, sigma0(w6))));
    Round(c, d, e, f, g, h, a, b, Add(K(cx5b9cca4ful), Inc(w6, sigma1(w4), w15, sigma0(w7))));
    Round(b, c, d, e, f, g, h, a, Add(K(cx682e6ff3ul), Inc(w7, sigma1(w5), w0, sigma0(w8))));
    Round(a, b, c, d, e, f, g, h, Add(K(cx748f82eeul), Inc(w8, sigma1(w6), w1, sigma0(w9))));
    Round(h, a, b, c, d, e, f, g, Add(K(cx78a5636ful), Inc(w9, sigma1(w7), w2, sigma0(w10))));
    Round(g, h, a, b, c, d, e, f, Add(K(cx84c87814ul), Inc(w10, sigma1(w8), w3, sigma0(w11))));
    Round(f, g, h, a, b, c, d, e, Add(K(cx8cc70208ul), Inc(w11, sigma1(w9), w4, sigma0(w12))));
    Round(e, f, g, h, a, b, c, d, Add(K(cx90befffaul), Inc(w12, sigma1(w10), w5, sigma0(w13))));
    Round(d, e, f, g, h, a, b, c, Add(K(cxa4506cebul), Inc(w13, sigma1(w11), w6, sigma0(w14))));
    Round(c, d, e, f, g, h, a, b, Add(K(cxbef9a3f7ul), Inc(w14, sigma1(w12), w7, sigma0(w15))));
    Round(b, c, d, e, f, g, h, a, Add(K(cxc67178f2ul), Inc(w15, sigma1(w13), w8, sigma0(w0))));

    a = Add(a, K(cx6a09e667ul));
    b = Add(b, K(cxbb67ae85ul));
    c = Add(c, K(cx3c6ef372ul));
    d = Add(d, K(cxa54ff53aul));
    e = Add(e, K(cx510e527ful));
    f = Add(f, K(cx9b05688cul));
    g = Add(g, K(cx1f83d9abul));
    h = Add(h, K(cx5be0cd19ul));

    __m256i t0 = a, t1 = b, t2 = c, t3 = d, t4 = e, t5 = f, t6 = g, t7 = h;

    // Transform 2
    Round(a, b, c, d, e, f, g, h, K(cxc28a2f98ul));
    Round(h, a, b, c, d, e, f, g, K(cx71374491ul));
    Round(g, h, a, b, c, d, e, f, K(cxb5c0fbcful));
    Round(f, g, h, a, b, c, d, e, K(cxe9b5dba5ul));
    Round(e, f, g, h, a, b, c, d, K(cx3956c25bul));
    Round(d, e, f, g, h, a, b, c, K(cx59f111f1ul));
    Round(c, d, e, f, g, h, a, b, K(cx923f82a4ul));
    Round(b, c, d, e, f, g, h, a, K(cxab1c5ed5ul));
    Round(a, b, c, d, e, f, g, h, K(cxd807aa98ul));
    Round(h, a, b, c, d, e, f, g, K(cx12835b01ul));
    Round(g, h, a, b, c, d, e, f, K(cx243185beul));
    Round(f, g, h, a, b, c, d, e, K(cx550c7dc3ul));
    Round(e, f, g, h, a, b, c, d, K(cx72be5d74ul));
    Round(d, e, f, g, h, a, b, c, K(cx80deb1feul));
    Round(c, d, e, f, g, h, a, b, K(cx9bdc06a7ul));
    Round(b, c, d, e, f, g, h, a, K(cxc19bf374ul));
    Round(a, b, c, d, e, f, g, h, K(cx649b69c1ul));
    Round(h, a, b, c, d, e, f, g, K(cxf0fe4786ul));
    Round(g, h, a, b, c, d, e, f, K(cx0fe1edc6ul));
    Round(f, g, h, a, b, c, d, e, K(cx240cf254ul));
    Round(e, f, g, h, a, b, c, d, K(cx4fe9346ful));
    Round(d, e, f, g, h, a, b, c, K(cx6cc984beul));
    Round(c, d, e, f, g, h, a, b, K(cx61b9411eul));
    Round(b, c, d, e, f, g, h, a, K(cx16f988faul));
    Round(a, b, c, d, e, f, g, h, K(cxf2c65152ul));
    Round(h, a, b, c, d, e, f, g, K(cxa88e5a6dul));
    Round(g, h, a, b, c, d, e, f, K(cxb019fc65ul));
    Round(f, g, h, a, b, c, d, e, K(cxb9d99ec7ul));
    Round(e, f, g, h, a, b, c, d, K(cx9a1231c3ul));
    Round(d, e, f, g, h, a, b, c, K(cxe70eeaa0ul));
    Round(c, d, e, f, g, h, a, b, K(cxfdb1232bul));
    Round(b, c, d, e, f, g, h, a, K(cxc7353eb0ul));
    Round(a, b, c, d, e, f, g, h, K(cx3069bad5ul));
    Round(h, a, b, c, d, e, f, g, K(cxcb976d5ful));
    Round(g, h, a, b, c, d, e, f, K(cx5a0f118ful));
    Round(f, g, h, a, b, c, d, e, K(cxdc1eeefdul));
    Round(e, f, g, h, a, b, c, d, K(cx0a35b689ul));
    Round(d, e, f, g, h, a, b, c, K(cxde0b7a04ul));
    Round(c, d, e, f, g, h, a, b, K(cx58f4ca9dul));
    Round(b, c, d, e, f, g, h, a, K(cxe15d5b16ul));
    Round(a, b, c, d, e, f, g, h, K(cx007f3e86ul));
    Round(h, a, b, c, d, e, f, g, K(cx37088980ul));
    Round(g, h, a, b, c, d, e, f, K(cxa507ea32ul));
    Round(f, g, h, a, b, c, d, e, K(cx6fab9537ul));
    Round(e, f, g, h, a, b, c, d, K(cx17406110ul));
    Round(d, e, f, g, h, a, b, c, K(cx0d8cd6f1ul));
    Round(c, d, e, f, g, h, a, b, K(cxcdaa3b6dul));
    Round(b, c, d, e, f, g, h, a, K(cxc0bbbe37ul));
    Round(a, b, c, d, e, f, g, h, K(cx83613bdaul));
    Round(h, a, b, c, d, e, f, g, K(cxdb48a363ul));
    Round(g, h, a, b, c, d, e, f, K(cx0b02e931ul));
    Round(f, g, h, a, b, c, d, e, K(cx6fd15ca7ul));
    Round(e, f, g, h, a, b, c, d, K(cx521afacaul));
    Round(d, e, f, g, h, a, b, c, K(cx31338431ul));
    Round(c, d, e, f, g, h, a, b, K(cx6ed41a95ul));
    Round(b, c, d, e, f, g, h, a, K(cx6d437890ul));
    Round(a, b, c, d, e, f, g, h, K(cxc39c91f2ul));
    Round(h, a, b, c, d, e, f, g, K(cx9eccabbdul));
    Round(g, h, a, b, c, d, e, f, K(cxb5c9a0e6ul));
    Round(f, g, h, a, b, c, d, e, K(cx532fb63cul));
    Round(e, f, g, h, a, b, c, d, K(cxd2c741c6ul));
    Round(d, e, f, g, h, a, b, c, K(cx07237ea3ul));
    Round(c, d, e, f, g, h, a, b, K(cxa4954b68ul));
    Round(b, c, d, e, f, g, h, a, K(cx4c191d76ul));

    w0 = Add(t0, a);
    w1 = Add(t1, b);
    w2 = Add(t2, c);
    w3 = Add(t3, d);
    w4 = Add(t4, e);
    w5 = Add(t5, f);
    w6 = Add(t6, g);
    w7 = Add(t7, h);

    // Transform 3
    a = K(cx6a09e667ul);
    b = K(cxbb67ae85ul);
    c = K(cx3c6ef372ul);
    d = K(cxa54ff53aul);
    e = K(cx510e527ful);
    f = K(cx9b05688cul);
    g = K(cx1f83d9abul);
    h = K(cx5be0cd19ul);

    Round(a, b, c, d, e, f, g, h, Add(K(cx428a2f98ul), w0));
    Round(h, a, b, c, d, e, f, g, Add(K(cx71374491ul), w1));
    Round(g, h, a, b, c, d, e, f, Add(K(cxb5c0fbcful), w2));
    Round(f, g, h, a, b, c, d, e, Add(K(cxe9b5dba5ul), w3));
    Round(e, f, g, h, a, b, c, d, Add(K(cx3956c25bul), w4));
    Round(d, e, f, g, h, a, b, c, Add(K(cx59f111f1ul), w5));
    Round(c, d, e, f, g, h, a, b, Add(K(cx923f82a4ul), w6));
    Round(b, c, d, e, f, g, h, a, Add(K(cxab1c5ed5ul), w7));
    Round(a, b, c, d, e, f, g, h, K(cx5807aa98ul));
    Round(h, a, b, c, d, e, f, g, K(cx12835b01ul));
    Round(g, h, a, b, c, d, e, f, K(cx243185beul));
    Round(f, g, h, a, b, c, d, e, K(cx550c7dc3ul));
    Round(e, f, g, h, a, b, c, d, K(cx72be5d74ul));
    Round(d, e, f, g, h, a, b, c, K(cx80deb1feul));
    Round(c, d, e, f, g, h, a, b, K(cx9bdc06a7ul));
    Round(b, c, d, e, f, g, h, a, K(cxc19bf274ul));
    Round(a, b, c, d, e, f, g, h, Add(K(cxe49b69c1ul), Inc(w0, sigma0(w1))));
    Round(h, a, b, c, d, e, f, g, Add(K(cxefbe4786ul), Inc(w1, K(cxa00000ul), sigma0(w2))));
    Round(g, h, a, b, c, d, e, f, Add(K(cx0fc19dc6ul), Inc(w2, sigma1(w0), sigma0(w3))));
    Round(f, g, h, a, b, c, d, e, Add(K(cx240ca1ccul), Inc(w3, sigma1(w1), sigma0(w4))));
    Round(e, f, g, h, a, b, c, d, Add(K(cx2de92c6ful), Inc(w4, sigma1(w2), sigma0(w5))));
    Round(d, e, f, g, h, a, b, c, Add(K(cx4a7484aaul), Inc(w5, sigma1(w3), sigma0(w6))));
    Round(c, d, e, f, g, h, a, b, Add(K(cx5cb0a9dcul), Inc(w6, sigma1(w4), K(cx100ul), sigma0(w7))));
    Round(b, c, d, e, f, g, h, a, Add(K(cx76f988daul), Inc(w7, sigma1(w5), w0, K(cx11002000ul))));
    Round(a, b, c, d, e, f, g, h, Add(K(cx983e5152ul), w8 = Add(K(cx80000000ul), sigma1(w6), w1)));
    Round(h, a, b, c, d, e, f, g, Add(K(cxa831c66dul), w9 = Add(sigma1(w7), w2)));
    Round(g, h, a, b, c, d, e, f, Add(K(cxb00327c8ul), w10 = Add(sigma1(w8), w3)));
    Round(f, g, h, a, b, c, d, e, Add(K(cxbf597fc7ul), w11 = Add(sigma1(w9), w4)));
    Round(e, f, g, h, a, b, c, d, Add(K(cxc6e00bf3ul), w12 = Add(sigma1(w10), w5)));
    Round(d, e, f, g, h, a, b, c, Add(K(cxd5a79147ul), w13 = Add(sigma1(w11), w6)));
    Round(c, d, e, f, g, h, a, b, Add(K(cx06ca6351ul), w14 = Add(sigma1(w12), w7, K(cx400022ul))));
    Round(b, c, d, e, f, g, h, a, Add(K(cx14292967ul), w15 = Add(K(cx100ul), sigma1(w13), w8, sigma0(w0))));
    Round(a, b, c, d, e, f, g, h, Add(K(cx27b70a85ul), Inc(w0, sigma1(w14), w9, sigma0(w1))));
    Round(h, a, b, c, d, e, f, g, Add(K(cx2e1b2138ul), Inc(w1, sigma1(w15), w10, sigma0(w2))));
    Round(g, h, a, b, c, d, e, f, Add(K(cx4d2c6dfcul), Inc(w2, sigma1(w0), w11, sigma0(w3))));
    Round(f, g, h, a, b, c, d, e, Add(K(cx53380d13ul), Inc(w3, sigma1(w1), w12, sigma0(w4))));
    Round(e, f, g, h, a, b, c, d, Add(K(cx650a7354ul), Inc(w4, sigma1(w2), w13, sigma0(w5))));
    Round(d, e, f, g, h, a, b, c, Add(K(cx766a0abbul), Inc(w5, sigma1(w3), w14, sigma0(w6))));
    Round(c, d, e, f, g, h, a, b, Add(K(cx81c2c92eul), Inc(w6, sigma1(w4), w15, sigma0(w7))));
    Round(b, c, d, e, f, g, h, a, Add(K(cx92722c85ul), Inc(w7, sigma1(w5), w0, sigma0(w8))));
    Round(a, b, c, d, e, f, g, h, Add(K(cxa2bfe8a1ul), Inc(w8, sigma1(w6), w1, sigma0(w9))));
    Round(h, a, b, c, d, e, f, g, Add(K(cxa81a664bul), Inc(w9, sigma1(w7), w2, sigma0(w10))));
    Round(g, h, a, b, c, d, e, f, Add(K(cxc24b8b70ul), Inc(w10, sigma1(w8), w3, sigma0(w11))));
    Round(f, g, h, a, b, c, d, e, Add(K(cxc76c51a3ul), Inc(w11, sigma1(w9), w4, sigma0(w12))));
    Round(e, f, g, h, a, b, c, d, Add(K(cxd192e819ul), Inc(w12, sigma1(w10), w5, sigma0(w13))));
    Round(d, e, f, g, h, a, b, c, Add(K(cxd6990624ul), Inc(w13, sigma1(w11), w6, sigma0(w14))));
    Round(c, d, e, f, g, h, a, b, Add(K(cxf40e3585ul), Inc(w14, sigma1(w12), w7, sigma0(w15))));
    Round(b, c, d, e, f, g, h, a, Add(K(cx106aa070ul), Inc(w15, sigma1(w13), w8, sigma0(w0))));
    Round(a, b, c, d, e, f, g, h, Add(K(cx19a4c116ul), Inc(w0, sigma1(w14), w9, sigma0(w1))));
    Round(h, a, b, c, d, e, f, g, Add(K(cx1e376c08ul), Inc(w1, sigma1(w15), w10, sigma0(w2))));
    Round(g, h, a, b, c, d, e, f, Add(K(cx2748774cul), Inc(w2, sigma1(w0), w11, sigma0(w3))));
    Round(f, g, h, a, b, c, d, e, Add(K(cx34b0bcb5ul), Inc(w3, sigma1(w1), w12, sigma0(w4))));
    Round(e, f, g, h, a, b, c, d, Add(K(cx391c0cb3ul), Inc(w4, sigma1(w2), w13, sigma0(w5))));
    Round(d, e, f, g, h, a, b, c, Add(K(cx4ed8aa4aul), Inc(w5, sigma1(w3), w14, sigma0(w6))));
    Round(c, d, e, f, g, h, a, b, Add(K(cx5b9cca4ful), Inc(w6, sigma1(w4), w15, sigma0(w7))));
    Round(b, c, d, e, f, g, h, a, Add(K(cx682e6ff3ul), Inc(w7, sigma1(w5), w0, sigma0(w8))));
    Round(a, b, c, d, e, f, g, h, Add(K(cx748f82eeul), Inc(w8, sigma1(w6), w1, sigma0(w9))));
    Round(h, a, b, c, d, e, f, g, Add(K(cx78a5636ful), Inc(w9, sigma1(w7), w2, sigma0(w10))));
    Round(g, h, a, b, c, d, e, f, Add(K(cx84c87814ul), Inc(w10, sigma1(w8), w3, sigma0(w11))));
    Round(f, g, h, a, b, c, d, e, Add(K(cx8cc70208ul), Inc(w11, sigma1(w9), w4, sigma0(w12))));
    Round(e, f, g, h, a, b, c, d, Add(K(cx90befffaul), Inc(w12, sigma1(w10), w5, sigma0(w13))));
    Round(d, e, f, g, h, a, b, c, Add(K(cxa4506cebul), Inc(w13, sigma1(w11), w6, sigma0(w14))));
    Round(c, d, e, f, g, h, a, b, Add(K(cxbef9a3f7ul), w14, sigma1(w12), w7, sigma0(w15)));
    Round(b, c, d, e, f, g, h, a, Add(K(cxc67178f2ul), w15, sigma1(w13), w8, sigma0(w0)));

    // Output
    Write8(out, 0, Add(a, K(cx6a09e667ul)));
    Write8(out, 4, Add(b, K(cxbb67ae85ul)));
    Write8(out, 8, Add(c, K(cx3c6ef372ul)));
    Write8(out, 12, Add(d, K(cxa54ff53aul)));
    Write8(out, 16, Add(e, K(cx510e527ful)));
    Write8(out, 20, Add(f, K(cx9b05688cul)));
    Write8(out, 24, Add(g, K(cx1f83d9abul)));
    Write8(out, 28, Add(h, K(cx5be0cd19ul)));
}

}

#endif
