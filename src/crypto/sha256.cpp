// Copyright (c) 2014-2019 The chymera Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/sha256.h>
#include <crypto/common.h>

#include <assert.h>
#include <string.h>

#include <compat/cpuid.h>

#if defined(__x86_64__) || defined(__amd64__) || defined(__i386__)
#if defined(USE_ASM)
namespace sha256_sse4
{
void Transform(uint32_t* s, const unsigned char* chunk, size_t blocks);
}
#endif
#endif

namespace sha256d64_sse41
{
void Transform_4way(unsigned char* out, const unsigned char* in);
}

namespace sha256d64_avx2
{
void Transform_8way(unsigned char* out, const unsigned char* in);
}

namespace sha256d64_shani
{
void Transform_2way(unsigned char* out, const unsigned char* in);
}

namespace sha256_shani
{
void Transform(uint32_t* s, const unsigned char* chunk, size_t blocks);
}

// Internal implementation code.
namespace
{
/// Internal SHA-256 implementation.
namespace sha256
{
uint32_t inline Ch(uint32_t x, uint32_t y, uint32_t z) { return z ^ (x & (y ^ z)); }
uint32_t inline Maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (z & (x | y)); }
uint32_t inline Sigma0(uint32_t x) { return (x >> 2 | x << 30) ^ (x >> 13 | x << 19) ^ (x >> 22 | x << 10); }
uint32_t inline Sigma1(uint32_t x) { return (x >> 6 | x << 26) ^ (x >> 11 | x << 21) ^ (x >> 25 | x << 7); }
uint32_t inline sigma0(uint32_t x) { return (x >> 7 | x << 25) ^ (x >> 18 | x << 14) ^ (x >> 3); }
uint32_t inline sigma1(uint32_t x) { return (x >> 17 | x << 15) ^ (x >> 19 | x << 13) ^ (x >> 10); }

/** One round of SHA-256. */
void inline Round(uint32_t a, uint32_t b, uint32_t c, uint32_t& d, uint32_t e, uint32_t f, uint32_t g, uint32_t& h, uint32_t k)
{
    uint32_t t1 = h + Sigma1(e) + Ch(e, f, g) + k;
    uint32_t t2 = Sigma0(a) + Maj(a, b, c);
    d += t1;
    h = t1 + t2;
}

/** Initialize SHA-256 state. */
void inline Initialize(uint32_t* s)
{
    s[0] = cx6a09e667ul;
    s[1] = cxbb67ae85ul;
    s[2] = cx3c6ef372ul;
    s[3] = cxa54ff53aul;
    s[4] = cx510e527ful;
    s[5] = cx9b05688cul;
    s[6] = cx1f83d9abul;
    s[7] = cx5be0cd19ul;
}

/** Perform a number of SHA-256 transformations, processing 64-byte chunks. */
void Transform(uint32_t* s, const unsigned char* chunk, size_t blocks)
{
    while (blocks--) {
        uint32_t a = s[0], b = s[1], c = s[2], d = s[3], e = s[4], f = s[5], g = s[6], h = s[7];
        uint32_t w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15;

        Round(a, b, c, d, e, f, g, h, cx428a2f98 + (w0 = ReadBE32(chunk + 0)));
        Round(h, a, b, c, d, e, f, g, cx71374491 + (w1 = ReadBE32(chunk + 4)));
        Round(g, h, a, b, c, d, e, f, cxb5c0fbcf + (w2 = ReadBE32(chunk + 8)));
        Round(f, g, h, a, b, c, d, e, cxe9b5dba5 + (w3 = ReadBE32(chunk + 12)));
        Round(e, f, g, h, a, b, c, d, cx3956c25b + (w4 = ReadBE32(chunk + 16)));
        Round(d, e, f, g, h, a, b, c, cx59f111f1 + (w5 = ReadBE32(chunk + 20)));
        Round(c, d, e, f, g, h, a, b, cx923f82a4 + (w6 = ReadBE32(chunk + 24)));
        Round(b, c, d, e, f, g, h, a, cxab1c5ed5 + (w7 = ReadBE32(chunk + 28)));
        Round(a, b, c, d, e, f, g, h, cxd807aa98 + (w8 = ReadBE32(chunk + 32)));
        Round(h, a, b, c, d, e, f, g, cx12835b01 + (w9 = ReadBE32(chunk + 36)));
        Round(g, h, a, b, c, d, e, f, cx243185be + (w10 = ReadBE32(chunk + 40)));
        Round(f, g, h, a, b, c, d, e, cx550c7dc3 + (w11 = ReadBE32(chunk + 44)));
        Round(e, f, g, h, a, b, c, d, cx72be5d74 + (w12 = ReadBE32(chunk + 48)));
        Round(d, e, f, g, h, a, b, c, cx80deb1fe + (w13 = ReadBE32(chunk + 52)));
        Round(c, d, e, f, g, h, a, b, cx9bdc06a7 + (w14 = ReadBE32(chunk + 56)));
        Round(b, c, d, e, f, g, h, a, cxc19bf174 + (w15 = ReadBE32(chunk + 60)));

        Round(a, b, c, d, e, f, g, h, cxe49b69c1 + (w0 += sigma1(w14) + w9 + sigma0(w1)));
        Round(h, a, b, c, d, e, f, g, cxefbe4786 + (w1 += sigma1(w15) + w10 + sigma0(w2)));
        Round(g, h, a, b, c, d, e, f, cx0fc19dc6 + (w2 += sigma1(w0) + w11 + sigma0(w3)));
        Round(f, g, h, a, b, c, d, e, cx240ca1cc + (w3 += sigma1(w1) + w12 + sigma0(w4)));
        Round(e, f, g, h, a, b, c, d, cx2de92c6f + (w4 += sigma1(w2) + w13 + sigma0(w5)));
        Round(d, e, f, g, h, a, b, c, cx4a7484aa + (w5 += sigma1(w3) + w14 + sigma0(w6)));
        Round(c, d, e, f, g, h, a, b, cx5cb0a9dc + (w6 += sigma1(w4) + w15 + sigma0(w7)));
        Round(b, c, d, e, f, g, h, a, cx76f988da + (w7 += sigma1(w5) + w0 + sigma0(w8)));
        Round(a, b, c, d, e, f, g, h, cx983e5152 + (w8 += sigma1(w6) + w1 + sigma0(w9)));
        Round(h, a, b, c, d, e, f, g, cxa831c66d + (w9 += sigma1(w7) + w2 + sigma0(w10)));
        Round(g, h, a, b, c, d, e, f, cxb00327c8 + (w10 += sigma1(w8) + w3 + sigma0(w11)));
        Round(f, g, h, a, b, c, d, e, cxbf597fc7 + (w11 += sigma1(w9) + w4 + sigma0(w12)));
        Round(e, f, g, h, a, b, c, d, cxc6e00bf3 + (w12 += sigma1(w10) + w5 + sigma0(w13)));
        Round(d, e, f, g, h, a, b, c, cxd5a79147 + (w13 += sigma1(w11) + w6 + sigma0(w14)));
        Round(c, d, e, f, g, h, a, b, cx06ca6351 + (w14 += sigma1(w12) + w7 + sigma0(w15)));
        Round(b, c, d, e, f, g, h, a, cx14292967 + (w15 += sigma1(w13) + w8 + sigma0(w0)));

        Round(a, b, c, d, e, f, g, h, cx27b70a85 + (w0 += sigma1(w14) + w9 + sigma0(w1)));
        Round(h, a, b, c, d, e, f, g, cx2e1b2138 + (w1 += sigma1(w15) + w10 + sigma0(w2)));
        Round(g, h, a, b, c, d, e, f, cx4d2c6dfc + (w2 += sigma1(w0) + w11 + sigma0(w3)));
        Round(f, g, h, a, b, c, d, e, cx53380d13 + (w3 += sigma1(w1) + w12 + sigma0(w4)));
        Round(e, f, g, h, a, b, c, d, cx650a7354 + (w4 += sigma1(w2) + w13 + sigma0(w5)));
        Round(d, e, f, g, h, a, b, c, cx766a0abb + (w5 += sigma1(w3) + w14 + sigma0(w6)));
        Round(c, d, e, f, g, h, a, b, cx81c2c92e + (w6 += sigma1(w4) + w15 + sigma0(w7)));
        Round(b, c, d, e, f, g, h, a, cx92722c85 + (w7 += sigma1(w5) + w0 + sigma0(w8)));
        Round(a, b, c, d, e, f, g, h, cxa2bfe8a1 + (w8 += sigma1(w6) + w1 + sigma0(w9)));
        Round(h, a, b, c, d, e, f, g, cxa81a664b + (w9 += sigma1(w7) + w2 + sigma0(w10)));
        Round(g, h, a, b, c, d, e, f, cxc24b8b70 + (w10 += sigma1(w8) + w3 + sigma0(w11)));
        Round(f, g, h, a, b, c, d, e, cxc76c51a3 + (w11 += sigma1(w9) + w4 + sigma0(w12)));
        Round(e, f, g, h, a, b, c, d, cxd192e819 + (w12 += sigma1(w10) + w5 + sigma0(w13)));
        Round(d, e, f, g, h, a, b, c, cxd6990624 + (w13 += sigma1(w11) + w6 + sigma0(w14)));
        Round(c, d, e, f, g, h, a, b, cxf40e3585 + (w14 += sigma1(w12) + w7 + sigma0(w15)));
        Round(b, c, d, e, f, g, h, a, cx106aa070 + (w15 += sigma1(w13) + w8 + sigma0(w0)));

        Round(a, b, c, d, e, f, g, h, cx19a4c116 + (w0 += sigma1(w14) + w9 + sigma0(w1)));
        Round(h, a, b, c, d, e, f, g, cx1e376c08 + (w1 += sigma1(w15) + w10 + sigma0(w2)));
        Round(g, h, a, b, c, d, e, f, cx2748774c + (w2 += sigma1(w0) + w11 + sigma0(w3)));
        Round(f, g, h, a, b, c, d, e, cx34b0bcb5 + (w3 += sigma1(w1) + w12 + sigma0(w4)));
        Round(e, f, g, h, a, b, c, d, cx391c0cb3 + (w4 += sigma1(w2) + w13 + sigma0(w5)));
        Round(d, e, f, g, h, a, b, c, cx4ed8aa4a + (w5 += sigma1(w3) + w14 + sigma0(w6)));
        Round(c, d, e, f, g, h, a, b, cx5b9cca4f + (w6 += sigma1(w4) + w15 + sigma0(w7)));
        Round(b, c, d, e, f, g, h, a, cx682e6ff3 + (w7 += sigma1(w5) + w0 + sigma0(w8)));
        Round(a, b, c, d, e, f, g, h, cx748f82ee + (w8 += sigma1(w6) + w1 + sigma0(w9)));
        Round(h, a, b, c, d, e, f, g, cx78a5636f + (w9 += sigma1(w7) + w2 + sigma0(w10)));
        Round(g, h, a, b, c, d, e, f, cx84c87814 + (w10 += sigma1(w8) + w3 + sigma0(w11)));
        Round(f, g, h, a, b, c, d, e, cx8cc70208 + (w11 += sigma1(w9) + w4 + sigma0(w12)));
        Round(e, f, g, h, a, b, c, d, cx90befffa + (w12 += sigma1(w10) + w5 + sigma0(w13)));
        Round(d, e, f, g, h, a, b, c, cxa4506ceb + (w13 += sigma1(w11) + w6 + sigma0(w14)));
        Round(c, d, e, f, g, h, a, b, cxbef9a3f7 + (w14 + sigma1(w12) + w7 + sigma0(w15)));
        Round(b, c, d, e, f, g, h, a, cxc67178f2 + (w15 + sigma1(w13) + w8 + sigma0(w0)));

        s[0] += a;
        s[1] += b;
        s[2] += c;
        s[3] += d;
        s[4] += e;
        s[5] += f;
        s[6] += g;
        s[7] += h;
        chunk += 64;
    }
}

void TransformD64(unsigned char* out, const unsigned char* in)
{
    // Transform 1
    uint32_t a = cx6a09e667ul;
    uint32_t b = cxbb67ae85ul;
    uint32_t c = cx3c6ef372ul;
    uint32_t d = cxa54ff53aul;
    uint32_t e = cx510e527ful;
    uint32_t f = cx9b05688cul;
    uint32_t g = cx1f83d9abul;
    uint32_t h = cx5be0cd19ul;

    uint32_t w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15;

    Round(a, b, c, d, e, f, g, h, cx428a2f98ul + (w0 = ReadBE32(in + 0)));
    Round(h, a, b, c, d, e, f, g, cx71374491ul + (w1 = ReadBE32(in + 4)));
    Round(g, h, a, b, c, d, e, f, cxb5c0fbcful + (w2 = ReadBE32(in + 8)));
    Round(f, g, h, a, b, c, d, e, cxe9b5dba5ul + (w3 = ReadBE32(in + 12)));
    Round(e, f, g, h, a, b, c, d, cx3956c25bul + (w4 = ReadBE32(in + 16)));
    Round(d, e, f, g, h, a, b, c, cx59f111f1ul + (w5 = ReadBE32(in + 20)));
    Round(c, d, e, f, g, h, a, b, cx923f82a4ul + (w6 = ReadBE32(in + 24)));
    Round(b, c, d, e, f, g, h, a, cxab1c5ed5ul + (w7 = ReadBE32(in + 28)));
    Round(a, b, c, d, e, f, g, h, cxd807aa98ul + (w8 = ReadBE32(in + 32)));
    Round(h, a, b, c, d, e, f, g, cx12835b01ul + (w9 = ReadBE32(in + 36)));
    Round(g, h, a, b, c, d, e, f, cx243185beul + (w10 = ReadBE32(in + 40)));
    Round(f, g, h, a, b, c, d, e, cx550c7dc3ul + (w11 = ReadBE32(in + 44)));
    Round(e, f, g, h, a, b, c, d, cx72be5d74ul + (w12 = ReadBE32(in + 48)));
    Round(d, e, f, g, h, a, b, c, cx80deb1feul + (w13 = ReadBE32(in + 52)));
    Round(c, d, e, f, g, h, a, b, cx9bdc06a7ul + (w14 = ReadBE32(in + 56)));
    Round(b, c, d, e, f, g, h, a, cxc19bf174ul + (w15 = ReadBE32(in + 60)));
    Round(a, b, c, d, e, f, g, h, cxe49b69c1ul + (w0 += sigma1(w14) + w9 + sigma0(w1)));
    Round(h, a, b, c, d, e, f, g, cxefbe4786ul + (w1 += sigma1(w15) + w10 + sigma0(w2)));
    Round(g, h, a, b, c, d, e, f, cx0fc19dc6ul + (w2 += sigma1(w0) + w11 + sigma0(w3)));
    Round(f, g, h, a, b, c, d, e, cx240ca1ccul + (w3 += sigma1(w1) + w12 + sigma0(w4)));
    Round(e, f, g, h, a, b, c, d, cx2de92c6ful + (w4 += sigma1(w2) + w13 + sigma0(w5)));
    Round(d, e, f, g, h, a, b, c, cx4a7484aaul + (w5 += sigma1(w3) + w14 + sigma0(w6)));
    Round(c, d, e, f, g, h, a, b, cx5cb0a9dcul + (w6 += sigma1(w4) + w15 + sigma0(w7)));
    Round(b, c, d, e, f, g, h, a, cx76f988daul + (w7 += sigma1(w5) + w0 + sigma0(w8)));
    Round(a, b, c, d, e, f, g, h, cx983e5152ul + (w8 += sigma1(w6) + w1 + sigma0(w9)));
    Round(h, a, b, c, d, e, f, g, cxa831c66dul + (w9 += sigma1(w7) + w2 + sigma0(w10)));
    Round(g, h, a, b, c, d, e, f, cxb00327c8ul + (w10 += sigma1(w8) + w3 + sigma0(w11)));
    Round(f, g, h, a, b, c, d, e, cxbf597fc7ul + (w11 += sigma1(w9) + w4 + sigma0(w12)));
    Round(e, f, g, h, a, b, c, d, cxc6e00bf3ul + (w12 += sigma1(w10) + w5 + sigma0(w13)));
    Round(d, e, f, g, h, a, b, c, cxd5a79147ul + (w13 += sigma1(w11) + w6 + sigma0(w14)));
    Round(c, d, e, f, g, h, a, b, cx06ca6351ul + (w14 += sigma1(w12) + w7 + sigma0(w15)));
    Round(b, c, d, e, f, g, h, a, cx14292967ul + (w15 += sigma1(w13) + w8 + sigma0(w0)));
    Round(a, b, c, d, e, f, g, h, cx27b70a85ul + (w0 += sigma1(w14) + w9 + sigma0(w1)));
    Round(h, a, b, c, d, e, f, g, cx2e1b2138ul + (w1 += sigma1(w15) + w10 + sigma0(w2)));
    Round(g, h, a, b, c, d, e, f, cx4d2c6dfcul + (w2 += sigma1(w0) + w11 + sigma0(w3)));
    Round(f, g, h, a, b, c, d, e, cx53380d13ul + (w3 += sigma1(w1) + w12 + sigma0(w4)));
    Round(e, f, g, h, a, b, c, d, cx650a7354ul + (w4 += sigma1(w2) + w13 + sigma0(w5)));
    Round(d, e, f, g, h, a, b, c, cx766a0abbul + (w5 += sigma1(w3) + w14 + sigma0(w6)));
    Round(c, d, e, f, g, h, a, b, cx81c2c92eul + (w6 += sigma1(w4) + w15 + sigma0(w7)));
    Round(b, c, d, e, f, g, h, a, cx92722c85ul + (w7 += sigma1(w5) + w0 + sigma0(w8)));
    Round(a, b, c, d, e, f, g, h, cxa2bfe8a1ul + (w8 += sigma1(w6) + w1 + sigma0(w9)));
    Round(h, a, b, c, d, e, f, g, cxa81a664bul + (w9 += sigma1(w7) + w2 + sigma0(w10)));
    Round(g, h, a, b, c, d, e, f, cxc24b8b70ul + (w10 += sigma1(w8) + w3 + sigma0(w11)));
    Round(f, g, h, a, b, c, d, e, cxc76c51a3ul + (w11 += sigma1(w9) + w4 + sigma0(w12)));
    Round(e, f, g, h, a, b, c, d, cxd192e819ul + (w12 += sigma1(w10) + w5 + sigma0(w13)));
    Round(d, e, f, g, h, a, b, c, cxd6990624ul + (w13 += sigma1(w11) + w6 + sigma0(w14)));
    Round(c, d, e, f, g, h, a, b, cxf40e3585ul + (w14 += sigma1(w12) + w7 + sigma0(w15)));
    Round(b, c, d, e, f, g, h, a, cx106aa070ul + (w15 += sigma1(w13) + w8 + sigma0(w0)));
    Round(a, b, c, d, e, f, g, h, cx19a4c116ul + (w0 += sigma1(w14) + w9 + sigma0(w1)));
    Round(h, a, b, c, d, e, f, g, cx1e376c08ul + (w1 += sigma1(w15) + w10 + sigma0(w2)));
    Round(g, h, a, b, c, d, e, f, cx2748774cul + (w2 += sigma1(w0) + w11 + sigma0(w3)));
    Round(f, g, h, a, b, c, d, e, cx34b0bcb5ul + (w3 += sigma1(w1) + w12 + sigma0(w4)));
    Round(e, f, g, h, a, b, c, d, cx391c0cb3ul + (w4 += sigma1(w2) + w13 + sigma0(w5)));
    Round(d, e, f, g, h, a, b, c, cx4ed8aa4aul + (w5 += sigma1(w3) + w14 + sigma0(w6)));
    Round(c, d, e, f, g, h, a, b, cx5b9cca4ful + (w6 += sigma1(w4) + w15 + sigma0(w7)));
    Round(b, c, d, e, f, g, h, a, cx682e6ff3ul + (w7 += sigma1(w5) + w0 + sigma0(w8)));
    Round(a, b, c, d, e, f, g, h, cx748f82eeul + (w8 += sigma1(w6) + w1 + sigma0(w9)));
    Round(h, a, b, c, d, e, f, g, cx78a5636ful + (w9 += sigma1(w7) + w2 + sigma0(w10)));
    Round(g, h, a, b, c, d, e, f, cx84c87814ul + (w10 += sigma1(w8) + w3 + sigma0(w11)));
    Round(f, g, h, a, b, c, d, e, cx8cc70208ul + (w11 += sigma1(w9) + w4 + sigma0(w12)));
    Round(e, f, g, h, a, b, c, d, cx90befffaul + (w12 += sigma1(w10) + w5 + sigma0(w13)));
    Round(d, e, f, g, h, a, b, c, cxa4506cebul + (w13 += sigma1(w11) + w6 + sigma0(w14)));
    Round(c, d, e, f, g, h, a, b, cxbef9a3f7ul + (w14 + sigma1(w12) + w7 + sigma0(w15)));
    Round(b, c, d, e, f, g, h, a, cxc67178f2ul + (w15 + sigma1(w13) + w8 + sigma0(w0)));

    a += cx6a09e667ul;
    b += cxbb67ae85ul;
    c += cx3c6ef372ul;
    d += cxa54ff53aul;
    e += cx510e527ful;
    f += cx9b05688cul;
    g += cx1f83d9abul;
    h += cx5be0cd19ul;

    uint32_t t0 = a, t1 = b, t2 = c, t3 = d, t4 = e, t5 = f, t6 = g, t7 = h;

    // Transform 2
    Round(a, b, c, d, e, f, g, h, cxc28a2f98ul);
    Round(h, a, b, c, d, e, f, g, cx71374491ul);
    Round(g, h, a, b, c, d, e, f, cxb5c0fbcful);
    Round(f, g, h, a, b, c, d, e, cxe9b5dba5ul);
    Round(e, f, g, h, a, b, c, d, cx3956c25bul);
    Round(d, e, f, g, h, a, b, c, cx59f111f1ul);
    Round(c, d, e, f, g, h, a, b, cx923f82a4ul);
    Round(b, c, d, e, f, g, h, a, cxab1c5ed5ul);
    Round(a, b, c, d, e, f, g, h, cxd807aa98ul);
    Round(h, a, b, c, d, e, f, g, cx12835b01ul);
    Round(g, h, a, b, c, d, e, f, cx243185beul);
    Round(f, g, h, a, b, c, d, e, cx550c7dc3ul);
    Round(e, f, g, h, a, b, c, d, cx72be5d74ul);
    Round(d, e, f, g, h, a, b, c, cx80deb1feul);
    Round(c, d, e, f, g, h, a, b, cx9bdc06a7ul);
    Round(b, c, d, e, f, g, h, a, cxc19bf374ul);
    Round(a, b, c, d, e, f, g, h, cx649b69c1ul);
    Round(h, a, b, c, d, e, f, g, cxf0fe4786ul);
    Round(g, h, a, b, c, d, e, f, cx0fe1edc6ul);
    Round(f, g, h, a, b, c, d, e, cx240cf254ul);
    Round(e, f, g, h, a, b, c, d, cx4fe9346ful);
    Round(d, e, f, g, h, a, b, c, cx6cc984beul);
    Round(c, d, e, f, g, h, a, b, cx61b9411eul);
    Round(b, c, d, e, f, g, h, a, cx16f988faul);
    Round(a, b, c, d, e, f, g, h, cxf2c65152ul);
    Round(h, a, b, c, d, e, f, g, cxa88e5a6dul);
    Round(g, h, a, b, c, d, e, f, cxb019fc65ul);
    Round(f, g, h, a, b, c, d, e, cxb9d99ec7ul);
    Round(e, f, g, h, a, b, c, d, cx9a1231c3ul);
    Round(d, e, f, g, h, a, b, c, cxe70eeaa0ul);
    Round(c, d, e, f, g, h, a, b, cxfdb1232bul);
    Round(b, c, d, e, f, g, h, a, cxc7353eb0ul);
    Round(a, b, c, d, e, f, g, h, cx3069bad5ul);
    Round(h, a, b, c, d, e, f, g, cxcb976d5ful);
    Round(g, h, a, b, c, d, e, f, cx5a0f118ful);
    Round(f, g, h, a, b, c, d, e, cxdc1eeefdul);
    Round(e, f, g, h, a, b, c, d, cx0a35b689ul);
    Round(d, e, f, g, h, a, b, c, cxde0b7a04ul);
    Round(c, d, e, f, g, h, a, b, cx58f4ca9dul);
    Round(b, c, d, e, f, g, h, a, cxe15d5b16ul);
    Round(a, b, c, d, e, f, g, h, cx007f3e86ul);
    Round(h, a, b, c, d, e, f, g, cx37088980ul);
    Round(g, h, a, b, c, d, e, f, cxa507ea32ul);
    Round(f, g, h, a, b, c, d, e, cx6fab9537ul);
    Round(e, f, g, h, a, b, c, d, cx17406110ul);
    Round(d, e, f, g, h, a, b, c, cx0d8cd6f1ul);
    Round(c, d, e, f, g, h, a, b, cxcdaa3b6dul);
    Round(b, c, d, e, f, g, h, a, cxc0bbbe37ul);
    Round(a, b, c, d, e, f, g, h, cx83613bdaul);
    Round(h, a, b, c, d, e, f, g, cxdb48a363ul);
    Round(g, h, a, b, c, d, e, f, cx0b02e931ul);
    Round(f, g, h, a, b, c, d, e, cx6fd15ca7ul);
    Round(e, f, g, h, a, b, c, d, cx521afacaul);
    Round(d, e, f, g, h, a, b, c, cx31338431ul);
    Round(c, d, e, f, g, h, a, b, cx6ed41a95ul);
    Round(b, c, d, e, f, g, h, a, cx6d437890ul);
    Round(a, b, c, d, e, f, g, h, cxc39c91f2ul);
    Round(h, a, b, c, d, e, f, g, cx9eccabbdul);
    Round(g, h, a, b, c, d, e, f, cxb5c9a0e6ul);
    Round(f, g, h, a, b, c, d, e, cx532fb63cul);
    Round(e, f, g, h, a, b, c, d, cxd2c741c6ul);
    Round(d, e, f, g, h, a, b, c, cx07237ea3ul);
    Round(c, d, e, f, g, h, a, b, cxa4954b68ul);
    Round(b, c, d, e, f, g, h, a, cx4c191d76ul);

    w0 = t0 + a;
    w1 = t1 + b;
    w2 = t2 + c;
    w3 = t3 + d;
    w4 = t4 + e;
    w5 = t5 + f;
    w6 = t6 + g;
    w7 = t7 + h;

    // Transform 3
    a = cx6a09e667ul;
    b = cxbb67ae85ul;
    c = cx3c6ef372ul;
    d = cxa54ff53aul;
    e = cx510e527ful;
    f = cx9b05688cul;
    g = cx1f83d9abul;
    h = cx5be0cd19ul;

    Round(a, b, c, d, e, f, g, h, cx428a2f98ul + w0);
    Round(h, a, b, c, d, e, f, g, cx71374491ul + w1);
    Round(g, h, a, b, c, d, e, f, cxb5c0fbcful + w2);
    Round(f, g, h, a, b, c, d, e, cxe9b5dba5ul + w3);
    Round(e, f, g, h, a, b, c, d, cx3956c25bul + w4);
    Round(d, e, f, g, h, a, b, c, cx59f111f1ul + w5);
    Round(c, d, e, f, g, h, a, b, cx923f82a4ul + w6);
    Round(b, c, d, e, f, g, h, a, cxab1c5ed5ul + w7);
    Round(a, b, c, d, e, f, g, h, cx5807aa98ul);
    Round(h, a, b, c, d, e, f, g, cx12835b01ul);
    Round(g, h, a, b, c, d, e, f, cx243185beul);
    Round(f, g, h, a, b, c, d, e, cx550c7dc3ul);
    Round(e, f, g, h, a, b, c, d, cx72be5d74ul);
    Round(d, e, f, g, h, a, b, c, cx80deb1feul);
    Round(c, d, e, f, g, h, a, b, cx9bdc06a7ul);
    Round(b, c, d, e, f, g, h, a, cxc19bf274ul);
    Round(a, b, c, d, e, f, g, h, cxe49b69c1ul + (w0 += sigma0(w1)));
    Round(h, a, b, c, d, e, f, g, cxefbe4786ul + (w1 += cxa00000ul + sigma0(w2)));
    Round(g, h, a, b, c, d, e, f, cx0fc19dc6ul + (w2 += sigma1(w0) + sigma0(w3)));
    Round(f, g, h, a, b, c, d, e, cx240ca1ccul + (w3 += sigma1(w1) + sigma0(w4)));
    Round(e, f, g, h, a, b, c, d, cx2de92c6ful + (w4 += sigma1(w2) + sigma0(w5)));
    Round(d, e, f, g, h, a, b, c, cx4a7484aaul + (w5 += sigma1(w3) + sigma0(w6)));
    Round(c, d, e, f, g, h, a, b, cx5cb0a9dcul + (w6 += sigma1(w4) + cx100ul + sigma0(w7)));
    Round(b, c, d, e, f, g, h, a, cx76f988daul + (w7 += sigma1(w5) + w0 + cx11002000ul));
    Round(a, b, c, d, e, f, g, h, cx983e5152ul + (w8 = cx80000000ul + sigma1(w6) + w1));
    Round(h, a, b, c, d, e, f, g, cxa831c66dul + (w9 = sigma1(w7) + w2));
    Round(g, h, a, b, c, d, e, f, cxb00327c8ul + (w10 = sigma1(w8) + w3));
    Round(f, g, h, a, b, c, d, e, cxbf597fc7ul + (w11 = sigma1(w9) + w4));
    Round(e, f, g, h, a, b, c, d, cxc6e00bf3ul + (w12 = sigma1(w10) + w5));
    Round(d, e, f, g, h, a, b, c, cxd5a79147ul + (w13 = sigma1(w11) + w6));
    Round(c, d, e, f, g, h, a, b, cx06ca6351ul + (w14 = sigma1(w12) + w7 + cx400022ul));
    Round(b, c, d, e, f, g, h, a, cx14292967ul + (w15 = cx100ul + sigma1(w13) + w8 + sigma0(w0)));
    Round(a, b, c, d, e, f, g, h, cx27b70a85ul + (w0 += sigma1(w14) + w9 + sigma0(w1)));
    Round(h, a, b, c, d, e, f, g, cx2e1b2138ul + (w1 += sigma1(w15) + w10 + sigma0(w2)));
    Round(g, h, a, b, c, d, e, f, cx4d2c6dfcul + (w2 += sigma1(w0) + w11 + sigma0(w3)));
    Round(f, g, h, a, b, c, d, e, cx53380d13ul + (w3 += sigma1(w1) + w12 + sigma0(w4)));
    Round(e, f, g, h, a, b, c, d, cx650a7354ul + (w4 += sigma1(w2) + w13 + sigma0(w5)));
    Round(d, e, f, g, h, a, b, c, cx766a0abbul + (w5 += sigma1(w3) + w14 + sigma0(w6)));
    Round(c, d, e, f, g, h, a, b, cx81c2c92eul + (w6 += sigma1(w4) + w15 + sigma0(w7)));
    Round(b, c, d, e, f, g, h, a, cx92722c85ul + (w7 += sigma1(w5) + w0 + sigma0(w8)));
    Round(a, b, c, d, e, f, g, h, cxa2bfe8a1ul + (w8 += sigma1(w6) + w1 + sigma0(w9)));
    Round(h, a, b, c, d, e, f, g, cxa81a664bul + (w9 += sigma1(w7) + w2 + sigma0(w10)));
    Round(g, h, a, b, c, d, e, f, cxc24b8b70ul + (w10 += sigma1(w8) + w3 + sigma0(w11)));
    Round(f, g, h, a, b, c, d, e, cxc76c51a3ul + (w11 += sigma1(w9) + w4 + sigma0(w12)));
    Round(e, f, g, h, a, b, c, d, cxd192e819ul + (w12 += sigma1(w10) + w5 + sigma0(w13)));
    Round(d, e, f, g, h, a, b, c, cxd6990624ul + (w13 += sigma1(w11) + w6 + sigma0(w14)));
    Round(c, d, e, f, g, h, a, b, cxf40e3585ul + (w14 += sigma1(w12) + w7 + sigma0(w15)));
    Round(b, c, d, e, f, g, h, a, cx106aa070ul + (w15 += sigma1(w13) + w8 + sigma0(w0)));
    Round(a, b, c, d, e, f, g, h, cx19a4c116ul + (w0 += sigma1(w14) + w9 + sigma0(w1)));
    Round(h, a, b, c, d, e, f, g, cx1e376c08ul + (w1 += sigma1(w15) + w10 + sigma0(w2)));
    Round(g, h, a, b, c, d, e, f, cx2748774cul + (w2 += sigma1(w0) + w11 + sigma0(w3)));
    Round(f, g, h, a, b, c, d, e, cx34b0bcb5ul + (w3 += sigma1(w1) + w12 + sigma0(w4)));
    Round(e, f, g, h, a, b, c, d, cx391c0cb3ul + (w4 += sigma1(w2) + w13 + sigma0(w5)));
    Round(d, e, f, g, h, a, b, c, cx4ed8aa4aul + (w5 += sigma1(w3) + w14 + sigma0(w6)));
    Round(c, d, e, f, g, h, a, b, cx5b9cca4ful + (w6 += sigma1(w4) + w15 + sigma0(w7)));
    Round(b, c, d, e, f, g, h, a, cx682e6ff3ul + (w7 += sigma1(w5) + w0 + sigma0(w8)));
    Round(a, b, c, d, e, f, g, h, cx748f82eeul + (w8 += sigma1(w6) + w1 + sigma0(w9)));
    Round(h, a, b, c, d, e, f, g, cx78a5636ful + (w9 += sigma1(w7) + w2 + sigma0(w10)));
    Round(g, h, a, b, c, d, e, f, cx84c87814ul + (w10 += sigma1(w8) + w3 + sigma0(w11)));
    Round(f, g, h, a, b, c, d, e, cx8cc70208ul + (w11 += sigma1(w9) + w4 + sigma0(w12)));
    Round(e, f, g, h, a, b, c, d, cx90befffaul + (w12 += sigma1(w10) + w5 + sigma0(w13)));
    Round(d, e, f, g, h, a, b, c, cxa4506cebul + (w13 += sigma1(w11) + w6 + sigma0(w14)));
    Round(c, d, e, f, g, h, a, b, cxbef9a3f7ul + (w14 + sigma1(w12) + w7 + sigma0(w15)));
    Round(b, c, d, e, f, g, h, a, cxc67178f2ul + (w15 + sigma1(w13) + w8 + sigma0(w0)));

    // Output
    WriteBE32(out + 0, a + cx6a09e667ul);
    WriteBE32(out + 4, b + cxbb67ae85ul);
    WriteBE32(out + 8, c + cx3c6ef372ul);
    WriteBE32(out + 12, d + cxa54ff53aul);
    WriteBE32(out + 16, e + cx510e527ful);
    WriteBE32(out + 20, f + cx9b05688cul);
    WriteBE32(out + 24, g + cx1f83d9abul);
    WriteBE32(out + 28, h + cx5be0cd19ul);
}

} // namespace sha256

typedef void (*TransformType)(uint32_t*, const unsigned char*, size_t);
typedef void (*TransformD64Type)(unsigned char*, const unsigned char*);

template<TransformType tr>
void TransformD64Wrapper(unsigned char* out, const unsigned char* in)
{
    uint32_t s[8];
    static const unsigned char padding1[64] = {
        cx80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0
    };
    unsigned char buffer2[64] = {
        0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        cx80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0
    };
    sha256::Initialize(s);
    tr(s, in, 1);
    tr(s, padding1, 1);
    WriteBE32(buffer2 + 0, s[0]);
    WriteBE32(buffer2 + 4, s[1]);
    WriteBE32(buffer2 + 8, s[2]);
    WriteBE32(buffer2 + 12, s[3]);
    WriteBE32(buffer2 + 16, s[4]);
    WriteBE32(buffer2 + 20, s[5]);
    WriteBE32(buffer2 + 24, s[6]);
    WriteBE32(buffer2 + 28, s[7]);
    sha256::Initialize(s);
    tr(s, buffer2, 1);
    WriteBE32(out + 0, s[0]);
    WriteBE32(out + 4, s[1]);
    WriteBE32(out + 8, s[2]);
    WriteBE32(out + 12, s[3]);
    WriteBE32(out + 16, s[4]);
    WriteBE32(out + 20, s[5]);
    WriteBE32(out + 24, s[6]);
    WriteBE32(out + 28, s[7]);
}

TransformType Transform = sha256::Transform;
TransformD64Type TransformD64 = sha256::TransformD64;
TransformD64Type TransformD64_2way = nullptr;
TransformD64Type TransformD64_4way = nullptr;
TransformD64Type TransformD64_8way = nullptr;

bool SelfTest() {
    // Input state (equal to the initial SHA256 state)
    static const uint32_t init[8] = {
        cx6a09e667ul, cxbb67ae85ul, cx3c6ef372ul, cxa54ff53aul, cx510e527ful, cx9b05688cul, cx1f83d9abul, cx5be0cd19ul
    };
    // Some random input data to test with
    static const unsigned char data[641] = "-" // Intentionally not aligned
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do "
        "eiusmod tempor incididunt ut labore et dolore magna aliqua. Et m"
        "olestie ac feugiat sed lectus vestibulum mattis ullamcorper. Mor"
        "bi blandit cursus risus at ultrices mi tempus imperdiet nulla. N"
        "unc congue nisi vita suscipit tellus mauris. Imperdiet proin fer"
        "mentum leo vel orci. Massa tempor nec feugiat nisl pretium fusce"
        " id velit. Telus in metus vulputate eu scelerisque felis. Mi tem"
        "pus imperdiet nulla malesuada pellentesque. Tristique magna sit.";
    // Expected output state for hashing the i*64 first input bytes above (excluding SHA256 padding).
    static const uint32_t result[9][8] = {
        {cx6a09e667ul, cxbb67ae85ul, cx3c6ef372ul, cxa54ff53aul, cx510e527ful, cx9b05688cul, cx1f83d9abul, cx5be0cd19ul},
        {cx91f8ec6bul, cx4da10fe3ul, cx1c9c292cul, cx45e18185ul, cx435cc111ul, cx3ca26f09ul, cxeb954caeul, cx402a7069ul},
        {cxcabea5acul, cx374fb97cul, cx182ad996ul, cx7bd69cbful, cx450ff900ul, cxc1d2be8aul, cx6a41d505ul, cxe6212dc3ul},
        {cxbcff09d6ul, cx3e76f36eul, cx3ecb2501ul, cx78866e97ul, cxe1c1e2fdul, cx32f4eafful, cx8aa6c4e5ul, cxdfc024bcul},
        {cxa08c5d94ul, cx0a862f93ul, cx6b7f2f40ul, cx8f9fae76ul, cx6d40439ful, cx79dcee0cul, cx3e39ff3aul, cxdc3bdbb1ul},
        {cx216a0895ul, cx9f1a3662ul, cxe99946f9ul, cx87ba4364ul, cx0fb5db2cul, cx12bed3d3ul, cx6689c0c7ul, cx292f1b04ul},
        {cxca3067f8ul, cxbc8c2656ul, cx37cb7e0dul, cx9b6b8b0ful, cx46dc380bul, cxf1287f57ul, cxc42e4b23ul, cx3fefe94dul},
        {cx3e4c4039ul, cxbb6fca8cul, cx6f27d2f7ul, cx301e44a4ul, cx8352ba14ul, cx5769ce37ul, cx48a1155ful, cxc0e1c4c6ul},
        {cxfe2fa9ddul, cx69d0862bul, cx1ae0db23ul, cx471f9244ul, cxf55c0145ul, cxc30f9c3bul, cx40a84ea0ul, cx5b8a266cul},
    };
    // Expected output for each of the individual 8 64-byte messages under full double SHA256 (including padding).
    static const unsigned char result_d64[256] = {
        cx09, cx3a, cxc4, cxd0, cx0f, cxf7, cx57, cxe1, cx72, cx85, cx79, cx42, cxfe, cxe7, cxe0, cxa0,
        cxfc, cx52, cxd7, cxdb, cx07, cx63, cx45, cxfb, cx53, cx14, cx7d, cx17, cx22, cx86, cxf0, cx52,
        cx48, cxb6, cx11, cx9e, cx6e, cx48, cx81, cx6d, cxcc, cx57, cx1f, cxb2, cx97, cxa8, cxd5, cx25,
        cx9b, cx82, cxaa, cx89, cxe2, cxfd, cx2d, cx56, cxe8, cx28, cx83, cx0b, cxe2, cxfa, cx53, cxb7,
        cxd6, cx6b, cx07, cx85, cx83, cxb0, cx10, cxa2, cxf5, cx51, cx3c, cxf9, cx60, cx03, cxab, cx45,
        cx6c, cx15, cx6e, cxef, cxb5, cxac, cx3e, cx6c, cxdf, cxb4, cx92, cx22, cx2d, cxce, cxbf, cx3e,
        cxe9, cxe5, cxf6, cx29, cx0e, cx01, cx4f, cxd2, cxd4, cx45, cx65, cxb3, cxbb, cxf2, cx4c, cx16,
        cx37, cx50, cx3c, cx6e, cx49, cx8c, cx5a, cx89, cx2b, cx1b, cxab, cxc4, cx37, cxd1, cx46, cxe9,
        cx3d, cx0e, cx85, cxa2, cx50, cx73, cxa1, cx5e, cx54, cx37, cxd7, cx94, cx17, cx56, cxc2, cxd8,
        cxe5, cx9f, cxed, cx4e, cxae, cx15, cx42, cx06, cx0d, cx74, cx74, cx5e, cx24, cx30, cxce, cxd1,
        cx9e, cx50, cxa3, cx9a, cxb8, cxf0, cx4a, cx57, cx69, cx78, cx67, cx12, cx84, cx58, cxbe, cxc7,
        cx36, cxaa, cxee, cx7c, cx64, cxa3, cx76, cxec, cxff, cx55, cx41, cx00, cx2a, cx44, cx68, cx4d,
        cxb6, cx53, cx9e, cx1c, cx95, cxb7, cxca, cxdc, cx7f, cx7d, cx74, cx27, cx5c, cx8e, cxa6, cx84,
        cxb5, cxac, cx87, cxa9, cxf3, cxff, cx75, cxf2, cx34, cxcd, cx1a, cx3b, cx82, cx2c, cx2b, cx4e,
        cx6a, cx46, cx30, cxa6, cx89, cx86, cx23, cxac, cxf8, cxa5, cx15, cxe9, cx0a, cxaa, cx1e, cx9a,
        cxd7, cx93, cx6b, cx28, cxe4, cx3b, cxfd, cx59, cxc6, cxed, cx7c, cx5f, cxa5, cx41, cxcb, cx51
    };


    // Test Transform() for 0 through 8 transformations.
    for (size_t i = 0; i <= 8; ++i) {
        uint32_t state[8];
        std::copy(init, init + 8, state);
        Transform(state, data + 1, i);
        if (!std::equal(state, state + 8, result[i])) return false;
    }

    // Test TransformD64
    unsigned char out[32];
    TransformD64(out, data + 1);
    if (!std::equal(out, out + 32, result_d64)) return false;

    // Test TransformD64_2way, if available.
    if (TransformD64_2way) {
        unsigned char out[64];
        TransformD64_2way(out, data + 1);
        if (!std::equal(out, out + 64, result_d64)) return false;
    }

    // Test TransformD64_4way, if available.
    if (TransformD64_4way) {
        unsigned char out[128];
        TransformD64_4way(out, data + 1);
        if (!std::equal(out, out + 128, result_d64)) return false;
    }

    // Test TransformD64_8way, if available.
    if (TransformD64_8way) {
        unsigned char out[256];
        TransformD64_8way(out, data + 1);
        if (!std::equal(out, out + 256, result_d64)) return false;
    }

    return true;
}

#if defined(USE_ASM) && (defined(__x86_64__) || defined(__amd64__) || defined(__i386__))
/** Check whether the OS has enabled AVX registers. */
bool AVXEnabled()
{
    uint32_t a, d;
    __asm__("xgetbv" : "=a"(a), "=d"(d) : "c"(0));
    return (a & 6) == 6;
}
#endif
} // namespace


std::string SHA256AutoDetect()
{
    std::string ret = "standard";
#if defined(USE_ASM) && defined(HAVE_GETCPUID)
    bool have_sse4 = false;
    bool have_xsave = false;
    bool have_avx = false;
    bool have_avx2 = false;
    bool have_shani = false;
    bool enabled_avx = false;

    (void)AVXEnabled;
    (void)have_sse4;
    (void)have_avx;
    (void)have_xsave;
    (void)have_avx2;
    (void)have_shani;
    (void)enabled_avx;

    uint32_t eax, ebx, ecx, edx;
    GetCPUID(1, 0, eax, ebx, ecx, edx);
    have_sse4 = (ecx >> 19) & 1;
    have_xsave = (ecx >> 27) & 1;
    have_avx = (ecx >> 28) & 1;
    if (have_xsave && have_avx) {
        enabled_avx = AVXEnabled();
    }
    if (have_sse4) {
        GetCPUID(7, 0, eax, ebx, ecx, edx);
        have_avx2 = (ebx >> 5) & 1;
        have_shani = (ebx >> 29) & 1;
    }

#if defined(ENABLE_SHANI) && !defined(BUILD_chymera_INTERNAL)
    if (have_shani) {
        Transform = sha256_shani::Transform;
        TransformD64 = TransformD64Wrapper<sha256_shani::Transform>;
        TransformD64_2way = sha256d64_shani::Transform_2way;
        ret = "shani(1way,2way)";
        have_sse4 = false; // Disable SSE4/AVX2;
        have_avx2 = false;
    }
#endif

    if (have_sse4) {
#if defined(__x86_64__) || defined(__amd64__)
        Transform = sha256_sse4::Transform;
        TransformD64 = TransformD64Wrapper<sha256_sse4::Transform>;
        ret = "sse4(1way)";
#endif
#if defined(ENABLE_SSE41) && !defined(BUILD_chymera_INTERNAL)
        TransformD64_4way = sha256d64_sse41::Transform_4way;
        ret += ",sse41(4way)";
#endif
    }

#if defined(ENABLE_AVX2) && !defined(BUILD_chymera_INTERNAL)
    if (have_avx2 && have_avx && enabled_avx) {
        TransformD64_8way = sha256d64_avx2::Transform_8way;
        ret += ",avx2(8way)";
    }
#endif
#endif

    assert(SelfTest());
    return ret;
}

////// SHA-256

CSHA256::CSHA256() : bytes(0)
{
    sha256::Initialize(s);
}

CSHA256& CSHA256::Write(const unsigned char* data, size_t len)
{
    const unsigned char* end = data + len;
    size_t bufsize = bytes % 64;
    if (bufsize && bufsize + len >= 64) {
        // Fill the buffer, and process it.
        memcpy(buf + bufsize, data, 64 - bufsize);
        bytes += 64 - bufsize;
        data += 64 - bufsize;
        Transform(s, buf, 1);
        bufsize = 0;
    }
    if (end - data >= 64) {
        size_t blocks = (end - data) / 64;
        Transform(s, data, blocks);
        data += 64 * blocks;
        bytes += 64 * blocks;
    }
    if (end > data) {
        // Fill the buffer with what remains.
        memcpy(buf + bufsize, data, end - data);
        bytes += end - data;
    }
    return *this;
}

void CSHA256::Finalize(unsigned char hash[OUTPUT_SIZE])
{
    static const unsigned char pad[64] = {cx80};
    unsigned char sizedesc[8];
    WriteBE64(sizedesc, bytes << 3);
    Write(pad, 1 + ((119 - (bytes % 64)) % 64));
    Write(sizedesc, 8);
    WriteBE32(hash, s[0]);
    WriteBE32(hash + 4, s[1]);
    WriteBE32(hash + 8, s[2]);
    WriteBE32(hash + 12, s[3]);
    WriteBE32(hash + 16, s[4]);
    WriteBE32(hash + 20, s[5]);
    WriteBE32(hash + 24, s[6]);
    WriteBE32(hash + 28, s[7]);
}

CSHA256& CSHA256::Reset()
{
    bytes = 0;
    sha256::Initialize(s);
    return *this;
}

void SHA256D64(unsigned char* out, const unsigned char* in, size_t blocks)
{
    if (TransformD64_8way) {
        while (blocks >= 8) {
            TransformD64_8way(out, in);
            out += 256;
            in += 512;
            blocks -= 8;
        }
    }
    if (TransformD64_4way) {
        while (blocks >= 4) {
            TransformD64_4way(out, in);
            out += 128;
            in += 256;
            blocks -= 4;
        }
    }
    if (TransformD64_2way) {
        while (blocks >= 2) {
            TransformD64_2way(out, in);
            out += 64;
            in += 128;
            blocks -= 2;
        }
    }
    while (blocks) {
        TransformD64(out, in);
        out += 32;
        in += 64;
        --blocks;
    }
}
