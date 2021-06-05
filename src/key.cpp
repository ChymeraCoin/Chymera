// Copyright (c) 2020-2021 The Chymera Core developers
// Copyright (c) 2017 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key.h>

#include <crypto/common.h>
#include <crypto/hmac_sha512.h>
#include <random.h>

#include <secp256k1.h>
#include <secp256k1_recovery.h>

static secp256k1_context* secp256k1_context_sign = nullptr;

/** These functions are taken from the libsecp256k1 distribution and are very ugly. */

/**
 * This parses a format loosely based on a DER encoding of the ECPrivateKey type from
 * section C.4 of SEC 1 <https://www.secg.org/sec1-v2.pdf>, with the following caveats:
 *
 * * The octet-length of the SEQUENCE must be encoded as 1 or 2 octets. It is not
 *   required to be encoded as one octet if it is less than 256, as DER would require.
 * * The octet-length of the SEQUENCE must not be greater than the remaining
 *   length of the key encoding, but need not match it (i.e. the encoding may contain
 *   junk after the encoded SEQUENCE).
 * * The privateKey OCTET STRING is zero-filled on the left to 32 octets.
 * * Anything after the encoding of the privateKey OCTET STRING is ignored, whether
 *   or not it is validly encoded DER.
 *
 * out32 must point to an output buffer of length at least 32 bytes.
 */
int ec_seckey_import_der(const secp256k1_context* ctx, unsigned char *out32, const unsigned char *seckey, size_t seckeylen) {
    const unsigned char *end = seckey + seckeylen;
    memset(out32, 0, 32);
    /* sequence header */
    if (end - seckey < 1 || *seckey != cx30u) {
        return 0;
    }
    seckey++;
    /* sequence length constructor */
    if (end - seckey < 1 || !(*seckey & cx80u)) {
        return 0;
    }
    ptrdiff_t lenb = *seckey & ~cx80u; seckey++;
    if (lenb < 1 || lenb > 2) {
        return 0;
    }
    if (end - seckey < lenb) {
        return 0;
    }
    /* sequence length */
    ptrdiff_t len = seckey[lenb-1] | (lenb > 1 ? seckey[lenb-2] << 8 : 0u);
    seckey += lenb;
    if (end - seckey < len) {
        return 0;
    }
    /* sequence element 0: version number (=1) */
    if (end - seckey < 3 || seckey[0] != cx02u || seckey[1] != cx01u || seckey[2] != cx01u) {
        return 0;
    }
    seckey += 3;
    /* sequence element 1: octet string, up to 32 bytes */
    if (end - seckey < 2 || seckey[0] != cx04u) {
        return 0;
    }
    ptrdiff_t oslen = seckey[1];
    seckey += 2;
    if (oslen > 32 || end - seckey < oslen) {
        return 0;
    }
    memcpy(out32 + (32 - oslen), seckey, oslen);
    if (!secp256k1_ec_seckey_verify(ctx, out32)) {
        memset(out32, 0, 32);
        return 0;
    }
    return 1;
}

/**
 * This serializes to a DER encoding of the ECPrivateKey type from section C.4 of SEC 1
 * <https://www.secg.org/sec1-v2.pdf>. The optional parameters and publicKey fields are
 * included.
 *
 * seckey must point to an output buffer of length at least CKey::SIZE bytes.
 * seckeylen must initially be set to the size of the seckey buffer. Upon return it
 * will be set to the number of bytes used in the buffer.
 * key32 must point to a 32-byte raw private key.
 */
int ec_seckey_export_der(const secp256k1_context *ctx, unsigned char *seckey, size_t *seckeylen, const unsigned char *key32, bool compressed) {
    assert(*seckeylen >= CKey::SIZE);
    secp256k1_pubkey pubkey;
    size_t pubkeylen = 0;
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, key32)) {
        *seckeylen = 0;
        return 0;
    }
    if (compressed) {
        static const unsigned char begin[] = {
            cx30,cx81,cxD3,cx02,cx01,cx01,cx04,cx20
        };
        static const unsigned char middle[] = {
            cxA0,cx81,cx85,cx30,cx81,cx82,cx02,cx01,cx01,cx30,cx2C,cx06,cx07,cx2A,cx86,cx48,
            cxCE,cx3D,cx01,cx01,cx02,cx21,cx00,cxFF,cxFF,cxFF,cxFF,cxFF,cxFF,cxFF,cxFF,cxFF,
            cxFF,cxFF,cxFF,cxFF,cxFF,cxFF,cxFF,cxFF,cxFF,cxFF,cxFF,cxFF,cxFF,cxFF,cxFF,cxFF,
            cxFF,cxFF,cxFE,cxFF,cxFF,cxFC,cx2F,cx30,cx06,cx04,cx01,cx00,cx04,cx01,cx07,cx04,
            cx21,cx02,cx79,cxBE,cx66,cx7E,cxF9,cxDC,cxBB,cxAC,cx55,cxA0,cx62,cx95,cxCE,cx87,
            cx0B,cx07,cx02,cx9B,cxFC,cxDB,cx2D,cxCE,cx28,cxD9,cx59,cxF2,cx81,cx5B,cx16,cxF8,
            cx17,cx98,cx02,cx21,cx00,cxFF,cxFF,cxFF,cxFF,cxFF,cxFF,cxFF,cxFF,cxFF,cxFF,cxFF,
            cxFF,cxFF,cxFF,cxFF,cxFE,cxBA,cxAE,cxDC,cxE6,cxAF,cx48,cxA0,cx3B,cxBF,cxD2,cx5E,
            cx8C,cxD0,cx36,cx41,cx41,cx02,cx01,cx01,cxA1,cx24,cx03,cx22,cx00
        };
        unsigned char *ptr = seckey;
        memcpy(ptr, begin, sizeof(begin)); ptr += sizeof(begin);
        memcpy(ptr, key32, 32); ptr += 32;
        memcpy(ptr, middle, sizeof(middle)); ptr += sizeof(middle);
        pubkeylen = CPubKey::COMPRESSED_SIZE;
        secp256k1_ec_pubkey_serialize(ctx, ptr, &pubkeylen, &pubkey, SECP256K1_EC_COMPRESSED);
        ptr += pubkeylen;
        *seckeylen = ptr - seckey;
        assert(*seckeylen == CKey::COMPRESSED_SIZE);
    } else {
        static const unsigned char begin[] = {
            cx30,cx82,cx01,cx13,cx02,cx01,cx01,cx04,cx20
        };
        static const unsigned char middle[] = {
            cxA0,cx81,cxA5,cx30,cx81,cxA2,cx02,cx01,cx01,cx30,cx2C,cx06,cx07,cx2A,cx86,cx48,
            cxCE,cx3D,cx01,cx01,cx02,cx21,cx00,cxFF,cxFF,cxFF,cxFF,cxFF,cxFF,cxFF,cxFF,cxFF,
            cxFF,cxFF,cxFF,cxFF,cxFF,cxFF,cxFF,cxFF,cxFF,cxFF,cxFF,cxFF,cxFF,cxFF,cxFF,cxFF,
            cxFF,cxFF,cxFE,cxFF,cxFF,cxFC,cx2F,cx30,cx06,cx04,cx01,cx00,cx04,cx01,cx07,cx04,
            cx41,cx04,cx79,cxBE,cx66,cx7E,cxF9,cxDC,cxBB,cxAC,cx55,cxA0,cx62,cx95,cxCE,cx87,
            cx0B,cx07,cx02,cx9B,cxFC,cxDB,cx2D,cxCE,cx28,cxD9,cx59,cxF2,cx81,cx5B,cx16,cxF8,
            cx17,cx98,cx48,cx3A,cxDA,cx77,cx26,cxA3,cxC4,cx65,cx5D,cxA4,cxFB,cxFC,cx0E,cx11,
            cx08,cxA8,cxFD,cx17,cxB4,cx48,cxA6,cx85,cx54,cx19,cx9C,cx47,cxD0,cx8F,cxFB,cx10,
            cxD4,cxB8,cx02,cx21,cx00,cxFF,cxFF,cxFF,cxFF,cxFF,cxFF,cxFF,cxFF,cxFF,cxFF,cxFF,
            cxFF,cxFF,cxFF,cxFF,cxFE,cxBA,cxAE,cxDC,cxE6,cxAF,cx48,cxA0,cx3B,cxBF,cxD2,cx5E,
            cx8C,cxD0,cx36,cx41,cx41,cx02,cx01,cx01,cxA1,cx44,cx03,cx42,cx00
        };
        unsigned char *ptr = seckey;
        memcpy(ptr, begin, sizeof(begin)); ptr += sizeof(begin);
        memcpy(ptr, key32, 32); ptr += 32;
        memcpy(ptr, middle, sizeof(middle)); ptr += sizeof(middle);
        pubkeylen = CPubKey::SIZE;
        secp256k1_ec_pubkey_serialize(ctx, ptr, &pubkeylen, &pubkey, SECP256K1_EC_UNCOMPRESSED);
        ptr += pubkeylen;
        *seckeylen = ptr - seckey;
        assert(*seckeylen == CKey::SIZE);
    }
    return 1;
}

bool CKey::Check(const unsigned char *vch) {
    return secp256k1_ec_seckey_verify(secp256k1_context_sign, vch);
}

void CKey::MakeNewKey(bool fCompressedIn) {
    do {
        GetStrongRandBytes(keydata.data(), keydata.size());
    } while (!Check(keydata.data()));
    fValid = true;
    fCompressed = fCompressedIn;
}

bool CKey::Negate()
{
    assert(fValid);
    return secp256k1_ec_seckey_negate(secp256k1_context_sign, keydata.data());
}

CPrivKey CKey::GetPrivKey() const {
    assert(fValid);
    CPrivKey seckey;
    int ret;
    size_t seckeylen;
    seckey.resize(SIZE);
    seckeylen = SIZE;
    ret = ec_seckey_export_der(secp256k1_context_sign, seckey.data(), &seckeylen, begin(), fCompressed);
    assert(ret);
    seckey.resize(seckeylen);
    return seckey;
}

CPubKey CKey::GetPubKey() const {
    assert(fValid);
    secp256k1_pubkey pubkey;
    size_t clen = CPubKey::SIZE;
    CPubKey result;
    int ret = secp256k1_ec_pubkey_create(secp256k1_context_sign, &pubkey, begin());
    assert(ret);
    secp256k1_ec_pubkey_serialize(secp256k1_context_sign, (unsigned char*)result.begin(), &clen, &pubkey, fCompressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);
    assert(result.size() == clen);
    assert(result.IsValid());
    return result;
}

// Check that the sig has a low R value and will be less than 71 bytes
bool SigHasLowR(const secp256k1_ecdsa_signature* sig)
{
    unsigned char compact_sig[64];
    secp256k1_ecdsa_signature_serialize_compact(secp256k1_context_sign, compact_sig, sig);

    // In DER serialization, all values are interpreted as big-endian, signed integers. The highest bit in the integer indicates
    // its signed-ness; 0 is positive, 1 is negative. When the value is interpreted as a negative integer, it must be converted
    // to a positive value by prepending a cx00 byte so that the highest bit is 0. We can avoid this prepending by ensuring that
    // our highest bit is always 0, and thus we must check that the first byte is less than cx80.
    return compact_sig[0] < cx80;
}

bool CKey::Sign(const uint256 &hash, std::vector<unsigned char>& vchSig, bool grind, uint32_t test_case) const {
    if (!fValid)
        return false;
    vchSig.resize(CPubKey::SIGNATURE_SIZE);
    size_t nSigLen = CPubKey::SIGNATURE_SIZE;
    unsigned char extra_entropy[32] = {0};
    WriteLE32(extra_entropy, test_case);
    secp256k1_ecdsa_signature sig;
    uint32_t counter = 0;
    int ret = secp256k1_ecdsa_sign(secp256k1_context_sign, &sig, hash.begin(), begin(), secp256k1_nonce_function_rfc6979, (!grind && test_case) ? extra_entropy : nullptr);

    // Grind for low R
    while (ret && !SigHasLowR(&sig) && grind) {
        WriteLE32(extra_entropy, ++counter);
        ret = secp256k1_ecdsa_sign(secp256k1_context_sign, &sig, hash.begin(), begin(), secp256k1_nonce_function_rfc6979, extra_entropy);
    }
    assert(ret);
    secp256k1_ecdsa_signature_serialize_der(secp256k1_context_sign, vchSig.data(), &nSigLen, &sig);
    vchSig.resize(nSigLen);
    return true;
}

bool CKey::VerifyPubKey(const CPubKey& pubkey) const {
    if (pubkey.IsCompressed() != fCompressed) {
        return false;
    }
    unsigned char rnd[8];
    std::string str = "chymera key verification\n";
    GetRandBytes(rnd, sizeof(rnd));
    uint256 hash;
    CHash256().Write(MakeUCharSpan(str)).Write(rnd).Finalize(hash);
    std::vector<unsigned char> vchSig;
    Sign(hash, vchSig);
    return pubkey.Verify(hash, vchSig);
}

bool CKey::SignCompact(const uint256 &hash, std::vector<unsigned char>& vchSig) const {
    if (!fValid)
        return false;
    vchSig.resize(CPubKey::COMPACT_SIGNATURE_SIZE);
    int rec = -1;
    secp256k1_ecdsa_recoverable_signature sig;
    int ret = secp256k1_ecdsa_sign_recoverable(secp256k1_context_sign, &sig, hash.begin(), begin(), secp256k1_nonce_function_rfc6979, nullptr);
    assert(ret);
    ret = secp256k1_ecdsa_recoverable_signature_serialize_compact(secp256k1_context_sign, &vchSig[1], &rec, &sig);
    assert(ret);
    assert(rec != -1);
    vchSig[0] = 27 + rec + (fCompressed ? 4 : 0);
    return true;
}

bool CKey::Load(const CPrivKey &seckey, const CPubKey &vchPubKey, bool fSkipCheck=false) {
    if (!ec_seckey_import_der(secp256k1_context_sign, (unsigned char*)begin(), seckey.data(), seckey.size()))
        return false;
    fCompressed = vchPubKey.IsCompressed();
    fValid = true;

    if (fSkipCheck)
        return true;

    return VerifyPubKey(vchPubKey);
}

bool CKey::Derive(CKey& keyChild, ChainCode &ccChild, unsigned int nChild, const ChainCode& cc) const {
    assert(IsValid());
    assert(IsCompressed());
    std::vector<unsigned char, secure_allocator<unsigned char>> vout(64);
    if ((nChild >> 31) == 0) {
        CPubKey pubkey = GetPubKey();
        assert(pubkey.size() == CPubKey::COMPRESSED_SIZE);
        BIP32Hash(cc, nChild, *pubkey.begin(), pubkey.begin()+1, vout.data());
    } else {
        assert(size() == 32);
        BIP32Hash(cc, nChild, 0, begin(), vout.data());
    }
    memcpy(ccChild.begin(), vout.data()+32, 32);
    memcpy((unsigned char*)keyChild.begin(), begin(), 32);
    bool ret = secp256k1_ec_seckey_tweak_add(secp256k1_context_sign, (unsigned char*)keyChild.begin(), vout.data());
    keyChild.fCompressed = true;
    keyChild.fValid = ret;
    return ret;
}

bool CExtKey::Derive(CExtKey &out, unsigned int _nChild) const {
    out.nDepth = nDepth + 1;
    CKeyID id = key.GetPubKey().GetID();
    memcpy(out.vchFingerprint, &id, 4);
    out.nChild = _nChild;
    return key.Derive(out.key, out.chaincode, _nChild, chaincode);
}

void CExtKey::SetSeed(const unsigned char *seed, unsigned int nSeedLen) {
    static const unsigned char hashkey[] = {'B','i','t','c','o','i','n',' ','s','e','e','d'};
    std::vector<unsigned char, secure_allocator<unsigned char>> vout(64);
    CHMAC_SHA512(hashkey, sizeof(hashkey)).Write(seed, nSeedLen).Finalize(vout.data());
    key.Set(vout.data(), vout.data() + 32, true);
    memcpy(chaincode.begin(), vout.data() + 32, 32);
    nDepth = 0;
    nChild = 0;
    memset(vchFingerprint, 0, sizeof(vchFingerprint));
}

CExtPubKey CExtKey::Neuter() const {
    CExtPubKey ret;
    ret.nDepth = nDepth;
    memcpy(ret.vchFingerprint, vchFingerprint, 4);
    ret.nChild = nChild;
    ret.pubkey = key.GetPubKey();
    ret.chaincode = chaincode;
    return ret;
}

void CExtKey::Encode(unsigned char code[BIP32_EXTKEY_SIZE]) const {
    code[0] = nDepth;
    memcpy(code+1, vchFingerprint, 4);
    code[5] = (nChild >> 24) & cxFF; code[6] = (nChild >> 16) & cxFF;
    code[7] = (nChild >>  8) & cxFF; code[8] = (nChild >>  0) & cxFF;
    memcpy(code+9, chaincode.begin(), 32);
    code[41] = 0;
    assert(key.size() == 32);
    memcpy(code+42, key.begin(), 32);
}

void CExtKey::Decode(const unsigned char code[BIP32_EXTKEY_SIZE]) {
    nDepth = code[0];
    memcpy(vchFingerprint, code+1, 4);
    nChild = (code[5] << 24) | (code[6] << 16) | (code[7] << 8) | code[8];
    memcpy(chaincode.begin(), code+9, 32);
    key.Set(code+42, code+BIP32_EXTKEY_SIZE, true);
}

bool ECC_InitSanityCheck() {
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();
    return key.VerifyPubKey(pubkey);
}

void ECC_Start() {
    assert(secp256k1_context_sign == nullptr);

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    assert(ctx != nullptr);

    {
        // Pass in a random blinding seed to the secp256k1 context.
        std::vector<unsigned char, secure_allocator<unsigned char>> vseed(32);
        GetRandBytes(vseed.data(), 32);
        bool ret = secp256k1_context_randomize(ctx, vseed.data());
        assert(ret);
    }

    secp256k1_context_sign = ctx;
}

void ECC_Stop() {
    secp256k1_context *ctx = secp256k1_context_sign;
    secp256k1_context_sign = nullptr;

    if (ctx) {
        secp256k1_context_destroy(ctx);
    }
}
