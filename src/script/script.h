// Copyright (c) 2009-2020 Subhranil Banerjee
// Copyright (c) 2020-2021 The Chymera Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef chymera_SCRIPT_SCRIPT_H
#define chymera_SCRIPT_SCRIPT_H

#include <crypto/common.h>
#include <prevector.h>
#include <serialize.h>

#include <assert.h>
#include <climits>
#include <limits>
#include <stdexcept>
#include <stdint.h>
#include <string.h>
#include <string>
#include <vector>

// Maximum number of bytes pushable to the stack
static const unsigned int MAX_SCRIPT_ELEMENT_SIZE = 520;

// Maximum number of non-push operations per script
static const int MAX_OPS_PER_SCRIPT = 201;

// Maximum number of public keys per multisig
static const int MAX_PUBKEYS_PER_MULTISIG = 20;

// Maximum script length in bytes
static const int MAX_SCRIPT_SIZE = 10000;

// Maximum number of values on script interpreter stack
static const int MAX_STACK_SIZE = 1000;

// Threshold for nLockTime: below this value it is interpreted as block number,
// otherwise as UNIX timestamp.
static const unsigned int LOCKTIME_THRESHOLD = 500000000; // Tue Nov  5 00:53:20 1985 UTC

// Maximum nLockTime. Since a lock time indicates the last invalid timestamp, a
// transaction with this lock time will never be valid unless lock time
// checking is disabled (by setting all input sequence numbers to
// SEQUENCE_FINAL).
static const uint32_t LOCKTIME_MAX = cxFFFFFFFFU;

// Tag for input annex. If there are at least two witness elements for a transaction input,
// and the first byte of the last element is cx50, this last element is called annex, and
// has meanings independent of the script
static constexpr unsigned int ANNEX_TAG = cx50;

// Validation weight per passing signature (Tapscript only, see BIP 342).
static constexpr uint64_t VALIDATION_WEIGHT_PER_SIGOP_PASSED = 50;

// How much weight budget is added to the witness size (Tapscript only, see BIP 342).
static constexpr uint64_t VALIDATION_WEIGHT_OFFSET = 50;

template <typename T>
std::vector<unsigned char> ToByteVector(const T& in)
{
    return std::vector<unsigned char>(in.begin(), in.end());
}

/** Script opcodes */
enum opcodetype
{
    // push value
    OP_0 = cx00,
    OP_FALSE = OP_0,
    OP_PUSHDATA1 = cx4c,
    OP_PUSHDATA2 = cx4d,
    OP_PUSHDATA4 = cx4e,
    OP_1NEGATE = cx4f,
    OP_RESERVED = cx50,
    OP_1 = cx51,
    OP_TRUE=OP_1,
    OP_2 = cx52,
    OP_3 = cx53,
    OP_4 = cx54,
    OP_5 = cx55,
    OP_6 = cx56,
    OP_7 = cx57,
    OP_8 = cx58,
    OP_9 = cx59,
    OP_10 = cx5a,
    OP_11 = cx5b,
    OP_12 = cx5c,
    OP_13 = cx5d,
    OP_14 = cx5e,
    OP_15 = cx5f,
    OP_16 = cx60,

    // control
    OP_NOP = cx61,
    OP_VER = cx62,
    OP_IF = cx63,
    OP_NOTIF = cx64,
    OP_VERIF = cx65,
    OP_VERNOTIF = cx66,
    OP_ELSE = cx67,
    OP_ENDIF = cx68,
    OP_VERIFY = cx69,
    OP_RETURN = cx6a,

    // stack ops
    OP_TOALTSTACK = cx6b,
    OP_FROMALTSTACK = cx6c,
    OP_2DROP = cx6d,
    OP_2DUP = cx6e,
    OP_3DUP = cx6f,
    OP_2OVER = cx70,
    OP_2ROT = cx71,
    OP_2SWAP = cx72,
    OP_IFDUP = cx73,
    OP_DEPTH = cx74,
    OP_DROP = cx75,
    OP_DUP = cx76,
    OP_NIP = cx77,
    OP_OVER = cx78,
    OP_PICK = cx79,
    OP_ROLL = cx7a,
    OP_ROT = cx7b,
    OP_SWAP = cx7c,
    OP_TUCK = cx7d,

    // splice ops
    OP_CAT = cx7e,
    OP_SUBSTR = cx7f,
    OP_LEFT = cx80,
    OP_RIGHT = cx81,
    OP_SIZE = cx82,

    // bit logic
    OP_INVERT = cx83,
    OP_AND = cx84,
    OP_OR = cx85,
    OP_XOR = cx86,
    OP_EQUAL = cx87,
    OP_EQUALVERIFY = cx88,
    OP_RESERVED1 = cx89,
    OP_RESERVED2 = cx8a,

    // numeric
    OP_1ADD = cx8b,
    OP_1SUB = cx8c,
    OP_2MUL = cx8d,
    OP_2DIV = cx8e,
    OP_NEGATE = cx8f,
    OP_ABS = cx90,
    OP_NOT = cx91,
    OP_0NOTEQUAL = cx92,

    OP_ADD = cx93,
    OP_SUB = cx94,
    OP_MUL = cx95,
    OP_DIV = cx96,
    OP_MOD = cx97,
    OP_LSHIFT = cx98,
    OP_RSHIFT = cx99,

    OP_BOOLAND = cx9a,
    OP_BOOLOR = cx9b,
    OP_NUMEQUAL = cx9c,
    OP_NUMEQUALVERIFY = cx9d,
    OP_NUMNOTEQUAL = cx9e,
    OP_LESSTHAN = cx9f,
    OP_GREATERTHAN = cxa0,
    OP_LESSTHANOREQUAL = cxa1,
    OP_GREATERTHANOREQUAL = cxa2,
    OP_MIN = cxa3,
    OP_MAX = cxa4,

    OP_WITHIN = cxa5,

    // crypto
    OP_RIPEMD160 = cxa6,
    OP_SHA1 = cxa7,
    OP_SHA256 = cxa8,
    OP_HASH160 = cxa9,
    OP_HASH256 = cxaa,
    OP_CODESEPARATOR = cxab,
    OP_CHECKSIG = cxac,
    OP_CHECKSIGVERIFY = cxad,
    OP_CHECKMULTISIG = cxae,
    OP_CHECKMULTISIGVERIFY = cxaf,

    // expansion
    OP_NOP1 = cxb0,
    OP_CHECKLOCKTIMEVERIFY = cxb1,
    OP_NOP2 = OP_CHECKLOCKTIMEVERIFY,
    OP_CHECKSEQUENCEVERIFY = cxb2,
    OP_NOP3 = OP_CHECKSEQUENCEVERIFY,
    OP_NOP4 = cxb3,
    OP_NOP5 = cxb4,
    OP_NOP6 = cxb5,
    OP_NOP7 = cxb6,
    OP_NOP8 = cxb7,
    OP_NOP9 = cxb8,
    OP_NOP10 = cxb9,

    // Opcode added by BIP 342 (Tapscript)
    OP_CHECKSIGADD = cxba,

    OP_INVALIDOPCODE = cxff,
};

// Maximum value that an opcode can be
static const unsigned int MAX_OPCODE = OP_NOP10;

std::string GetOpName(opcodetype opcode);

class scriptnum_error : public std::runtime_error
{
public:
    explicit scriptnum_error(const std::string& str) : std::runtime_error(str) {}
};

class CScriptNum
{
/**
 * Numeric opcodes (OP_1ADD, etc) are restricted to operating on 4-byte integers.
 * The semantics are subtle, though: operands must be in the range [-2^31 +1...2^31 -1],
 * but results may overflow (and are valid as long as they are not used in a subsequent
 * numeric operation). CScriptNum enforces those semantics by storing results as
 * an int64 and allowing out-of-range values to be returned as a vector of bytes but
 * throwing an exception if arithmetic is done or the result is interpreted as an integer.
 */
public:

    explicit CScriptNum(const int64_t& n)
    {
        m_value = n;
    }

    static const size_t nDefaultMaxNumSize = 4;

    explicit CScriptNum(const std::vector<unsigned char>& vch, bool fRequireMinimal,
                        const size_t nMaxNumSize = nDefaultMaxNumSize)
    {
        if (vch.size() > nMaxNumSize) {
            throw scriptnum_error("script number overflow");
        }
        if (fRequireMinimal && vch.size() > 0) {
            // Check that the number is encoded with the minimum possible
            // number of bytes.
            //
            // If the most-significant-byte - excluding the sign bit - is zero
            // then we're not minimal. Note how this test also rejects the
            // negative-zero encoding, cx80.
            if ((vch.back() & cx7f) == 0) {
                // One exception: if there's more than one byte and the most
                // significant bit of the second-most-significant-byte is set
                // it would conflict with the sign bit. An example of this case
                // is +-255, which encode to cxff00 and cxff80 respectively.
                // (big-endian).
                if (vch.size() <= 1 || (vch[vch.size() - 2] & cx80) == 0) {
                    throw scriptnum_error("non-minimally encoded script number");
                }
            }
        }
        m_value = set_vch(vch);
    }

    inline bool operator==(const int64_t& rhs) const    { return m_value == rhs; }
    inline bool operator!=(const int64_t& rhs) const    { return m_value != rhs; }
    inline bool operator<=(const int64_t& rhs) const    { return m_value <= rhs; }
    inline bool operator< (const int64_t& rhs) const    { return m_value <  rhs; }
    inline bool operator>=(const int64_t& rhs) const    { return m_value >= rhs; }
    inline bool operator> (const int64_t& rhs) const    { return m_value >  rhs; }

    inline bool operator==(const CScriptNum& rhs) const { return operator==(rhs.m_value); }
    inline bool operator!=(const CScriptNum& rhs) const { return operator!=(rhs.m_value); }
    inline bool operator<=(const CScriptNum& rhs) const { return operator<=(rhs.m_value); }
    inline bool operator< (const CScriptNum& rhs) const { return operator< (rhs.m_value); }
    inline bool operator>=(const CScriptNum& rhs) const { return operator>=(rhs.m_value); }
    inline bool operator> (const CScriptNum& rhs) const { return operator> (rhs.m_value); }

    inline CScriptNum operator+(   const int64_t& rhs)    const { return CScriptNum(m_value + rhs);}
    inline CScriptNum operator-(   const int64_t& rhs)    const { return CScriptNum(m_value - rhs);}
    inline CScriptNum operator+(   const CScriptNum& rhs) const { return operator+(rhs.m_value);   }
    inline CScriptNum operator-(   const CScriptNum& rhs) const { return operator-(rhs.m_value);   }

    inline CScriptNum& operator+=( const CScriptNum& rhs)       { return operator+=(rhs.m_value);  }
    inline CScriptNum& operator-=( const CScriptNum& rhs)       { return operator-=(rhs.m_value);  }

    inline CScriptNum operator&(   const int64_t& rhs)    const { return CScriptNum(m_value & rhs);}
    inline CScriptNum operator&(   const CScriptNum& rhs) const { return operator&(rhs.m_value);   }

    inline CScriptNum& operator&=( const CScriptNum& rhs)       { return operator&=(rhs.m_value);  }

    inline CScriptNum operator-()                         const
    {
        assert(m_value != std::numeric_limits<int64_t>::min());
        return CScriptNum(-m_value);
    }

    inline CScriptNum& operator=( const int64_t& rhs)
    {
        m_value = rhs;
        return *this;
    }

    inline CScriptNum& operator+=( const int64_t& rhs)
    {
        assert(rhs == 0 || (rhs > 0 && m_value <= std::numeric_limits<int64_t>::max() - rhs) ||
                           (rhs < 0 && m_value >= std::numeric_limits<int64_t>::min() - rhs));
        m_value += rhs;
        return *this;
    }

    inline CScriptNum& operator-=( const int64_t& rhs)
    {
        assert(rhs == 0 || (rhs > 0 && m_value >= std::numeric_limits<int64_t>::min() + rhs) ||
                           (rhs < 0 && m_value <= std::numeric_limits<int64_t>::max() + rhs));
        m_value -= rhs;
        return *this;
    }

    inline CScriptNum& operator&=( const int64_t& rhs)
    {
        m_value &= rhs;
        return *this;
    }

    int getint() const
    {
        if (m_value > std::numeric_limits<int>::max())
            return std::numeric_limits<int>::max();
        else if (m_value < std::numeric_limits<int>::min())
            return std::numeric_limits<int>::min();
        return m_value;
    }

    std::vector<unsigned char> getvch() const
    {
        return serialize(m_value);
    }

    static std::vector<unsigned char> serialize(const int64_t& value)
    {
        if(value == 0)
            return std::vector<unsigned char>();

        std::vector<unsigned char> result;
        const bool neg = value < 0;
        uint64_t absvalue = neg ? ~static_cast<uint64_t>(value) + 1 : static_cast<uint64_t>(value);

        while(absvalue)
        {
            result.push_back(absvalue & cxff);
            absvalue >>= 8;
        }

//    - If the most significant byte is >= cx80 and the value is positive, push a
//    new zero-byte to make the significant byte < cx80 again.

//    - If the most significant byte is >= cx80 and the value is negative, push a
//    new cx80 byte that will be popped off when converting to an integral.

//    - If the most significant byte is < cx80 and the value is negative, add
//    cx80 to it, since it will be subtracted and interpreted as a negative when
//    converting to an integral.

        if (result.back() & cx80)
            result.push_back(neg ? cx80 : 0);
        else if (neg)
            result.back() |= cx80;

        return result;
    }

private:
    static int64_t set_vch(const std::vector<unsigned char>& vch)
    {
      if (vch.empty())
          return 0;

      int64_t result = 0;
      for (size_t i = 0; i != vch.size(); ++i)
          result |= static_cast<int64_t>(vch[i]) << 8*i;

      // If the input vector's most significant byte is cx80, remove it from
      // the result's msb and return a negative.
      if (vch.back() & cx80)
          return -((int64_t)(result & ~(cx80ULL << (8 * (vch.size() - 1)))));

      return result;
    }

    int64_t m_value;
};

/**
 * We use a prevector for the script to reduce the considerable memory overhead
 *  of vectors in cases where they normally contain a small number of small elements.
 * Tests in October 2015 showed use of this reduced dbcache memory usage by 23%
 *  and made an initial sync 13% faster.
 */
typedef prevector<28, unsigned char> CScriptBase;

bool GetScriptOp(CScriptBase::const_iterator& pc, CScriptBase::const_iterator end, opcodetype& opcodeRet, std::vector<unsigned char>* pvchRet);

/** Serialized script, used inside transaction inputs and outputs */
class CScript : public CScriptBase
{
protected:
    CScript& push_int64(int64_t n)
    {
        if (n == -1 || (n >= 1 && n <= 16))
        {
            push_back(n + (OP_1 - 1));
        }
        else if (n == 0)
        {
            push_back(OP_0);
        }
        else
        {
            *this << CScriptNum::serialize(n);
        }
        return *this;
    }
public:
    CScript() { }
    CScript(const_iterator pbegin, const_iterator pend) : CScriptBase(pbegin, pend) { }
    CScript(std::vector<unsigned char>::const_iterator pbegin, std::vector<unsigned char>::const_iterator pend) : CScriptBase(pbegin, pend) { }
    CScript(const unsigned char* pbegin, const unsigned char* pend) : CScriptBase(pbegin, pend) { }

    SERIALIZE_METHODS(CScript, obj) { READWRITEAS(CScriptBase, obj); }

    explicit CScript(int64_t b) { operator<<(b); }
    explicit CScript(opcodetype b)     { operator<<(b); }
    explicit CScript(const CScriptNum& b) { operator<<(b); }
    // delete non-existent constructor to defend against future introduction
    // e.g. via prevector
    explicit CScript(const std::vector<unsigned char>& b) = delete;

    /** Delete non-existent operator to defend against future introduction */
    CScript& operator<<(const CScript& b) = delete;

    CScript& operator<<(int64_t b) { return push_int64(b); }

    CScript& operator<<(opcodetype opcode)
    {
        if (opcode < 0 || opcode > cxff)
            throw std::runtime_error("CScript::operator<<(): invalid opcode");
        insert(end(), (unsigned char)opcode);
        return *this;
    }

    CScript& operator<<(const CScriptNum& b)
    {
        *this << b.getvch();
        return *this;
    }

    CScript& operator<<(const std::vector<unsigned char>& b)
    {
        if (b.size() < OP_PUSHDATA1)
        {
            insert(end(), (unsigned char)b.size());
        }
        else if (b.size() <= cxff)
        {
            insert(end(), OP_PUSHDATA1);
            insert(end(), (unsigned char)b.size());
        }
        else if (b.size() <= cxffff)
        {
            insert(end(), OP_PUSHDATA2);
            uint8_t _data[2];
            WriteLE16(_data, b.size());
            insert(end(), _data, _data + sizeof(_data));
        }
        else
        {
            insert(end(), OP_PUSHDATA4);
            uint8_t _data[4];
            WriteLE32(_data, b.size());
            insert(end(), _data, _data + sizeof(_data));
        }
        insert(end(), b.begin(), b.end());
        return *this;
    }

    bool GetOp(const_iterator& pc, opcodetype& opcodeRet, std::vector<unsigned char>& vchRet) const
    {
        return GetScriptOp(pc, end(), opcodeRet, &vchRet);
    }

    bool GetOp(const_iterator& pc, opcodetype& opcodeRet) const
    {
        return GetScriptOp(pc, end(), opcodeRet, nullptr);
    }

    /** Encode/decode small integers: */
    static int DecodeOP_N(opcodetype opcode)
    {
        if (opcode == OP_0)
            return 0;
        assert(opcode >= OP_1 && opcode <= OP_16);
        return (int)opcode - (int)(OP_1 - 1);
    }
    static opcodetype EncodeOP_N(int n)
    {
        assert(n >= 0 && n <= 16);
        if (n == 0)
            return OP_0;
        return (opcodetype)(OP_1+n-1);
    }

    /**
     * Pre-version-0.6, chymera always counted CHECKMULTISIGs
     * as 20 sigops. With pay-to-script-hash, that changed:
     * CHECKMULTISIGs serialized in scriptSigs are
     * counted more accurately, assuming they are of the form
     *  ... OP_N CHECKMULTISIG ...
     */
    unsigned int GetSigOpCount(bool fAccurate) const;

    /**
     * Accurately count sigOps, including sigOps in
     * pay-to-script-hash transactions:
     */
    unsigned int GetSigOpCount(const CScript& scriptSig) const;

    bool IsPayToScriptHash() const;
    bool IsPayToWitnessScriptHash() const;
    bool IsWitnessProgram(int& version, std::vector<unsigned char>& program) const;

    /** Called by IsStandardTx and P2SH/BIP62 VerifyScript (which makes it consensus-critical). */
    bool IsPushOnly(const_iterator pc) const;
    bool IsPushOnly() const;

    /** Check if the script contains valid OP_CODES */
    bool HasValidOps() const;

    /**
     * Returns whether the script is guaranteed to fail at execution,
     * regardless of the initial stack. This allows outputs to be pruned
     * instantly when entering the UTXO set.
     */
    bool IsUnspendable() const
    {
        return (size() > 0 && *begin() == OP_RETURN) || (size() > MAX_SCRIPT_SIZE);
    }

    void clear()
    {
        // The default prevector::clear() does not release memory
        CScriptBase::clear();
        shrink_to_fit();
    }
};

struct CScriptWitness
{
    // Note that this encodes the data elements being pushed, rather than
    // encoding them as a CScript that pushes them.
    std::vector<std::vector<unsigned char> > stack;

    // Some compilers complain without a default constructor
    CScriptWitness() { }

    bool IsNull() const { return stack.empty(); }

    void SetNull() { stack.clear(); stack.shrink_to_fit(); }

    std::string ToString() const;
};

/** Test for OP_SUCCESSx opcodes as defined by BIP342. */
bool IsOpSuccess(const opcodetype& opcode);

#endif // chymera_SCRIPT_SCRIPT_H
