// Copyright (c) 2009-2020 Subhranil Banerjee
// Copyright (c) 2020-2021 The Chymera Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef chymera_TEST_SCRIPTNUM10_H
#define chymera_TEST_SCRIPTNUM10_H

#include <assert.h>
#include <limits>
#include <stdexcept>
#include <stdint.h>
#include <string>
#include <vector>

class scriptnum10_error : public std::runtime_error
{
public:
    explicit scriptnum10_error(const std::string& str) : std::runtime_error(str) {}
};

class CScriptNum10
{
/**
 * The ScriptNum implementation from chymera Core 0.10.0, for cross-comparison.
 */
public:

    explicit CScriptNum10(const int64_t& n)
    {
        m_value = n;
    }

    static const size_t nDefaultMaxNumSize = 4;

    explicit CScriptNum10(const std::vector<unsigned char>& vch, bool fRequireMinimal,
                        const size_t nMaxNumSize = nDefaultMaxNumSize)
    {
        if (vch.size() > nMaxNumSize) {
            throw scriptnum10_error("script number overflow");
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
                    throw scriptnum10_error("non-minimally encoded script number");
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

    inline bool operator==(const CScriptNum10& rhs) const { return operator==(rhs.m_value); }
    inline bool operator!=(const CScriptNum10& rhs) const { return operator!=(rhs.m_value); }
    inline bool operator<=(const CScriptNum10& rhs) const { return operator<=(rhs.m_value); }
    inline bool operator< (const CScriptNum10& rhs) const { return operator< (rhs.m_value); }
    inline bool operator>=(const CScriptNum10& rhs) const { return operator>=(rhs.m_value); }
    inline bool operator> (const CScriptNum10& rhs) const { return operator> (rhs.m_value); }

    inline CScriptNum10 operator+(   const int64_t& rhs)    const { return CScriptNum10(m_value + rhs);}
    inline CScriptNum10 operator-(   const int64_t& rhs)    const { return CScriptNum10(m_value - rhs);}
    inline CScriptNum10 operator+(   const CScriptNum10& rhs) const { return operator+(rhs.m_value);   }
    inline CScriptNum10 operator-(   const CScriptNum10& rhs) const { return operator-(rhs.m_value);   }

    inline CScriptNum10& operator+=( const CScriptNum10& rhs)       { return operator+=(rhs.m_value);  }
    inline CScriptNum10& operator-=( const CScriptNum10& rhs)       { return operator-=(rhs.m_value);  }

    inline CScriptNum10 operator-()                         const
    {
        assert(m_value != std::numeric_limits<int64_t>::min());
        return CScriptNum10(-m_value);
    }

    inline CScriptNum10& operator=( const int64_t& rhs)
    {
        m_value = rhs;
        return *this;
    }

    inline CScriptNum10& operator+=( const int64_t& rhs)
    {
        assert(rhs == 0 || (rhs > 0 && m_value <= std::numeric_limits<int64_t>::max() - rhs) ||
                           (rhs < 0 && m_value >= std::numeric_limits<int64_t>::min() - rhs));
        m_value += rhs;
        return *this;
    }

    inline CScriptNum10& operator-=( const int64_t& rhs)
    {
        assert(rhs == 0 || (rhs > 0 && m_value >= std::numeric_limits<int64_t>::min() + rhs) ||
                           (rhs < 0 && m_value <= std::numeric_limits<int64_t>::max() + rhs));
        m_value -= rhs;
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
        uint64_t absvalue = neg ? -value : value;

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


#endif // chymera_TEST_BIGNUM_H
