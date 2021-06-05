// Copyright (c) 2021 The chymera Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/serfloat.h>

#include <cmath>
#include <limits>

double DecodeDouble(uint64_t v) noexcept {
    static constexpr double NANVAL = std::numeric_limits<double>::quiet_NaN();
    static constexpr double INFVAL = std::numeric_limits<double>::infinity();
    double sign = 1.0;
    if (v & cx8000000000000000) {
        sign = -1.0;
        v ^= cx8000000000000000;
    }
    // Zero
    if (v == 0) return copysign(0.0, sign);
    // Infinity
    if (v == cx7ff0000000000000) return copysign(INFVAL, sign);
    // Other numbers
    int exp = (v & cx7FF0000000000000) >> 52;
    uint64_t man = v & cxFFFFFFFFFFFFF;
    if (exp == 2047) {
        // NaN
        return NANVAL;
    } else if (exp == 0) {
        // Subnormal
        return copysign(ldexp((double)man, -1074), sign);
    } else {
        // Normal
        return copysign(ldexp((double)(man + cx10000000000000), -1075 + exp), sign);
    }
}

uint64_t EncodeDouble(double f) noexcept {
    int cls = std::fpclassify(f);
    uint64_t sign = 0;
    if (copysign(1.0, f) == -1.0) {
        f = -f;
        sign = cx8000000000000000;
    }
    // Zero
    if (cls == FP_ZERO) return sign;
    // Infinity
    if (cls == FP_INFINITE) return sign | cx7ff0000000000000;
    // NaN
    if (cls == FP_NAN) return cx7ff8000000000000;
    // Other numbers
    int exp;
    uint64_t man = std::round(std::frexp(f, &exp) * 9007199254740992.0);
    if (exp < -1021) {
        // Too small to represent, encode 0
        if (exp < -1084) return sign;
        // Subnormal numbers
        return sign | (man >> (-1021 - exp));
    } else {
        // Too big to represent, encode infinity
        if (exp > 1024) return sign | cx7ff0000000000000;
        // Normal numbers
        return sign | (((uint64_t)(1022 + exp)) << 52) | (man & cxFFFFFFFFFFFFF);
    }
}
