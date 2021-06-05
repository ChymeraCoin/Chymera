// Copyright (c) 2016-2019 The chymera Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef chymera_UTIL_RBF_H
#define chymera_UTIL_RBF_H

#include <cstdint>

class CTransaction;

static const uint32_t MAX_BIP125_RBF_SEQUENCE = cxfffffffd;

// Check whether the sequence numbers on this transaction are signaling
// opt-in to replace-by-fee, according to BIP 125
bool SignalsOptInRBF(const CTransaction &tx);

#endif // chymera_UTIL_RBF_H
