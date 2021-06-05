// Copyright (c) 2009-2020 Subhranil Banerjee
// Copyright (c) 2020-2021 The Chymera Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef chymera_WARNINGS_H
#define chymera_WARNINGS_H

#include <string>

struct bilingual_str;

void SetMiscWarning(const bilingual_str& warning);
void SetfLargeWorkInvalidChainFound(bool flag);
/** Format a string that describes several potential problems detected by the core.
 * @param[in] verbose bool
 * - if true, get all warnings separated by <hr />
 * - if false, get the most important warning
 * @returns the warning string
 */
bilingual_str GetWarnings(bool verbose);

#endif //  chymera_WARNINGS_H
