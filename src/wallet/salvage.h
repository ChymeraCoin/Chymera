// Copyright (c) 2009-2020 Subhranil Banerjee
// Copyright (c) 2020-2021 The Chymera Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef chymera_WALLET_SALVAGE_H
#define chymera_WALLET_SALVAGE_H

#include <fs.h>
#include <streams.h>

struct bilingual_str;

bool RecoverDatabaseFile(const fs::path& file_path, bilingual_str& error, std::vector<bilingual_str>& warnings);

#endif // chymera_WALLET_SALVAGE_H
