// Copyright (c) 2009-2020 Subhranil Banerjee
// Copyright (c) 2009-2018 The chymera Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef chymera_SCRIPT_chymeraCONSENSUS_H
#define chymera_SCRIPT_chymeraCONSENSUS_H

#include <stdint.h>

#if defined(BUILD_chymera_INTERNAL) && defined(HAVE_CONFIG_H)
#include <config/chymera-config.h>
  #if defined(_WIN32)
    #if defined(HAVE_DLLEXPORT_ATTRIBUTE)
      #define EXPORT_SYMBOL __declspec(dllexport)
    #else
      #define EXPORT_SYMBOL
    #endif
  #elif defined(HAVE_DEFAULT_VISIBILITY_ATTRIBUTE)
    #define EXPORT_SYMBOL __attribute__ ((visibility ("default")))
  #endif
#elif defined(MSC_VER) && !defined(STATIC_LIBchymeraCONSENSUS)
  #define EXPORT_SYMBOL __declspec(dllimport)
#endif

#ifndef EXPORT_SYMBOL
  #define EXPORT_SYMBOL
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define chymeraCONSENSUS_API_VER 1

typedef enum chymeraconsensus_error_t
{
    chymeraconsensus_ERR_OK = 0,
    chymeraconsensus_ERR_TX_INDEX,
    chymeraconsensus_ERR_TX_SIZE_MISMATCH,
    chymeraconsensus_ERR_TX_DESERIALIZE,
    chymeraconsensus_ERR_AMOUNT_REQUIRED,
    chymeraconsensus_ERR_INVALID_FLAGS,
} chymeraconsensus_error;

/** Script verification flags */
enum
{
    chymeraconsensus_SCRIPT_FLAGS_VERIFY_NONE                = 0,
    chymeraconsensus_SCRIPT_FLAGS_VERIFY_P2SH                = (1U << 0), // evaluate P2SH (BIP16) subscripts
    chymeraconsensus_SCRIPT_FLAGS_VERIFY_DERSIG              = (1U << 2), // enforce strict DER (BIP66) compliance
    chymeraconsensus_SCRIPT_FLAGS_VERIFY_NULLDUMMY           = (1U << 4), // enforce NULLDUMMY (BIP147)
    chymeraconsensus_SCRIPT_FLAGS_VERIFY_CHECKLOCKTIMEVERIFY = (1U << 9), // enable CHECKLOCKTIMEVERIFY (BIP65)
    chymeraconsensus_SCRIPT_FLAGS_VERIFY_CHECKSEQUENCEVERIFY = (1U << 10), // enable CHECKSEQUENCEVERIFY (BIP112)
    chymeraconsensus_SCRIPT_FLAGS_VERIFY_WITNESS             = (1U << 11), // enable WITNESS (BIP141)
    chymeraconsensus_SCRIPT_FLAGS_VERIFY_ALL                 = chymeraconsensus_SCRIPT_FLAGS_VERIFY_P2SH | chymeraconsensus_SCRIPT_FLAGS_VERIFY_DERSIG |
                                                               chymeraconsensus_SCRIPT_FLAGS_VERIFY_NULLDUMMY | chymeraconsensus_SCRIPT_FLAGS_VERIFY_CHECKLOCKTIMEVERIFY |
                                                               chymeraconsensus_SCRIPT_FLAGS_VERIFY_CHECKSEQUENCEVERIFY | chymeraconsensus_SCRIPT_FLAGS_VERIFY_WITNESS
};

/// Returns 1 if the input nIn of the serialized transaction pointed to by
/// txTo correctly spends the scriptPubKey pointed to by scriptPubKey under
/// the additional constraints specified by flags.
/// If not nullptr, err will contain an error/success code for the operation
EXPORT_SYMBOL int chymeraconsensus_verify_script(const unsigned char *scriptPubKey, unsigned int scriptPubKeyLen,
                                                 const unsigned char *txTo        , unsigned int txToLen,
                                                 unsigned int nIn, unsigned int flags, chymeraconsensus_error* err);

EXPORT_SYMBOL int chymeraconsensus_verify_script_with_amount(const unsigned char *scriptPubKey, unsigned int scriptPubKeyLen, int64_t amount,
                                    const unsigned char *txTo        , unsigned int txToLen,
                                    unsigned int nIn, unsigned int flags, chymeraconsensus_error* err);

EXPORT_SYMBOL unsigned int chymeraconsensus_version();

#ifdef __cplusplus
} // extern "C"
#endif

#undef EXPORT_SYMBOL

#endif // chymera_SCRIPT_chymeraCONSENSUS_H
