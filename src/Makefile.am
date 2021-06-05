# Copyright (c) 2013-2016 The chymera Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# Pattern rule to print variables, e.g. make print-top_srcdir
print-%:
	@echo '$*'='$($*)'

DIST_SUBDIRS = secp256k1 univalue

AM_LDFLAGS = $(LIBTOOL_LDFLAGS) $(HARDENED_LDFLAGS) $(GPROF_LDFLAGS) $(SANITIZER_LDFLAGS)
AM_CXXFLAGS = $(DEBUG_CXXFLAGS) $(HARDENED_CXXFLAGS) $(WARN_CXXFLAGS) $(NOWARN_CXXFLAGS) $(ERROR_CXXFLAGS) $(GPROF_CXXFLAGS) $(SANITIZER_CXXFLAGS)
AM_CPPFLAGS = $(DEBUG_CPPFLAGS) $(HARDENED_CPPFLAGS)
AM_LIBTOOLFLAGS = --preserve-dup-deps
PTHREAD_FLAGS = $(PTHREAD_CFLAGS) $(PTHREAD_LIBS)
EXTRA_LIBRARIES =

if EMBEDDED_UNIVALUE
LIBUNIVALUE = univalue/libunivalue.la

$(LIBUNIVALUE): $(wildcard univalue/lib/*) $(wildcard univalue/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)
else
LIBUNIVALUE = $(UNIVALUE_LIBS)
endif

chymera_INCLUDES=-I$(builddir) -I$(srcdir)/secp256k1/include $(BDB_CPPFLAGS) $(BOOST_CPPFLAGS) $(LEVELDB_CPPFLAGS)

chymera_INCLUDES += $(UNIVALUE_CFLAGS)

LIBchymera_SERVER=libchymera_server.a
LIBchymera_COMMON=libchymera_common.a
LIBchymera_CONSENSUS=libchymera_consensus.a
LIBchymera_CLI=libchymera_cli.a
LIBchymera_UTIL=libchymera_util.a
LIBchymera_CRYPTO_BASE=crypto/libchymera_crypto_base.a
LIBchymeraQT=qt/libchymeraqt.a
LIBSECP256K1=secp256k1/libsecp256k1.la

if ENABLE_ZMQ
LIBchymera_ZMQ=libchymera_zmq.a
endif
if BUILD_chymera_LIBS
LIBchymeraCONSENSUS=libchymeraconsensus.la
endif
if ENABLE_WALLET
LIBchymera_WALLET=libchymera_wallet.a
LIBchymera_WALLET_TOOL=libchymera_wallet_tool.a
endif

LIBchymera_CRYPTO= $(LIBchymera_CRYPTO_BASE)
if ENABLE_SSE41
LIBchymera_CRYPTO_SSE41 = crypto/libchymera_crypto_sse41.a
LIBchymera_CRYPTO += $(LIBchymera_CRYPTO_SSE41)
endif
if ENABLE_AVX2
LIBchymera_CRYPTO_AVX2 = crypto/libchymera_crypto_avx2.a
LIBchymera_CRYPTO += $(LIBchymera_CRYPTO_AVX2)
endif
if ENABLE_SHANI
LIBchymera_CRYPTO_SHANI = crypto/libchymera_crypto_shani.a
LIBchymera_CRYPTO += $(LIBchymera_CRYPTO_SHANI)
endif

$(LIBSECP256K1): $(wildcard secp256k1/src/*.h) $(wildcard secp256k1/src/*.c) $(wildcard secp256k1/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)

# Make is not made aware of per-object dependencies to avoid limiting building parallelization
# But to build the less dependent modules first, we manually select their order here:
EXTRA_LIBRARIES += \
  $(LIBchymera_CRYPTO) \
  $(LIBchymera_UTIL) \
  $(LIBchymera_COMMON) \
  $(LIBchymera_CONSENSUS) \
  $(LIBchymera_SERVER) \
  $(LIBchymera_CLI) \
  $(LIBchymera_IPC) \
  $(LIBchymera_WALLET) \
  $(LIBchymera_WALLET_TOOL) \
  $(LIBchymera_ZMQ)

lib_LTLIBRARIES = $(LIBchymeraCONSENSUS)

bin_PROGRAMS =
noinst_PROGRAMS =
TESTS =
BENCHMARKS =

if BUILD_chymeraD
  bin_PROGRAMS += chymerad
endif

if BUILD_chymera_NODE
  bin_PROGRAMS += chymera-node
endif

if BUILD_chymera_CLI
  bin_PROGRAMS += chymera-cli
endif

if BUILD_chymera_TX
  bin_PROGRAMS += chymera-tx
endif

if ENABLE_WALLET
if BUILD_chymera_WALLET
  bin_PROGRAMS += chymera-wallet
endif
endif

if BUILD_chymera_UTIL
  bin_PROGRAMS += chymera-util
endif

.PHONY: FORCE check-symbols check-security
# chymera core #
chymera_CORE_H = \
  addrdb.h \
  addrman.h \
  attributes.h \
  banman.h \
  base58.h \
  bech32.h \
  blockencodings.h \
  blockfilter.h \
  bloom.h \
  chain.h \
  chainparams.h \
  chainparamsbase.h \
  chainparamsseeds.h \
  checkqueue.h \
  clientversion.h \
  coins.h \
  compat.h \
  compat/assumptions.h \
  compat/byteswap.h \
  compat/cpuid.h \
  compat/endian.h \
  compat/sanity.h \
  compressor.h \
  consensus/consensus.h \
  consensus/tx_check.h \
  consensus/tx_verify.h \
  core_io.h \
  core_memusage.h \
  cuckoocache.h \
  dbwrapper.h \
  external_signer.h \
  flatfile.h \
  fs.h \
  httprpc.h \
  httpserver.h \
  i2p.h \
  index/base.h \
  index/blockfilterindex.h \
  index/coinstatsindex.h \
  index/disktxpos.h \
  index/txindex.h \
  indirectmap.h \
  init.h \
  init/common.h \
  interfaces/chain.h \
  interfaces/echo.h \
  interfaces/handler.h \
  interfaces/init.h \
  interfaces/ipc.h \
  interfaces/node.h \
  interfaces/wallet.h \
  key.h \
  key_io.h \
  logging.h \
  logging/timer.h \
  mapport.h \
  memusage.h \
  merkleblock.h \
  miner.h \
  net.h \
  net_permissions.h \
  net_processing.h \
  net_types.h \
  netaddress.h \
  netbase.h \
  netmessagemaker.h \
  node/blockstorage.h \
  node/coin.h \
  node/coinstats.h \
  node/context.h \
  node/psbt.h \
  node/transaction.h \
  node/ui_interface.h \
  node/utxo_snapshot.h \
  noui.h \
  outputtype.h \
  policy/feerate.h \
  policy/fees.h \
  policy/packages.h \
  policy/policy.h \
  policy/rbf.h \
  policy/settings.h \
  pow.h \
  protocol.h \
  psbt.h \
  random.h \
  randomenv.h \
  reverse_iterator.h \
  rpc/blockchain.h \
  rpc/client.h \
  rpc/mining.h \
  rpc/net.h \
  rpc/protocol.h \
  rpc/rawtransaction_util.h \
  rpc/register.h \
  rpc/request.h \
  rpc/server.h \
  rpc/util.h \
  scheduler.h \
  script/descriptor.h \
  script/keyorigin.h \
  script/sigcache.h \
  script/sign.h \
  script/signingprovider.h \
  script/standard.h \
  shutdown.h \
  signet.h \
  streams.h \
  support/allocators/secure.h \
  support/allocators/zeroafterfree.h \
  support/cleanse.h \
  support/events.h \
  support/lockedpool.h \
  sync.h \
  threadinterrupt.h \
  threadsafety.h \
  timedata.h \
  torcontrol.h \
  txdb.h \
  txmempool.h \
  txorphanage.h \
  txrequest.h \
  undo.h \
  util/asmap.h \
  util/bip32.h \
  util/bytevectorhash.h \
  util/check.h \
  util/epochguard.h \
  util/error.h \
  util/fees.h \
  util/getuniquepath.h \
  util/golombrice.h \
  util/hash_type.h \
  util/hasher.h \
  util/macros.h \
  util/message.h \
  util/moneystr.h \
  util/rbf.h \
  util/readwritefile.h \
  util/serfloat.h \
  util/settings.h \
  util/sock.h \
  util/spanparsing.h \
  util/string.h \
  util/system.h \
  util/thread.h \
  util/threadnames.h \
  util/time.h \
  util/tokenpipe.h \
  util/trace.h \
  util/translation.h \
  util/ui_change_type.h \
  util/url.h \
  util/vector.h \
  validation.h \
  validationinterface.h \
  versionbits.h \
  versionbitsinfo.h \
  wallet/bdb.h \
  wallet/coincontrol.h \
  wallet/coinselection.h \
  wallet/context.h \
  wallet/crypter.h \
  wallet/db.h \
  wallet/dump.h \
  wallet/external_signer_scriptpubkeyman.h \
  wallet/feebumper.h \
  wallet/fees.h \
  wallet/ismine.h \
  wallet/load.h \
  wallet/receive.h \
  wallet/rpcwallet.h \
  wallet/salvage.h \
  wallet/scriptpubkeyman.h \
  wallet/spend.h \
  wallet/sqlite.h \
  wallet/transaction.h \
  wallet/wallet.h \
  wallet/walletdb.h \
  wallet/wallettool.h \
  wallet/walletutil.h \
  walletinitinterface.h \
  warnings.h \
  zmq/zmqabstractnotifier.h \
  zmq/zmqnotificationinterface.h \
  zmq/zmqpublishnotifier.h \
  zmq/zmqrpc.h \
  zmq/zmqutil.h


obj/build.h: FORCE
	@$(MKDIR_P) $(builddir)/obj
	@$(top_srcdir)/share/genbuild.sh "$(abs_top_builddir)/src/obj/build.h" \
	  "$(abs_top_srcdir)"
libchymera_util_a-clientversion.$(OBJEXT): obj/build.h

ipc/capnp/libchymera_ipc_a-ipc.$(OBJEXT): $(libchymera_ipc_mpgen_input:=.h)

# server: shared between chymerad and chymera-qt
# Contains code accessing mempool and chain state that is meant to be separated
# from wallet and gui code (see node/README.md). Shared code should go in
# libchymera_common or libchymera_util libraries, instead.
libchymera_server_a_CPPFLAGS = $(AM_CPPFLAGS) $(chymera_INCLUDES) $(MINIUPNPC_CPPFLAGS) $(NATPMP_CPPFLAGS) $(EVENT_CFLAGS) $(EVENT_PTHREADS_CFLAGS)
libchymera_server_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libchymera_server_a_SOURCES = \
  addrdb.cpp \
  addrman.cpp \
  banman.cpp \
  blockencodings.cpp \
  blockfilter.cpp \
  chain.cpp \
  consensus/tx_verify.cpp \
  dbwrapper.cpp \
  flatfile.cpp \
  httprpc.cpp \
  httpserver.cpp \
  i2p.cpp \
  index/base.cpp \
  index/blockfilterindex.cpp \
  index/coinstatsindex.cpp \
  index/txindex.cpp \
  init.cpp \
  mapport.cpp \
  miner.cpp \
  net.cpp \
  net_processing.cpp \
  node/blockstorage.cpp \
  node/coin.cpp \
  node/coinstats.cpp \
  node/context.cpp \
  node/interfaces.cpp \
  node/psbt.cpp \
  node/transaction.cpp \
  node/ui_interface.cpp \
  noui.cpp \
  policy/fees.cpp \
  policy/rbf.cpp \
  policy/settings.cpp \
  pow.cpp \
  rest.cpp \
  rpc/blockchain.cpp \
  rpc/mining.cpp \
  rpc/misc.cpp \
  rpc/net.cpp \
  rpc/rawtransaction.cpp \
  rpc/server.cpp \
  script/sigcache.cpp \
  shutdown.cpp \
  signet.cpp \
  timedata.cpp \
  torcontrol.cpp \
  txdb.cpp \
  txmempool.cpp \
  txorphanage.cpp \
  txrequest.cpp \
  validation.cpp \
  validationinterface.cpp \
  versionbits.cpp \
  $(chymera_CORE_H)

if ENABLE_WALLET
libchymera_server_a_SOURCES += wallet/init.cpp
endif
if !ENABLE_WALLET
libchymera_server_a_SOURCES += dummywallet.cpp
endif

if ENABLE_ZMQ
libchymera_zmq_a_CPPFLAGS = $(AM_CPPFLAGS) $(chymera_INCLUDES) $(ZMQ_CFLAGS)
libchymera_zmq_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libchymera_zmq_a_SOURCES = \
  zmq/zmqabstractnotifier.cpp \
  zmq/zmqnotificationinterface.cpp \
  zmq/zmqpublishnotifier.cpp \
  zmq/zmqrpc.cpp \
  zmq/zmqutil.cpp
endif


# wallet: shared between chymerad and chymera-qt, but only linked
# when wallet enabled
libchymera_wallet_a_CPPFLAGS = $(AM_CPPFLAGS) $(chymera_INCLUDES) $(SQLITE_CFLAGS)
libchymera_wallet_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libchymera_wallet_a_SOURCES = \
  wallet/coincontrol.cpp \
  wallet/context.cpp \
  wallet/crypter.cpp \
  wallet/db.cpp \
  wallet/dump.cpp \
  wallet/external_signer_scriptpubkeyman.cpp \
  wallet/feebumper.cpp \
  wallet/fees.cpp \
  wallet/interfaces.cpp \
  wallet/load.cpp \
  wallet/receive.cpp \
  wallet/rpcdump.cpp \
  wallet/rpcwallet.cpp \
  wallet/scriptpubkeyman.cpp \
  wallet/spend.cpp \
  wallet/transaction.cpp \
  wallet/wallet.cpp \
  wallet/walletdb.cpp \
  wallet/walletutil.cpp \
  wallet/coinselection.cpp \
  $(chymera_CORE_H)

if USE_SQLITE
libchymera_wallet_a_SOURCES += wallet/sqlite.cpp
endif
if USE_BDB
libchymera_wallet_a_SOURCES += wallet/bdb.cpp wallet/salvage.cpp
endif

libchymera_wallet_tool_a_CPPFLAGS = $(AM_CPPFLAGS) $(chymera_INCLUDES)
libchymera_wallet_tool_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libchymera_wallet_tool_a_SOURCES = \
  wallet/wallettool.cpp \
  $(chymera_CORE_H)

# crypto primitives library
crypto_libchymera_crypto_base_a_CPPFLAGS = $(AM_CPPFLAGS)
crypto_libchymera_crypto_base_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
crypto_libchymera_crypto_base_a_SOURCES = \
  crypto/aes.cpp \
  crypto/aes.h \
  crypto/chacha_poly_aead.h \
  crypto/chacha_poly_aead.cpp \
  crypto/chacha20.h \
  crypto/chacha20.cpp \
  crypto/common.h \
  crypto/hkdf_sha256_32.cpp \
  crypto/hkdf_sha256_32.h \
  crypto/hmac_sha256.cpp \
  crypto/hmac_sha256.h \
  crypto/hmac_sha512.cpp \
  crypto/hmac_sha512.h \
  crypto/poly1305.h \
  crypto/poly1305.cpp \
  crypto/muhash.h \
  crypto/muhash.cpp \
  crypto/ripemd160.cpp \
  crypto/ripemd160.h \
  crypto/sha1.cpp \
  crypto/sha1.h \
  crypto/sha256.cpp \
  crypto/sha256.h \
  crypto/sha3.cpp \
  crypto/sha3.h \
  crypto/sha512.cpp \
  crypto/sha512.h \
  crypto/siphash.cpp \
  crypto/siphash.h

if USE_ASM
crypto_libchymera_crypto_base_a_SOURCES += crypto/sha256_sse4.cpp
endif

crypto_libchymera_crypto_sse41_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
crypto_libchymera_crypto_sse41_a_CPPFLAGS = $(AM_CPPFLAGS)
crypto_libchymera_crypto_sse41_a_CXXFLAGS += $(SSE41_CXXFLAGS)
crypto_libchymera_crypto_sse41_a_CPPFLAGS += -DENABLE_SSE41
crypto_libchymera_crypto_sse41_a_SOURCES = crypto/sha256_sse41.cpp

crypto_libchymera_crypto_avx2_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
crypto_libchymera_crypto_avx2_a_CPPFLAGS = $(AM_CPPFLAGS)
crypto_libchymera_crypto_avx2_a_CXXFLAGS += $(AVX2_CXXFLAGS)
crypto_libchymera_crypto_avx2_a_CPPFLAGS += -DENABLE_AVX2
crypto_libchymera_crypto_avx2_a_SOURCES = crypto/sha256_avx2.cpp

crypto_libchymera_crypto_shani_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
crypto_libchymera_crypto_shani_a_CPPFLAGS = $(AM_CPPFLAGS)
crypto_libchymera_crypto_shani_a_CXXFLAGS += $(SHANI_CXXFLAGS)
crypto_libchymera_crypto_shani_a_CPPFLAGS += -DENABLE_SHANI
crypto_libchymera_crypto_shani_a_SOURCES = crypto/sha256_shani.cpp

# consensus: shared between all executables that validate any consensus rules.
libchymera_consensus_a_CPPFLAGS = $(AM_CPPFLAGS) $(chymera_INCLUDES)
libchymera_consensus_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libchymera_consensus_a_SOURCES = \
  amount.h \
  arith_uint256.cpp \
  arith_uint256.h \
  consensus/merkle.cpp \
  consensus/merkle.h \
  consensus/params.h \
  consensus/tx_check.cpp \
  consensus/validation.h \
  hash.cpp \
  hash.h \
  prevector.h \
  primitives/block.cpp \
  primitives/block.h \
  primitives/transaction.cpp \
  primitives/transaction.h \
  pubkey.cpp \
  pubkey.h \
  script/chymeraconsensus.cpp \
  script/interpreter.cpp \
  script/interpreter.h \
  script/script.cpp \
  script/script.h \
  script/script_error.cpp \
  script/script_error.h \
  serialize.h \
  span.h \
  tinyformat.h \
  uint256.cpp \
  uint256.h \
  util/strencodings.cpp \
  util/strencodings.h \
  version.h

# common: shared between chymerad, and chymera-qt and non-server tools
libchymera_common_a_CPPFLAGS = $(AM_CPPFLAGS) $(chymera_INCLUDES)
libchymera_common_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libchymera_common_a_SOURCES = \
  base58.cpp \
  bech32.cpp \
  bloom.cpp \
  chainparams.cpp \
  coins.cpp \
  compressor.cpp \
  core_read.cpp \
  core_write.cpp \
  external_signer.cpp \
  init/common.cpp \
  key.cpp \
  key_io.cpp \
  merkleblock.cpp \
  netaddress.cpp \
  netbase.cpp \
  net_permissions.cpp \
  outputtype.cpp \
  policy/feerate.cpp \
  policy/policy.cpp \
  protocol.cpp \
  psbt.cpp \
  rpc/rawtransaction_util.cpp \
  rpc/external_signer.cpp \
  rpc/util.cpp \
  scheduler.cpp \
  script/descriptor.cpp \
  script/sign.cpp \
  script/signingprovider.cpp \
  script/standard.cpp \
  versionbitsinfo.cpp \
  warnings.cpp \
  $(chymera_CORE_H)

# util: shared between all executables.
# This library *must* be included to make sure that the glibc
# backward-compatibility objects and their sanity checks are linked.
libchymera_util_a_CPPFLAGS = $(AM_CPPFLAGS) $(chymera_INCLUDES)
libchymera_util_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libchymera_util_a_SOURCES = \
  support/lockedpool.cpp \
  chainparamsbase.cpp \
  clientversion.cpp \
  compat/glibcxx_sanity.cpp \
  compat/strnlen.cpp \
  fs.cpp \
  interfaces/echo.cpp \
  interfaces/handler.cpp \
  interfaces/init.cpp \
  logging.cpp \
  random.cpp \
  randomenv.cpp \
  rpc/request.cpp \
  support/cleanse.cpp \
  sync.cpp \
  threadinterrupt.cpp \
  util/asmap.cpp \
  util/bip32.cpp \
  util/bytevectorhash.cpp \
  util/error.cpp \
  util/fees.cpp \
  util/getuniquepath.cpp \
  util/hasher.cpp \
  util/sock.cpp \
  util/system.cpp \
  util/message.cpp \
  util/moneystr.cpp \
  util/rbf.cpp \
  util/readwritefile.cpp \
  util/settings.cpp \
  util/thread.cpp \
  util/threadnames.cpp \
  util/serfloat.cpp \
  util/spanparsing.cpp \
  util/strencodings.cpp \
  util/string.cpp \
  util/time.cpp \
  util/tokenpipe.cpp \
  $(chymera_CORE_H)

if USE_LIBEVENT
libchymera_util_a_SOURCES += util/url.cpp
endif

if GLIBC_BACK_COMPAT
libchymera_util_a_SOURCES += compat/glibc_compat.cpp
AM_LDFLAGS += $(COMPAT_LDFLAGS)
endif

# cli: shared between chymera-cli and chymera-qt
libchymera_cli_a_CPPFLAGS = $(AM_CPPFLAGS) $(chymera_INCLUDES)
libchymera_cli_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libchymera_cli_a_SOURCES = \
  compat/stdin.h \
  compat/stdin.cpp \
  rpc/client.cpp \
  $(chymera_CORE_H)

nodist_libchymera_util_a_SOURCES = $(srcdir)/obj/build.h
#

# chymerad & chymera-node binaries #
chymera_daemon_sources = chymerad.cpp
chymera_bin_cppflags = $(AM_CPPFLAGS) $(chymera_INCLUDES)
chymera_bin_cxxflags = $(AM_CXXFLAGS) $(PIE_FLAGS)
chymera_bin_ldflags = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS) $(PTHREAD_FLAGS)

if TARGET_WINDOWS
chymera_daemon_sources += chymerad-res.rc
endif

chymera_bin_ldadd = \
  $(LIBchymera_WALLET) \
  $(LIBchymera_COMMON) \
  $(LIBchymera_UTIL) \
  $(LIBUNIVALUE) \
  $(LIBchymera_ZMQ) \
  $(LIBchymera_CONSENSUS) \
  $(LIBchymera_CRYPTO) \
  $(LIBLEVELDB) \
  $(LIBLEVELDB_SSE42) \
  $(LIBMEMENV) \
  $(LIBSECP256K1)

chymera_bin_ldadd += $(BOOST_LIBS) $(BDB_LIBS) $(MINIUPNPC_LIBS) $(NATPMP_LIBS) $(EVENT_PTHREADS_LIBS) $(EVENT_LIBS) $(ZMQ_LIBS) $(SQLITE_LIBS)

chymerad_SOURCES = $(chymera_daemon_sources) init/chymerad.cpp
chymerad_CPPFLAGS = $(chymera_bin_cppflags)
chymerad_CXXFLAGS = $(chymera_bin_cxxflags)
chymerad_LDFLAGS = $(chymera_bin_ldflags)
chymerad_LDADD = $(LIBchymera_SERVER) $(chymera_bin_ldadd)

chymera_node_SOURCES = $(chymera_daemon_sources) init/chymera-node.cpp
chymera_node_CPPFLAGS = $(chymera_bin_cppflags)
chymera_node_CXXFLAGS = $(chymera_bin_cxxflags)
chymera_node_LDFLAGS = $(chymera_bin_ldflags)
chymera_node_LDADD = $(LIBchymera_SERVER) $(chymera_bin_ldadd) $(LIBchymera_IPC) $(LIBMULTIPROCESS_LIBS)

# chymera-cli binary #
chymera_cli_SOURCES = chymera-cli.cpp
chymera_cli_CPPFLAGS = $(AM_CPPFLAGS) $(chymera_INCLUDES) $(EVENT_CFLAGS)
chymera_cli_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
chymera_cli_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS) $(PTHREAD_FLAGS)

if TARGET_WINDOWS
chymera_cli_SOURCES += chymera-cli-res.rc
endif

chymera_cli_LDADD = \
  $(LIBchymera_CLI) \
  $(LIBUNIVALUE) \
  $(LIBchymera_UTIL) \
  $(LIBchymera_CRYPTO)

chymera_cli_LDADD += $(BOOST_LIBS) $(EVENT_LIBS)
#

# chymera-tx binary #
chymera_tx_SOURCES = chymera-tx.cpp
chymera_tx_CPPFLAGS = $(AM_CPPFLAGS) $(chymera_INCLUDES)
chymera_tx_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
chymera_tx_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS) $(PTHREAD_FLAGS)

if TARGET_WINDOWS
chymera_tx_SOURCES += chymera-tx-res.rc
endif

chymera_tx_LDADD = \
  $(LIBUNIVALUE) \
  $(LIBchymera_COMMON) \
  $(LIBchymera_UTIL) \
  $(LIBchymera_CONSENSUS) \
  $(LIBchymera_CRYPTO) \
  $(LIBSECP256K1)

chymera_tx_LDADD += $(BOOST_LIBS)
#

# chymera-wallet binary #
chymera_wallet_SOURCES = chymera-wallet.cpp
chymera_wallet_CPPFLAGS = $(chymera_bin_cppflags)
chymera_wallet_CXXFLAGS = $(chymera_bin_cxxflags)
chymera_wallet_LDFLAGS = $(chymera_bin_ldflags)
chymera_wallet_LDADD = $(LIBchymera_WALLET_TOOL) $(chymera_bin_ldadd)

if TARGET_WINDOWS
chymera_wallet_SOURCES += chymera-wallet-res.rc
endif
#

# chymera-util binary #
chymera_util_SOURCES = chymera-util.cpp
chymera_util_CPPFLAGS = $(AM_CPPFLAGS) $(chymera_INCLUDES)
chymera_util_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
chymera_util_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS) $(PTHREAD_FLAGS)

if TARGET_WINDOWS
chymera_util_SOURCES += chymera-util-res.rc
endif

chymera_util_LDADD = \
  $(LIBchymera_COMMON) \
  $(LIBchymera_UTIL) \
  $(LIBUNIVALUE) \
  $(LIBchymera_CONSENSUS) \
  $(LIBchymera_CRYPTO) \
  $(LIBSECP256K1)

chymera_util_LDADD += $(BOOST_LIBS)
#

# chymeraconsensus library #
if BUILD_chymera_LIBS
include_HEADERS = script/chymeraconsensus.h
libchymeraconsensus_la_SOURCES = support/cleanse.cpp $(crypto_libchymera_crypto_base_a_SOURCES) $(libchymera_consensus_a_SOURCES)

if GLIBC_BACK_COMPAT
  libchymeraconsensus_la_SOURCES += compat/glibc_compat.cpp
endif

libchymeraconsensus_la_LDFLAGS = $(AM_LDFLAGS) -no-undefined $(RELDFLAGS)
libchymeraconsensus_la_LIBADD = $(LIBSECP256K1)
libchymeraconsensus_la_CPPFLAGS = $(AM_CPPFLAGS) -I$(builddir)/obj -I$(srcdir)/secp256k1/include -DBUILD_chymera_INTERNAL
libchymeraconsensus_la_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)

endif
#

CTAES_DIST =  crypto/ctaes/bench.c
CTAES_DIST += crypto/ctaes/ctaes.c
CTAES_DIST += crypto/ctaes/ctaes.h
CTAES_DIST += crypto/ctaes/README.md
CTAES_DIST += crypto/ctaes/test.c

CLEANFILES = $(EXTRA_LIBRARIES)

CLEANFILES += *.gcda *.gcno
CLEANFILES += compat/*.gcda compat/*.gcno
CLEANFILES += consensus/*.gcda consensus/*.gcno
CLEANFILES += crc32c/src/*.gcda crc32c/src/*.gcno
CLEANFILES += crypto/*.gcda crypto/*.gcno
CLEANFILES += index/*.gcda index/*.gcno
CLEANFILES += interfaces/*.gcda interfaces/*.gcno
CLEANFILES += node/*.gcda node/*.gcno
CLEANFILES += policy/*.gcda policy/*.gcno
CLEANFILES += primitives/*.gcda primitives/*.gcno
CLEANFILES += rpc/*.gcda rpc/*.gcno
CLEANFILES += script/*.gcda script/*.gcno
CLEANFILES += support/*.gcda support/*.gcno
CLEANFILES += univalue/*.gcda univalue/*.gcno
CLEANFILES += util/*.gcda util/*.gcno
CLEANFILES += wallet/*.gcda wallet/*.gcno
CLEANFILES += wallet/test/*.gcda wallet/test/*.gcno
CLEANFILES += zmq/*.gcda zmq/*.gcno
CLEANFILES += obj/build.h

EXTRA_DIST = $(CTAES_DIST)


config/chymera-config.h: config/stamp-h1
	@$(MAKE) -C $(top_builddir) $(subdir)/$(@)
config/stamp-h1: $(top_srcdir)/$(subdir)/config/chymera-config.h.in $(top_builddir)/config.status
	$(AM_V_at)$(MAKE) -C $(top_builddir) $(subdir)/$(@)
$(top_srcdir)/$(subdir)/config/chymera-config.h.in:  $(am__configure_deps)
	$(AM_V_at)$(MAKE) -C $(top_srcdir) $(subdir)/config/chymera-config.h.in

clean-local:
	-$(MAKE) -C secp256k1 clean
	-$(MAKE) -C univalue clean
	-rm -f leveldb/*/*.gcda leveldb/*/*.gcno leveldb/helpers/memenv/*.gcda leveldb/helpers/memenv/*.gcno
	-rm -f config.h
	-rm -rf test/__pycache__

.rc.o:
	@test -f $(WINDRES)
	## FIXME: How to get the appropriate modulename_CPPFLAGS in here?
	$(AM_V_GEN) $(WINDRES) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(CPPFLAGS) -DWINDRES_PREPROC -i $< -o $@

check-symbols: $(bin_PROGRAMS)
if TARGET_DARWIN
	@echo "Checking macOS dynamic libraries..."
	$(AM_V_at) OTOOL=$(OTOOL) $(PYTHON) $(top_srcdir)/contrib/devtools/symbol-check.py $(bin_PROGRAMS)
endif

if TARGET_WINDOWS
	@echo "Checking Windows dynamic libraries..."
	$(AM_V_at) OBJDUMP=$(OBJDUMP) $(PYTHON) $(top_srcdir)/contrib/devtools/symbol-check.py $(bin_PROGRAMS)
endif

if GLIBC_BACK_COMPAT
	@echo "Checking glibc back compat..."
	$(AM_V_at) CPPFILT=$(CPPFILT) $(PYTHON) $(top_srcdir)/contrib/devtools/symbol-check.py $(bin_PROGRAMS)
endif

check-security: $(bin_PROGRAMS)
if HARDEN
	@echo "Checking binary security..."
	$(AM_V_at) OBJDUMP=$(OBJDUMP) OTOOL=$(OTOOL) $(PYTHON) $(top_srcdir)/contrib/devtools/security-check.py $(bin_PROGRAMS)
endif

libchymera_ipc_mpgen_input = \
  ipc/capnp/echo.capnp \
  ipc/capnp/init.capnp
EXTRA_DIST += $(libchymera_ipc_mpgen_input)
%.capnp:

if BUILD_MULTIPROCESS
LIBchymera_IPC=libchymera_ipc.a
libchymera_ipc_a_SOURCES = \
  ipc/capnp/init-types.h \
  ipc/capnp/protocol.cpp \
  ipc/capnp/protocol.h \
  ipc/exception.h \
  ipc/interfaces.cpp \
  ipc/process.cpp \
  ipc/process.h \
  ipc/protocol.h
libchymera_ipc_a_CPPFLAGS = $(AM_CPPFLAGS) $(chymera_INCLUDES)
libchymera_ipc_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS) $(LIBMULTIPROCESS_CFLAGS)

include $(MPGEN_PREFIX)/include/mpgen.mk
libchymera_ipc_mpgen_output = \
  $(libchymera_ipc_mpgen_input:=.c++) \
  $(libchymera_ipc_mpgen_input:=.h) \
  $(libchymera_ipc_mpgen_input:=.proxy-client.c++) \
  $(libchymera_ipc_mpgen_input:=.proxy-server.c++) \
  $(libchymera_ipc_mpgen_input:=.proxy-types.c++) \
  $(libchymera_ipc_mpgen_input:=.proxy-types.h) \
  $(libchymera_ipc_mpgen_input:=.proxy.h)
nodist_libchymera_ipc_a_SOURCES = $(libchymera_ipc_mpgen_output)
CLEANFILES += $(libchymera_ipc_mpgen_output)
endif

if EMBEDDED_LEVELDB
include Makefile.crc32c.include
include Makefile.leveldb.include
endif

include Makefile.test_util.include
include Makefile.test_fuzz.include

if ENABLE_TESTS
include Makefile.test.include
endif

if ENABLE_BENCH
include Makefile.bench.include
endif

if ENABLE_QT
include Makefile.qt.include
endif

if ENABLE_QT_TESTS
include Makefile.qttest.include
endif
