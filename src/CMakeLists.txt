# Copyright (c) 2017 The Bitcoin developers

cmake_minimum_required(VERSION 3.13)
project(bitcoind)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Default visibility is hidden on all targets.
set(CMAKE_C_VISIBILITY_PRESET hidden)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)

option(BUILD_BITCOIN_DAEMON "Build zeniqd" ON)
option(BUILD_BITCOIN_WALLET "Activate the wallet functionality" ON)
option(BUILD_BITCOIN_ZMQ "Activate the ZeroMQ functionalities" ON)
option(BUILD_BITCOIN_SEEDER "Build zeniq-seeder" ON)
option(BUILD_BITCOIN_CLI "Build zeniq-cli" ON)
option(BUILD_BITCOIN_TX "Build zeniq-tx" ON)
option(BUILD_BITCOIN_QT "Build zeniq-qt" ON)
option(BUILD_LIBBITCOINCONSENSUS "Build the zeniqconsenus shared library" OFF)
option(ENABLE_BIP70 "Enable BIP70 (payment protocol) support in GUI" ON)
option(ENABLE_HARDENING "Harden the executables" ON)
option(ENABLE_REDUCE_EXPORTS "Reduce the amount of exported symbols" OFF)
option(ENABLE_STATIC_LIBGCC "Statically link libgcc" OFF)
option(ENABLE_STATIC_LIBSTDCXX "Statically link libstdc++" OFF)
option(ENABLE_GLIBC_BACK_COMPAT "Enable Glibc compatibility features" OFF)
option(ENABLE_QRCODE "Enable QR code display" ON)
option(ENABLE_UPNP "Enable UPnP support" ON)
option(ENABLE_WERROR "Promote some compiler warnings to errors" OFF)
option(START_WITH_UPNP "Make UPnP the default to map ports" OFF)
option(ENABLE_CLANG_TIDY "Enable clang-tidy checks for Zeniq Node" OFF)
option(ENABLE_PROFILING "Select the profiling tool to use" OFF)
option(USE_JEMALLOC_EXPERIMENTAL "Use jemalloc as an allocation library (experimental)" OFF)

if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
	set(DEFAULT_ENABLE_DBUS_NOTIFICATIONS ON)
endif()
option(ENABLE_DBUS_NOTIFICATIONS "Enable DBus desktop notifications. Linux only." ${DEFAULT_ENABLE_DBUS_NOTIFICATIONS})

# If ccache is available, then use it.
find_program(CCACHE ccache)
if(CCACHE)
	message(STATUS "Using ccache: ${CCACHE}")
	set(CMAKE_C_COMPILER_LAUNCHER ${CCACHE})
	set(CMAKE_CXX_COMPILER_LAUNCHER ${CCACHE})
endif(CCACHE)

# Disable what we do not need for the native build.
include(NativeExecutable)
native_add_cmake_flags(
	"-DBUILD_BITCOIN_WALLET=OFF"
	"-DBUILD_BITCOIN_QT=OFF"
	"-DBUILD_BITCOIN_ZMQ=OFF"
	"-DENABLE_QRCODE=OFF"
	"-DENABLE_UPNP=OFF"
	# Forward the current setting for clang-tidy
	"-DENABLE_CLANG_TIDY=${ENABLE_CLANG_TIDY}"
)

if(ENABLE_CLANG_TIDY)
	include(ClangTidy)
endif()

if(ENABLE_SANITIZERS)
	include(Sanitizers)
	enable_sanitizers(${ENABLE_SANITIZERS})
endif()

include(AddCompilerFlags)

# Prefer -g3, defaults to -g if unavailable
foreach(LANGUAGE C CXX)
	set(COMPILER_DEBUG_LEVEL -g)
	check_compiler_flags(G3_IS_SUPPORTED ${LANGUAGE} -g3)
	if(${G3_IS_SUPPORTED})
		set(COMPILER_DEBUG_LEVEL -g3)
	endif()
	add_compile_options_to_configuration_for_language(Debug ${LANGUAGE} ${COMPILER_DEBUG_LEVEL})
endforeach()

# Define the debugging symbols DEBUG and DEBUG_LOCKORDER when the Debug build
# type is selected.
add_compile_definitions_to_configuration(Debug DEBUG DEBUG_LOCKORDER)

# Add -ftrapv when building in Debug
add_compile_options_to_configuration(Debug -ftrapv)

# All versions of gcc that we commonly use for building are subject to bug
# https://gcc.gnu.org/bugzilla/show_bug.cgi?id=90348. To work around that, set
# -fstack-reuse=none for all gcc builds. (Only gcc understands this flag)
if(NOT ENABLE_CLANG_TIDY)
	add_compiler_flags(-fstack-reuse=none)
endif()

# Ensure that WINDRES_PREPROC is enabled when using windres.
if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
	# Ensure that WINDRES_PREPROC is enabled when using windres.
	list(APPEND CMAKE_RC_FLAGS "-DWINDRES_PREPROC")

	# Build all static so there is no dll file to distribute.
	add_linker_flags(-static)
endif()

if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
	add_compile_definitions(MAC_OSX OBJC_OLD_DISPATCH_PROTOTYPES=0)
	add_linker_flags(-Wl,-dead_strip_dylibs)
endif()

if(ENABLE_REDUCE_EXPORTS)
	# Default visibility is set by CMAKE_<LANG>_VISIBILITY_PRESET, but this
	# doesn't tell if the visibility set is effective.
	# Check if the flag -fvisibility=hidden is supported, as using the hidden
	# visibility is a requirement to reduce exports.
	check_compiler_flags(HAS_CXX_FVISIBILITY CXX -fvisibility=hidden)
	if(NOT HAS_CXX_FVISIBILITY)
		message(FATAL_ERROR "Cannot set default symbol visibility. Use -DENABLE_REDUCE_EXPORTS=OFF.")
	endif()

	# Also hide symbols from static libraries
	add_linker_flags(-Wl,--exclude-libs,ALL)
endif()

# Enable statically linking libgcc
if(ENABLE_STATIC_LIBGCC)
	add_linker_flags(-static-libgcc)
endif()

# Enable statically linking libstdc++
if(ENABLE_STATIC_LIBSTDCXX)
	add_linker_flags(-static-libstdc++)
endif()

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(ENABLE_HARDENING)
	# Enable stack protection
	add_cxx_compiler_flags(-fstack-protector-all -Wstack-protector)

	# Enable some buffer overflow checking, except in -O0 builds which
	# do not support them
	add_compiler_flags(-U_FORTIFY_SOURCE)
	add_compile_options($<$<NOT:$<CONFIG:Debug>>:-D_FORTIFY_SOURCE=2>)

	# Enable ASLR (these flags are primarily targeting MinGw)
	add_linker_flags(-Wl,--dynamicbase -Wl,--nxcompat -Wl,--high-entropy-va)

	# Make the relocated sections read-only
	add_linker_flags(-Wl,-z,relro -Wl,-z,now)

	# CMake provides the POSITION_INDEPENDENT_CODE property to set PIC/PIE.
	# Unfortunately setting the -pie linker flag this way require CMake >= 3.14,
	# which is not widely distributed at the time of writing.
	# FIXME: remove the fallback case when cmake >= 3.14 get enforced.
	if(POLICY CMP0083)
		cmake_policy(SET CMP0083 NEW)
		include(CheckPIESupported)
		check_pie_supported()
	elseif(NOT ${CMAKE_SYSTEM_NAME} MATCHES "Windows")
		check_linker_flag(PIE_IS_SUPPORTED -pie)
		if(${PIE_IS_SUPPORTED})
			add_link_options($<$<STREQUAL:$<TARGET_PROPERTY:TYPE>,EXECUTABLE>:-pie>)
		endif()
	endif()

	if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
		# MinGw provides its own libssp for stack smashing protection
		link_libraries(ssp)
	endif()
endif()

if(ENABLE_PROFILING MATCHES "gprof")
	message(STATUS "Enable profiling with gprof")

	# -pg is incompatible with -pie. Since hardening and profiling together
	# doesn't make sense, we simply make them mutually exclusive here.
	# Additionally, hardened toolchains may force -pie by default, in which
	# case it needs to be turned off with -no-pie.
	if(ENABLE_HARDENING)
		message(FATAL_ERROR "Profiling with gprof requires disabling hardening with -DENABLE_HARDENING=OFF.")
	endif()
	add_linker_flags(-no-pie)

	add_compiler_flags(-pg)
	add_linker_flags(-pg)
endif()

# Enable warning
add_c_compiler_flags(-Wnested-externs -Wstrict-prototypes)
add_compiler_flags(
	-Wall
	-Wextra
	-Wformat
	-Wvla
	-Wcast-align
	-Wunused-parameter
	-Wmissing-braces
	-Wthread-safety-analysis
	-Wshadow
	-Wrange-loop-analysis
	-Wredundant-decls
)
# The -Wformat-security option is dependent on -Wformat on GCC. Check for it
# together with -Wformat to avoid a warning.
add_compiler_flag_group(-Wformat -Wformat-security)
add_cxx_compiler_flags(
	-Wredundant-move
)

option(EXTRA_WARNINGS "Enable extra warnings" OFF)
if(EXTRA_WARNINGS)
	add_cxx_compiler_flags(-Wsuggest-override)
else()
	add_compiler_flags(-Wno-unused-parameter)
	add_compiler_flags(-Wno-implicit-fallthrough)
endif()

if(ENABLE_WERROR)
	add_compiler_flags(
		-Werror=vla
		-Werror=thread-safety-analysis
	)
endif()

# Create a target for OpenSSL
include(BrewHelper)
find_brew_prefix(OPENSSL_ROOT_DIR openssl)
find_package(OpenSSL REQUIRED)

# libtool style configure
add_subdirectory(config)

# Enable LFS (Large File Support) on targets that don't have it natively.
# This should be defined before the libraries are included as leveldb need the
# definition to be set.
if(NOT HAVE_LARGE_FILE_SUPPORT)
	add_compile_definitions(_FILE_OFFSET_BITS=64)
	add_linker_flags(-Wl,--large-address-aware)
endif()

if(ENABLE_GLIBC_BACK_COMPAT)
	# Wrap some glibc functions with ours
	add_linker_flags(-Wl,--wrap=__divmoddi4)
	add_linker_flags(-Wl,--wrap=log2f)

	if(NOT HAVE_LARGE_FILE_SUPPORT)
		add_linker_flags(-Wl,--wrap=fcntl -Wl,--wrap=fcntl64)
	endif()
endif()

if(USE_JEMALLOC_EXPERIMENTAL)
	find_package(Jemalloc REQUIRED)
	link_libraries(Jemalloc::jemalloc)
endif()


# Make sure that all the global compiler and linker flags are set BEFORE
# including the libraries so they apply as needed.


# libraries
add_subdirectory(crypto)
add_subdirectory(leveldb)
add_subdirectory(secp256k1)
add_subdirectory(univalue)

# Find the git root, and returns the full path to the .git/logs/HEAD file if
# it exists.
function(find_git_head_logs_file RESULT)
	find_package(Git)
	if(GIT_FOUND)
		execute_process(
			COMMAND "${GIT_EXECUTABLE}" "rev-parse" "--show-toplevel"
			WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
			OUTPUT_VARIABLE GIT_ROOT
			RESULT_VARIABLE GIT_RESULT
			OUTPUT_STRIP_TRAILING_WHITESPACE
			ERROR_QUIET
		)

		if(GIT_RESULT EQUAL 0)
			set(GIT_LOGS_DIR "${GIT_ROOT}/.git/logs")
			set(GIT_HEAD_LOGS_FILE "${GIT_LOGS_DIR}/HEAD")
			# If the .git/logs/HEAD does not exist, create it
			if(NOT EXISTS "${GIT_HEAD_LOGS_FILE}")
				file(MAKE_DIRECTORY "${GIT_LOGS_DIR}")
				file(TOUCH "${GIT_HEAD_LOGS_FILE}")
			endif()
			set(${RESULT} "${GIT_HEAD_LOGS_FILE}" PARENT_SCOPE)
		endif()
	endif()
endfunction()

find_git_head_logs_file(GIT_HEAD_LOGS_FILE)

set(OBJ_DIR "${CMAKE_CURRENT_BINARY_DIR}/obj")
file(MAKE_DIRECTORY "${OBJ_DIR}")
set(BUILD_HEADER "${OBJ_DIR}/build.h")
set(BUILD_HEADER_TMP "${BUILD_HEADER}.tmp")

add_custom_command(
	DEPENDS
		"${GIT_HEAD_LOGS_FILE}"
		"${CMAKE_SOURCE_DIR}/share/genbuild.sh"
	OUTPUT
		"${BUILD_HEADER}"
	COMMAND
		"${CMAKE_SOURCE_DIR}/share/genbuild.sh"
		"${BUILD_HEADER_TMP}"
		"${CMAKE_SOURCE_DIR}"
	COMMAND
		${CMAKE_COMMAND} -E copy_if_different "${BUILD_HEADER_TMP}" "${BUILD_HEADER}"
	COMMAND
		${CMAKE_COMMAND} -E remove "${BUILD_HEADER_TMP}"
)

# Because the Zeniq Node source code is disorganised, we
# end up with a bunch of libraries without any apparent
# cohesive structure. This is inherited from Bitcoin Core
# and reflecting this.
# TODO: Improve the structure once cmake is rocking.

# Various completely unrelated features shared by all executables.
add_library(util
	chainparamsbase.cpp
	clientversion.cpp
	compat/glibc_sanity.cpp
	compat/glibcxx_sanity.cpp
	compat/strnlen.cpp
	fs.cpp
	logging.cpp
	random.cpp
	rpc/protocol.cpp
	rpc/util.cpp
	support/cleanse.cpp
	support/lockedpool.cpp
	sync.cpp
	threadinterrupt.cpp
	uint256.cpp
	util/moneystr.cpp
	util/saltedhashers.cpp
	util/strencodings.cpp
	util/system.cpp
	util/threadnames.cpp
	util/time.cpp

	# obj/build.h
	"${BUILD_HEADER}"
)

target_compile_definitions(util PUBLIC -DBOOST_FILESYSTEM_VERSION=3)

target_compile_definitions(util PUBLIC HAVE_CONFIG_H HAVE_BUILD_INFO)
target_include_directories(util
	PUBLIC
		.
		# To access the config/ and obj/ directories
		${CMAKE_CURRENT_BINARY_DIR}
)

if(ENABLE_GLIBC_BACK_COMPAT)
	target_sources(util PRIVATE compat/glibc_compat.cpp)
endif()

set(Boost_USE_STATIC_LIBS ON)

# Target specific configs
if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
	set(Boost_USE_STATIC_RUNTIME ON)
	set(Boost_THREADAPI win32)

	find_package(SHLWAPI REQUIRED)
	# We cannot use the imported target here, because cmake will introduce an
	# -isystem compilation directive and cause the build to fail with MinGw.
	# This comes from a couple cmake bugs:
	#  - https://gitlab.kitware.com/cmake/cmake/issues/16291
	#  - https://gitlab.kitware.com/cmake/cmake/issues/19095
	# These issues are solved from cmake 3.14.1. Once this version is enforced,
	# the following can be used:
	# target_link_libraries(util SHLWAPI::shlwapi)
	target_link_libraries(util ${SHLWAPI_LIBRARIES})
	target_include_directories(util PUBLIC ${SHLWAPI_INCLUDE_DIRS})

	find_library(WS2_32_LIBRARY NAMES ws2_32)
	target_link_libraries(util ${WS2_32_LIBRARY})

	target_compile_definitions(util PUBLIC BOOST_THREAD_USE_LIB)
endif()

# Boost packages
set(BOOST_PACKAGES_REQUIRED chrono filesystem thread)

function(prepend var prefix)
	set(listVar "")
	foreach(f ${ARGN})
		list(APPEND listVar "${prefix}${f}")
	endforeach(f)
	set(${var} "${listVar}" PARENT_SCOPE)
endfunction(prepend)

prepend(BOOST_LIBRARIES "Boost::" ${BOOST_PACKAGES_REQUIRED})

find_package(Boost 1.81 REQUIRED ${BOOST_PACKAGES_REQUIRED})
target_link_libraries(util univalue crypto ${BOOST_LIBRARIES})

# Make sure boost uses std::atomic (it doesn't before 1.63)
target_compile_definitions(util PUBLIC BOOST_SP_USE_STD_ATOMIC BOOST_AC_USE_STD_ATOMIC)

# More completely unrelated features shared by all executables.
# Because nothing says this is different from util than "common"
add_library(common
	amount.cpp
	base58.cpp
	cashaddr.cpp
	cashaddrenc.cpp
	chainparams.cpp
	config.cpp
	consensus/merkle.cpp
	coins.cpp
	compressor.cpp
	feerate.cpp
	core_read.cpp
	core_write.cpp
	hash.cpp
	key.cpp
	key_io.cpp
	keystore.cpp
	net_permissions.cpp
	netaddress.cpp
	netbase.cpp
	primitives/block.cpp
	protocol.cpp
	psbt.cpp
	scheduler.cpp
	warnings.cpp
)

target_compile_definitions(common PUBLIC -DBOOST_FILESYSTEM_VERSION=3)
target_link_libraries(common util secp256k1)

# script library
add_library(script
	script/bitfield.cpp
	script/descriptor.cpp
	script/interpreter.cpp
	script/ismine.cpp
	script/script.cpp
	script/script_error.cpp
	script/script_execution_context.cpp
	script/sigencoding.cpp
	script/sign.cpp
	script/standard.cpp
)

target_compile_definitions(script PUBLIC -DBOOST_FILESYSTEM_VERSION=3)
target_link_libraries(script common)

# libbitcoinconsensus
add_library(bitcoinconsensus
	arith_uint256.cpp
	hash.cpp
	primitives/transaction.cpp
	pubkey.cpp
	uint256.cpp
	util/strencodings.cpp
)

target_compile_definitions(bitcoinconsensus PUBLIC -DBOOST_FILESYSTEM_VERSION=3)
target_link_libraries(bitcoinconsensus script)

include(InstallationHelper)
if(BUILD_LIBBITCOINCONSENSUS)
	target_compile_definitions(bitcoinconsensus
		PUBLIC
			BUILD_BITCOIN_INTERNAL
			HAVE_CONSENSUS_LIB
	)

	install_shared_library(bitcoinconsensus
		script/bitcoinconsensus.cpp
		PUBLIC_HEADER script/bitcoinconsensus.h
	)
endif()

# Bitcoin server facilities
add_library(server
	addrdb.cpp
	addrman.cpp
	banman.cpp
	bloom.cpp
	blockencodings.cpp
	blockfilter.cpp
	chain.cpp
	checkpoints.cpp
	config.cpp
	consensus/activation.cpp
	consensus/tx_verify.cpp
	consensus/tx_check.cpp
	dsproof/dsproof.cpp
	dsproof/dsproof_create.cpp
	dsproof/dsproof_validate.cpp
	dsproof/storage.cpp
	dsproof/storage_cleanup.cpp
	dbwrapper.cpp
	flatfile.cpp
	gbtlight.cpp
	httprpc.cpp
	httpserver.cpp
	index/base.cpp
	index/txindex.cpp
	init.cpp
	interfaces/chain.cpp
	interfaces/handler.cpp
	interfaces/node.cpp
	merkleblock.cpp
	miner.cpp
	net.cpp
	net_processing.cpp
	node/transaction.cpp
	noui.cpp
	outputtype.cpp
	policy/fees.cpp
	policy/policy.cpp
	pow.cpp
	dma.cpp
	rest.cpp
	rpc/abc.cpp
	rpc/blockchain.cpp
	rpc/command.cpp
	rpc/dsproof.cpp
	rpc/jsonrpcrequest.cpp
	rpc/mining.cpp
	rpc/misc.cpp
	rpc/net.cpp
	rpc/rawtransaction.cpp
	rpc/server.cpp
	script/scriptcache.cpp
	script/sigcache.cpp
	shutdown.cpp
	timedata.cpp
	torcontrol.cpp
	txdb.cpp
	txmempool.cpp
	ui_interface.cpp
	validation.cpp
	validationinterface.cpp
)

target_compile_definitions(server PUBLIC -DBOOST_FILESYSTEM_VERSION=3)
target_include_directories(server PRIVATE leveldb/helpers/memenv)

# This require libevent
set(EVENT_MIN_VERSION 2.0.22)
find_package(Event ${EVENT_MIN_VERSION} REQUIRED COMPONENTS event)

target_link_libraries(server
	Event::event
	bitcoinconsensus
	leveldb
	memenv
	boost_filesystem
)

if(NOT ${CMAKE_SYSTEM_NAME} MATCHES "Windows")
	find_package(Event ${EVENT_MIN_VERSION} REQUIRED COMPONENTS pthreads)
	target_link_libraries(server Event::pthreads)
endif()

if(ENABLE_UPNP)
	find_package(MiniUPnPc 1.5 REQUIRED)
	target_link_libraries(server MiniUPnPc::miniupnpc)

	if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
		find_library(IPHLPAPI_LIBRARY NAMES iphlpapi)
		if(NOT IPHLPAPI_LIBRARY)
			message(FATAL_ERROR "Lib iphlpapi is missing")
		endif()
		target_link_libraries(server ${IPHLPAPI_LIBRARY})

		target_compile_definitions(server
			PUBLIC -DSTATICLIB
			PUBLIC -DMINIUPNP_STATICLIB
		)
	endif()
endif()

# Test suite.
add_subdirectory(test)

# Benchmark suite.
add_subdirectory(bench)

# Wallet
if(BUILD_BITCOIN_WALLET)
	add_subdirectory(wallet)
	target_link_libraries(server wallet)
	# There is a circular dependency between wallet and server, see:
	# https://github.com/bitcoin/bitcoin/pull/14437#discussion_r226237048
	# target_link_libraries(wallet server)
else()
	target_sources(server PRIVATE dummywallet.cpp)
endif()

# ZeroMQ
if(BUILD_BITCOIN_ZMQ)
	add_subdirectory(zmq)
	target_link_libraries(server zmq)
endif()

# RPC client support
add_library(rpcclient rpc/client.cpp)
target_link_libraries(rpcclient univalue util)

# zeniq-seeder
if(BUILD_BITCOIN_SEEDER)
	add_subdirectory(seeder)
endif()

include(BinaryTest)

# zeniq-cli
if(BUILD_BITCOIN_CLI)
	add_executable(zeniq-cli bitcoin-cli.cpp)
	target_compile_definitions(zeniq-cli PUBLIC -DBOOST_FILESYSTEM_VERSION=3)
	if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
		target_sources(zeniq-cli PRIVATE bitcoin-cli-res.rc)
	endif()

	target_link_libraries(zeniq-cli common rpcclient Event::event)

	add_to_symbols_check(zeniq-cli)
	add_to_security_check(zeniq-cli)

	install_target(zeniq-cli)
endif()

# zeniq-tx
if(BUILD_BITCOIN_TX)
	add_executable(zeniq-tx bitcoin-tx.cpp)
	target_compile_definitions(zeniq-tx PUBLIC -DBOOST_FILESYSTEM_VERSION=3)
	if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
		target_sources(zeniq-tx PRIVATE bitcoin-tx-res.rc)
	endif()

	target_link_libraries(zeniq-tx bitcoinconsensus)

	add_to_symbols_check(zeniq-tx)
	add_to_security_check(zeniq-tx)

	install_target(zeniq-tx)
endif()

# zeniqd
if(BUILD_BITCOIN_DAEMON)
	add_executable(zeniqd bitcoind.cpp)
	target_compile_definitions(zeniqd PUBLIC -DBOOST_FILESYSTEM_VERSION=3)
	target_link_libraries(zeniqd server)
	if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
		target_sources(zeniqd PRIVATE bitcoind-res.rc)
	endif()

	add_to_symbols_check(zeniqd)
	add_to_security_check(zeniqd)

	install_target(zeniqd)
endif()

# zeniq-qt
if(BUILD_BITCOIN_QT)
	add_subdirectory(qt)
endif()

