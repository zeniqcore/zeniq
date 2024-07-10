# Copyright (c) 2017 The Bitcoin developers

project(wallet)

# Add Berkeley DB dependency.
find_package(BerkeleyDB 5.3 REQUIRED)
# If the system uses libdb_cxx higher than 5.3 this is and must be used

# Add event dependency. This is only required for evhttp_uridecode
# in rpcwallet.cpp so it may be worth considering using an alternative.
find_package(Event 2.0.22 REQUIRED COMPONENTS event)

add_library(wallet
	../interfaces/wallet.cpp
	coincontrol.cpp
	coinselection.cpp
	crypter.cpp
	db.cpp
	fees.cpp
	init.cpp
	psbtwallet.cpp
	rpcdump.cpp
	rpcwallet.cpp
	wallet.cpp
	walletdb.cpp
	walletutil.cpp
)

target_compile_definitions(wallet PUBLIC -DBOOST_FILESYSTEM_VERSION=3)
target_link_libraries(wallet server script univalue Event::event ${BerkeleyDB_Cxx_LIBRARY})
