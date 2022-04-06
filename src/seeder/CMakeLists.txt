# Copyright (c) 2017-2019 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

project(bitcoin-seeder)

add_library(seeder bitcoin.cpp db.cpp dns.cpp)
target_link_libraries(seeder common bitcoinconsensus)

add_executable(zeniq-seeder main.cpp)
target_link_libraries(zeniq-seeder common bitcoinconsensus seeder)

include(BinaryTest)
add_to_symbols_check(zeniq-seeder)
add_to_security_check(zeniq-seeder)

include(InstallationHelper)
install_target(zeniq-seeder)

add_subdirectory(test)
