# Copyright (c) 2019 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

project(bitcoin-seeder-test)

include(TestSuite)
create_test_suite(bitcoin-seeder)
add_dependencies(check check-bitcoin-seeder)

add_boost_unit_tests_to_suite(bitcoin-seeder test_bitcoin-seeder
	# TODO: make a test library
	../../test/setup_common.cpp

	TESTS
		p2p_messaging_tests.cpp
		parse_name_tests.cpp
		write_name_tests.cpp
)

target_link_libraries(test_bitcoin-seeder
	common
	bitcoinconsensus
	seeder
	server
)

target_compile_definitions(test_bitcoin-seeder PUBLIC DMA_TESTING=1)
