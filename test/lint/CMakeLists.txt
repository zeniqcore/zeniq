# Copyright (c) 2020 The Bitcoin developers

project(bitcoin-lint)

include(TestSuite)
create_test_suite(lint)
add_dependencies(check check-lint)

add_lint_script_tests_to_suite(lint
TESTS
	check-doc.py
	check-rpc-mappings.py
	lint-assertions.sh
	lint-boost-dependencies.sh
	# lint-circular-dependencies.sh
	lint-cpp.sh
	lint-format-strings.sh
	lint-python-format.sh
	lint-python-mutable-default-parameters.sh
	lint-python-utf8-encoding.sh
	lint-python.sh
	lint-tests.sh
	lint-yaml.sh
	# lint-shell-locale.sh
	# lint-includes.sh
)
