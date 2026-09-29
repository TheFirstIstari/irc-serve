cmake_minimum_required(VERSION 3.20)
include(CTest)

# Tests (added from the top-level CMakeLists.txt)

# Ensure assert() checks are not compiled out in Release builds used by CI.
add_compile_options($<$<CONFIG:Release>:-UNDEBUG>)

# Every test directory below has its own CMakeLists.txt, contracts included (#86).
# The `test_contracts` static library that used to be defined here is gone: its
# only symbol, assert_contract_exact_result(), had no callers, so it was removed
# rather than left as a header and a definition that assert contracts are being
# checked. The 17 targets that linked it now link irc_core alone.
add_subdirectory(protocol)
add_subdirectory(federation)
add_subdirectory(compliance)
add_subdirectory(loadbal)
add_subdirectory(integration)
add_subdirectory(contracts)
