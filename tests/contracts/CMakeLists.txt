# Tests for the contracts/ directory. This file did not exist (#86): every other
# test directory has one, and tests/CMakeLists.txt reached in here by path
# (`contracts/lockfree_contract.c`) to build the only target. The source
# resolved only because #include is relative to the including file, which is a
# coincidence of the include path rather than a build arrangement.
#
# The dead `regress_contracts` library that used to be built here is gone. Its
# only symbol, assert_contract_exact_result(), was declared in a header and
# called from nowhere, and a test helper with no callers is worse than no helper:
# it reads as evidence that contracts are being checked when nothing checks them.

add_executable(test_lockfree_contract lockfree_contract.c)
target_link_libraries(test_lockfree_contract PRIVATE pthread)
add_test(NAME LockfreeContract COMMAND test_lockfree_contract)
