# Tests (added from the top-level CMakeLists.txt)
# Ensure assert() checks are not compiled out in Release builds used by CI.
add_compile_options($<$<CONFIG:Release>:-UNDEBUG>)

add_subdirectory(protocol)
add_subdirectory(federation)
add_subdirectory(compliance)
add_subdirectory(loadbal)

add_library(test_contracts STATIC contracts/regress_contracts.c)