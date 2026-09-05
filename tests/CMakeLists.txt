cmake_minimum_required(VERSION 3.20)
include(CTest)

add_library(test_contracts STATIC contracts/regress_contracts.c)

add_subdirectory(protocol)
add_subdirectory(federation)
add_subdirectory(compliance)
add_subdirectory(loadbal)
