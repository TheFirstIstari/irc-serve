cmake_minimum_required(VERSION 3.20)
project(irc-serve VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

option(BUILD_TESTING "Build tests" ON)
option(BUILD_BENCHMARK "Build benchmarks" ON)

# Compiler warnings (performance + correctness)
add_compile_options(
  $<$<C_COMPILER_ID:GNU,Clang>:-Wall -Wextra -Werror -Wpedantic>
  $<$<C_COMPILER_ID:GNU>:-fstrict-aliasing -fno-omit-frame-pointer>
  $<$<C_COMPILER_ID:Clang>:-Weverything -Wno-padded -Wno-unused-macros>
)

# Source layout
add_subdirectory(src)

if(BUILD_TESTING AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/CMakeLists.txt")
  enable_testing()
  add_subdirectory(tests)
endif()

if(BUILD_BENCHMARK AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/benchmark/CMakeLists.txt")
  add_subdirectory(tests/benchmark)
endif()
