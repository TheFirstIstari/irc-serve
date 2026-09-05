cmake_minimum_required(VERSION 3.20)
project(irc-serve VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

option(BUILD_TESTING "Build tests" ON)
option(BUILD_BENCHMARK "Build benchmarks" ON)

# Compiler warnings (performance + correctness)
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
  add_compile_options(-Wall -Wextra -Werror -Wpedantic -O2)
  if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    add_compile_options(-fstrict-aliasing -fno-omit-frame-pointer)
  elseif(CMAKE_C_COMPILER_ID STREQUAL "Clang")
    add_compile_options(-Weverything -Wno-padded -Wno-unused-macros)
  endif()
endif()

# Source layout
add_subdirectory(src)

if(BUILD_TESTING AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/CMakeLists.txt")
  enable_testing()
  add_subdirectory(tests)
endif()

if(BUILD_BENCHMARK AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/benchmark/CMakeLists.txt")
  add_subdirectory(tests/benchmark)
endif()
