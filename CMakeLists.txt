cmake_minimum_required(VERSION 3.20)
project(irc-serve VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# DO NOT "FIX" THIS BY SETTING CMAKE_C_EXTENSIONS TO ON.
# Building strict C11 (extensions OFF) makes GCC/Clang pass -std=c11, which
# defines __STRICT_ANSI__. On glibc that hides every POSIX declaration behind
# <features.h> unless a feature-test macro is requested explicitly, so the
# build breaks on Linux only -- Apple headers ignore __STRICT_ANSI__, which is
# why this passed locally. Switching to gnu11 (or adding -D_GNU_SOURCE /
# -std=gnu11) would silence the errors by also re-enabling the GNU-specific
# surface area, quietly losing the portable strict-C11 guarantee this project
# deliberately keeps. Opt back into POSIX explicitly instead, by name.
#
# _POSIX_C_SOURCE=200809L provides select(), the FD_* macros, struct timeval,
# struct sigaction, the socket calls, inet_ntop(), htons()/ntohs() and pthread_*.
# _DEFAULT_SOURCE is additionally required for getrusage() (glibc guards it
# behind __USE_MISC || __USE_XOPEN_EXTENDED, neither of which _POSIX_C_SOURCE
# alone sets) and for INET_ADDRSTRLEN (behind __USE_MISC). Both are needed.
#
# Top-level add_compile_definitions() applies to every target defined in this
# directory and in all add_subdirectory() scopes below: irc_core, irc-serve,
# and all test/benchmark executables.
add_compile_definitions(_POSIX_C_SOURCE=200809L _DEFAULT_SOURCE)

# The two macros above are enough for glibc, but defining _POSIX_C_SOURCE
# explicitly *lowers* the Darwin header feature level: <sys/cdefs.h> sets
# __DARWIN_C_LEVEL to _POSIX_C_SOURCE whenever _POSIX_C_SOURCE is defined
# without _DARWIN_C_SOURCE, and that drops the level from __DARWIN_C_FULL
# (900000L) to 200809. Two things then disappear on macOS:
#   * <sys/select.h> stops declaring fd_set / the FD_* macros
#     -> src/node_main.c: "use of undeclared identifier 'fd_set'".
#   * <sys/resource.h> only declares struct rusage::ru_maxrss when
#     __DARWIN_C_LEVEL >= __DARWIN_C_FULL, so it degrades to ru_opaque[14]
#     -> tests/benchmark/footprint.c: "no member named 'ru_maxrss'".
# _DARWIN_C_SOURCE puts __DARWIN_C_LEVEL back to __DARWIN_C_FULL, i.e. exactly
# the level macOS headers used before any of these macros were defined, so
# macOS behaviour is unchanged. glibc does not recognise _DARWIN_C_SOURCE, so it
# is inert on Linux and changes nothing there.
if(APPLE)
  add_compile_definitions(_DARWIN_C_SOURCE)
endif()

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

# Enable testing unconditionally: benchmark tests are registered under
# BUILD_BENCHMARK (independent of BUILD_TESTING), so they must be runnable
# via CTest whenever BUILD_BENCHMARK=ON.
enable_testing()

if(BUILD_TESTING AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/CMakeLists.txt")
  add_subdirectory(tests)
endif()

if(BUILD_BENCHMARK AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/benchmark/CMakeLists.txt")
  add_subdirectory(tests/benchmark)
endif()
