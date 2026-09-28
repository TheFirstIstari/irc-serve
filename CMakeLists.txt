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
    # -Weverything is kept on purpose: it is what surfaced the real API-hygiene
    # defects fixed alongside it (-Wmissing-prototypes on tags_parse /
    # tags_serialize / sasl_* / assert_contract_exact_result). Narrowing it to
    # a hand-picked list would hide the next one, so only the specific
    # diagnostics below are opted out, each with its reason.
    #
    # -Wno-unsafe-buffer-usage: an experimental Clang diagnostic that fires on
    # essentially ALL pointer arithmetic and indexing in C (`p++`, `line[i]`,
    # `end - rn`, strncpy bounds). The sites it flags in protocol_parse.c and
    # ircv3_tags.c are ordinary, already bounds-checked parsing code.
    # Satisfying it would mean rewriting correct parsers into unnatural forms
    # with no safety gain, so it is disabled rather than obeyed. Do NOT
    # re-enable it and then "fix" the parsers to satisfy it.
    #
    # -Wno-declaration-after-statement: enforces C89 declaration placement.
    # This project is explicitly C11 (CMAKE_C_STANDARD 11 above), where
    # mid-block declarations are legal and idiomatic; -Wpedantic turns this on
    # for C99+ and it contradicts the declared standard. Disabled so the
    # dialect and the warning set agree.
    #
    # -Wno-padded / -Wno-unused-macros: struct padding is deliberate and the
    # log/assertion macros are used across translation-unit boundaries.
    #
    # -Wno-disabled-macro-expansion: a GLIBC HEADER artifact, not a code defect.
    # bits/sigaction.h defines sa_handler as __sigaction_handler.sa_handler --
    # whose expansion still contains the token sa_handler, so Clang disables the
    # recursive re-expansion and reports it. Any `sa.sa_handler = ...` therefore
    # warns on glibc while building clean on macOS/BSD. There is no way to fix
    # this from our side short of not using sigaction, so it is disabled.
    set(IRC_CLANG_WARNINGS -Weverything -Wno-padded -Wno-unused-macros
                           -Wno-declaration-after-statement
                           -Wno-disabled-macro-expansion)

    # -Wno-unsafe-buffer-usage is only RECOGNISED by Clang 16+ (the diagnostic
    # itself was added in 16). On Clang 15 or older the unknown option becomes
    # -Wunknown-warning-option, which -Werror promotes to a hard build failure
    # -- so a suppression intended to keep the build green would instead turn it
    # red. Guard it on the compiler version rather than assuming a modern Clang.
    if(CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL 16)
      list(APPEND IRC_CLANG_WARNINGS -Wno-unsafe-buffer-usage)
    endif()

    add_compile_options(${IRC_CLANG_WARNINGS})
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
