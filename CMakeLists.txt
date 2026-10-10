cmake_minimum_required(VERSION 3.20)

# ---------------------------------------------------------------------------
# THE VERSION, AND WHY IT IS READ OUT OF A HEADER RATHER THAN WRITTEN HERE
# ---------------------------------------------------------------------------
# IT USED TO BE A LITERAL -- a second copy of a number whose first copy is
# src/core/server.h's IRC_SERVE_VERSION, which is what 002, 004, PONG, the FEDERATE
# handshake and the startup line all report. Two copies of a version is the same
# failure as two copies of a constant, and it had already happened: README.md's Status
# heading claimed v1.0.0 while this file and the binary both said the number below,
# which is not a value that drifted but a value that was never connected to anything.
#
# THE LITERAL IS NOT REPEATED HERE EVEN IN THIS COMMENT, and
# tests/integration/test_version_truth.c searches the whole file for one and fails on
# a match -- comments included. That is the reason: a version written down in prose is
# a version that goes stale silently, which is exactly what the README's did. The
# history of the change is in git, which is where a historical number belongs.
#
# SO THE HEADER IS THE ONE DEFINITION AND EVERYTHING ELSE DERIVES FROM IT:
#
#   src/core/server.h            the definition. It is there rather than here because
#                                it is the value the C code reports on the wire.
#   CMakeLists.txt (this block)  parsed out of the header at configure time, so
#                                project() VERSION and anything packaging reads are
#                                the header's number and not a copy of it.
#   --help                       prints IRC_SERVE_VERSION, so the flag surface and
#                                the startup line cannot disagree.
#   packaging/arch/PKGBUILD      `pkgver` is a sed of the same header.
#   packaging/debian/changelog   NOT derived -- a changelog is a record of what was
#                                uploaded, not a place to compute anything -- so
#                                tests/integration/test_version_truth.c asserts its
#                                newest entry agrees instead.
#
# AND A FATAL ERROR IF THE PARSE FINDS NOTHING, rather than a default. A regex that
# stops matching because someone reformatted the macro would otherwise leave the
# build configuring against a version that does not exist, which is the exact shape of
# the bug this block exists to remove: a build that works and reports something false.
#
# WHY NOT THE OTHER DIRECTION (a version file that C includes and CMake reads as a
# whole file): a header is what the C code already includes, so there is one file to
# open and no build-order dependency between configure and compile.
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/src/core/server.h" _irc_serve_server_h)
string(REGEX MATCH
       "#[ \t]*define[ \t]+IRC_SERVE_VERSION[ \t]+\"irc-serve-([0-9]+\\.[0-9]+\\.[0-9]+)\""
       _irc_serve_version_match "${_irc_serve_server_h}")
if(NOT _irc_serve_version_match)
  message(FATAL_ERROR
    "irc-serve: could not find IRC_SERVE_VERSION in src/core/server.h.\n"
    "This project keeps exactly ONE copy of the version, and it is that macro; "
    "CMake reads it rather than repeating it. If the macro was renamed or "
    "reformatted, the regex above is what has to change -- not a second literal.")
endif()
set(IRC_SERVE_VERSION "${CMAKE_MATCH_1}")
message(STATUS "irc-serve: version ${IRC_SERVE_VERSION} (from src/core/server.h)")

project(irc-serve VERSION ${IRC_SERVE_VERSION} LANGUAGES C)

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

# ---------------------------------------------------------------------------
# IRC_LSAN_PROBE: build the tests that prove the sanitizers are working at all
# ---------------------------------------------------------------------------
# OFF by default, and it is the only option here whose default exists to keep the gate's
# numbers unchanged rather than because the feature is unfinished.
#
# WHAT IT TURNS ON, which is TWO probes and not one, and the name is narrower than
# what the switch does:
#
#   * tests/integration/lsan_probe.c -- leaks 64 KiB in a child process on purpose and
#     FAILS unless LeakSanitizer reports it and exits non-zero. Registered as a CTest
#     test.
#   * tests/integration/asan_coverage_probe.c -- provokes one finding per Address-
#     Sanitizer error class this project reports a count for and FAILS unless
#     AddressSanitizer names each one. Deliberately NOT registered with ctest; the
#     Linux cell runs it directly and prints one COVER line per class. See
#     tests/integration/CMakeLists.txt for why the asymmetry with lsan_probe is right.
#
# WHY IT IS OPT-IN. The probes are red on any platform without the coverage they
# assert -- that is what makes them probes. Leaving them in the default gate would
# mean shipping tests that fail on macOS, or passing an option that makes 13 cells
# lie about which tests ran, or neutering the probes until they pass everywhere and
# therefore prove nothing. scripts/gate.sh's Linux cell passes -DIRC_LSAN_PROBE=ON
# because that cell is the only place in this project where the answer exists.
#
# WHAT IT COSTS WHEN OFF: two `if()`s in tests/integration/CMakeLists.txt and two
# unused source files. What it costs when ON: two executables to build, one process
# that leaks 64 KiB per run and four that provoke a memory error on purpose. Neither
# is worth paying by default.
#
# IT IS NOT A SUBSTITUTE FOR THE SUITE RUNNING UNDER THE SANITIZERS, which is the
# thing that actually finds defects in this tree's 100 tests. This option only answers
# the prior question -- is the thing that finds them switched on.
option(IRC_LSAN_PROBE "Build the deliberate-leak and ASan-class probes that prove the sanitizers are live" OFF)

# ---------------------------------------------------------------------------
# IRC_FORTIFY: -D_FORTIFY_SOURCE=2, opt-in, and READ THIS BEFORE TRUSTING IT
# ---------------------------------------------------------------------------
# Added because of a Linux-only build break this option cannot catch. glibc
# declares read() (and write(), fread(), pipe()) with __wur, i.e.
# __attribute__((warn_unused_result)), and GCC honours that attribute only when
# the result is really used -- `(void)read(...)` is an error, not a discard. A
# test discarded one exactly that way; all twelve macOS gate cells and both
# ci_linux jobs went red with -Werror=unused-result, and every macOS cell had
# built it clean, because macOS does not declare read() with that attribute at
# all. Clang additionally exempts an explicit (void) cast, so even a real glibc
# declaration compiled through clang would have stayed quiet.
#
# SO WHAT DOES THIS OPTION ACTUALLY BUY? Measured, on this machine, at -O0 and
# -O2, with gcc-16 and with Apple clang under the full -Weverything set:
# NOTHING. The macOS SDK declares zero __*_chk entry points -- no __read_chk, no
# __memcpy_chk -- so _FORTIFY_SOURCE selects code that does not exist there. The
# cell below is clean before the flag and clean after it.
#
# The reason is the point: this class of defect lives in the PLATFORM'S
# DECLARATION of a function, not in a fortify header and not in a warning flag.
# No -D flag on macOS can conjure a glibc declaration, so no macOS cell can ever
# see this diagnostic. THIS IS NOT A SUBSTITUTE FOR THE LINUX CI JOB. That job
# already exists and already caught this; it is the gate for this class, and
# ci_macos is not a slower version of it -- it is blind to it.
#
# WHAT THE OPTION ACTUALLY DOES TODAY, corrected because this block used to claim
# something that was not true of it.
#
# IT WAS: "it makes the fortify define part of a configuration the developer
# actually builds and runs the suite in". Nothing built it. Measured on this tree:
# `scripts/gate.sh`, `scripts/gate-linux-cell.sh` and every job in
# `.github/workflows/ci.yml` pass no -DIRC_FORTIFY at all, and no Makefile target
# does either. The one place the flag was forwarded is `local-ci.sh`, which passes
# `-DIRC_FORTIFY="${IRC_FORTIFY:-OFF}"` -- so `IRC_FORTIFY=1 ./local-ci.sh` does
# build and run the whole suite with the define, and nothing else does. The sentence
# described a command a developer can type and implied a cell that runs on its own.
#
# WHY NO CELL WAS ADDED INSTEAD, which is the part that is a decision rather than an
# observation. A gate cell here would build and run the suite a thirteenth time to
# assert something the paragraph above already MEASURED to be unobservable on this
# platform: the SDK declares no __*_chk entry points, so _FORTIFY_SOURCE selects no
# code. That is a cell with no oracle behind it -- it cannot fail for the reason it
# exists, and a gate that carries cells which cannot fail teaches the next reader
# that gate cells are cheap. The gate for this class is `ci_linux_cachyos` and
# `scripts/gate.sh --linux`, on glibc, where the define does have effect; that job
# already exists and already caught the defect this option was added for.
#
# So the option stays as what it is: a documented way to build the suite with the
# define on a machine where fortify does something, reached by naming the variable.
# It is OFF by default so no existing configuration changes -- the same argument as
# IRC_SANITIZE below.
option(IRC_FORTIFY "Build with -D_FORTIFY_SOURCE=2 (see the note above: no-op on macOS)" OFF)
if(IRC_FORTIFY)
  add_compile_definitions(_FORTIFY_SOURCE=2)
endif()

# ---------------------------------------------------------------------------
# IRC_SANITIZE: the opt-in AddressSanitizer + UndefinedBehaviorSanitizer build
# ---------------------------------------------------------------------------
# OFF, and it has to STAY off by default. These flags go on every target in the
# tree -- irc-serve and all of the tests -- because the point of the build is
# the shipped binary: the integration tests exec $&lt;TARGET_FILE:irc-serve&gt;, so
# a sanitizer build that only instrumented the test executables would assert
# against an uninstrumented node and catch nothing. Both halves of the tree are
# instrumented here, so the node that answers WHO on a sanitized run is itself
# the instrumented one.
#
# Opt-in rather than default-on because it is a DIFFERENT BUILD, not a stricter
# one: a sanitizer run is slower, reports differently, and needs its own runtime
# options, so folding it into the gcc/clang x Release/Debug matrix would make
# that matrix mean "the plain build" plus four more copies of it. OFF here also
# means no existing configuration changes: nothing in the gcc/clang matrix, on
# any runner, gets a new flag.
#
# -g is here because an ASan report without file:line is close to useless, and
# this tree's flag set has no -g at all. -fno-omit-frame-pointer is here because
# the stack has to be walkable to be worth printing, and the warning block below
# only asks for it under GCC.
#
# RUNNING IT: UBSAN_OPTIONS=halt_on_error=1, so a UBSan diagnostic fails the run
# instead of printing and passing, and ASAN_OPTIONS=detect_leaks=1 for LSan --
# which is a LINUX-ONLY capability here. LeakSanitizer is not supported on
# Darwin, and an ASan binary built with detect_leaks=1 HANGS on macOS rather than
# reporting, so the leak gate belongs to the Linux CI job and nowhere else.
if(IRC_SANITIZE)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -g)
  # The sanitizer runtime has to be on the LINK line of every executable as well
  # as the compile line, or the instrumented objects reference __asan_* symbols
  # that nothing provides. add_link_options (3.13+) applies to targets in this
  # directory and in the subdirectories added below, exactly like the compile
  # options above.
  add_link_options(-fsanitize=address,undefined)
endif()

# Compiler warnings (performance + correctness)
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
  add_compile_options(-Wall -Wextra -Werror -Wpedantic -O2)
  if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    add_compile_options(-fstrict-aliasing -fno-omit-frame-pointer)
  elseif(CMAKE_C_COMPILER_ID MATCHES "Clang")
    # -------------------------------------------------------------------------
    # THIS GATE IS MATCHES, NOT STREQUAL, AND THAT IS THE WHO FIX (#85)
    # -------------------------------------------------------------------------
    # It used to be `STREQUAL "Clang"`. CMake reports Apple's compiler as
    # "AppleClang", so STREQUAL never matched on any macOS developer machine and
    # -Weverything was silently skipped locally -- while ci_macos, which is a
    # REQUIRED check, builds with exactly that compiler. In other words the
    # strictest warning set in the tree has never run on the platform most of it
    # is written on, and nothing said so.
    #
    # The fix has a complication, which is why the suppressions below are
    # conditional rather than one flat list: Apple clang's -Weverything is a
    # DIFFERENT SET from upstream clang's. A flat list is wrong in both
    # directions -- it passes options Apple has no member for, and omits the ones
    # only Apple has. So the shared set is below, and the two conditional blocks
    # after it each add exactly what their compiler needs and nothing else.
    #
    # -Weverything is kept on purpose: it is what surfaced the real API-hygiene
    # defects fixed alongside it (-Wmissing-prototypes on tags_parse /
    # tags_serialize / sasl_*). Narrowing it to a hand-picked list would hide the
    # next one, so only the specific diagnostics below are opted out, each with
    # its reason.
    #
    # THE SHARED SET, and the reasoning is upstream clang's, unchanged:
    #
    # -Wno-unsafe-buffer-usage: an experimental Clang diagnostic that fires on
    # essentially ALL pointer arithmetic and indexing in C (`p++`, `line[i]`,
    # `end - rn`, strncpy bounds). The sites it flags in protocol_parse.c and
    # ircv3_tags.c are ordinary, already bounds-checked parsing code.
    # Satisfying it would mean rewriting correct parsers into unnatural forms
    # with no safety gain, so it is disabled rather than obeyed. Do NOT
    # re-enable it and then "fix" the parsers to satisfy it.
    # ** UPSTREAM CLANG ONLY -- see the conditional block below. Apple clang
    # does not have this diagnostic in its -Weverything group at all. **
    #
    # -Wno-declaration-after-statement: enforces C89 declaration placement.
    # This project is explicitly C11 (CMAKE_C_STANDARD 11 above), where
    # mid-block declarations are legal and idiomatic; -Wpedantic turns this on
    # for C99+ and it contradicts the declared standard. Disabled so the
    # dialect and the warning set agree. Both compilers have it, for the same
    # reason, so it is in the shared set.
    #
    # -Wno-padded / -Wno-unused-macros: struct padding is deliberate, and the
    # log/assertion macros are used across translation-unit boundaries.
    # (A caveat recorded rather than acted on: the -Wunused-macros half of that
    # reason does not cover the nine FILE-LOCAL macros it actually hides --
    # T_READY_MS in test_conn_lifecycle.c and one like it in eight other
    # integration tests -- which really are dead. Both compilers report them.
    # See docs/SPEC_TRACKING.md; they are pre-existing and deliberately left.)
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

    # ---- UPSTREAM CLANG ONLY ---------------------------------------------
    # -Wno-unsafe-buffer-usage is only RECOGNISED by Clang 16+ (the diagnostic
    # itself was added in 16). On Clang 15 or older the unknown option becomes
    # -Wunknown-warning-option, which -Werror promotes to a hard build failure
    # -- so a suppression intended to keep the build green would instead turn it
    # red. Guard it on the compiler version rather than assuming a modern Clang.
    #
    # Scoped to STREQUAL "Clang" now, and that is the second half of #85: Apple
    # clang excludes -Wunsafe-buffer-usage from its -Weverything group, so the
    # option is not needed there. It happens to still be a RECOGNISED flag name
    # in Apple clang 21, but relying on that would be relying on a driver detail
    # with no bearing on whether the diagnostic exists -- and if a future Apple
    # clang ever adds it to the group, this block is the one place to notice.
    if(CMAKE_C_COMPILER_ID STREQUAL "Clang")
      if(CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL 16)
        list(APPEND IRC_CLANG_WARNINGS -Wno-unsafe-buffer-usage)
      endif()
    endif()

    # ---- APPLE CLANG ONLY -------------------------------------------------
    # -Wno-poison-system-directories. This is the ONE diagnostic Apple clang has
    # that upstream clang does not, and it is the only suppression added by #85.
    #
    # It is not a code diagnostic at all. Apple clang puts /usr/local/include in
    # the SYSTEM include search path, and then warns, once per translation unit,
    # that a system directory outside the active SDK is "unsafe for
    # cross-compilation". It fires on an empty file with no #include in it, so it
    # says nothing whatever about this project's source.
    #
    # It fires here because a Homebrew Node install has left /usr/local/include on
    # this machine, populated with a `node` directory. That is a property of the
    # TOOLCHAIN INSTALLATION, not of the repository, and there is nothing this
    # CMakeLists can do about it -- the only fix would be to remove the
    # directory. Suppressing it here rather than leaving the build red is the
    # lesser evil, and it is scoped to AppleClang because upstream clang never had
    # the diagnostic in the group and must keep the gate it already passes.
    #
    # Honest caveat: this suppression will NOT fire on a runner that does not have
    # /usr/local/include in its clang search path, so ci_macos is not made green
    # by suppressing it -- it simply will not produce the diagnostic. The
    # suppression exists for the developer machine, which is the population #85 is
    # actually about.
    if(CMAKE_C_COMPILER_ID STREQUAL "AppleClang")
      list(APPEND IRC_CLANG_WARNINGS -Wno-poison-system-directories)
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
