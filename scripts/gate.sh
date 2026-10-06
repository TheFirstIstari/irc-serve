#!/usr/bin/env bash
# gate.sh -- the local build gate: 3 compilers x Release/Debug x WITH_TLS ON/OFF.
#
#   ./scripts/gate.sh                 all 12 cells, default job counts
#   ./scripts/gate.sh -j 2            serial-ish ctest, for bisecting
#   ./scripts/gate.sh --no-asan       skip the ASan+UBSan cell
#   GATE_BUILD_ROOT=/tmp/g ./scripts/gate.sh
#
# WHY THIS IS COMMITTED RATHER THAN LIVING IN /tmp. It used to, and /tmp did not
# survive the machine, which meant the project's own definition of "green" was
# unavailable exactly when someone wanted to reproduce it. A gate that cannot be
# re-run by the next person is a habit, not a gate.
#
# EVERY CELL IS CONFIGURED INTO A FRESH DIRECTORY, and that is load-bearing
# rather than tidy. A reused build directory reports "Built target" for a file it
# did not recompile, so a cell that should have caught a compile error reports
# success instead. Fresh directories are the difference between a gate and a
# formality.
#
# WHY WITH_TLS IS A DIMENSION RATHER THAN A FLAG. The matrix was six builds of
# WITH_TLS=OFF only, and a line in a TLS-only fixture compiled clean under both
# clangs and then failed under gcc-16 the moment an ON cell existed. A compiler is
# evidence about a file only if it compiled that file, so the feature set is an
# argument rather than an assumption.
#
# WHAT A CELL ASSERTS, all four or it is not green:
#   0 compiler errors, 0 compiler warnings, 0 failed tests, 0 skipped tests.
# Warnings are counted, not tolerated: this tree builds with -Werror, so a warning
# that survived to the log came from a path the flags do not cover, and treating
# it as noise is how the next -Werror regression arrives unannounced.
#
# THE TEST COUNT IS REPORTED, NOT PINNED. Tests get added, and a hardcoded 85
# would turn every addition into a gate failure while catching nothing -- the
# invariants that matter are zero failures and zero skips. Set GATE_EXPECT_TESTS
# to pin it when a specific number is what you are checking.
#
# PORTABILITY. bash, not sh, and no GNU-only flag anywhere: the same script has to
# run on macOS (BSD grep/sed/find) and on Linux. It creates every directory it
# uses and assumes no build directory exists, so it is safe to run in a fresh
# clone or straight after a `git clean -xdf`.

set -euo pipefail

# ---------------------------------------------------------------------------
# Arguments.
# ---------------------------------------------------------------------------
CTEST_JOBS_BUILD=8      # cmake --build --parallel; the machine's cores, capped
CTEST_JOBS_TEST=""      # ctest -j; defaults to the build job count when empty
RUN_ASAN=1
while [ $# -gt 0 ]; do
    case "$1" in
        -j)   shift
              CTEST_JOBS_TEST="${1:-}"
              [ -n "$CTEST_JOBS_TEST" ] || { echo "gate.sh: -j needs a number" >&2; exit 2; } ;;
        -j*)  CTEST_JOBS_TEST="${1#-j}" ;;
        --no-asan) RUN_ASAN=0 ;;
        -h|--help) sed -n '2,40p' "$0"; exit 0 ;;
        *) echo "gate.sh: unknown argument '$1' (try --help)" >&2; exit 2 ;;
    esac
    shift
done

# ---------------------------------------------------------------------------
# Environment / discovery.
# ---------------------------------------------------------------------------
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
root=$(cd -- "$here/.." && pwd)

# Portable core count. nproc is GNU/Linux; sysctl is BSD/macOS; /proc is a third
# fallback. Without this the script would run a 12-cell matrix one core at a time.
if [ -z "${CTEST_JOBS_BUILD:-}" ] || [ "$CTEST_JOBS_BUILD" = "8" ]; then
    cores=""
    if command -v nproc >/dev/null 2>&1; then cores=$(nproc)
    elif command -v sysctl >/dev/null 2>&1; then cores=$(sysctl -n hw.ncpu 2>/dev/null || echo "")
    elif [ -r /proc/cpuinfo ]; then cores=$(grep -c '^processor' /proc/cpuinfo || echo "")
    fi
    CTEST_JOBS_BUILD=${cores:-4}
fi
[ -n "$CTEST_JOBS_TEST" ] || CTEST_JOBS_TEST="$CTEST_JOBS_BUILD"

# Compilers are DISCOVERED, never hardcoded. The previous version of this script
# pointed at /opt/homebrew/bin/gcc-16 and /opt/homebrew/opt/llvm@23/bin/clang,
# which is precisely why it could only ever run on one machine -- the same reason
# it is being committed. Two things make discovery necessary rather than
# convenient:
#
#   * /usr/bin/gcc, /usr/bin/clang and /usr/bin/cc are all Apple's clang on
#     macOS. They are three names for one compiler and must produce ONE cell, so
#     candidates are deduplicated by their version string.
#   * Homebrew's versioned LLVM formulae are KEG-ONLY, so their bin/ directories
#     are not on PATH at all. Probing PATH alone finds Apple clang and nothing
#     else, and the gate would then report "only 1 compiler" while looking like a
#     working gate. `brew --prefix` is asked where brew exists; no Homebrew path
#     is written into this file, which is what keeps it running on an Intel Mac
#     and on Linux.
#
# GATE_COMPILERS overrides the probe entirely.
labels=""
entries=""              # newline-separated "label<TAB>path"
add_candidate() {
    # $1 = label, $2 = path to the compiler
    local label="$1" path="$2"
    [ -x "$path" ] || return 0
    local version
    version=$("$path" --version 2>/dev/null | head -1 || true)
    [ -n "$version" ] || return 0
    # Matched with grep -Fx against a newline list rather than a shell case
    # pattern: a version string contains spaces, dots and parentheses, and a case
    # pattern would have to escape every one of them.
    if printf '%s\n' "$seen" | grep -Fxq -- "$version"; then
        return 0
    fi
    seen="${seen}${version}
"
    # ONE record per line, TAB separated. Two lines per compiler looked tidier
    # and was wrong: the reader below pairs label and path per line, so a
    # two-line record silently shifted every path by one -- which would have
    # handed the sanitizer cell the wrong compiler and mislabelled every cell
    # while still producing twelve green ones.
    entries="${entries}${label}	${path}
"
}

seen=""
for c in ${GATE_COMPILERS:-gcc-16 gcc-15 gcc-14 gcc clang-23 clang-22 clang-21 clang cc}; do
    p=$(command -v "$c" 2>/dev/null || true)
    [ -n "$p" ] || continue
    label="$c"
    # Apple's /usr/bin compiler reports itself as Apple clang no matter which of
    # its three names was used, and the project's own warning branches switch on
    # exactly that string, so label it that way rather than "gcc".
    case "$p" in
        /usr/bin/cc|/usr/bin/gcc|/usr/bin/clang) label="AppleClang" ;;
    esac
    add_candidate "$label" "$p"
done

# Only when the caller has not named the compilers. GATE_COMPILERS means "use
# exactly these", and probing Homebrew afterwards would quietly widen it -- which
# is how "give me two compilers" turns back into three and the gate stops being
# the thing that was asked for.
if [ -z "${GATE_COMPILERS:-}" ] && command -v brew >/dev/null 2>&1; then
    bprefix=$(brew --prefix 2>/dev/null || true)
    if [ -n "$bprefix" ]; then
        for p in "$bprefix"/opt/llvm@*/bin/clang "$bprefix"/opt/llvm/bin/clang; do
            [ -x "$p" ] || continue
            add_candidate "$(basename "$(dirname "$(dirname "$p")")")" "$p"
        done
    fi
fi

labels=${labels# }

# The label<TAB>path pairs are stored in the order they were discovered, so they
# are walked by index rather than by re-deriving a parallel list.
all_labels=()
all_paths=()
while IFS= read -r line; do
    [ -n "$line" ] || continue
    all_labels+=("${line%%	*}")
    all_paths+=("${line#*	}")
done <<EOF
$(printf '%s' "$entries" | grep -v '^$')
EOF

# ---------------------------------------------------------------------------
# EXACTLY THREE COMPILERS, CHOSEN BY A DOCUMENTED RULE.
# ---------------------------------------------------------------------------
# The gate is 3 compilers x Release/Debug x WITH_TLS ON/OFF = 12 cells, and it
# must be 12 cells on every machine. Discovery alone does not give that: this one
# sees gcc-16, AppleClang, llvm@22 and llvm@23, which would be 16 cells. A gate
# whose size depends on what happens to be installed is a gate whose result
# cannot be compared with last week's, so the count is fixed here rather than
# discovered.
#
# Selection order, and why:
#   1. GCC. The strictest of the three and the one that finds things -- it is the
#      only compiler here that reports the glibc __wur class at all.
#   2. The NEWEST upstream Clang. -Weverything is upstream clang's set, and
#      Apple clang excludes -Wunsafe-buffer-usage from it, so the two are not
#      substitutes for each other. Newest wins because that is where new
#      diagnostics appear first.
#   3. AppleClang, because the required ci_macos check builds with exactly it.
# Slots are then filled from whatever is left, so a machine with two of the
# preferred three still runs 12 cells instead of quietly running 8.
selected=()      # indices into all_labels
# Used indices are tracked in a plain space-separated string rather than an
# associative array: `declare -A` is bash 4, and /bin/bash on macOS is 3.2, so the
# associative form fails at startup on the platform half this gate runs on.
# A space-separated string of small non-negative integers is all that is needed
# and works identically on both.
used=" "

is_used() { case "$used" in *" $1 "*) return 0 ;; esac; return 1; }
mark_used() { used="${used}$1 "; }

pick_newest_clang() {
    local best_idx="" best_ver=0 i lbl ver
    for i in "${!all_labels[@]}"; do
        is_used "$i" && continue
        lbl=${all_labels[$i]}
        case "$lbl" in
            llvm@*|llvm-[0-9]*|clang-[0-9]*)
                ver=$(printf '%s' "$lbl" | sed -n 's/.*[^0-9]\([0-9][0-9]*\)$/\1/p')
                [ -n "$ver" ] || ver=0
                if [ "$ver" -gt "$best_ver" ]; then best_ver=$ver; best_idx=$i; fi
                ;;
        esac
    done
    [ -n "$best_idx" ] && printf '%s' "$best_idx"
}

first_matching() {
    # The glob is passed unquoted on purpose -- it must expand as a pattern.
    local pat="$1" i
    for i in "${!all_labels[@]}"; do
        is_used "$i" && continue
        # shellcheck disable=SC2254  # $pat is a glob on purpose, not a literal
        case "${all_labels[$i]}" in
            $pat) printf '%s' "$i"; return 0 ;;
        esac
    done
    return 1
}

if idx=$(first_matching 'gcc*'); then
    selected+=("$idx"); mark_used "$idx"
fi
if idx=$(pick_newest_clang); then
    selected+=("$idx"); mark_used "$idx"
fi
if idx=$(first_matching 'AppleClang'); then
    selected+=("$idx"); mark_used "$idx"
fi
# Fill any remaining slots from the unused pool, in discovery order.
for i in "${!all_labels[@]}"; do
    [ "${#selected[@]}" -ge 3 ] && break
    is_used "$i" && continue
    selected+=("$i"); mark_used "$i"
done
# Fill from the preferred slots first in the summary.
compiler_count=${#selected[@]}

labels=""
for i in "${selected[@]}"; do
    labels="${labels} ${all_labels[$i]}"
done
labels=${labels# }

unused=""
for i in "${!all_labels[@]}"; do
    is_used "$i" && continue
    unused="${unused} ${all_labels[$i]}"
done
unused=${unused# }

# THREE COMPILERS, AND SAY SO IF THERE AREN'T. A gate that silently runs six cells
# and prints "GATE OK" is the exact failure this project keeps having: a check
# that reports success for work it did not do. Fewer than three is a failure of
# the GATE, not of the tree.
if [ "$compiler_count" -lt 3 ]; then
    echo "gate.sh: only $compiler_count distinct C compiler(s) found: ${labels:-<none>}" >&2
    echo "gate.sh: this gate is defined as 3 compilers. Install more, or set" >&2
    echo "gate.sh: GATE_COMPILERS=\"gcc-16 clang cc\" to name them explicitly." >&2
    exit 1
fi

GATE_BUILD_ROOT=${GATE_BUILD_ROOT:-"$root/build-gate"}
mkdir -p "$GATE_BUILD_ROOT"

echo "irc-serve gate"
echo "  source        : $root"
echo "  build root    : $GATE_BUILD_ROOT"
echo "  compilers    :$(printf ' %s' $labels)"
[ -n "$unused" ] && echo "  not in gate  :$unused  (see the selection rule in this file)"
echo "  build -j      : $CTEST_JOBS_BUILD"
echo "  ctest -j      : $CTEST_JOBS_TEST"
echo "  ctest timeout : 200s"
echo

# ---------------------------------------------------------------------------
# THE PORTABILITY RATCHET, once, before any cell
# ---------------------------------------------------------------------------
# It is here and not in each cell because it is a property of the SOURCE, not of a
# build: thirteen cells on one libc cannot tell that a symbol they all accept is not
# in the standard this tree is written against. Three defects in this project were
# invisible to every cell and visible only on Linux -- the glibc `__wur` class, a
# `<sys/wait.h>` included transitively by one libc's headers and not the other's, and
# `memmem()` declared without a feature-test macro by the macOS SDK and hidden behind
# one by glibc -- and the common shape is that the local gate is not a portability
# oracle. That is a gap in the gate rather than in any one file, so the gate names it.
#
# The check is cheap, so running it per cell would cost nothing, but running it once
# says what it is: ONE answer about the source, not thirteen agreeing with themselves.
#
# It counts as a FAILED CHECK rather than a failed CELL, on purpose. The cell total is
# a claim about the build matrix; inflating it would make the matrix look worse than it
# is, and folding it into a cell would make a source problem look like a build
# problem. It is neither, so it is reported as its own thing and fails the gate on its
# own line.
FAILED_CHECKS=0
SUMMARY=""
echo "--- portability ratchet (source-wide) ---"
if "$root/scripts/check-portability.sh" > "$GATE_BUILD_ROOT/portability.log" 2>&1; then
    sed -n '1p' "$GATE_BUILD_ROOT/portability.log" | sed 's/^/  /'
    SUMMARY="${SUMMARY}check-portability OK\n"
else
    printf '  %-26s %s\n' "check-portability.sh" "FAILED"
    sed -n '2,40p' "$GATE_BUILD_ROOT/portability.log" | sed 's/^/      /'
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
    SUMMARY="${SUMMARY}check-portability FAILED\n"
fi

# ---------------------------------------------------------------------------
# The SECOND source-wide ratchet, and why it is here rather than in one cell
# ---------------------------------------------------------------------------
# Same argument as the one above and it is worth stating rather than repeating: this
# is a property of the SOURCE, so one answer is right and thirteen agreeing with
# themselves would only be thirteen. It is a source check rather than a build
# property because what it watches is a text pattern -- a peer string reaching a
# `printf` -- which no compiler and no sanitizer has an opinion about.
#
# It is counted as a FAILED CHECK, not as a failed cell, for the reason the
# portability ratchet above gives: inflating the cell count would make the build
# matrix look worse than it is, and folding it into a cell would make a source
# problem look like a build problem.
echo "--- teardown-helper audit (source-wide, strict) ---"
# `--strict` and not the full enumeration, and the difference is the whole design of
# the script: the enumeration cannot tell a helper from its caller, so gating on it
# would gate on a question it cannot answer. `--strict` gates on the two helpers whose
# NAME promises a whole-job release -- tf_done and tf_report -- which is a short list,
# has no false positives, and is red when tf_done is restored to freeing nothing.
#
# WHAT IT IS NOT: a leak detector. It reads the BODY, so it catches the shape that
# caused PR #140's LeakSanitizer finding and it would not catch a leak introduced any
# other way. LeakSanitizer on the Linux CI job remains the only runtime oracle for the
# leak itself, and nothing here changes that.
if python3 "$root/scripts/audit-teardown.py" --strict \
        > "$GATE_BUILD_ROOT/teardown.log" 2>&1; then
    sed -n '1p' "$GATE_BUILD_ROOT/teardown.log" | sed 's/^/  /'
    tail -1 "$GATE_BUILD_ROOT/teardown.log" | sed 's/^/  /'
    SUMMARY="${SUMMARY}audit-teardown(strict) OK\n"
else
    printf '  %-26s %s\n' "audit-teardown.py" "FAILED"
    sed -n '1,40p' "$GATE_BUILD_ROOT/teardown.log" | sed 's/^/      /'
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
    SUMMARY="${SUMMARY}audit-teardown(strict) FAILED\n"
fi

echo "--- packaging truth (source-wide) ---"
if python3 "$root/scripts/check-packaging.py" > "$GATE_BUILD_ROOT/packaging.log" 2>&1; then
    sed -n '1p' "$GATE_BUILD_ROOT/packaging.log" | sed 's/^/  /'
    SUMMARY="${SUMMARY}check-packaging OK\n"
else
    printf '  %-26s %s\n' "check-packaging.py" "FAILED"
    sed -n '1,40p' "$GATE_BUILD_ROOT/packaging.log" | sed 's/^/      /'
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
    SUMMARY="${SUMMARY}check-packaging FAILED\n"
fi

echo "--- peer log-site sweep (source-wide) ---"
if python3 "$root/scripts/check-peer-log-sites.py" > "$GATE_BUILD_ROOT/peerlog.log" 2>&1; then
    sed -n '1p' "$GATE_BUILD_ROOT/peerlog.log" | sed 's/^/  /'
    SUMMARY="${SUMMARY}check-peer-log-sites OK\n"
else
    printf '  %-26s %s\n' "check-peer-log-sites.py" "FAILED"
    sed -n '1,40p' "$GATE_BUILD_ROOT/peerlog.log" | sed 's/^/      /'
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
    SUMMARY="${SUMMARY}check-peer-log-sites FAILED\n"
fi
echo

# ---------------------------------------------------------------------------
# One cell. Errors and warnings are counted on the BUILD LOG, so a cell that
# built nothing cannot report "0 errors" by having produced no log at all.
# ---------------------------------------------------------------------------
TOTAL_CELLS=0
FAILED_CELLS=0

run_cell() {
    # Extra CMake arguments are the remaining positional parameters, not one
    # pre-joined string: word-splitting a string to recover a list is how a flag
    # containing a space silently becomes two.
    local label="$1" cc="$2" bt="$3" tls="$4"
    shift 4
    TOTAL_CELLS=$((TOTAL_CELLS + 1))

    local d="$GATE_BUILD_ROOT/${label}_${bt}_tls${tls}"
    local cfglog="$d.configure.log"
    local buildlog="$d.build.log"
    local testlog="$d.test.log"

    # Fresh, every time. See the header.
    rm -rf "$d"

    local cfg=(cmake -B "$d" -S "$root"
               -DCMAKE_BUILD_TYPE="$bt"
               -DBUILD_TESTING=ON
               -DWITH_TLS="$tls"
               -DCMAKE_C_COMPILER="$cc")
    if [ "$#" -gt 0 ]; then cfg+=("$@"); fi

    if ! "${cfg[@]}" > "$cfglog" 2>&1; then
        printf '  %-26s %-7s tls=%-3s CONFIGURE FAILED\n' "$label" "$bt" "$tls"
        tail -n 6 "$cfglog" | sed 's/^/      /'
        FAILED_CELLS=$((FAILED_CELLS + 1))
        SUMMARY="${SUMMARY}$label $bt tls=$tls CONFIGURE FAILED\n"
        return
    fi

    if ! cmake --build "$d" --parallel "$CTEST_JOBS_BUILD" > "$buildlog" 2>&1; then
        printf '  %-26s %-7s tls=%-3s BUILD FAILED\n' "$label" "$bt" "$tls"
        grep -m5 -E 'error:|warning:' "$buildlog" | sed 's/^/      /'
        FAILED_CELLS=$((FAILED_CELLS + 1))
        SUMMARY="${SUMMARY}$label $bt tls=$tls BUILD FAILED\n"
        return
    fi

    # Counted, not just exit-coded: a build can succeed and still print warnings
    # from a path the flag set does not cover.
    local errs warns
    errs=$(grep -c 'error:' "$buildlog" || true)
    warns=$(grep -c 'warning:' "$buildlog" || true)
    if [ "$errs" != "0" ] || [ "$warns" != "0" ]; then
        printf '  %-26s %-7s tls=%-3s build OK but errors=%s warnings=%s\n' \
            "$label" "$bt" "$tls" "$errs" "$warns"
        grep -m5 -E 'error:|warning:' "$buildlog" | sed 's/^/      /'
        FAILED_CELLS=$((FAILED_CELLS + 1))
        SUMMARY="${SUMMARY}$label $bt tls=$tls errors=$errs warnings=$warns\n"
        return
    fi

    # A cell that only builds cannot tell a compile-time fix from a runtime one,
    # so every cell also runs the suite.
    if ! ctest --test-dir "$d" -j "$CTEST_JOBS_TEST" --timeout 200 > "$testlog" 2>&1; then
        printf '  %-26s %-7s tls=%-3s build OK, TESTS FAILED\n' "$label" "$bt" "$tls"
        grep -E 'tests passed|tests failed out of|Failed|Timeout' "$testlog" | head -4 | sed 's/^/      /'
        FAILED_CELLS=$((FAILED_CELLS + 1))
        SUMMARY="${SUMMARY}$label $bt tls=$tls TESTS FAILED\n"
        return
    fi

    # SKIPS ARE A SEPARATE INVARIANT, not part of ctest's exit code. ctest cannot
    # express "a test skipped", and that blind spot is what once let eight dead
    # tests pass unnoticed, so the ratchet is asked directly.
    local skipverdict="skips OK"
    if ! "$root/scripts/check-skips.sh" -b "$d" "$testlog" > "$d.skips.log" 2>&1; then
        skipverdict="SKIP RATCHET FAILED"
        FAILED_CELLS=$((FAILED_CELLS + 1))
        SUMMARY="${SUMMARY}$label $bt tls=$tls SKIP RATCHET FAILED\n"
        tail -n 4 "$d.skips.log" | sed 's/^/      /'
    fi

    local passed
    passed=$(grep -oE '[0-9]+% tests passed(, [0-9]+ tests failed)? out of [0-9]+' "$testlog" | head -1 || true)
    [ -n "$passed" ] || passed="(no totals line)"

    printf '  %-26s %-7s tls=%-3s build OK  0 errors 0 warnings  %s  [%s]\n' \
        "$label" "$bt" "$tls" "$passed" "$skipverdict"
    SUMMARY="${SUMMARY}$label $bt tls=$tls OK  0/0  $passed  $skipverdict\n"
}

# ---------------------------------------------------------------------------
# The 12 cells.
# ---------------------------------------------------------------------------
echo "--- 12-cell build/test matrix ---"
for idx in "${selected[@]}"; do
    label=${all_labels[$idx]}
    ccp=${all_paths[$idx]}
    for bt in Release Debug; do
        for tls in OFF ON; do
            run_cell "$label" "$ccp" "$bt" "$tls"
        done
    done
done

# ---------------------------------------------------------------------------
# The sanitizer cell. WITH_TLS=ON only, and that is the whole point of it: a
# WITH_TLS=OFF sanitizer build compiles zero tokens of OpenSSL, so it says
# nothing whatsoever about SSL* or SSL_CTX*.
#
# LEAK DETECTION IS OFF HERE AND THAT IS NOT AN OMISSION. LeakSanitizer does not
# exist on Darwin -- measured, not assumed: an ASan binary run with
# detect_leaks=1 aborts with "AddressSanitizer: detect_leaks is not supported on
# this platform", taking all 85 tests with it. The ONLY leak check for TLS in this
# project is ci_sanitizers' WITH_TLS=ON cell on Linux, and no local script can
# replace it. What this cell checks here is the memory-error half of ASan plus
# UBSan, both of which do run on Darwin.
# ---------------------------------------------------------------------------
if [ "$RUN_ASAN" = "1" ]; then
    echo
    echo "--- ASan + UBSan, WITH_TLS=ON, gcc Release (LeakSanitizer excluded: Darwin) ---"
    # Pick a GCC for the sanitizer cell: GCC is the strictest of the three and
    # the one that finds things. Falls back to the first compiler if none of the
    # discovered ones is GCC.
    gccbin=""
    gccpath=""
    for idx in "${selected[@]}"; do
        case "${all_labels[$idx]}" in
            gcc*)
                gccbin=${all_labels[$idx]}
                gccpath=${all_paths[$idx]}
                break
                ;;
        esac
    done
    if [ -z "$gccpath" ]; then
        gccbin=${all_labels[${selected[0]}]}
        gccpath=${all_paths[${selected[0]}]}
    fi
    TOTAL_CELLS=$((TOTAL_CELLS + 1))

    ad="$GATE_BUILD_ROOT/asan_tlsON_Release"
    rm -rf "$ad"
    if cmake -B "$ad" -S "$root" -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON \
            -DWITH_TLS=ON -DIRC_SANITIZE=ON -DCMAKE_C_COMPILER="$gccpath" \
            > "$ad.configure.log" 2>&1 \
       && cmake --build "$ad" --parallel "$CTEST_JOBS_BUILD" > "$ad.build.log" 2>&1; then
        errs=$(grep -c 'error:' "$ad.build.log" || true)
        warns=$(grep -c 'warning:' "$ad.build.log" || true)
        if [ "$errs" = "0" ] && [ "$warns" = "0" ]; then
            if ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=halt_on_error=1 \
               ctest --test-dir "$ad" -j "$CTEST_JOBS_TEST" --timeout 200 > "$ad.test.log" 2>&1; then
                if "$root/scripts/check-skips.sh" -b "$ad" "$ad.test.log" > "$ad.skips.log" 2>&1; then
                    printf '  %-26s %-7s tls=%-3s build OK  0 errors 0 warnings  %s  [skips OK]\n' \
                        "asan+ubsan $(basename "$gccbin")" Release ON \
                        "$(grep -oE '[0-9]+% tests passed(, [0-9]+ tests failed)? out of [0-9]+' "$ad.test.log" | head -1 || echo '(no totals)')"
                    SUMMARY="${SUMMARY}asan+ubsan tls=ON OK\n"
                else
                    printf '  %-26s %-7s tls=%-3s build OK, SKIP RATCHET FAILED\n' "asan+ubsan" Release ON
                    FAILED_CELLS=$((FAILED_CELLS + 1))
                    SUMMARY="${SUMMARY}asan+ubsan tls=ON SKIP RATCHET FAILED\n"
                fi
            else
                printf '  %-26s %-7s tls=%-3s build OK, TESTS FAILED (sanitizer finding or test failure)\n' \
                    "asan+ubsan $(basename "$gccbin")" Release ON
                grep -m4 -E 'ERROR: |runtime error|tests failed out of' "$ad.test.log" | sed 's/^/      /'
                FAILED_CELLS=$((FAILED_CELLS + 1))
                SUMMARY="${SUMMARY}asan+ubsan tls=ON TESTS FAILED\n"
            fi
        else
            printf '  %-26s %-7s tls=%-3s build OK but errors=%s warnings=%s\n' \
                "asan+ubsan $(basename "$gccbin")" Release ON "$errs" "$warns"
            FAILED_CELLS=$((FAILED_CELLS + 1))
            SUMMARY="${SUMMARY}asan+ubsan tls=ON errors=$errs warnings=$warns\n"
        fi
    else
        printf '  %-26s %-7s tls=%-3s CONFIGURE OR BUILD FAILED\n' "asan+ubsan" Release ON
        tail -n 6 "$ad.configure.log" "$ad.build.log" 2>/dev/null | sed 's/^/      /'
        FAILED_CELLS=$((FAILED_CELLS + 1))
        SUMMARY="${SUMMARY}asan+ubsan tls=ON CONFIGURE OR BUILD FAILED\n"
    fi
fi

# ---------------------------------------------------------------------------
# Optional pinned test count, then the verdict.
# ---------------------------------------------------------------------------
echo
if [ -n "${GATE_EXPECT_TESTS:-}" ]; then
    got=$(printf '%s' "$SUMMARY" | grep -oE 'out of [0-9]+' | head -1 | grep -oE '[0-9]+' || true)
    if [ -n "$got" ] && [ "$got" != "$GATE_EXPECT_TESTS" ]; then
        echo "gate.sh: GATE_EXPECT_TESTS=$GATE_EXPECT_TESTS but the suite ran $got tests" >&2
        FAILED_CELLS=$((FAILED_CELLS + 1))
    fi
fi

printf '%b' "$SUMMARY" | sed 's/^/  /'

echo
# The count is REPORTED, not asserted, and it says what actually ran. An earlier
# version hardcoded "+ 1 sanitizer cell", which was wrong under --no-asan: the
# total said 13 while 12 ran. A summary that describes a cell the run skipped is
# the small version of the lie this gate exists to prevent.
if [ "$RUN_ASAN" = "1" ]; then
    echo "cells run: $TOTAL_CELLS (12 build cells + 1 ASan+UBSan cell)"
else
    echo "cells run: $TOTAL_CELLS (12 build cells; --no-asan, so no sanitizer cell)"
fi
if [ "$FAILED_CELLS" = "0" ] && [ "$FAILED_CHECKS" = "0" ]; then
    echo "GATE RESULT: PASS  (failures: 0)"
    exit 0
fi
# BOTH COUNTS, because a run where the matrix is clean and a source check is not is a
# different failure from a run where a cell is red, and reporting only the cell count
# would let the second look like the first.
echo "GATE RESULT: FAIL  (failed cells: $FAILED_CELLS, failed checks: $FAILED_CHECKS)"
exit 1