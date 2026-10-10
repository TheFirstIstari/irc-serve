#!/usr/bin/env bash
# gate.sh -- the local build gate: 3 compilers x Release/Debug x WITH_TLS ON/OFF.
#
#   ./scripts/gate.sh                 all 12 cells, default job counts
#   ./scripts/gate.sh -j 2            serial-ish ctest, for bisecting
#   ./scripts/gate.sh --no-asan       skip the ASan+UBSan cell
#   ./scripts/gate.sh --linux         ALSO run the Linux cell: glibc + ASan + LSan +
#                                     UBSan in a docker container. Opt-in because it is
#                                     two full sanitized builds, and it degrades to a
#                                     visible SKIP when docker is unavailable.
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
# ASAN_SELFTEST means "describe this gate's sanitizer cell's coverage contract and
# exit". It is declared HERE for the same reason RUN_LINUX is declared twice: the
# argument parser assigns to a variable whose first declaration is three hundred lines
# further down, which reads as if the flag does nothing.
ASAN_SELFTEST=0
# RUN_LINUX is INITIALISED HERE and again to 0 further down, where the cell itself is.
# The second assignment is the load-bearing one and the first exists so that the
# argument parser above has a variable to set: a parser that assigns to a variable first
# declared three hundred lines later is a script that reads as if the flag does nothing.
RUN_LINUX=0
LINUX_SKIPPED=0
while [ $# -gt 0 ]; do
    case "$1" in
        -j)   shift
              CTEST_JOBS_TEST="${1:-}"
              [ -n "$CTEST_JOBS_TEST" ] || { echo "gate.sh: -j needs a number" >&2; exit 2; } ;;
        -j*)  CTEST_JOBS_TEST="${1#-j}" ;;
        --no-asan) RUN_ASAN=0 ;;
        --linux)   RUN_LINUX=1 ;;
        # Describe this gate's ASan cell's coverage contract and exit, without
        # building anything. The teeth for that contract are measured against it, and
        # they need the answer in about a second on a machine that may not have three
        # compilers installed.
        --asan-selftest) ASAN_SELFTEST=1 ;;
        # Extra arguments for the Linux cell, passed through verbatim. This exists so a
        # developer bisecting a Linux-only failure can say `--linux --linux-args=--no-probe`
        # without this file growing a second Linux-related flag; and it is a single
        # `GATE_LINUX_ARGS` word rather than a set of flags precisely because the cell
        # has exactly two options and a passthrough is harder to get wrong than two
        # flags that drift out of step with it.
        --linux-args=*) GATE_LINUX_ARGS="${1#--linux-args=}" ;;
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

# ---------------------------------------------------------------------------
# asan_cell_selftest: THIS GATE'S OWN SANITIZER CELL STATES ITS COVERAGE, and it
# can be checked without running a sanitizer.
#
# WHY IT EXISTS AT ALL, because the Linux cell's argument applies here verbatim and
# this cell had the identical defect. The Darwin ASan+UBSan cell printed a count of
# findings and nothing about what was watching, and the count was about three of the
# four ASan classes the project names -- stack-use-after-return, the class that found
# the real nf_free() defect, is off by default in Homebrew gcc 16 on macOS. A count
# beside nothing is the shape of a claim nobody can check. The fix is a coverage
# statement; a coverage statement that is only ever checked by the cell that produces
# it is a statement nobody re-checks, because editing it costs a full sanitized build
# to notice.
#
# WHAT IT CHECKS, and the three directions are the three ways the statement can go
# missing without anything turning red:
#
#   1. THE RENDERER still emits it. A canned complete ledger and a canned incomplete
#      one go through scripts/gate-linux-cell.sh --report-render -- the same call this
#      cell makes at run time -- and the coverage block, the incomplete banner and
#      the machine-readable trailer must all still be there. Deleting the coverage
#      block from the shared renderer turns this red HERE and in the Linux cell and
#      in ci_sanitizers, because all three call it. That direction has its own fault,
#      report_coverage_statement_removed.py.
#   2. THIS CELL STILL CALLS IT. Removing the call -- the easiest edit of all, since
#      it deletes code rather than changing it -- must be red. Its fault is
#      asan_cell_coverage_statement_removed.py.
#   3. CI'S CELL STILL CALLS IT, for the same reason and in the same direction. Two
#      cells in two files reporting sanitizer counts are two chances to lose the
#      statement, and this pass exists because one of them had already. Its fault is
#      ci_sanitizers_coverage_statement_removed.py.
#
# WHAT IT IS NOT: it does not prove any class is watched here. That needs a real ASan
# run, which is what this cell and scripts/gate-linux-cell.sh do. This is the FORMAT
# contract, checked where it is cheap, which is the split the Linux cell's header
# already argues for and which is why it runs on macOS at all.
# ---------------------------------------------------------------------------
asan_cell_selftest() {
    local fail=0 out

    local renderer="$root/scripts/gate-linux-cell.sh"
    if [ ! -x "$renderer" ]; then
        echo "gate.sh --asan-selftest: FAIL -- $renderer is missing or not executable, so" \
             "the coverage statement this cell prints cannot be rendered at all" >&2
        return 1
    fi

    # `|| true` on both assignments is LOAD-BEARING and not defensive tidiness:
    # --report-render's exit status IS the completeness verdict, so the second one is
    # non-zero BY CONSTRUCTION, and this script runs under `set -e`. Without it the
    # self-test would die on the very failure it is constructing and print nothing at
    # all -- which is the failure mode this file exists to end, committed to a new
    # place.
    out=$(printf 'COVER heap-use-after-free PROVED\nCOVER stack-use-after-scope PROVED\nCOVER heap-buffer-overflow PROVED\nCOVER stack-use-after-return PROVED\n' \
          | bash "$renderer" --report-render 2>&1) || true
    case "$out" in
        *"sanitizer coverage"*) ;;
        *) echo "gate.sh --asan-selftest: FAIL -- the shared renderer carries NO COVERAGE STATEMENT: a findings count beside nothing that says what was watched is the failure this pass exists to end" >&2
           fail=1 ;;
    esac
    case "$out" in
        *"coverage=complete"*) ;;
        *) echo "gate.sh --asan-selftest: FAIL -- the all-proved report does not record coverage=complete" >&2
           fail=1 ;;
    esac
    out=$(printf 'COVER heap-use-after-free PROVED\nCOVER stack-use-after-scope NOT-COVERED (needs -fsanitize-address-use-after-scope)\n' \
          | bash "$renderer" --report-render 2>&1) || true
    case "$out" in
        *"SANITIZER COVERAGE INCOMPLETE"*) ;;
        *) echo "gate.sh --asan-selftest: FAIL -- an unproved class did not produce the loud banner, so a bare count would read as a result" >&2
           fail=1 ;;
    esac
    case "$out" in
        *"coverage=INCOMPLETE"*) ;;
        *) echo "gate.sh --asan-selftest: FAIL -- the completeness marker does not record the incomplete state" >&2
           fail=1 ;;
    esac

    # 2 and 3. Both cells still ask for it.
    #
    # COMMENTS ARE FILTERED OUT, and that is not a nicety -- it is the first of two
    # ways this check was wrong when it was first written. Both call sites are NAMED in
    # the prose of the file that contains them ("reused rather than reimplemented", "the
    # same call this cell makes at run time"), so a plain grep for the call was
    # satisfied by a comment describing a call that no longer existed.
    #
    # They are source checks, and the messages say so. They cannot know whether the
    # step that was deleted would have worked; they know it is gone.
    #
    # NO PIPELINE, and this is the second time this repository has learned it:
    # ci_sanitizers' `ldd | grep -q` step carries a comment saying that under
    # pipefail a `cmd | grep -q` can fail on SIGPIPE when grep exits first, and turn
    # a passing check into a spurious failure. `grep -v ... | grep -q` has exactly
    # that shape and it failed here for exactly that reason -- on the UNFAULTED tree,
    # which is the worst way for a check to be wrong. So the filter and the match are
    # separate statements, and the match is a shell substring test on the filtered
    # text: no pipe, no SIGPIPE, and no regex to misread.
    #
    # THE NEEDLES ARE ASSEMBLED AT RUN TIME AND NOT WRITTEN AS LITERALS, for the same
    # reason. The first version of this check matched the string
    # `gate-linux-cell.sh" --report-render` and the line doing the matching CONTAINED
    # that string, so the check was satisfied by itself and reported green against a
    # fault that had deleted the cell's call -- the second time this check was wrong in
    # the same way. Splitting the needle means no line in this file spells it out, so
    # the only place the string can appear is the code being checked. A self-test that
    # satisfied itself. Splitting the needle means no line in this file spells it out, so
    # the only place the string can appear is the code being checked. A self-test that
    # satisfies its own assertion is worse than one that does not run: it converts a
    # missing check into a reported pass.
    #
    # All three faults -- this comment's two ways, above, and the `set -e` death in the
    # canned-incomplete render -- were caught by running each tooth against the
    # UNFAULTED tree before believing it. A check written and not immediately
    # adversarially exercised is a check whose first exercise is somebody else's
    # problem.
    _tail='gate-linux-cell.sh'
    _needle_cell="$_tail\" --report-render"
    _needle_ci="$_tail --report-render"
    _cell_code=$(grep -v '^[[:space:]]*#' "$root/scripts/gate.sh")
    case "$_cell_code" in
        *"$_needle_cell"*) ;;
        *)
            echo "gate.sh --asan-selftest: FAIL -- this gate's ASan cell no longer calls the coverage" \
                 "renderer, so its sanitizer findings count is being printed with nothing that" \
                 "says which classes were being watched. That is the defect this check exists for." >&2
            fail=1
            ;;
    esac
    _ci_code=$(grep -v '^[[:space:]]*#' "$root/.github/workflows/ci.yml")
    case "$_ci_code" in
        *"$_needle_ci"*) ;;
        *)
            echo "gate.sh --asan-selftest: FAIL -- .github/workflows/ci.yml's ci_sanitizers job no longer" \
                 "calls the coverage renderer, so that job's sanitizer findings count is being printed" \
                 "with nothing that says which classes were being watched." >&2
            fail=1
            ;;
    esac

    if [ "$fail" != "0" ]; then
        return 1
    fi
    echo "gate.sh --asan-selftest: OK -- the ASan+UBSan cell states its coverage per class through the shared renderer, and both this gate's cell and ci_sanitizers still ask for it."
    return 0
}

# --asan-selftest EXITS HERE: before the banner, before the source-wide checks and
# before every cell. It is a statement about text, and it is most in question on the
# machine that cannot run the cell it describes.
if [ "$ASAN_SELFTEST" = "1" ]; then
    asan_cell_selftest
    exit $?
fi

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
if "$root/scripts/check-portability.py" > "$GATE_BUILD_ROOT/portability.log" 2>&1; then
    sed -n '1p' "$GATE_BUILD_ROOT/portability.log" | sed 's/^/  /'
    SUMMARY="${SUMMARY}check-portability OK\n"
else
    printf '  %-26s %s\n' "check-portability.py" "FAILED"
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
    sed -n '2,40p' "$GATE_BUILD_ROOT/peerlog.log" | sed 's/^/      /'
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
    SUMMARY="${SUMMARY}check-peer-log-sites FAILED\n"
fi

# ---------------------------------------------------------------------------
# THE LINUX CELL'S REPORT CONTRACT, checked here rather than in the cell.
# ---------------------------------------------------------------------------
# WHY IT IS HERE AND NOT ONLY IN `gate.sh --linux`. The Linux cell prints a count of
# sanitizer findings, and a count of zero is only meaningful next to a statement of
# what was being watched -- it did not watch one class for as long as the cell
# existed, and said nothing. Its own report now states its coverage per class, and a
# coverage statement that is only ever checked by the cell that produces it is a
# statement nobody re-checks: editing the report to drop the coverage block would
# cost two minutes of container build to notice, so it would not be noticed.
#
# So the cell grew `--report-selftest`, which renders the report from canned inputs
# and asserts the rendered text still carries its build type, its per-class coverage
# and its completeness marker. It needs no docker, no Linux and no build, so it runs
# here, on macOS, on every gate invocation -- which is where the report is most in
# question, because macOS is where the cell cannot run at all.
#
# WHAT IT IS NOT: it does not check that the classes really are watched in the
# container. That is tests/integration/asan_coverage_probe.c's job, run inside the
# cell with the cell's own ASAN_OPTIONS. This is the format contract; that is the
# measurement. A check that ran only where it is cheap is how the cheap half stays
# alive between the expensive runs.
echo "--- linux-cell report contract (source-wide) ---"
if "$root/scripts/gate-linux-cell.sh" --report-selftest > "$GATE_BUILD_ROOT/linuxreport.log" 2>&1; then
    sed -n '1p' "$GATE_BUILD_ROOT/linuxreport.log" | sed 's/^/  /'
    SUMMARY="${SUMMARY}linux-cell report contract OK\n"
else
    printf '  %-26s %s\n' "gate-linux-cell.sh --report-selftest" "FAILED"
    sed -n '1,40p' "$GATE_BUILD_ROOT/linuxreport.log" | sed 's/^/      /'
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
    SUMMARY="${SUMMARY}linux-cell report contract FAILED\n"
fi

# THE SAME ARGUMENT, APPLIED TO THIS GATE'S OWN SANITIZER CELL, WHICH HAD THE SAME
# DEFECT: a count of findings and nothing about what was watching. See
# asan_cell_selftest's comment for why a coverage statement nobody re-checks is not a
# coverage statement. It is a FAILED CHECK and not a failed CELL for the reason the
# ones above are: it is neither a build problem nor a source problem, it is a
# statement about what a report says.
echo "--- this gate's ASan-cell coverage contract (source-wide) ---"
if asan_cell_selftest > "$GATE_BUILD_ROOT/asanreport.log" 2>&1; then
    sed -n '1p' "$GATE_BUILD_ROOT/asanreport.log" | sed 's/^/  /'
    SUMMARY="${SUMMARY}asan-cell coverage contract OK\n"
else
    printf '  %-26s %s\n' "gate.sh --asan-selftest" "FAILED"
    sed -n '1,40p' "$GATE_BUILD_ROOT/asanreport.log" | sed 's/^/      /'
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
    SUMMARY="${SUMMARY}asan-cell coverage contract FAILED\n"
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
# this platform", taking every test in the binary with it. The ONLY leak check for
# TLS in this
# project is ci_sanitizers' WITH_TLS=ON cell on Linux, and no local script can
# replace it. What this cell checks here is the memory-error half of ASan plus
# UBSan, both of which do run on Darwin.
#
# WHAT THIS CELL NOW STATES ABOUT WHAT IT WAS WATCHING, because before this change
# it printed a count of findings and nothing else, and a count of zero is only a
# statement about what was being watched. The specific gap, measured on this
# machine on 2026-10-10 with the shipped tests/integration/asan_coverage_probe:
#
#   toolchain                    ASAN_OPTIONS                            verdict
#   ---------------------------  --------------------------------------  -----------------------
#   Homebrew gcc 16.2.0          detect_leaks=0                          stack-use-after-return NOT-COVERED
#   Homebrew gcc 16.2.0          detect_leaks=0:...after_return=1       all four classes PROVED
#   Apple clang 21.0.0           detect_leaks=0:...after_return=1       stack-use-after-SCOPE NOT-COVERED
#   Homebrew clang 23.1.2        detect_leaks=0:...after_return=1       stack-use-after-SCOPE NOT-COVERED
#
# TWO CONCLUSIONS, AND THE SECOND ONE IS NOT FIXED HERE. First, detect_leaks=0
# alone left this cell watching three of the four classes it could watch -- and
# stack-use-after-return is the class that found this project's real nf_free()
# registry defect, so this cell was reporting a clean bill of health for exactly
# the failure mode that had already bitten the tree. That is fixed, below, by
# passing the option explicitly. Second, NEITHER CLANG watches stack-use-after-scope
# unless the build carries -fsanitize-address-use-after-scope, which nothing in this
# repository passes. That is a COMPILE flag: turning it on would change what the
# whole suite is instrumented to find, which is a decision with its own cost and is
# not this change's to make. It is stated here, and it is the reason the coverage
# block below names classes individually instead of printing one number.
#
# The cell therefore BUILDS the opt-in probes beside the suite
# (-DIRC_LSAN_PROBE=ON) and RUNS the coverage one directly, with the cell's own
# ASAN_OPTIONS, and prints the SAME per-class statement the Linux cell prints --
# rendered by the same function, scripts/gate-linux-cell.sh --report-render, so
# there is one answer to "is this coverage complete" in this repository rather than
# three. `scripts/gate.sh --asan-selftest` checks that the call is still there.
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
    # -DIRC_LSAN_PROBE=ON BUILDS THE TWO OPT-IN PROBES BESIDE THE SUITE, and this is
    # the reason: before it, this cell could not say what it was watching, because
    # nothing in the cell was built that could say it. The header above has the
    # measurement for why that was not a formality.
    #
    # IT ADDS NO TEST TO THE RUN, and ctest is told so explicitly below with -E. The
    # switch registers `LeakSanitizerProbe` as a CTest test, and that probe FAILS BY
    # DESIGN on Darwin -- LeakSanitizer does not exist here, which is the whole reason
    # this cell passes detect_leaks=0. A test that is red on purpose in the normal
    # gate stops being distinguishable from a test that is red because something
    # broke. So it is BUILT (which is what proves the sanitizer toolchain can compile
    # the probe) and EXCLUDED FROM CTEST (which is what keeps the run honest). The
    # class probe beside it is run directly instead.
    if cmake -B "$ad" -S "$root" -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON \
            -DWITH_TLS=ON -DIRC_SANITIZE=ON -DIRC_LSAN_PROBE=ON \
            -DCMAKE_C_COMPILER="$gccpath" \
            > "$ad.configure.log" 2>&1 \
       && cmake --build "$ad" --parallel "$CTEST_JOBS_BUILD" > "$ad.build.log" 2>&1; then
        errs=$(grep -c 'error:' "$ad.build.log" || true)
        warns=$(grep -c 'warning:' "$ad.build.log" || true)

        # ---------------------------------------------------------------------
        # WHAT THIS CELL WAS WATCHING, MEASURED IN THIS RUN.
        #
        # The probe runs DIRECTLY and under the cell's own ASAN_OPTIONS, never through
        # ctest, for the reason tests/integration/CMakeLists.txt gives at length: ctest
        # reports one thing -- "a test failed" -- and here a failure means "this
        # toolchain was not watching a class", which is a fact about the GATE and not
        # about the software. Printing that as a red suite line is the misleading
        # report this project keeps finding.
        #
        # The renderer is scripts/gate-linux-cell.sh's, so "is this coverage complete"
        # has ONE answer in this repository: the Linux cell, this cell, and
        # ci_sanitizers all call the same function, and its exit status is the verdict.
        # ---------------------------------------------------------------------
        asan_opts="detect_leaks=0:detect_stack_use_after_return=1"
        cov_ok=1
        printf '  %-26s %-7s tls=%-3s coverage: ASAN_OPTIONS=%s\n' \
            "asan+ubsan $(basename "$gccbin")" Release ON "$asan_opts"
        ASAN_OPTIONS="$asan_opts" "$ad/tests/integration/asan_coverage_probe" \
            > "$ad.cov.log" 2>&1 || true
        if bash "$root/scripts/gate-linux-cell.sh" --report-render < "$ad.cov.log" \
                > "$ad.covreport.log" 2>&1; then
            cov_ok=1
        else
            cov_ok=0
        fi
        sed -n '/sanitizer coverage/,$p' "$ad.covreport.log" | sed 's/^/      /'
        # MACHINE AND TOOLCHAIN, because a coverage claim is a claim about a toolchain
        # and a reader who does not know which cannot make it.
        printf '      measured on: %s, %s, Release, ASAN_OPTIONS=%s\n' \
            "$(uname -sr)" "$gccbin (macOS)" "$asan_opts"

        if [ "$errs" = "0" ] && [ "$warns" = "0" ] && [ "$cov_ok" = "1" ]; then
            if ASAN_OPTIONS="$asan_opts" UBSAN_OPTIONS=halt_on_error=1 \
               ctest --test-dir "$ad" -j "$CTEST_JOBS_TEST" --timeout 200 \
                     -E '^LeakSanitizerProbe$' > "$ad.test.log" 2>&1; then
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
        elif [ "$cov_ok" != "1" ]; then
            # THE CELL BUILT CLEAN AND THE SUITE WOULD HAVE PASSED, AND IT IS STILL
            # RED, because "0 findings" under an incomplete coverage statement is not
            # a result. This is the same decision scripts/gate-linux-cell.sh makes and
            # for the same stated reason: the cell's job is the claim that it watched
            # something, and a run that cannot show what it watched has not done that
            # job. The lines above name the class; the clang rows in this cell's
            # header comment say which toolchains land here (either clang leaves
            # stack-use-after-scope unwatched, because nothing in this tree passes
            # -fsanitize-address-use-after-scope).
            printf '  %-26s %-7s tls=%-3s SANITIZER COVERAGE INCOMPLETE -- the counts above do not mean what they look like\n' \
                "asan+ubsan $(basename "$gccbin")" Release ON
            FAILED_CELLS=$((FAILED_CELLS + 1))
            SUMMARY="${SUMMARY}asan+ubsan tls=ON COVERAGE INCOMPLETE\n"
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
# The Linux cell: glibc, ASan + LSan + UBSan, in a container.
# ---------------------------------------------------------------------------
# OPT-IN with --linux, and it is a CELL and not a FAILED CHECK, on purpose. It is a
# build of the source and a run of the suite, so it is the same kind of evidence the
# other thirteen cells produce, and counting it as a source check would inflate the
# check list with a thing that is not a source check. It is also the most expensive
# cell by a wide margin -- two full sanitized builds of the whole suite in a
# container -- so it is asked for rather than paid for by default.
#
# WHY IT IS HERE AT ALL: six defects in this project have been invisible to every
# macOS cell and visible only on Linux. glibc's __wur, a <sys/wait.h> included by one
# libc's headers and not the other's, memmem(), a tf_done() leak, a 64 KiB test leak,
# and a debian/rules that configured nothing at all. The common cause is not any one of
# them: it is that this gate is not an oracle for the platform the software ships on,
# and a gate that cannot see a class of defect reports its own blindness as green.
# LeakSanitizer does not exist on Darwin at all, so no local configuration of this
# script can close that gap -- only a Linux userspace can, which is what this cell is.
#
# DEGRADATION, WHICH IS THE PART THAT MATTERS. scripts/gate-linux-cell.sh has THREE
# exit codes -- 0 ran and passed, 1 ran and failed, 3 did not run -- and this block
# prints a DIFFERENT WORD for each. A cell that skips and prints OK is the decorative
# check this project keeps finding; a cell that prints "SKIPPED, the Linux cell did not
# run" while the gate still passes is the honest version of the same thing, and the
# reason the exit code is separate is that the summary line and the matrix total can
# then both be honest about it.
#
# The matrix total below counts what RAN and says so, and prints the skipped cells
# separately rather than folding them into either number.
if [ "$RUN_LINUX" = "1" ]; then
    echo
    echo "--- Linux cell: glibc, ASan + LeakSanitizer + UBSan (docker) ---"
    if "$root/scripts/gate-linux-cell.sh" ${GATE_LINUX_ARGS:-} \
            > "$GATE_BUILD_ROOT/linux-cell.log" 2>&1; then
        LINUX_VERDICT="PASS"
        LINUX_SKIPPED=0
        # Every line, indented, because the counts in it are the measurement and a
        # summary that says "PASS" without the numbers is the same claim this cell
        # exists to stop being asked to take on trust.
        sed -n '/^--- WITH_TLS=OFF: ctest/,$p' "$GATE_BUILD_ROOT/linux-cell.log" \
            | sed 's/^/  /'
        TOTAL_CELLS=$((TOTAL_CELLS + 1))
        SUMMARY="${SUMMARY}linux-cell (glibc+ASan+LSan+UBSan, tls=OFF+ON) OK\n"
    else
        rc=$?
        if [ "$rc" = "3" ]; then
            # THE THIRD OUTCOME, and the one this whole branch exists for.
            LINUX_VERDICT="SKIPPED"
            LINUX_SKIPPED=1
            printf '  %-26s %s\n' "linux-cell" "DID NOT RUN (see below)"
            sed -n '1,40p' "$GATE_BUILD_ROOT/linux-cell.log" | sed 's/^/      /'
            # NOT a failure. A machine without docker has not found a defect, and
            # failing the gate for it would train people to disable the gate. But it
            # is also not a pass, and it is not counted as a cell that ran -- so the
            # total below says "12 of 13 ran" rather than claiming thirteen.
            LINUX_REASON=$(sed -n '2p' "$GATE_BUILD_ROOT/linux-cell.log" 2>/dev/null || true)
            SUMMARY="${SUMMARY}linux-cell SKIPPED (did not run; not counted as a cell)\n"
        else
            LINUX_VERDICT="FAIL"
            LINUX_SKIPPED=0
            printf '  %-26s %s\n' "linux-cell" "FAILED"
            sed -n '1,60p' "$GATE_BUILD_ROOT/linux-cell.log" | sed 's/^/      /'
            TOTAL_CELLS=$((TOTAL_CELLS + 1))
            FAILED_CELLS=$((FAILED_CELLS + 1))
            SUMMARY="${SUMMARY}linux-cell FAILED\n"
        fi
    fi
fi

# ---------------------------------------------------------------------------
# The docs-truth check, AFTER the cells and not before them.
# ---------------------------------------------------------------------------
# IT NEEDS A BUILD TREE and it reads the tree with `ctest -N`, so WHERE IN THIS SCRIPT
# IT RUNS IS LOAD-BEARING. The first version ran it here at the top, with the other
# source-wide checks, and picked the alphabetically-first directory under
# $GATE_BUILD_ROOT -- which, because `run_cell()` only `rm -rf`s the cell it is about
# to build, is a LEFTOVER from the previous run whenever this one is interrupted or
# the two disagree about the compiler set. It read a stale 95-test tree and reported
# four "stale claims" that were this tree's own 98. That is the silent-substitution
# failure the check's own header warns about, committed by the gate itself, and the
# only thing that prevents it is that this check REFUSES to substitute a tree.
#
# After the cells, the first cell's directory is guaranteed to have just been
# configured by this run.
echo
echo "--- docs truth (needs a build tree, so: after the cells) ---"
# `${selected[0]}` is an INDEX into all_labels, not a label -- which is why the
# first version of this built the path "0_Release_tlsOFF" and the check refused it.
# The refusal was correct and the path was wrong, and that is the check working.
DOCS_BUILD="$GATE_BUILD_ROOT/${all_labels[${selected[0]}]}_Release_tlsOFF"
if python3 "$root/scripts/check-docs-truth.py" --build "$DOCS_BUILD" \
        > "$GATE_BUILD_ROOT/docstruth.log" 2>&1; then
    sed -n '1p' "$GATE_BUILD_ROOT/docstruth.log" | sed 's/^/  /'
    SUMMARY="${SUMMARY}check-docs-truth OK\n"
else
    printf '  %-26s %s\n' "check-docs-truth.py" "FAILED"
    sed -n '1,40p' "$GATE_BUILD_ROOT/docstruth.log" | sed 's/^/      /'
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
    SUMMARY="${SUMMARY}check-docs-truth FAILED\n"
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
# Linux verdict in the summary block, so the SKIPPED word appears in the same place a
# reader looks for the result rather than only in the prose above.
if [ "$RUN_LINUX" = "1" ]; then
    printf '  %-26s %s\n' "linux-cell" "$LINUX_VERDICT"
fi

# The count is REPORTED, not asserted, and it says what actually ran. An earlier
# version hardcoded "+ 1 sanitizer cell", which was wrong under --no-asan: the
# total said 13 while 12 ran. A summary that describes a cell the run skipped is
# the small version of the lie this gate exists to prevent.
# THE COUNT IS WHAT RAN, AND THE ARITHMETIC IS SPELLED OUT rather than computed into a
# string, because a total that is assembled from a template is a total that can claim a
# cell ran when it did not. That failure has already happened once in this file -- an
# earlier version hardcoded "+ 1 sanitizer cell" and said 13 under --no-asan while 12
# ran -- so the parts are named here instead.
_cells_desc="12 build cells"
if [ "$RUN_ASAN" = "1" ]; then
    _cells_desc="$_cells_desc + 1 ASan+UBSan cell"
else
    _cells_desc="$_cells_desc (--no-asan, so no sanitizer cell)"
fi
if [ "$RUN_LINUX" = "1" ]; then
    if [ "$LINUX_VERDICT" = "PASS" ]; then
        _cells_desc="$_cells_desc + 1 Linux cell (glibc, ASan+LSan+UBSan)"
    elif [ "$LINUX_VERDICT" = "FAIL" ]; then
        _cells_desc="$_cells_desc + 1 Linux cell (FAILED)"
    else
        # SKIPPED IS NOT COUNTED. A total that said "13 cells" when twelve ran and one
        # did not is a total that lies by addition, and the number is the one thing
        # about a gate matrix that people read without the log.
        _cells_desc="$_cells_desc (--linux requested; the Linux cell DID NOT RUN and is not counted)"
    fi
fi
echo "cells run: $TOTAL_CELLS ($_cells_desc)"
if [ "$RUN_LINUX" = "1" ] && [ "$LINUX_VERDICT" = "SKIPPED" ]; then
    echo "LINUX CELL: NOT RUN -- not a pass, not a failure, and not counted above."
    echo "  LeakSanitizer does not exist on this platform, so no leak in this tree is"
    echo "  excluded by anything this run did. Run it on a Linux host with docker:"
    echo "    ./scripts/gate-linux-cell.sh"
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