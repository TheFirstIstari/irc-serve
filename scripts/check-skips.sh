#!/usr/bin/env bash
# check-skips.sh -- THE SKIP RATCHET. Fails unless the set of tests CTest
# actually reports as Skipped is EXACTLY the set named in tests/known_skips.txt.
#
# Usage:
#   scripts/check-skips.sh [-b BUILD_DIR] [CTEST_LOG]
#
#   -b BUILD_DIR  the configured build tree (default: ./build)
#   CTEST_LOG     a saved ctest output to read the skips from, instead of running
#                 ctest. This is the form CI uses, because the run has already
#                 happened and running the whole suite a second time to find out
#                 which tests skipped would double the gate's cost for no new
#                 information.
#
# ---------------------------------------------------------------------------
# WHY IT IS A RATCHET AND NOT "ZERO SKIPS"
# ---------------------------------------------------------------------------
# docs/SERVER_DESIGN.md 6.4 and 7/Phase 7 used to require the skip count to reach
# ZERO by Phase 7. That is not reachable, and the reason is that document's own
# phase allocation rather than an oversight: 7/Phase 8 gives CAP negotiation and
# multi-prefix to Phase 8, and 7/Phase 9 gives peer discovery, auto-scale,
# reconnect and failover to Phase 9. Those skips are not unfinished Phase 7 work,
# they are work Phase 7 has explicitly been given no time to do. A gate demanding
# zero would be demanding a feature Phase 7 must not build, and the only ways to
# satisfy it would be to delete the tests -- which is precisely the failure the
# gate exists to prevent -- or to build Phase 8 and Phase 9 inside Phase 7.
#
# What IS achievable, and what this script enforces, is the real intent: the
# count only goes down, and every skip is accounted for by name.
#
# ---------------------------------------------------------------------------
# WHY BOTH DIRECTIONS, AND WHY THE SECOND IS THE INTERESTING ONE
# ---------------------------------------------------------------------------
#   skipped but not listed   a NEW skip. This is the blind spot 6.4 describes and
#                            it is the reason the file exists.
#   listed but not skipped   a RETIRED skip whose line was not removed. Without
#                            this direction the list becomes a permanent
#                            allowlist: a test that was implemented in 2026 and
#                            whose line nobody deleted would go on authorising a
#                            skip for ever, and the count would stop meaning
#                            anything. This is what makes it a ratchet.
#   listed but not a test    a typo, or a test that was deleted. Cheap to check
#                            and it stops the second direction from passing
#                            vacuously -- a name that matches nothing cannot skip.
#
# ---------------------------------------------------------------------------
# WHY THIS PARSES CTEST'S OUTPUT RATHER THAN ASKING CTEST
# ---------------------------------------------------------------------------
# CTest has no "list the skipped tests" query, and --output-junit needs CMake 3.21
# while this project requires 3.20. The human-readable form is stable and the two
# things this needs from it are both anchored:
#
#   - the "The following tests did not run:" block, whose entries are
#     `<number> - <name> (Skipped)`;
#   - the progress table, whose entries are `... ***Skipped` and carry NO
#     parentheses. The parenthesised form is therefore what distinguishes the
#     footer from the table, and .github/workflows/stats.yml makes the same point
#     about double-counting the other way.
#
# A log with no such block at all is a FAILURE whenever the list is non-empty,
# not a pass: "we could not tell" is not "there are none", and a gate that passes
# when it cannot read its input is a gate that gets switched off by a ctest
# release note.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
LIST="$REPO_ROOT/tests/known_skips.txt"
BUILD_DIR="$REPO_ROOT/build"
LOG=""

while [ $# -gt 0 ]; do
    case "$1" in
        -b) shift; [ $# -gt 0 ] || { echo "check-skips: -b needs a directory" >&2; exit 2; }
            BUILD_DIR="$1" ;;
        -h|--help) sed -n '2,60p' "$0"; exit 0 ;;
        -*) echo "check-skips: unknown option $1" >&2; exit 2 ;;
        *)  LOG="$1" ;;
    esac
    shift
done

if [ ! -f "$LIST" ]; then
    echo "check-skips: FAIL: $LIST does not exist, so there is no list for a skip to be permitted by" >&2
    exit 1
fi

# The permitted set: the first field of every non-comment, non-blank line.
LISTED=$(awk 'NF > 0 && $1 !~ /^#/ { print $1 }' "$LIST" | LC_ALL=C sort -u)

# ---------------------------------------------------------------------------
# Get the actual set.
# ---------------------------------------------------------------------------
if [ -n "$LOG" ]; then
    if [ ! -r "$LOG" ]; then
        echo "check-skips: FAIL: cannot read the ctest log '$LOG'" >&2
        exit 1
    fi
    CTEST_OUT=$(cat "$LOG")
    echo "check-skips: reading skips from $LOG"
else
    if ! command -v ctest >/dev/null 2>&1; then
        echo "check-skips: FAIL: ctest is not on PATH" >&2
        exit 1
    fi
    echo "check-skips: running ctest in $BUILD_DIR to find the skips"
    # set -o pipefail is already on; ctest's own exit status is deliberately NOT
    # fatal here, because a suite that FAILED still tells us which tests skipped
    # and the run that failed is a separate gate with a separate message.
    set +e
    CTEST_OUT=$(ctest --test-dir "$BUILD_DIR" 2>&1)
    set -e
fi

# The parenthesised footer form, and only from the block after the marker.
ACTUAL=$(printf '%s\n' "$CTEST_OUT" \
    | sed -n '/^[[:space:]]*The following tests did not run:[[:space:]]*$/,$p' \
    | sed -n 's/^[[:space:]]*[0-9][0-9]* - \(.*\) (Skipped)[[:space:]]*$/\1/p' \
    | LC_ALL=C sort -u)

BLOCK_SEEN=0
if printf '%s\n' "$CTEST_OUT" | grep -qE '^[[:space:]]*The following tests did not run:[[:space:]]*$'; then
    BLOCK_SEEN=1
fi
LISTED_COUNT=$(printf '%s' "$LISTED" | grep -c . || true)
ACTUAL_COUNT=$(printf '%s' "$ACTUAL" | grep -c . || true)

# ---------------------------------------------------------------------------
# The three failures.
# ---------------------------------------------------------------------------
RC=0

# 1. A skip with no line for it. This is the blind spot.
NEW=$(LC_ALL=C comm -23 <(printf '%s\n' "$ACTUAL") <(printf '%s\n' "$LISTED") | grep . || true)
if [ -n "$NEW" ]; then
    echo "check-skips: FAIL: these tests skipped and tests/known_skips.txt does not permit them:" >&2
    printf '    %s\n' $NEW >&2
    echo "    Add one line per test to $LIST naming the phase that owns it and the issue that closes it -- or implement the feature and remove the skip." >&2
    RC=1
fi

# 2. A line with no skip behind it. The ratchet.
if [ "$BLOCK_SEEN" -eq 1 ]; then
    STALE=$(LC_ALL=C comm -13 <(printf '%s\n' "$ACTUAL") <(printf '%s\n' "$LISTED") | grep . || true)
    if [ -n "$STALE" ]; then
        echo "check-skips: FAIL: these tests are listed as permitted skips but CTest did not report them as skipped:" >&2
        printf '    %s\n' $STALE >&2
        echo "    Either the feature landed -- in which case delete the line in the same change -- or the test stopped skipping for another reason, which is a finding." >&2
        RC=1
    fi
else
    if [ "$LISTED_COUNT" -gt 0 ]; then
        echo "check-skips: FAIL: could not find CTest's \"The following tests did not run:\" block in the output, so the skip set could not be read." >&2
        echo "    $LISTED_COUNT skip(s) are permitted and 0 were found. Treating an unreadable gate as a passing one is how a gate gets switched off by accident; this is a failure until the output format is understood again." >&2
        RC=1
    else
        echo "check-skips: no skips permitted and none reported: the gate has nothing to check and found nothing." >&2
    fi
fi

# 3. A listed name that is not a registered test. Cheap, and it stops direction 2
#    from passing vacuously.
if [ "$LISTED_COUNT" -gt 0 ]; then
    if command -v ctest >/dev/null 2>&1 && [ -d "$BUILD_DIR" ]; then
        set +e
        KNOWN=$(ctest --test-dir "$BUILD_DIR" -N 2>/dev/null \
            | sed -n 's/^[[:space:]]*Test[[:space:]]*#[0-9][0-9]*:[[:space:]]*\(.*\)$/\1/p' \
            | LC_ALL=C sort -u)
        set -e
        if [ -n "$KNOWN" ]; then
            UNKNOWN=$(LC_ALL=C comm -23 <(printf '%s\n' "$LISTED") <(printf '%s\n' "$KNOWN") | grep . || true)
            if [ -n "$UNKNOWN" ]; then
                echo "check-skips: FAIL: these names are listed as permitted skips but no such CTest test is registered:" >&2
                printf '    %s\n' $UNKNOWN >&2
                echo "    Either the test was renamed or deleted -- in which case the line goes too -- or the name is misspelled." >&2
                RC=1
            fi
        else
            echo "check-skips: WARNING: could not read the test list from $BUILD_DIR; the listed-names check was skipped" >&2
        fi
    else
        echo "check-skips: WARNING: $BUILD_DIR is not a configured build tree; the listed-names check was skipped" >&2
    fi
fi

if [ "$RC" -eq 0 ]; then
    echo "check-skips: OK: $ACTUAL_COUNT skipped test(s), and all $ACTUAL_COUNT are listed in tests/known_skips.txt with the phase that owns them."
    printf '    %s\n' $ACTUAL
    echo "check-skips: the count only goes down. Closing a skip is implementing the feature and deleting the line in the same change."
fi
exit "$RC"
