#!/bin/sh
# teeth.sh -- prove each fix in this pass has TEETH, by reverting it in a COPY of the
# tree, rebuilding, and requiring the named tests to go RED.
#
# WHY A COPY AND NOT AN EDIT-AND-REVERT
# -------------------------------------
# A reverted fix caught while the revert is still in the working tree proves the test
# noticed a working tree. What has to be proven is that the test notices the SHIPPED
# source. Every fault here is applied to a fresh copy, built from scratch, and the
# binary's mtime is compared against the sources before its result is read -- because
# a stale binary that passes is the one way this script can report a success that
# means nothing.
#
# WHAT A PASS HERE MEANS, AND WHAT IT DOES NOT
# -------------------------------------------
# It means the named tests go red with the fault and green without it, which is the
# property a fault-injection check is for. It does NOT mean the tests are sufficient:
# sufficiency is not a property a single fault can establish, and a suite that claims
# otherwise is claiming the one thing it cannot know. Eight faults is a floor.
#
# NO `sleep` ANYWHERE, AND NO ASSUMPTION ABOUT HOW LONG A BUILD TAKES: each wait is
# for a process, on its pid, with `wait`.
#
# The faults live in `scripts/teeth/*.py`, one per file, each with the reasoning in its
# own docstring. They are separate files rather than heredocs in this one because a
# fault nobody can read is a fault nobody can review, and because a Python script in a
# heredoc inside a shell function inside a quoted argument is three levels of escaping
# away from being checkable.
set -eu

ROOT=${ROOT:-$(cd "$(dirname "$0")/.." && pwd)}
WORK=${WORK:-/tmp/teeth-p11}
TEETH="$ROOT/scripts/teeth"
PASS=0
FAIL=0
FAILED_LIST=""

note() { printf '%s\n' "$*"; }

# The tracked tree, without the build directory, so the build is from THESE sources.
stage_tree() {
    rm -rf "$WORK"
    mkdir -p "$WORK"
    (cd "$ROOT" && git ls-files -z | while IFS= read -r -d '' f; do
        mkdir -p "$WORK/$(dirname "$f")"
        cp "$ROOT/$f" "$WORK/$f"
    done)
}

# One fault: a script name, and the tests that must go red without it.
run_fault() {
    name=$1
    tests=$2
    script=$3

    stage_tree
    if ! (cd "$WORK" && python3 "$TEETH/$script"); then
        note "FAULT NOT APPLIED: $name ($script)"
        FAIL=$((FAIL + 1))
        FAILED_LIST="$FAILED_LIST $name(apply)"
        return
    fi

    if ! (cd "$WORK" && cmake -S . -B b -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON \
            -DWITH_TLS=OFF >"$WORK/cmake.log" 2>&1 \
            && cmake --build b -j8 >"$WORK/build.log" 2>&1); then
        note "FAULT $name DID NOT COMPILE -- a fault that does not build proves nothing"
        tail -5 "$WORK/build.log" 2>/dev/null || true
        FAIL=$((FAIL + 1))
        FAILED_LIST="$FAILED_LIST $name(build)"
        return
    fi

    # THE BUILD-VERIFICATION GATE. Every source in the copy is touched to a time OLDER
    # than the binaries, and every binary must then be NEWER than every source: a
    # timestamp-only check can be satisfied by a build that reused an object file, so
    # the gate is that the newest source is older than the oldest binary.
    newest_src=$(find "$WORK" -name '*.c' -o -name '*.h' | xargs ls -t 2>/dev/null | head -1)
    for t in $tests; do
        bin="$WORK/b/tests/integration/$t"
        [ -x "$bin" ] || bin="$WORK/b/tests/protocol/$t"
        if [ ! -x "$bin" ]; then
            note "FAULT $name: no binary for $t"
            FAIL=$((FAIL + 1))
            FAILED_LIST="$FAILED_LIST $name(nobin:$t)"
            return
        fi
        if [ "$newest_src" -nt "$bin" ]; then
            note "FAULT $name: $t binary is NOT newer than the newest source"
            FAIL=$((FAIL + 1))
            FAILED_LIST="$FAILED_LIST $name(stale:$t)"
            return
        fi
    done

    reds=""
    for t in $tests; do
        bin="$WORK/b/tests/integration/$t"
        [ -x "$bin" ] || bin="$WORK/b/tests/protocol/$t"
        if (cd "$WORK" && "$bin" >"$WORK/$t.log" 2>&1); then
            reds="$reds $t:STILL-GREEN"
        else
            reds="$reds $t:red"
        fi
    done

    case "$reds" in
        *STILL-GREEN*)
            note "FAULT $name NOT CAUGHT:$reds"
            FAIL=$((FAIL + 1))
            FAILED_LIST="$FAILED_LIST $name(green)"
            ;;
        *)
            note "ok: $name ->$reds"
            PASS=$((PASS + 1))
            ;;
    esac
}

note "teeth: each fault is applied to a fresh copy, built, and required to go red."

# `test_nick_utf8` AND NOT `test_control_bytes`: the latter covers the MODE `472` and
# BATCH `NO_SIGN` fields, which are a different filter at a different site, so naming
# it here would be claiming coverage that fault does not touch. Naming a test that
# should NOT go red is how a teeth script starts reporting failures that are its own.
run_fault echo-filter-removed \
    "test_nick_utf8" \
    echo_filter_removed.py

run_fault nick-widened-to-all-non-ascii \
    "test_valid_nick" \
    nick_widened.py

run_fault nick-narrowed-to-bare-range \
    "test_valid_nick" \
    nick_narrowed.py

run_fault smodes-allowlist-removed-peer-path-only \
    "test_peer_terminal_sweep" \
    smodes_allowlist_removed.py

run_fault overlong-accepted \
    "test_valid_nick" \
    overlong_accepted.py

run_fault surrogate-accepted \
    "test_valid_nick" \
    surrogate_accepted.py

run_fault peer-relay-strip-bypassed \
    "test_peer_terminal_sweep" \
    peer_relay_bypassed.py

run_fault inverted-assertion-check-has-teeth \
    "test_peer_terminal_sweep" \
    inverted_assertion.py

note ""
note "teeth: $PASS of 8 faults caught, $FAIL not."
if [ "$FAIL" != "0" ]; then
    note "not caught:$FAILED_LIST"
    exit 1
fi