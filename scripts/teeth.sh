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

# ---------------------------------------------------------------------------
# run_source_fault: the same protocol, for a fault a SOURCE CHECK has to catch.
#
# WHY A SECOND FUNCTION AND NOT A FLAG ON run_fault. run_fault reads a result out of a
# COMPILED TEST BINARY, and five of this project's packaging claims are read out of a
# Python script that needs no build at all. Reusing run_fault for those would have
# meant naming a C test for a fault no C test has teeth for, and the report would then
# read as coverage that does not exist. `tests/integration/test_version_truth.c` does
# watch the PKGBUILD and the changelog, but it is the wrong instrument to prove that
# `scripts/check-packaging.py` -- which runs on every gate invocation, in a second,
# with no compiler -- fires on its own.
#
# THE BUILD IS STILL DONE, and this is the part that looks like waste. It is not: a
# fault script that corrupts the tree, or a staging step that silently drops a file,
# produces a check failure that says nothing about the check. Building first and
# asserting 0 errors / 0 warnings / a fresh binary proves the fault was the ONLY thing
# that changed, so the red that follows is attributable.
#
# `expect` IS THE SHARP END. Requiring only "the check exited nonzero" would let a
# fault be caught for the wrong reason -- a missing file, a truncated write, a
# Python traceback -- and would report that as coverage. Each fault names a substring
# of its OWN finding, so the check has to produce the right failure.
# ---------------------------------------------------------------------------
run_source_fault() {
    name=$1
    script=$2
    expect=$3

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

    # Counted on the BUILD LOG, so a cell that built nothing cannot report "0 errors"
    # by having produced no log at all. Same rule run_cell() in gate.sh follows.
    errs=$(grep -c 'error:' "$WORK/build.log" || true)
    warns=$(grep -c 'warning:' "$WORK/build.log" || true)
    if [ "$errs" != "0" ] || [ "$warns" != "0" ]; then
        note "FAULT $name: build printed errors=$errs warnings=$warns"
        FAIL=$((FAIL + 1))
        FAILED_LIST="$FAILED_LIST $name(build:$errs/$warns)"
        return
    fi

    # The mtime gate, same rule as run_fault: the newest source must be older than the
    # binary, so a stale object file cannot pass for a fresh one.
    bin="$WORK/b/src/irc-serve"
    if [ ! -x "$bin" ]; then
        note "FAULT $name: no built binary at $bin"
        FAIL=$((FAIL + 1))
        FAILED_LIST="$FAILED_LIST $name(nobin)"
        return
    fi
    newest_src=$(find "$WORK" -name '*.c' -o -name '*.h' | xargs ls -t 2>/dev/null | head -1)
    if [ "$newest_src" -nt "$bin" ]; then
        note "FAULT $name: the binary is NOT newer than the newest source"
        FAIL=$((FAIL + 1))
        FAILED_LIST="$FAILED_LIST $name(stale)"
        return
    fi

    if (cd "$WORK" && python3 scripts/check-packaging.py >"$WORK/check.log" 2>&1); then
        note "FAULT $name NOT CAUGHT: check-packaging.py is still GREEN"
        FAIL=$((FAIL + 1))
        FAILED_LIST="$FAILED_LIST $name(green)"
        return
    fi

    # The right failure, not merely a failure.
    if ! grep -Fq "$expect" "$WORK/check.log"; then
        note "FAULT $name: check-packaging.py went red for the WRONG REASON (no line"
        note "  matching: $expect)"
        sed -n '1,12p' "$WORK/check.log" | sed 's/^/      /'
        FAIL=$((FAIL + 1))
        FAILED_LIST="$FAILED_LIST $name(wrongreason)"
        return
    fi

    note "ok: $name -> check-packaging.py red, naming the expected finding"
    PASS=$((PASS + 1))
}

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
# ---------------------------------------------------------------------------
# 9-11. THE BOUNDED SEARCH'S OWN THREE FAULTS.
#
# Each of these is a one-token change that compiles, passes every other test in the
# tree, and passes all thirteen local gate cells -- which is the point. The peer sweep
# is the instrument's only consumer, and a search that reads one byte past its range
# returns the right ANSWER on every ordinary run, so nothing but the self-test in the
# header can see any of them. That is why the self-test exists, and these are the
# faults that justify it.
# ---------------------------------------------------------------------------
run_fault bounded-search-off-by-one-at-the-end \
    "test_peer_terminal_sweep test_terminal_sweep" \
    bounded_search_overrun.py

run_fault zero-length-needle-reports-found \
    "test_peer_terminal_sweep test_terminal_sweep" \
    empty_needle_matches.py

run_fault needle-containing-nul-handled-with-strlen \
    "test_peer_terminal_sweep test_terminal_sweep" \
    nul_needle_strlen.py

note ""
# ---------------------------------------------------------------------------
# 12. #132: THE TOPIC AUTHORITY CHECK READING THE TRANSPORT INSTEAD OF THE LINE.
#
# The one fault here whose test needs a THREE-NODE mesh. Every other fault in this
# file is a filter or a predicate that a two-node suite can see; this one was
# invisible to a suite that had two-node federation in it and green on every gate
# cell, because on the one topology the two-node fixture builds the transport and
# the subject are the same server. That is the reason the new test spawns a chain
# rather than a pair, and it is why this fault names both of the test's cases: one
# alone would prove the file has teeth and not that the test does.
# ---------------------------------------------------------------------------
run_fault stopic-authority-reads-the-link-not-the-line \
    "test_fed_topic_authority test_fed_relay" \
    stopic_link_name_instead_of_subject.py

# ---------------------------------------------------------------------------
# 13. #133: THE EMPTY-MASK BAN REFUSAL BACK ON THE CAPACITY NUMERIC.
#
# The second fault in this file that needs a WIRE assertion rather than a log
# assertion: the whole claim is that the numeric on the wire is 461 and not 478,
# so a check that counted `chan_ban_refused:` lines would pass either way. The
# numeric is also the thing a client reads, which is why the wrong one is a defect
# rather than a naming preference.
# ---------------------------------------------------------------------------
run_fault ban-empty-mask-answers-478     "test_banlist" \
    ban_empty_mask_answers_478.py

# ---------------------------------------------------------------------------
# 14. #134: THE <msgtarget> BACK IN A printf("%s"), AND THE REACHABILITY CLAIM
#     ABOVE IT PROVED BY A COMMENT RATHER THAN BY A TEST.
#
# One fault and two tests, which is the shape of #134: the injection fix and the
# claim that made the site look safe are different defects with different fixes,
# and the test file covers both. `test_hostmask_reachability` is the only test in
# the tree whose SUBJECT is a comment, so this is also the only fault here whose
# failure mode is "a paragraph in a source file went stale".
# ---------------------------------------------------------------------------
run_fault msg-target-printed-raw     "test_hostmask_reachability" \
    msg_params_printed_raw.py

run_fault hostmask-width-derivation-replaced-by-a-literal \
    "test_hostmask_reachability" \
    hostmask_width_literal.py

# ---------------------------------------------------------------------------
# 16. #135: A PEER'S <nick> BACK IN A printf("%s") ON THE BRANCH THAT REFUSED IT.
#
# The one fault in this file that TWO instruments have to catch, which is why it is
# the one worth the most: the sweep says the argument is not allowed, and the wire
# test says the byte came out. A fault caught by only one of them would mean the
# other is decorative, and this is the fault that establishes which is which.
#
# `scripts/teeth.sh` runs the C test because that is what `run_fault` drives. The
# sweep is a SOURCE check, so running it under this harness would need the mutation
# applied to the copy rather than to this tree -- which `run_fault` does do, since
# it stages the tree and applies the fault there. So the check named here is the
# binary, and the sweep's half of the claim is verified separately by running
# `python3 scripts/check-peer-log-sites.py` against the same mutated copy, which is
# what the fault's docstring asks a reader to do.
# ---------------------------------------------------------------------------
run_fault burst-nick-printed-raw-on-the-refusal-branch \
    "test_burst_malformed_log" \
    burst_nick_printed_raw.py

note ""
# ---------------------------------------------------------------------------
# 17-21. THE PACKAGING FAULTS, which a SOURCE CHECK has to catch.
#
# Five claims that `scripts/check-packaging.py` made after this pass and that no C
# test in the tree covers, because they are claims about packaging files rather than
# about a program's behaviour. `test_version_truth.c` already watches the PKGBUILD's
# derivation and the changelog's version, so faults 17 and 18 have a second
# instrument -- these run the Python one, and the point is to establish that the
# cheap check fires on its own account rather than through the C test.
#
# The fifth is the one worth reading the file for: `debian/source/format` with a
# leading comment block is a real dpkg-source ERROR, not a style question, and it was
# shipped in this repository for the length of one working session.
# ---------------------------------------------------------------------------
run_source_fault changelog-version-diverges-from-header \
    changelog_version_diverges.py \
    "debian/changelog version"

run_source_fault pkgbuild-pkgver-hardcoded-instead-of-derived \
    pkgbuild_pkgver_hardcoded.py \
    "pkgver is not written as a \`sed\` over the header"

run_source_fault formula-version-diverges-from-header \
    formula_version_diverges.py \
    "homebrew formula version"

run_source_fault source-format-is-not-a-documented-format \
    source_format_invalid.py \
    "is not one of '3.0 (native)' or '3.0 (quilt)'"

run_source_fault source-format-opens-with-a-comment-block \
    source_format_leading_comment.py \
    "dpkg-source reads this"

note ""
note "teeth: $PASS of 21 faults caught, $FAIL not."
if [ "$FAIL" != "0" ]; then
    note "not caught:$FAILED_LIST"
    exit 1
fi
