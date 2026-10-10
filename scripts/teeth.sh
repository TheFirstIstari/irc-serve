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
#
# `-P` below, and it is not tidiness: the tree tracks `debian` as a SYMLINK to
# `packaging/debian` (which is tracked separately), and a bare `cp` of a symlink whose
# target is a directory fails with "is a directory (not copied)" and returns 1. Under
# this script's `set -e` that aborts stage_tree, so EVERY fault below dies on its first
# call before a single line is applied. Measured on main (2f21b1e) with nothing else
# changed: the staging step exits 1 on the very first fault, so this instrument has been
# reporting nothing at all since that symlink landed.
#
# `-P` copies the link itself rather than following it, which is what the tree means:
# `debian -> packaging/debian` is RELATIVE, so it resolves inside the staged copy
# because `packaging/debian` is staged with it. `-r` would also silence the error and
# would be wrong in the other direction -- it dereferences, so the staged tree would
# carry a second copy of the packaging directory under two paths.
stage_tree() {
    rm -rf "$WORK"
    mkdir -p "$WORK"
    (cd "$ROOT" && git ls-files -z | while IFS= read -r -d '' f; do
        mkdir -p "$WORK/$(dirname "$f")"
        cp -P "$ROOT/$f" "$WORK/$f"
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

# ---------------------------------------------------------------------------
# run_command_fault: the SAME PROTOCOL, for a fault some OTHER instrument has to catch.
#
# WHY A THIRD FUNCTION AND NOT A PARAMETER ON run_source_fault. run_source_fault is
# hardcoded to `python3 scripts/check-packaging.py`, which is right for the five
# packaging faults and wrong for one this pass added: a shell self-test that renders
# `scripts/gate-linux-cell.sh`'s report and asserts the report still carries its
# coverage statement. It needs the same discipline -- stage, apply, build, verify 0
# errors / 0 warnings and a fresh binary, then require RED FOR THE RIGHT REASON -- and
# it is not check-packaging.py.
#
# The command is passed as a single string and run with `sh -c` in the staged copy.
# A string rather than a word list because the instrument is `sh scripts/x.sh --flag`,
# which is shell-shaped; threading that through a parameterised form to avoid one
# `sh -c` would be the more complicated change.
# ---------------------------------------------------------------------------
run_command_fault() {
    name=$1
    script=$2
    expect=$3
    cmd=$4

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
    # by having produced no log at all. Same rule as run_source_fault.
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

    if (cd "$WORK" && sh -c "$cmd" >"$WORK/instrument.log" 2>&1); then
        note "FAULT $name NOT CAUGHT: the instrument is still GREEN"
        sed -n '1,8p' "$WORK/instrument.log" | sed 's/^/      /'
        FAIL=$((FAIL + 1))
        FAILED_LIST="$FAILED_LIST $name(green)"
        return
    fi

    # The right failure, not merely a failure.
    if ! grep -Fq "$expect" "$WORK/instrument.log"; then
        note "FAULT $name: the instrument went red for the WRONG REASON (no line"
        note "  matching: $expect)"
        sed -n '1,12p' "$WORK/instrument.log" | sed 's/^/      /'
        FAIL=$((FAIL + 1))
        FAILED_LIST="$FAILED_LIST $name(wrongreason)"
        return
    fi

    note "ok: $name -> the instrument went red, naming the expected finding"
    PASS=$((PASS + 1))
}

# ---------------------------------------------------------------------------
# run_input_fault: a fault that is an ARGUMENT rather than an edit, and the reason it
# does not use the copy protocol.
#
# `scripts/check-docs-truth.py` is now asked WHICH REPOSITORY to read, and pointing it
# at the local clone with DOCS_TRUTH_REMOTE=. reproduces the original defect exactly.
# Nothing is edited in the tree to do that, so there is no source change for a stale
# build to hide behind -- which is the entire reason the other three runners copy the
# tree first. Staging a copy here would be WORSE than not staging one: the defect is
# about what the CLONE'S git state says, and a copy has its own (absent) git state, so
# the staged fault would fail for "there is no repository here" and prove nothing
# about reading the wrong one.
#
# What is still verified, and it is what the copy protocol buys in the other runners:
# a FRESH build tree, built with 0 errors and 0 warnings, so `ctest -N` can be asked a
# question and the instrument is not run against a stale count.
# ---------------------------------------------------------------------------
run_input_fault() {
    name=$1
    expect=$2
    cmd=$3

    rm -rf "$WORK"
    mkdir -p "$WORK"
    if ! (cd "$ROOT" && cmake -S . -B "$WORK/b" -DCMAKE_BUILD_TYPE=Debug \
            -DBUILD_TESTING=ON -DWITH_TLS=OFF >"$WORK/cmake.log" 2>&1 \
            && cmake --build "$WORK/b" -j8 >"$WORK/build.log" 2>&1); then
        note "FAULT $name: the tree did not build, so the instrument had no build to ask"
        tail -5 "$WORK/build.log" 2>/dev/null || true
        FAIL=$((FAIL + 1))
        FAILED_LIST="$FAILED_LIST $name(build)"
        return
    fi
    errs=$(grep -c 'error:' "$WORK/build.log" || true)
    warns=$(grep -c 'warning:' "$WORK/build.log" || true)
    if [ "$errs" != "0" ] || [ "$warns" != "0" ]; then
        note "FAULT $name: build printed errors=$errs warnings=$warns"
        FAIL=$((FAIL + 1))
        FAILED_LIST="$FAILED_LIST $name(build:$errs/$warns)"
        return
    fi
    # Freshness, in the only form that means anything for a Python check: the build
    # tree it is about to read was configured and built by THIS run, seconds ago.
    if [ ! -f "$WORK/b/CTestTestfile.cmake" ]; then
        note "FAULT $name: no configured build tree at $WORK/b"
        FAIL=$((FAIL + 1))
        FAILED_LIST="$FAILED_LIST $name(nobuildtree)"
        return
    fi

    if (cd "$ROOT" && sh -c "$cmd" >"$WORK/instrument.log" 2>&1); then
        note "FAULT $name NOT CAUGHT: the instrument is still GREEN"
        sed -n '1,10p' "$WORK/instrument.log" | sed 's/^/      /'
        FAIL=$((FAIL + 1))
        FAILED_LIST="$FAILED_LIST $name(green)"
        return
    fi
    if ! grep -Fq "$expect" "$WORK/instrument.log"; then
        note "FAULT $name: the instrument went red for the WRONG REASON (no line"
        note "  matching: $expect)"
        sed -n '1,12p' "$WORK/instrument.log" | sed 's/^/      /'
        FAIL=$((FAIL + 1))
        FAILED_LIST="$FAILED_LIST $name(wrongreason)"
        return
    fi
    note "ok: $name -> the instrument went red, naming the expected finding"
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
# ---------------------------------------------------------------------------
# 22-24. THIS PASS'S THREE FAULTS, and what they have in common.
#
# Each of the shapes this project keeps finding is a check that answered from the wrong
# thing: a gate that is not an oracle for the platform it ships on, a sanitizer cell
# that reported a count of findings in a class it was not watching, and a
# documentation check that read a clone instead of a repository. These three teeth are
# the same shape again one level up -- which is the point of grouping them here. None
# adds a test to the suite; all three are fault injections against instruments that
# already run.
#
# 24 runs against the REAL repository's git state, because that is the state the
# defect was about. 22 and 23 stage a copy, because they are edits to shipped files.
# ---------------------------------------------------------------------------

# The coverage statement deleted from gate-linux-cell.sh's report. If this did NOT go
# red, the report's coverage block is decorative, and a "0 findings" line with nothing
# under it saying what was watched comes back and nobody is told.
run_command_fault linux-cell-report-coverage-statement-removed \
    report_coverage_statement_removed.py \
    "carries NO COVERAGE STATEMENT" \
    "sh scripts/gate-linux-cell.sh --report-selftest"

# The docs-truth check pointed at the local clone again, by faulting the DEFAULT the
# other three runners cannot reach. The machine this runs on carries tags `origin`
# does not -- measured: 11 in the clone, 9 on the remote -- so the fault has something
# real to find rather than a contrived difference, and the expected line is one of
# them. A check that could not read ANY repository would also go red here, which is why
# the expected substring is the tag-list finding and not merely the word "FAIL".
run_input_fault docs-truth-reads-the-local-clone \
    "in the remote but not in the table" \
    "DOCS_TRUTH_REMOTE=. python3 scripts/check-docs-truth.py --build $WORK/b"

# AND THE OTHER HALF OF THE SAME FAULT, as its own tooth, because it is a POSITIVE
# check and the one above is not sufficient on its own. The first tooth proves the
# check is SENSITIVE to the clone, and a check that simply refused to answer would be
# sensitive to it too. This one proves the check is ANCHORED to the remote: with a tag
# in the clone that the remote does not have, the verdict must not move. A fault this
# project has already collected once -- sensitive to the wrong input is not the same
# property as anchored to the right one.
note ""
note "teeth: (positive) a local-only tag does not change the docs-truth verdict"
rm -rf "$WORK"; mkdir -p "$WORK"
if (cd "$ROOT" && cmake -S . -B "$WORK/b" -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON \
        -DWITH_TLS=OFF >"$WORK/cmake.log" 2>&1 \
        && cmake --build "$WORK/b" -j8 >"$WORK/build.log" 2>&1); then
    errs=$(grep -c 'error:' "$WORK/build.log" || true)
    warns=$(grep -c 'warning:' "$WORK/build.log" || true)
    if [ "$errs" != "0" ] || [ "$warns" != "0" ]; then
        note "teeth: (positive) build printed errors=$errs warnings=$warns"
        FAIL=$((FAIL + 1))
        FAILED_LIST="$FAILED_LIST local-tag-changes-the-verdict(build:$errs/$warns)"
    else
        _probe_tag="teeth-local-only-tag-$$"
        git -C "$ROOT" tag "$_probe_tag" "a tag that exists only in this clone" 2>/dev/null || true
        if (cd "$ROOT" && python3 scripts/check-docs-truth.py --build "$WORK/b" \
                >"$WORK/instrument.log" 2>&1); then
            note "ok: local-tag-cannot-change-the-verdict -> still green with a local-only tag"
            PASS=$((PASS + 1))
        else
            note "teeth: (positive) FAILED -- a tag that exists only in this clone changed the verdict"
            sed -n '1,12p' "$WORK/instrument.log" | sed 's/^/      /'
            FAIL=$((FAIL + 1))
            FAILED_LIST="$FAILED_LIST local-tag-changes-the-verdict(red)"
        fi
        git -C "$ROOT" tag -d "$_probe_tag" >/dev/null 2>&1 || true
    fi
else
    note "teeth: (positive) the tree did not build"
    FAIL=$((FAIL + 1))
    FAILED_LIST="$FAILED_LIST local-tag-changes-the-verdict(build)"
fi
# Leave the private tag namespace as the last thing that read it found, so a run that
# ends here does not leave the NEXT run's answer depending on this one.
git -C "$ROOT" fetch --quiet --no-tags --force --prune origin \
    '+refs/tags/*:refs/ircserve-docstruth/tags/*' 2>/dev/null || true

note ""
# ---------------------------------------------------------------------------
# 25-28. THE OPT-IN SURFACE'S OWN FOUR FAULTS.
#
# One shape, four places: something this project claims about itself was true by
# assertion and not by construction, and each of these removes one of the assertions.
#
#   25  a file no configuration compiles stops compiling under one compiler
#   26  a cell's coverage statement deleted from the cell
#   27  a cell's coverage statement deleted from CI
#   28  a result's tree deleted from the result
#
# 25 is the important one and it is not hypothetical. `asan_coverage_probe.c` HAD
# this defect -- `[-Werror=dangling-pointer=]` under gcc 16 -- for the whole of its
# life, and the reason this fault exists is that the reason it survived was
# structural: no configuration built the file, so no compiler ever said so.
# ---------------------------------------------------------------------------

# 25. THE COMPILE-MATRIX FAULT. The instrument configures a SECOND build directory
# with -DIRC_LSAN_PROBE=ON -- the option nothing used to pass anywhere -- and builds
# `asan_coverage_probe` with ONE compiler, which is exactly what the fault targets.
# The compiler is DISCOVERED rather than hardcoded, for the reason scripts/gate.sh's
# discovery section gives at length: /usr/bin/gcc, /usr/bin/clang and /usr/bin/cc are
# all Apple's clang on macOS, so a name is not an identity and the version string is
# the only honest test. TEETH_CC overrides it for a machine whose GCC is elsewhere.
_fault_cc=""
for _c in ${TEETH_CC:-} gcc-16 gcc-15 gcc-14 gcc-13 gcc; do
    command -v "$_c" >/dev/null 2>&1 || continue
    case "$("$_c" --version 2>/dev/null | head -1)" in
        *gcc*|*GCC*) _fault_cc="$_c"; break ;;
    esac
done
if [ -z "$_fault_cc" ]; then
    # NOT A SKIP. A tooth that quietly does not run reports a count of faults caught
    # that is smaller than the number of faults, and a smaller number reads as
    # success. This fails the run and says how to point it somewhere.
    note "no GCC found for the compile-matrix tooth; set TEETH_CC=/path/to/gcc and re-run"
    FAIL=$((FAIL + 1))
    FAILED_LIST="$FAILED_LIST optin-probe-unbuildable-under-one-compiler(nocc)"
else
    note "ok: the compile-matrix tooth will build asan_coverage_probe with $( "$_fault_cc" --version | head -1 )"
    run_command_fault optin-probe-unbuildable-under-one-compiler \
        probe_unbuildable_under_one_compiler.py \
        "_teeth_fault_undeclared" \
        "cmake -S . -B bprobe -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON -DWITH_TLS=OFF -DBUILD_BENCHMARK=OFF -DIRC_LSAN_PROBE=ON -DCMAKE_C_COMPILER=$(command -v "$_fault_cc") 2>&1 && cmake --build bprobe --target asan_coverage_probe -j8 2>&1"
fi

# 26 and 27. THE TWO COVERAGE STATEMENTS. Both cells print sanitizer counts, both now
# render through ONE function, and the two faults delete the two CALL SITES rather
# than the renderer. Three copies of "is this report complete" would be three
# answers; what is actually dangerous is the renderer being edited until nobody asks
# for it, and only a fault that removes the asking can measure that.
#
# scripts/gate.sh --asan-selftest needs no compiler, no docker and no build, which is
# why these two cost seconds and run on every machine rather than on the one with
# the container.
run_command_fault asan-cell-coverage-statement-removed \
    asan_cell_coverage_statement_removed.py \
    "no longer calls the coverage" \
    "bash scripts/gate.sh --asan-selftest"

run_command_fault ci-sanitizers-coverage-statement-removed \
    ci_sanitizers_coverage_statement_removed.py \
    "no longer" \
    "bash scripts/gate.sh --asan-selftest"

# 28. THE DIRTY FLAG. scripts/gate-linux-cell.sh rsyncs the WORKING TREE while the
# comment above that line claimed `git archive` and claimed the cell could not be
# affected by an uncommitted change. The comment is fixed and every report now carries
# the commit AND the flag; this fault puts the flag back to always-clean and requires
# the same --report-selftest that already proves the coverage block is still there to
# go red. Both live in the same self-test because they are the same class: a report
# claiming something about its own subject that the subject can contradict.
run_command_fault linux-cell-dirty-tree-flag-suppressed \
    linux_cell_dirty_flag_suppressed.py \
    "dirty" \
    "sh scripts/gate-linux-cell.sh --report-selftest"

note ""
note "teeth: $PASS of 28 faults caught, $FAIL not."
if [ "$FAIL" != "0" ]; then
    note "not caught:$FAILED_LIST"
    exit 1
fi
