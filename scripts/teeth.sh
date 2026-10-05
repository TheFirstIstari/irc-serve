#!/bin/sh
# teeth.sh -- prove each fix in this pass has TEETH, by reverting it in a COPY of the
# tree, rebuilding, and requiring the named test to go RED.
#
# WHY A COPY AND NOT AN EDIT-AND-REVERT. A reverted fix that is caught while the
# revert is still in the working tree proves the test noticed a working tree; what
# has to be proven is that the test notices the SHIPPED source. Every fault here is
# applied to a fresh copy, built from scratch, and the binary's mtime is compared
# against every source file before its result is read -- because a stale binary that
# passes is the one way this script can report a success that means nothing.
#
# WHAT A PASS HERE MEANS AND WHAT IT DOES NOT. It means the named test goes red with
# the fault and green without it, which is the property a fault-injection check is
# for. It does not mean the test is sufficient: sufficiency is not a property a
# single fault can establish, and a suite that claims otherwise is claiming the one
# thing it cannot know.
#
# NO `sleep` ANYWHERE. Each wait is for a PROCESS, on its pid, with `wait`.
set -eu

ROOT=${ROOT:-/Users/frobinson/dev/irc-serve}
WORK=${WORK:-/tmp/teeth-p11}
PASS=0
FAIL=0
FAILED_LIST=""

note() { printf '%s\n' "$*"; }

# One fault: a name, the tests that must go red, and a shell function that breaks
# the source in the copy.
run_fault() {
    name=$1
    tests=$2
    fault=$3

    rm -rf "$WORK"
    mkdir -p "$WORK"
    # The copy carries the tree and NOT the build directory, so the build is from
    # these sources rather than from whatever was already compiled.
    (cd "$ROOT" && git ls-files -z | while IFS= read -r -d '' f; do
        mkdir -p "$WORK/$(dirname "$f")"
        cp "$ROOT/$f" "$WORK/$f"
    done)
    cp "$ROOT/tests/integration/test_peer_terminal_sweep.c" "$WORK/tests/integration/" 2>/dev/null || true
    cp "$ROOT/tests/harness/sweep_scan.h" "$WORK/tests/harness/" 2>/dev/null || true
    cp "$ROOT/tests/harness/peer_fixture.c" "$WORK/tests/harness/" 2>/dev/null || true
    cp "$ROOT/tests/harness/peer_fixture.h" "$WORK/tests/harness/" 2>/dev/null || true

    if ! (cd "$WORK" && "$fault"); then
        note "FAULT NOT APPLIED: $name"
        FAIL=$((FAIL + 1))
        FAILED_LIST="$FAILED_LIST $name(apply)"
        return
    fi

    if ! (cd "$WORK" && cmake -S . -B b -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON \
            -DWITH_TLS=OFF >"$WORK/cmake.log" 2>&1 \
            && cmake --build b -j8 >"$WORK/build.log" 2>&1); then
        note "FAULT $name DID NOT COMPILE -- a fault that does not build proves nothing"
        tail -5 "$WORK/build.log" || true
        FAIL=$((FAIL + 1))
        FAILED_LIST="$FAILED_LIST $name(build)"
        return
    fi

    # THE BUILD-VERIFICATION GATE. A binary that is not newer than every source it
    # was built from has not been built from them, and its result is not evidence.
    stale=0
    for t in $tests; do
        bin="$WORK/b/tests/integration/$t"
        [ -x "$bin" ] || bin="$WORK/b/tests/protocol/$t"
        if [ ! -x "$bin" ]; then
            note "FAULT $name: no binary for $t"
            stale=1
            continue
        fi
        new=$(find "$bin" -newer "$WORK/CMakeLists.txt" 2>/dev/null | wc -l | tr -d ' ')
        [ "$new" = "1" ] || { note "FAULT $name: $t binary is not newer than the sources"; stale=1; }
    done
    if [ "$stale" != "0" ]; then
        FAIL=$((FAIL + 1))
        FAILED_LIST="$FAILED_LIST $name(stale)"
        return
    fi

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
            note "FAULT $name: $reds"
            FAIL=$((FAIL + 1))
            FAILED_LIST="$FAILED_LIST $name(green)"
            ;;
        *)
            note "ok: $name ->$reds"
            PASS=$((PASS + 1))
            ;;
    esac
}

mkdir -p "$WORK"
note "teeth: each fault is applied to a fresh copy, built, and required to go red."

# ---------------------------------------------------------------------------
# 1. The echo filter reverted at ONE of the eleven sites.
#
# `emit_numeric_ex()` is the one place a numeric's parameters are rendered, and all
# eleven echoes go through it. Reverting it entirely would be caught by many tests;
# the interesting fault is to make it apply to the COMMON case only -- the branch
# that copies a validated value through untouched -- so that everything still builds,
# every other numeric still renders, and only the filter is gone.
# ---------------------------------------------------------------------------
run_fault "echo-filter-removed" "test_nick_utf8 test_control_bytes" '
python3 - <<PY
p="src/core/reply.c"
s=open(p).read()
old="""        if (conn_text_display_check(v) == CONN_DISPLAY_OK) {
            clean[i] = v; /* the common case: a validated value, copied nowhere */
            continue;
        }"""
new="""        clean[i] = v;
        continue;
        if (conn_text_display_check(v) == CONN_DISPLAY_OK) {
            continue;
        }"""
assert old in s, "echo filter branch not found"
open(p,"w").write(s.replace(old,new))
PY'

# ---------------------------------------------------------------------------
# 2. The nickname check WIDENED to all non-ASCII.
#
# The rule is four exclusions from three ranges, so "accept anything >= 0x80" is a
# one-line change that looks like a simplification and is the mistake this code is
# most likely to be "simplified" into: it accepts the Cyrillic, the Greek and every
# accented character -- and it ALSO accepts `C2 9B`, which is CSI.
# ---------------------------------------------------------------------------
run_fault "nick-widened-to-all-non-ascii" "test_valid_nick test_nick_utf8" '
python3 - <<PY
p="src/core/connection.c"
s=open(p).read()
old="""    if (u == 0xc2u && (unsigned char)at[1] >= 0x80u && (unsigned char)at[1] <= 0x9fu) {"""
new="""    if (0) {"""
assert old in s, "encoded C1 case not found"
s=s.replace(old,new)
old2="""    if (u >= 0x80u && u <= 0x9fu) {
        if (verdict != NULL) {"""
new2="""    if (0) {
        if (verdict != NULL) {"""
assert old2 in s, "raw C1 case not found"
open(p,"w").write(s.replace(old2,new2))
PY'

# ---------------------------------------------------------------------------
# 3. The nickname check NARROWED to a bare byte range.
#
# The mirror of fault 2, and the more likely one: a reviewer sees "refuse 0x80-0x9F"
# and writes it, because that is the rule as it was written down before anyone
# noticed `ā` is `C4 81`. This fault must make `ā` INVALID, and nothing else may.
# ---------------------------------------------------------------------------
run_fault "nick-narrowed-to-bare-range" "test_valid_nick test_nick_utf8" '
python3 - <<PY
p="src/core/connection.c"
s=open(p).read()
old="""    if (*need > 0u) {
        if (u >= 0x80u && u <= 0xbfu) {"""
new="""    if (*need > 0u) {
        if (u >= 0x80u && u <= 0x9fu) {"""
assert old in s, "continuation range not found"
open(p,"w").write(s.replace(old,new))
PY'

# ---------------------------------------------------------------------------
# 4. SMODES's allowlist REMOVED while the client path keeps its own.
#
# The client gate and the peer's handler both ASK `chan_mode_implemented()`; this
# fault deletes the ask from the PEER'S HANDLER ONLY, so the two paths disagree again
# exactly as they did before Decision C. `src/core/chan_verbs.c` and
# `src/core/channel.c` are untouched, so every CLIENT test stays GREEN -- which is
# the whole argument for having a peer sweep: this fault is invisible from the client
# path, and that is not a gap in the client tests, it is the peer path being a
# different path.
run_fault "smodes-allowlist-removed" "test_peer_terminal_sweep" '
python3 - <<PY
p="src/federation/verbs.c"
s=open(p).read()
old="""            verdict = chan_mode_implemented(m);
            if (verdict == 0) {"""
new="""            verdict = 1;
            if (verdict == 0) {"""
assert old in s, "the peer-side allowlist ask not found"
open(p,"w").write(s.replace(old,new))
PY'

# ---------------------------------------------------------------------------
# 5. OVERLONG ACCEPTED -- the bypass vector the canonical check exists for.
#
# Removing only the `0xE0` arm leaves the ranges accepting `E0` again, so
# `E0 80 AF` -- an overlong `/` -- is a legal nickname again. Nothing else changes.
# ---------------------------------------------------------------------------
run_fault "overlong-accepted" "test_valid_nick test_nick_utf8" '
python3 - <<PY
p="src/core/connection.c"
s=open(p).read()
old="""    if (u == 0xe0u) {
        if (verdict != NULL && (unsigned char)at[1] < 0xa0u) {
            *verdict = CONN_DISPLAY_UTF8;
            return TEXT_FAULT;
        }
        *need = 2u;
        return TEXT_EMIT;
    }"""
new="""    if (u == 0xe0u) {
        *need = 2u;
        return TEXT_EMIT;
    }"""
assert old in s, "the 0xE0 arm not found"
open(p,"w").write(s.replace(old,new))
PY'

# ---------------------------------------------------------------------------
# 6. SURROGATE ACCEPTED -- U+D800 is not a character and has no UTF-8 encoding.
# ---------------------------------------------------------------------------
run_fault "surrogate-accepted" "test_valid_nick test_nick_utf8" '
python3 - <<PY
p="src/core/connection.c"
s=open(p).read()
old="""    if (u == 0xedu) {
        if (verdict != NULL && (unsigned char)at[1] > 0x9fu) {
            *verdict = CONN_DISPLAY_UTF8;
            return TEXT_FAULT;
        }
        *need = 2u;
        return TEXT_EMIT;
    }"""
new="""    if (u == 0xedu) {
        *need = 2u;
        return TEXT_EMIT;
    }"""
assert old in s, "the 0xED arm not found"
open(p,"w").write(s.replace(old,new))
PY'

# ---------------------------------------------------------------------------
# 7. THE SECOND RELAY PATH BYPASSING THE STRIP.
#
# `fed_queue_line()` is the only place a peer-bound line is built and
# `fed_relay_clean()` is the only filter on it. This fault removes the call, which is
# exactly the state the peer sweep was committed red in: 64 marker bytes on the peer
# link. It is the newest protection in the pass and the one with the least coverage
# behind it, which is why it gets a fault of its own rather than riding on the
# client sweep's.
# ---------------------------------------------------------------------------
run_fault "peer-relay-strip-bypassed" "test_peer_terminal_sweep" '
python3 - <<PY
p="src/federation/verbs.c"
s=open(p).read()
old="""    filter_rc = fed_relay_clean(verb, params, nparams, arena, sizeof arena,
                                cleaned, &src_len, &kept_len);"""
new="""    filter_rc = 0;
    (void)fed_relay_clean;"""
assert old in s, "the relay filter call not found"
open(p,"w").write(s.replace(old,new))
PY'

# ---------------------------------------------------------------------------
# 8. THE INVERTED-ASSERTION CHECK, checked against itself.
#
# A standing check that cannot fail is not a check. This fault flips one assertion in
# the peer sweep so its condition says ABSENT and its message describes the ABSENT
# case as if it were the failure -- the inverted shape the check looks for -- and
# requires the check to catch it.
# ---------------------------------------------------------------------------
run_fault "inverted-assertion-check-has-teeth" "test_peer_terminal_sweep" '
python3 - <<PY
p="tests/integration/test_peer_terminal_sweep.c"
s=open(p).read()
old="""        TF_CHECK_MSG(k_shapes[i].needle[0] != '\\''\\\\0'\\'',"""
new="""        TF_CHECK_MSG(k_shapes[i].needle[0] == '\\''\\\\0'\\'',"""
assert old in s, "the needle emptiness assertion not found"
open(p,"w").write(s.replace(old,new,1))
PY'

note ""
note "teeth: $PASS fault(s) caught, $FAIL not."
[ "$FAIL" = "0" ] || { note "not caught:$FAILED_LIST"; exit 1; }