/* test_hs_deadline.c -- T2's handshake deadline, asserted directly.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS IS A UNIT TEST AND NOT ANOTHER CASE IN test_fed_handshake.c
 * ---------------------------------------------------------------------------
 * The defect this file exists for could only ever be OBSERVED by winning a race,
 * and a defect that can only be observed by winning a race cannot be
 * regression-tested. The shape of it:
 *
 *   poll_loop_step() samples now_ms with server_now_ms(), and THEN calls
 *   server_tick(). So the value every deadline in a tick is measured against was
 *   read BEFORE any of the tick's work.
 *
 *   fed_link_promote() runs inside that tick -- the promotion is at the top of
 *   fed_tick()'s per-link walk and T2's switch arm is at the bottom of the same
 *   walk -- and it stamps link->created_ms from a FRESH server_now_ms() of its
 *   own.
 *
 * So on any tick that takes at least one millisecond between step 8's clock read
 * and the promotion, created_ms is numerically NEWER than the now_ms it is about
 * to be compared against. Both readings are in the right order in real time and
 * CLOCK_MONOTONIC cannot run backwards, so this is not a clock fault.
 *
 * `now_ms - link->created_ms` is UNSIGNED, so a stamp one millisecond in the
 * future reads as an age of 2^64-1, which is larger than every possible
 * timeout. T2 therefore declared the handshake timed out ON THE TICK THAT
 * CREATED IT: the connection was marked CLOSING with its FEDERATE still sitting
 * in the write queue, the peer saw a clean close having read nothing, and the
 * link sat in HANDSHAKE_SENT until a retry that never came. From a failing
 * tests/integration/test_fed_handshake.c run:
 *
 *   promote peer=irc.b fd=5 queue_rc=0 pending=80 now=4044447577
 *   T2       created=4044447577 now=4044447576 age=18446744073709551615 hs=1000
 *
 * Two consequences that are asserted here rather than argued:
 *
 *   - A tick that reaches the promotion inside the SAME millisecond produces an
 *     age of 0 and is correctly not due. That is why this reproduced at roughly
 *     one run in three UNDER LOAD and not at all on an idle machine, and why the
 *     integration suite could only ever have measured it as a flake.
 *   - Raising the timeout does not help. The age is 2^64-1; no budget is larger
 *     than that. Phase 8 raised the handshake budget 5000 -> 6000 -> 12000 and
 *     changed nothing, which is consistent with the cause not being the budget.
 *
 * ---------------------------------------------------------------------------
 * WHAT IS ACTUALLY ASSERTED
 * ---------------------------------------------------------------------------
 * fed_hs_due(created_ms, now_ms) -- the whole of T2's clock test -- and its
 * contract is one rule plus three ordinary cases:
 *
 *   created_ms == 0            NOT due. No attempt is stamped (fed_link_reset()
 *                              clears it), so there is nothing to be late for.
 *   now_ms < created_ms        NOT due. THE RULE, and the whole reason the
 *                              predicate is exported.
 *   now_ms == created_ms       NOT due, since the timeout has not elapsed.
 *   now_ms == created + hs-1   NOT due, one millisecond short.
 *   now_ms == created + hs     DUE, on the bound.
 *
 * The two boundary cases either side of the timeout are both here because
 * `>=` against a millisecond clock is exactly where an off-by-one hides, and
 * because "the last millisecond before the deadline" is the value an
 * off-by-one produces and the assertion above it is not.
 *
 * fed_set_timeouts() is called rather than the timeout being passed in, so this
 * asserts the value T2 actually compares against and not a copy of it. A 0
 * argument keeps the built-in, which is what the first case uses.
 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "federation/link.h"

/* The shipped default, named so the arithmetic below cannot drift from it. */
#define HS_MS 5000u

int main(void)
{
    /* The built-in, so "created == now" is checked against the value a deployed
     * node uses. IRC_FED_HS_TIMEOUT_MS is the same number; using the constant
     * rather than a literal is what keeps the two from being edited apart. */
    fed_set_timeouts(0, IRC_FED_HS_TIMEOUT_MS, 0, 0);
    assert(IRC_FED_HS_TIMEOUT_MS == HS_MS);

    /* --- the reset case: nothing stamped, nothing due ------------------ */
    assert(fed_hs_due(0, 0) == 0);
    assert(fed_hs_due(0, HS_MS) == 0);
    assert(fed_hs_due(0, UINT64_MAX) == 0);

    /* --- THE RULE: a stamp in the future is not due --------------------- */
    /* One millisecond is the measured case, and it is the smallest non-zero
     * gap, so it is the one that has to hold: this is the assertion the whole
     * file exists for, and against the unfixed code it fails here. */
    assert(fed_hs_due(1000, 999) == 0);

    /* Wider gaps for the same reason, including the one that makes the
     * subtraction wrap furthest. Every one of these is "created one tick
     * boundary newer than now", expressed at other scales. */
    assert(fed_hs_due(HS_MS, 0) == 0);
    assert(fed_hs_due(HS_MS, HS_MS - 1u) == 0);
    assert(fed_hs_due(1000000u, 1) == 0);
    assert(fed_hs_due(UINT64_MAX, 0) == 0);
    assert(fed_hs_due(UINT64_MAX, UINT64_MAX - 1u) == 0);

    /* --- the ordinary boundaries, which must not have been broken -------- */
    /* Same instant: no time has passed. */
    assert(fed_hs_due(1000, 1000) == 0);
    /* One millisecond short of the timeout. */
    assert(fed_hs_due(1000, 1000 + HS_MS - 1u) == 0);
    /* Exactly on the timeout: due. `>=`, not `>`. */
    assert(fed_hs_due(1000, 1000 + HS_MS) != 0);
    /* Well past it. */
    assert(fed_hs_due(1000, 1000 + HS_MS + 10000u) != 0);

    /* --- the override is the value compared, not a copy ----------------- */
    /* So this file would notice if the predicate ever stopped consulting the
     * global the tick sets, which is the one way a refactor could keep the
     * arithmetic right and the wiring wrong. */
    fed_set_timeouts(0, 100u, 0, 0);
    assert(fed_hs_due(1000, 1000 + 99u) == 0);
    assert(fed_hs_due(1000, 1000 + 100u) != 0);
    /* And the rule still holds under the override, which is the case a future
     * change to the ordering inside fed_hs_due() would break. */
    assert(fed_hs_due(1000, 999) == 0);

    printf("ok: hs_deadline\n");
    return 0;
}
