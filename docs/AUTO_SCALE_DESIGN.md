# Auto-Scaling — design spec, and the record of why it was not built as written

**Status: the contracts in this document are NOT the shipped feature, and never will
be as written.** Phase 9 (`#83`) implemented auto-scale within the boundary below.
This file is kept because it is the clearest statement of what was *proposed*, and a
reader who finds `AutoScale` in `tests/known_skips.txt`'s history deserves to see the
proposal that was declined rather than only the decision.

The original draft of this document specified five observable functions. **None of
them exists, and the reasons are structural rather than a matter of effort.**

---

## 1. What was proposed, and what happened to each contract

| Proposed | Shipped | Why |
|---|---|---|
| `int node_spawned(void)` — spawn when `get_connection_load() > threshold` | **never built** | Node lifecycle is a **supervisor's** job (systemd, an orchestrator, a replica controller), not a peer's. And the input does not exist: see §2 below. |
| `int node_shutdown(void)` — graceful stop when load drops | **not built as a contract**; the *graceful leave* half is built and observable | A node shutting **itself** down on a threshold is node lifecycle again. A node **announcing** that it is going away is a different thing, it is a protocol behaviour, and it is what `server_shutdown()` now does. |
| `int get_connection_load(void)` — an observable load metric | **replaced by `fed_set_load()`** | This node measures no load. See §2. |
| `int federation_propagate_state(void)` — hash-equal propagation to a new node | **never built** | Propagation to a node that does not exist yet is spawn again. What exists is propagation to a node that is **already a peer**. |
| `double mean_rss_mb(void)` after a spawn/shutdown cycle | **kept, in `tests/benchmark/footprint.c`** | The footprint bound is real and is tested; the *cycle* it was to be measured around is the part that was declined. |

---

## 2. The load argument, which is the whole decision

**`load_pct` is an operator's value, not a measurement.** `fed_set_load(s, pct)` sets
it; nothing measures it, because there is no measurement in this codebase to make.
The placeholder test's reason for existing said so directly — "honest CTest skip
rather than fabricated node lifecycle / 'RSS' claims" — and that was a statement about
a boundary, not about missing work.

The consequence is exact rather than a matter of taste: **a node that spawned or
stopped another node on a load signal would be deciding on a number it does not
believe**, and on a mesh the failure mode is a fork bomb. There is no threshold that
fixes this, because the problem is the *provenance* of the number and no threshold
changes where a percentage comes from.

So the honest load feature is **propagation**, and it propagates what a peer *says*
about itself rather than anything this node inferred:

- A peer publishes its figure in an `ADVERTISE`; this node records it and reports it.
- `fed_set_shed_pct(s, pct)` sets the level at or above which this node reports a
  peer as shedding. **The default is 0 = no opinion**, because the level at which a
  peer's load matters is a deployment's judgement and a shipped constant would be
  inventing a figure this codebase cannot justify.
- The report is one line per **crossing**, not per tick:
  ```
  [observable] fed_shed: peer=<name> load=42% threshold=30% action=REPORT_ONLY rebalance=NO reason=NO_MOVE_MECHANISM
  ```
  The `action=` and `reason=` tokens are load-bearing rather than documentation:
  "and then what?" is the question every reader of a mesh-load feature asks, and the
  answer being "nothing, and here is why" belongs **on the wire**.

## 3. Why propagation stops at reporting, specifically

Two structural reasons, not caution:

- **§2.2 of `docs/SERVER_DESIGN.md` makes a channel's origin immutable** and fails
  closed when it dies. Re-homing a channel to a quieter node *is* origin re-election,
  which §9's risk table records as not to be begun without re-opening §2.4's dedup
  key. There is no "move the channel" call to make.
- **A client's session belongs to the node its socket is connected to.** §4.3 has no
  session-transfer verb and no client-visible redirect, so "send the load elsewhere"
  has no mechanism on either end.

A third reason is about scope rather than structure, and is recorded here because the
first two are the ones that will stop a future attempt: **there is no supervisor in
this repository**, so there is nothing that *could* act on a report even if the node
were willing to.

## 4. What was built instead — the graceful leave

The half of this document that turned out to be a node's business:

- `server_shutdown()` calls `fed_send_shutdown()` **before** it closes anything, so a
  `SIGTERM`'d node puts `SHUTDOWN` on the wire on its way out. Until Phase 9 that
  function had **no caller anywhere in `src/`** — so no node ever announced anything,
  and every peer discovered a departure by timeout and spent a retry budget on it.
- A peer that receives one marks the link **cleanly departed**, purges that origin's
  roster, relays a `SQUIT` onward to a node two hops away, and **arms no retry**.
- Two defects in `core/poll_loop.c` had to be fixed for that goodbye to survive its own
  journey, and both are documented at the site: a node that wrote its last line and
  closed in the same breath had that line **discarded** (the end-of-stream arm returned
  without framing what it had already read — and "send the line, then go" *is* the
  graceful leave), and a departing node had to **drain** each peer socket before
  closing, because a `close()` with unread data in the receive queue makes the kernel
  send `RST` rather than `FIN`, and an `RST` discards the goodbye in flight.

## 5. Where the acceptance lives

`tests/integration/test_autoscale.c`, over real nodes and real sockets, asserting
observable wire lines only. No payload in it is written by the test except the third
case's, which exists precisely to reach the framing defect that the (correctly robust)
shipped departure path hides. The CTest name is `AutoScale` and it is **not a skip**:
`tests/known_skips.txt` is empty and `scripts/check-skips.sh` enforces that.

See `docs/SERVER_DESIGN.md` §2.3 and §7/Phase 9 for the same decision stated where a
reader of the design will find it before they find this file.
