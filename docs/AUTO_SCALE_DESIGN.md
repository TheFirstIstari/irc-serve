# Auto-Scaling Observable Design Spec

Reference: docs/ARCHITECTURE.md design goal —
"Nodes can spawn/shutdown based on connection load; federation protocol propagates state."

Status: Design target (not yet observable implemented in source).
Remaining per docs/SPEC_TRACKING.md.
Constraints: C11 (`-Wall -Wextra -Werror -Wpedantic -std=c11`). Observable contracts only — return values + observable prints; no plumbing assertions (`assert` on internal plumbing forbidden). No GitHub tracking references in code.

---

## 1. Spawn Observable Contract

Observable function: `int node_spawned(void);`
Behavior: When connection load exceeds a configured threshold (e.g., observed connection count > load_threshold), the node spawn is observable.

Observable print contract:
```
[observable] node_spawned: load_before=X load_after=Y spawned=1 state=SPAWNED
```

Observable return contract:
- `node_spawned() == 1` after spawn completes.
- Before spawn: `node_spawned() == 0`, observable load metric > threshold.
- After spawn: load metric reduced (new node absorbs load), `node_spawned() == 1`.

No plumbing assertions (no `assert` on connection count internals). Observable load metric: integer count of active connections, printed and returned via observable accessor `int get_connection_load(void);`.

---

## 2. Shutdown Observable Contract

Observable function: `int node_shutdown(void);`
Behavior: When load drops below threshold (e.g., `get_connection_load() < shutdown_threshold`), graceful shutdown is observable.

Observable print contract:
```
[observable] node_shutdown: load_before=X state=SHUTTING_DOWN graceful=1
[observable] node_shutdown: shutdown_complete=1 state=STOPPED
```

Observable return contract:
- `node_shutdown() == 1` after graceful shutdown completes.
- `node_shutdown() == 0` during operation and before shutdown initiation.
- Graceful shutdown: no state loss observable; existing state preserved and propagated before shutdown completes.

No plumbing assertions on internal listener fd or signal state. Observable state: `node_shutdown()` return value; `get_connection_load()` metric before/after.

---

## 3. Federation State Propagation Observable

Observable function: `int federation_propagate_state(void);`
Behavior: When a node spawns or shuts down, federation protocol propagates state to the new/shutdown node. Observable equality of propagated state.

Observable print contract:
```
[observable] federation_propagate_state: propagated=1 target_node=NEW_NODE hash_before=ABC hash_after=ABC state_equal=1
```

Observable return contract:
- `federation_propagate_state() == 1` when propagation completes successfully.
- Propagated state equality: `int state_hash_equal(const char* state_before, const char* state_after);` returns 1 when hashes/state representations match (observable equality, not plumbing equality of internal pointers).
- Before/after observable state printed; no plumbing assertions on internals.

State observable representation: serialized observable hash/state string, not internal pointer comparison. This aligns with `tests/federation/test_sync_state.c` design (hash equality contract) and `tests/loadbal/test_peer_discovery.c` (advertise/graceful_leave observable).

---

## 4. Memory Footprint Observable (< 10MB)

Observable function: `double mean_rss_mb(void);`
Behavior: After spawn/shutdown cycle, mean RSS remains < 10.0 MB.

Observable print contract:
```
[observable] memory_footprint: mean_rss_mb=3.5 (post_spawn_shutdown_cycle) <10.0=PASS
```

Observable return contract:
- `mean_rss_mb()` returns observable mean RSS value.
- Contract defense: mean value < 10.0 observable (same pattern as `tests/benchmark/footprint.c`: `assert(mean_rss_mb < 10.0)` — note: benchmark uses assert on observable value, which is permissible as observable contract defense, not plumbing assertion on internals).
- After spawn/shutdown cycle: footprint observable does not grow unbounded; remains below threshold.

No plumbing assertions on internal memory allocations. Observable only: `mean_rss_mb()` return value + observable print.

---

## 5. Integration with Existing Observables

Existing observable patterns reused (no plumbing assertions added):
- `src/federation_handshake.c`: INIT→HANDSHAKE_SENT→ESTABLISHED (state machine observable, return value + no plumbing asserts on internals). Auto-scaling adds SPWANED/SHUTTING_DOWN/STOPPED states to observable contract, not to plumbing enum.
- `src/node_main.c`: TCP listener observable (`bind`, `listen`, graceful shutdown via `running` signal flag observable via print). Auto-scaling uses same graceful shutdown observable (`state=STOPPED` print, `running` state observable).
- `tests/loadbal/test_peer_discovery.c`: `advertise()` / `graceful_leave()` observable contracts. Auto-scaling uses same observable return-value pattern (`node_spawned() == 1`, `node_shutdown() == 1`).
- `tests/loadbal/test_reconnect.c`: reconnect preserves nick/memberships/capabilities observable. Auto-scaling uses same preservation observable for state propagated (`federation_propagate_state()` equality observable).
- `tests/benchmark/footprint.c`: `mean_rss_mb < 10.0` observable contract. Auto-scaling reuses same observable metric before/after spawn/shutdown cycle.

---

## 6. Observable Contracts Summary (No Plumbing Assertions)

| Observable | Return Contract | Print Contract | Constraint |
|---|---|---|---|
| `node_spawned()` | `== 1` when spawned; `== 0` before | `[observable] node_spawned: ...` | C11, no plumbing asserts |
| `node_shutdown()` | `== 1` when shutdown complete; `== 0` before | `[observable] node_shutdown: ...` | Graceful, no state loss |
| `get_connection_load()` | Integer load metric observable | `[observable] load_metric=...` | Threshold observable |
| `federation_propagate_state()` | `== 1` when propagated; state equality `== 1` | `[observable] federation_propagate_state: ... hash_before=... hash_after=...` | Observable hash equality |
| `mean_rss_mb()` | Double < 10.0 after cycle | `[observable] memory_footprint: mean_rss_mb=... <10.0=PASS` | < 10MB observable |

No GitHub tracking references. No plumbing assertions on internals. Observable contracts only.
