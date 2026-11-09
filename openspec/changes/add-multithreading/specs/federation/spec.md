# Federation (delta: multithreading)

## ADDED Requirements

### Requirement: Loop-thread affinity for link and burst state

Federation control state SHALL be touched only by the loop thread.

#### Scenario: Forward from dispatch
- **WHEN** dispatch on the loop thread resolves forward targets
- **THEN** it queues to links directly (as today); writers never see
  `server_link_t`, burst shadows, dedup tables, or nickreg.

#### Scenario: Tick affinity
- **WHEN** `fed_tick`, burst install, or resume sweep runs
- **THEN** it runs on the loop thread with no federation lock held by writers.
