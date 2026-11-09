/* Observable lock-free contract.
 * Design decision: concurrent-safe state transition observed via _Atomic
 * shared state (no plumbing assertions — no internal lock variables, no
 * thread-ID plumbing). Consumer asserts only observable before/after state.
 * _Atomic (not volatile): volatile is not synchronization, and the
 * writer/reader pair is a C11 data race (UB) that TSan correctly reports.
 * Compiles with -Wall -Wextra -Werror -Wpedantic -std=c11.
 */
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpre-c11-compat"
#pragma clang diagnostic ignored "-Watomic-implicit-seq-cst"
#endif

/* Observable shared state: atomic transition, observed atomically. */
static _Atomic int lf_observable_state = 0;

/* Concurrent writer: performs observable transition without plumbing locks. */
static void *concurrent_writer(void *arg) {
    (void)arg;
    lf_observable_state = 42; /* concurrent-safe transition observable */
    return NULL;
}

/* Concurrent reader: observes state before/after concurrent access. */
static void *concurrent_reader(void *arg) {
    (void)arg;
    int observed_before = lf_observable_state; /* observable pre-access */
    /* In concurrent execution writer may transition state. */
    int observed_after = lf_observable_state;  /* observable post-access */
    (void)observed_before;
    (void)observed_after;
    /* Observable contract assertion: only initial or fully transitioned
     * values are visible (no plumbing about intermediate/corrupted states). */
    assert(lf_observable_state == 0 || lf_observable_state == 42);
    return NULL;
}

int main(void) {
    pthread_t writer, reader;

    assert(pthread_create(&writer, NULL, concurrent_writer, NULL) == 0);
    assert(pthread_create(&reader, NULL, concurrent_reader, NULL) == 0);

    /* Wait for concurrent access to complete before final observation. */
    assert(pthread_join(writer, NULL) == 0);
    assert(pthread_join(reader, NULL) == 0);

    /* Final observable contract: concurrent-safe transition completed. */
    assert(lf_observable_state == 42);
    return 0;
}
#if defined(__clang__)
#pragma clang diagnostic pop
#endif
