/* Observable regression contracts only; no plumbing assertions. */
#include <assert.h>

#include "regress_contracts.h"

void assert_contract_exact_result(int expected, int observed) {
    assert(expected == observed);
}
