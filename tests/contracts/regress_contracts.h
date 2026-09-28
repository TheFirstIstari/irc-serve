#ifndef TEST_REGRESS_CONTRACTS_H
#define TEST_REGRESS_CONTRACTS_H

/* Observable regression-contract helpers.
 *
 * assert_contract_exact_result(expected, observed) asserts that `observed`
 * equals `expected` exactly. The helpers here are deliberately plumbing-free:
 * they assert and nothing else -- no logging, no state, no return value. */

/* Assert `expected == observed`. */
void assert_contract_exact_result(int expected, int observed);

#endif /* TEST_REGRESS_CONTRACTS_H */
