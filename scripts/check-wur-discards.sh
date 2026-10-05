#!/usr/bin/env bash
# check-wur-discards.sh — fail on `(void)fn(...)` where glibc marks fn __wur.
#
# WHY THIS EXISTS, IN ONE PARAGRAPH
# glibc declares some libc functions with __attribute__((warn_unused_result)).
# GCC honours that attribute only when the result is GENUINELY used, so the
# idiomatic-looking discard
#
#     (void)read(fd, buf, sizeof buf);
#
# is not a discard at all — it is -Werror=unused-result on every GCC build
# against glibc. This happened: one such line in tests/integration/test_tls.c
# turned ci_test, ci_benchmark, ci_compliance and both ci_sanitizers cells red
# (see db6362f, and the run at 30c2aac's PR). It is invisible to every macOS
# cell, because the macOS SDK does not declare read() with that attribute at
# all, and invisible to Clang even against real glibc headers, because Clang
# exempts an explicit (void) cast from warn_unused_result.
#
# WHAT THIS IS NOT
# This is NOT a substitute for the Linux gcc build, and the comment below the
# list says so at the point of use. That build compiles against real glibc
# declarations and is authoritative for the whole class; this is a HOST-
# INDEPENDENT tripwire for the short list below, so that the defect is caught on
# a machine that has no glibc at all rather than only on one that does. It sees
# one specific pattern. It cannot see a warn_unused_result function outside the
# list, and it cannot see any warning the declaration produces by other means.
#
# WHY THE LIST IS SHORT AND WHY IT IS WRITTEN DOWN HERE
# It was derived by parsing every __wur-marked declaration out of a glibc
# header tree (508 headers, 272 declarations carrying __wur, 186 distinct
# names) and intersecting that with the 96 distinct functions this tree
# actually discards -- 1161 live `(void)fn(` sites at the time of writing. The
# intersection is what a discard here could plausibly hit, and it is empty
# today, which is the correct state: the one real site was fixed in db6362f.
#
# fwrite IS DELIBERATELY ABSENT. It is the obvious candidate and it is NOT
# marked: glibc declares it
#
#     extern size_t fwrite (const void *__restrict __ptr, size_t __size,
#                           size_t __n, FILE *__restrict __s) __nonnull((4));
#
# with __nonnull and no __wur. read(), write(), pipe(), fread(), getline() and
# getdelim() all carry it. Listing fwrite would have meant the gate claimed to
# enforce something the headers do not say.
#
# NOTHING IS MARKED IN THIS PROJECT'S OWN HEADERS: src/ and tests/ contain no
# warn_unused_result of their own, verified by grep. So the list needs no
# project-local additions today; if one is ever added, it belongs on this list.
#
# HOW A VIOLATION IS FIXED: cast the VARIABLE, not the call.
#     ssize_t drained = read(fds[0], sink, sizeof sink);
#     (void)drained;
# No pragma and no -Wno-unused-result; both would also silence a genuinely
# dropped write(), and this project does not narrow its warning set.

set -euo pipefail

# ---------------------------------------------------------------------------
# Locate the repository without depending on the caller's working directory.
# CI runs this from the workspace root and local-ci.sh runs it from the root,
# but a gate that only works when invoked one particular way is a gate that
# gets skipped.
# ---------------------------------------------------------------------------
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
root=$(cd -- "$here/.." && pwd)

# ---------------------------------------------------------------------------
# The list. glibc __wur declarations this project could reach.
# ---------------------------------------------------------------------------
WUR_FUNCS='read|write|pipe|fread|getline|getdelim'

stripper="$here/strip-c-comments.awk"
if [[ ! -f "$stripper" ]]; then
    echo "check-wur-discards: missing $stripper" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Collect sources. `src` and `tests` are named explicitly rather than found
# with `find .` because a find from the root would walk every build directory
# under it and match generated copies of the same source.
#
# This script needs NO build directory, so it runs before any build exists --
# which is the point: it must not require a configured tree to have been built.
# ---------------------------------------------------------------------------
sources=()
for d in src tests; do
    while IFS= read -r f; do
        [[ -n "$f" ]] && sources+=("$f")
    done < <(find "$root/$d" -type f \( -name '*.c' -o -name '*.h' \) 2>/dev/null | sort)
done

if [[ ${#sources[@]} -eq 0 ]]; then
    # Nothing to check is a broken checkout, not a pass. A gate that reports
    # success because it found no files is worse than no gate.
    echo "check-wur-discards: no sources found under $root/src or $root/tests" >&2
    exit 1
fi

pattern="\(void\)[[:space:]]*(${WUR_FUNCS})[[:space:]]*\("

violations=0
sites=0
for f in "${sources[@]}"; do
    # Comments and string literals are blanked first, by the stateful stripper.
    # This tree's own header comment in tests/integration/test_tls.c QUOTES
    # `(void)read(...)` inside a block comment, so a grep without this step
    # matches the documentation of the defect it is looking for. Comments were
    # the only difference between 1162 naive matches and 1161 real ones.
    while IFS=: read -r lineno text; do
        [[ -z "$lineno" ]] && continue
        violations=$((violations + 1))
        printf '%s:%s:%s\n' "${f#"$root"/}" "$lineno" "$text" >&2
    done < <(awk -f "$stripper" "$f" | grep -nE "$pattern" || true)
    n=$(awk -f "$stripper" "$f" | grep -cE '\(void\)[[:space:]]*[A-Za-z_][A-Za-z0-9_]*[[:space:]]*\(' || true)
    sites=$((sites + n))
done

if [[ "$violations" -gt 0 ]]; then
    cat >&2 <<EOF

check-wur-discards: FAILED -- $violations (void) discard(s) of a glibc __wur function.

Each of these is -Werror=unused-result under GCC against glibc. The
declaration carries warn_unused_result, and GCC does not treat an explicit
(void) cast as a use.

Fix by casting the VARIABLE, not the call:

    ssize_t drained = read(fd, buf, sizeof buf);
    (void)drained;

Not with a pragma and not with -Wno-unused-result: both would also silence a
genuinely dropped write(), and this project does not narrow its warning set.

glibc __wur functions checked: $WUR_FUNCS
(live (void)fn( call sites scanned across the tree: $sites)
EOF
    exit 1
fi

echo "check-wur-discards: OK -- no (void) discard of a glibc __wur function ($sites live (void) call sites scanned)"
exit 0