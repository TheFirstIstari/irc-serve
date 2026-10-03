#!/bin/sh
# No AI attribution in this repository's history.
#
# WHY THIS EXISTS RATHER THAN A COMMIT-MESSAGE TEMPLATE. Attribution has been
# stripped from `main` twice by rewriting history, and it came back both times --
# a subagent's own commit message reintroduced it after the rewrite. A rewrite is
# the wrong tool for a rule that has to hold on every future commit, because it is
# expensive, it invalidates every SHA, and it only says anything about the past.
#
# So the rule is enforced forward instead: this runs in CI over the commit range
# being pushed, and refuses the push. What is checked:
#
#   1. no `Co-Authored-By` / `Signed-off-by` / `Reviewed-by` trailer naming an AI
#   2. no "Generated with <AI>" footer
#   3. no AI identity in the AUTHOR or COMMITTER fields
#
# Copilot is deliberately NOT matched: its attributions are the operator's own
# commits made in GitHub's editor and are left alone by request.
#
# The range is every commit reachable from HEAD but not from the merge base with
# the base branch, so an ordinary PR is checked for what it ADDS. On the default
# branch it falls back to the last 200 commits, which is a bounded sweep rather
# than the whole history on every push.
set -eu

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$REPO_ROOT"

BASE="${1:-}"
REF="${2:-HEAD}"
# Copilot is DELIBERATELY ABSENT from this list. Its trailers are the operator's
# own commits authored in GitHub's editor, and they are wanted: the point of this
# gate is that an assistant working in THIS repository does not put its own name
# on the operator's commits. Matching Copilot here would flag 16 of the
# repository's own historical commits on the first run and be switched off.
PATTERN='claude|anthropic|gpt-[0-9]|chatgpt|codeium|qwen|deepseek[ -]?coder|gemini|llama'

if [ -z "$BASE" ]; then
    # No base given: sweep a bounded window of recent history. The window is
    # CLAMPED to the history that exists -- an unclamped `HEAD~200..HEAD` on a
    # young repository resolves to an invalid range, `git rev-list --count`
    # prints 0, and a gate that scans nothing passes everything. That is the
    # false-pass this project has been bitten by repeatedly, in a place where it
    # would have been invisible.
    # `~0..HEAD` is empty, so a young repository needs the whole history spelled
    # as a single ref rather than a range.
    TOTAL=$(git rev-list --count HEAD 2>/dev/null || echo 0)
    WINDOW=200
    if [ "$TOTAL" -le "$WINDOW" ]; then
        RANGE="HEAD"
    else
        RANGE="HEAD~$WINDOW..HEAD"
    fi
else
    MB=$(git merge-base "$BASE" "$REF" 2>/dev/null || echo "")
    if [ -z "$MB" ]; then
        RANGE="$REF"
    else
        RANGE="$MB..$REF"
    fi
fi

COUNT=$(git rev-list --count "$RANGE" 2>/dev/null || echo 0)
echo "check-attribution: scanning $COUNT commit(s) in $RANGE" >&2

STATUS=0

# 1 and 2: trailers and footers in the message body.
# --format=%B gives the raw message; the message is scanned as one blob so a
# trailer cannot hide by being split across a continuation line.
HITS=$(git log --format='%H' "$RANGE" 2>/dev/null | while read -r sha; do
    if git log -1 --format='%B' "$sha" 2>/dev/null \
        | grep -qiE "(co-authored-by|signed-off-by|reviewed-by|acked-by)[[:space:]]*:.*($PATTERN)|generated with.*($PATTERN)"; then
        printf '  %s  %s\n' "$(printf '%s' "$sha" | cut -c1-9)" \
            "$(git log -1 --format='%s' "$sha" | cut -c1-60)"
    fi
done)

if [ -n "$HITS" ]; then
    echo "check-attribution: FAIL: these commits carry an AI attribution trailer:" >&2
    printf '%s\n' "$HITS" >&2
    STATUS=1
fi

# 3: author or committer identity.
IDHITS=$(git log --format='%an|%ae|%cn|%ce' "$RANGE" 2>/dev/null | sort -u | \
    grep -iE "($PATTERN)" || true)
if [ -n "$IDHITS" ]; then
    echo "check-attribution: FAIL: an AI identity is in an author or committer field:" >&2
    printf '  %s\n' "$IDHITS" >&2
    STATUS=1
fi

if [ "$STATUS" -eq 0 ]; then
    echo "check-attribution: OK: no AI attribution in $RANGE" >&2
fi
exit "$STATUS"
