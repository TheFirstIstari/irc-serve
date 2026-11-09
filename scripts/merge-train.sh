#!/usr/bin/env bash
# merge-train.sh -- land a stack of PRs through a strict branch protection.
#
#   ./scripts/merge-train.sh 157 158 159
#   ./scripts/merge-train.sh --timeout-min 120 157 158 159
#
# `main` requires branches to be up to date and 7 checks green, so merging one
# PR flips the rest to BEHIND and each needs a full CI rerun. Doing that by
# hand is an afternoon. This loops it: bring every branch up to date, then
# merge each PR the moment its checks go green, until none are open.
#
# It never bypasses protection (no --admin): a PR merges only when GitHub
# reports it CLEAN. On timeout it exits 1 listing what is left.
#
# Needs: gh (authenticated), git. Run from the repo root.
set -euo pipefail

TIMEOUT_MIN=180
PRS=""

usage() {
    echo "usage: $0 [--timeout-min N] PR [PR...]" >&2
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --timeout-min)
            TIMEOUT_MIN="$2"; shift 2 ;;
        --timeout-min=*)
            TIMEOUT_MIN="${1#--timeout-min=}"; shift ;;
        -h|--help)
            usage ;;
        -*)
            usage ;;
        *)
            PRS="$PRS $1"; shift ;;
    esac
done

[ -z "$PRS" ] && usage

# All branches up to date first, so their CI runs in parallel instead of one
# wave per merge.
# shellcheck disable=SC2086
for p in $PRS; do
    state=$(gh pr view "$p" --json state --jq '.state')
    [ "$state" = "OPEN" ] || { echo "PR $p is $state; skipping"; continue; }
    branch=$(gh pr view "$p" --json headRefName --jq '.headRefName')
    base=$(gh pr view "$p" --json baseRefName --jq '.baseRefName')
    [ "$base" = "main" ] || { echo "PR $p targets $base, not main; skipping" >&2; continue; }
    git fetch -q origin "$branch" 2>/dev/null || true
    if git merge-base --is-ancestor "origin/$branch" origin/main 2>/dev/null; then
        echo "PR $p ($branch): already contains main"
        continue
    fi
    echo "PR $p ($branch): merging main in"
    git checkout -q "$branch"
    if ! git merge -q origin/main -m "Merge main" 2>/dev/null; then
        echo "PR $p ($branch): CONFLICT with main, left for a person" >&2
        git merge --abort 2>/dev/null || true
    else
        git push -q origin "$branch" 2>&1 | tail -1
    fi
done

deadline=$(( $(date +%s) + TIMEOUT_MIN * 60 ))
# shellcheck disable=SC2086
while [ -n "$PRS" ]; do
    remaining=""
    states=$(gh pr list --state open --json number,mergeStateStatus \
        --jq 'map("\(.number):\(.mergeStateStatus)") | join(" ")')
    for p in $PRS; do
        case " $states " in
            *" $p:MERGED "*|*" $p:CLOSED "*) continue ;; # gone; gh lags
        esac
        state=$(gh pr view "$p" --json state,mergeStateStatus \
            --jq '"\(.state)/\(.mergeStateStatus)"')
        case "$state" in
            MERGED/*|CLOSED/*) continue ;;
            OPEN/CLEAN)
                echo "merging $p"
                gh pr merge "$p" --merge 2>&1 | tail -1 ;;
            *) remaining="$remaining $p" ;;
        esac
    done
    PRS="$remaining"
    [ -z "$PRS" ] && { echo "train landed"; exit 0; }
    [ "$(date +%s)" -ge "$deadline" ] && {
        echo "timeout; still open:$PRS" >&2; exit 1; }
    sleep 180
done
