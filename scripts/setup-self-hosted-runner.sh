#!/usr/bin/env bash
# Registers this machine as a self-hosted GitHub Actions runner for irc-serve.
#
# READ THIS BEFORE RUNNING IT.
#
# This repository is PUBLIC. Anyone who can open a pull request can get their
# code executed on this machine if a self-hosted runner is attached to jobs that
# accept pull_request events. There are documented cases of cryptominers being
# installed this way. Mitigations applied by the accompanying ci.yml change:
#
#   * the runner is a LABEL target, so only the `build_cachyos` job uses it
#   * that job does NOT run on pull_request -- it runs on push to main only,
#     so a hostile PR cannot reach this machine
#   * the registration token is not stored; supply it via the environment
#
# If you later add the label to a job that runs on pull_request, you have
# reintroduced the exposure.
#
# Usage:
#   GH_RUNNER_TOKEN=<token> ./scripts/setup-self-hosted-runner.sh
#
# The token comes from:
#   https://github.com/TheFirstIstari/irc-serve/settings/actions/runners/new
# (or `gh api repos/TheFirstIstari/irc-serve/actions/runners/registration-token`)
set -euo pipefail

REPO="${GITHUB_REPOSITORY:-TheFirstIstari/irc-serve}"
LABEL="${RUNNER_LABEL:-cachyos-x8664}"
RUNNER_NAME="${RUNNER_NAME:-cachyos-x8664}"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.actions-runner}"
RUNNER_USER="${RUNNER_USER:-$(id -un)}"

say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
die() { printf '\033[31merror: %s\033[0m\n' "$*" >&2; exit 1; }

say "Preflight"
[ "$(uname -s)" = "Linux" ] || die "expected Linux, got $(uname -s)"
command -v curl >/dev/null || die "curl is required"
command -v cmake >/dev/null || {
  say "installing build dependencies (CachyOS)"
  sudo pacman -S --needed --noconfirm cmake ninja gcc clang git
}
for t in cmake git gcc clang; do
  command -v "$t" >/dev/null || die "$t is missing after dependency install"
done
printf '  cmake %s\n' "$(cmake --version | head -1 | awk '{print $3}')"
printf '  gcc   %s\n' "$(gcc --version | head -1 | awk '{print $NF}')"
printf '  clang %s\n' "$(clang --version | head -1)"

say "Fetching the runner"
mkdir -p "$INSTALL_DIR"
VER=2.328.0
URL="https://github.com/actions/runner/releases/download/v${VER}/actions-runner-linux-x64-${VER}.tar.gz"
tarball="$(mktemp)"
curl -fsSL "$URL" -o "$tarball"
tar -xzf "$tarball" -C "$INSTALL_DIR"
rm -f "$tarball"
"$INSTALL_DIR/bin/installdependencies.sh" 2>/dev/null || \
  sudo "$INSTALL_DIR/bin/installdependencies.sh" || \
  say "installdependencies.sh could not run (needs sudo); continuing"

say "Registering with ${REPO}"
if "$INSTALL_DIR/config.sh" list | grep -q .; then
  say "a runner is already configured here; removing it first"
  TOKEN_TO_REMOVE="$("$INSTALL_DIR/config.sh" list --json 2>/dev/null | head -1 || true)"
  say "remove it by hand if needed: $INSTALL_DIR/config.sh remove"
fi

[ -n "${GH_RUNNER_TOKEN:-}" ] || \
  die "GH_RUNNER_TOKEN is not set. Create one at https://github.com/$REPO/settings/actions/runners/new"

"$INSTALL_DIR/config.sh" \
  --unattended \
  --url "https://github.com/$REPO" \
  --token "$GH_RUNNER_TOKEN" \
  --name "$RUNNER_NAME" \
  --labels "$LABEL" \
  --work "$INSTALL_DIR/_work" \
  --replace \
  --no-default-labels

say "Installing as a systemd service (user scope, starts on login)"
mkdir -p "$HOME/.config/systemd/user"
sed -e "s|__RUNNER_DIR__|$INSTALL_DIR|g" \
    -e "s|__RUNNER_USER__|$RUNNER_USER|g" \
    "$(dirname "$0")/actions-runner.service" > "$HOME/.config/systemd/user/actions-runner.service"

systemctl --user daemon-reload
systemctl --user enable --now actions-runner.service
sleep 3
systemctl --user --no-pager --lines=5 status actions-runner.service || true

say "Verifying the label actually took effect"
# This check is not ceremonial. `config.sh --labels` has been observed to leave
# only the default labels on the runner, and because the default set
# (self-hosted, Linux, X64) looks like a normal successful registration, the
# failure is invisible until a job targeting the custom label sits queued
# forever.
RID=$(gh api "repos/$REPO/actions/runners" --jq '.runners[] | select(.name=="'"$RUNNER_NAME"'") | .id')
if [ -z "$RID" ]; then
  say "could not find runner '$RUNNER_NAME' (is gh authenticated?)"
  say "verify on the Settings -> Actions -> Runners page"
else
  LABELS=$(gh api "repos/$REPO/actions/runners/$RID" --jq '.labels[].name' | tr '\n' ' ')
  printf '  runner has labels: %s\n' "$LABELS"

  if printf '%s\n' "$LABELS" | tr ' ' '\n' | grep -qx "$LABEL"; then
    printf '  ok: %s is present\n' "$LABEL"
  else
    say "'$LABEL' is MISSING -- a job targeting it would queue forever."
    say "applying it through the API instead"
    # Send ONLY the custom label. The defaults (self-hosted, Linux, X64) are
    # read-only and GitHub rejects the request with HTTP 422 if included.
    gh api -X PUT "repos/$REPO/actions/runners/$RID/labels" -F "labels[]=$LABEL" >/dev/null
    printf '  labels now: %s\n' \
      "$(gh api "repos/$REPO/actions/runners/$RID" --jq '.labels[].name' | tr '\n' ' ')"
  fi
fi

cat <<EOF

Done. The runner is online with label '$LABEL'.

Next steps:
  1. The accompanying ci.yml adds a build_cachyos job that targets this label.
     Push to main and watch it run; check with
       gh run list --workflow ci.yml
  2. Confirm the exposure is what you intended. The job runs on push to main
     only, so a pull request from anyone -- including a fork -- cannot execute
     code here. If you ever add this label to a pull_request-triggered job, that
     protection is gone.
  3. The runner executes untrusted build steps as $RUNNER_USER with your
     passwordless sudo. That is inherent to self-hosted runners.
EOF
