#!/usr/bin/env bash
# Registers N self-hosted GitHub Actions runners for irc-serve, running
# permanently and in parallel.
#
# TWO THINGS THIS FIXES, both of which the previous version got wrong.
#
# 1. It installed a USER systemd unit (~/.config/systemd/user, `systemctl
#    --user`, WantedBy=default.target). User units only start when that user has
#    an active login session, so the runner went offline at every reboot and
#    whenever the last session ended. That is why the runner was offline. This
#    version installs a SYSTEM unit with WantedBy=multi-user.target, so it starts
#    at boot with no login.
#
# 2. It registered ONE runner. A runner process handles exactly one job at a
#    time, so a 4-way build matrix was forced to run serially on the self-hosted
#    machine -- slower in wall clock than the parallel hosted matrix it replaced.
#    This version registers N runners, each in its own directory under a
#    templated systemd unit, so N jobs run concurrently again.
#
# SECURITY. This machine executes untrusted build steps. The job is gated in
# ci.yml by push-to-main only, plus the `self-hosted` environment whose sole
# required reviewer is the owner. The owner's own pushes bypass that review by
# design. Do not add this label to a pull_request-triggered job.
#
# Usage:
#   GH_RUNNER_TOKEN=<token> sudo -E ./scripts/setup-self-hosted-runner.sh
#
# Run it with sudo so it can install the system unit. The runner itself still
# runs as the invoking user, NOT root.
#
# To change the instance count later, edit INSTANCES in /etc/default/irc-serve-runner
# and re-run, or just enable more instances:
#   sudo systemctl enable --now actions-runner@5
set -euo pipefail

REPO="${GITHUB_REPOSITORY:-TheFirstIstari/irc-serve}"
RUNNER_NAME="${RUNNER_NAME:-cachyos-x8664}"
INSTALL_ROOT="${INSTALL_ROOT:-$HOME/.actions-runners}"
INSTANCES="${INSTANCES:-4}"
RUNNER_USER="${SUDO_USER:-$(id -un)}"
RUNNER_HOME="$HOME"
VER="${RUNNER_VERSION:-2.337.0}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

say()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
die()  { printf '\033[31merror: %s\033[0m\n' "$*" >&2; exit 1; }

if [ "$(id -u)" -ne 0 ]; then
  die "needs sudo to install the SYSTEM unit (user units stop at logout). Re-run: sudo -E $0"
fi

say "Preflight"
[ "$(uname -s)" = "Linux" ] || die "expected Linux, got $(uname -s)"
for t in curl tar cmake; do
  command -v "$t" >/dev/null || die "$t is required"
done
if ! command -v gcc >/dev/null || ! command -v clang >/dev/null; then
  say "installing build dependencies"
  pacman -S --needed --noconfirm base-devel cmake gcc clang || die "dependency install failed"
fi
printf '  host   : %s\n' "$(uname -srm)"
printf '  distro : %s\n' "$(. /etc/os-release && echo "$PRETTY_NAME")"
printf '  cpus   : %s\n' "$(nproc)"
printf '  user   : %s (the runner does NOT run as root)\n' "$RUNNER_USER"

say "Stopping the old user-scope runner"
# The previous install's unit. Remove it, or it will fight the system unit.
if sudo -u "$RUNNER_USER" systemctl --user is-active actions-runner.service 2>/dev/null; then
  sudo -u "$RUNNER_USER" systemctl --user disable --now actions-runner.service || true
  say "  stopped"
fi

say "Fetching the runner tarball (v$VER)"
# The archive unpacks run.sh, config.sh, bin/, externals/ into the target
# directory itself -- there is no wrapper folder. So extract into a staging
# directory that becomes the instance directory, rather than into $TMP and
# copying the whole thing including the tarball.
mkdir -p "$INSTALL_ROOT"
STAGE=$(mktemp -d "$INSTALL_ROOT/.stage.XXXXXX")
trap 'rm -rf "$STAGE"' EXIT
curl -fsSL "https://github.com/actions/runner/releases/download/v${VER}/actions-runner-linux-x64-${VER}.tar.gz" -o "$STAGE/runner.tgz"
tar -xzf "$STAGE/runner.tgz" -C "$STAGE"
[ -x "$STAGE/run.sh" ] || die "unexpected archive layout: $STAGE/run.sh not found"

[ -n "${GH_RUNNER_TOKEN:-}" ] || die "GH_RUNNER_TOKEN is not set. Create one at https://github.com/$REPO/settings/actions/runners/new"

URL="https://github.com/$REPO"
LABELS="self-hosted,Linux,X64,${RUNNER_NAME}"

for i in $(seq 1 "$INSTANCES"); do
  NAME="${RUNNER_NAME}-${i}"
  DIR="$INSTALL_ROOT/$NAME"
  say "Instance $i/$INSTANCES  ->  $NAME"
  rm -rf "$DIR"
  mkdir -p "$DIR"
  ( cd "$STAGE" && tar -cf - --exclude=runner.tgz . ) | tar -xf - -C "$DIR"
  [ -x "$DIR/run.sh" ] || die "$DIR/run.sh missing after copy"
  chown -R "$RUNNER_USER":"$RUNNER_USER" "$DIR"

  sudo -u "$RUNNER_USER" "$DIR/config.sh" \
    --unattended \
    --url "$URL" \
    --token "$GH_RUNNER_TOKEN" \
    --name "$NAME" \
    --labels "$LABELS" \
    --work "$DIR/_work" \
    --replace \
    --no-default-labels >/dev/null || die "config.sh failed for $NAME"

  "$DIR/bin/installdependencies.sh" >/dev/null 2>&1 || true
  echo "  registered"
done

say "Installing the SYSTEM systemd template"
SERVICE=/etc/systemd/system/actions-runner@.service
sed -e "s|__RUNNER_USER__|$RUNNER_USER|g" \
    -e "s|__INSTALL_ROOT__|$INSTALL_ROOT|g" \
    -e "s|__RUNNER_NAME__|$RUNNER_NAME|g" \
    "$SCRIPT_DIR/actions-runner@.service" > "$SERVICE"
chmod 644 "$SERVICE"

cat > /etc/default/irc-serve-runner <<DEF
# Instance count for actions-runner@.service. Raise for more parallelism.
INSTANCES=$INSTANCES
DEF

systemctl daemon-reload

say "Enabling $INSTANCES instances at boot"
for i in $(seq 1 "$INSTANCES"); do
  systemctl enable --now "actions-runner@$i.service" >/dev/null
  echo "  actions-runner@$i enabled"
done

say "Status"
sleep 6
for i in $(seq 1 "$INSTANCES"); do
  printf '  @%s: %s\n' "$i" "$(systemctl is-active "actions-runner@$i.service")"
done

say "Verifying GitHub sees them"
sleep 8
gh api "$REPO/actions/runners" --jq \
  '.runners[] | select(.name | startswith("'"$RUNNER_NAME"'")) | "  \(.name)  \(.status)  labels=\(.labels | map(.name) | join(","))"' \
  2>/dev/null || echo "  (could not query; check Settings -> Actions -> Runners)"

cat <<EOF

Done. $INSTANCES runners, permanent, concurrent.

  * System units, so they start at boot with no login. This is the fix for the
    offline problem: the previous user-scope unit stopped at logout.
  * $INSTANCES concurrent jobs, so the build matrix parallelises again instead of
    serialising behind one runner.
  * Each instance is independent: sudo systemctl restart actions-runner@3
    affects one runner, not all of them.

Check them with:
  systemctl list-units 'actions-runner@*'
  journalctl -u actions-runner@1 -f

To add more parallelism later:
  sudo systemctl enable --now actions-runner@5

SECURITY: these execute untrusted build steps on this machine. Keep the job
push-to-main only, and keep the \`self-hosted\` environment gate. See
docs/DEVELOPMENT.md.
EOF
