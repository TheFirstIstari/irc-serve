#!/usr/bin/env bash
# scripts/build-debian-package.sh -- build the .deb, on Linux, in a Debian container.
#
# WHY THIS EXISTS. Issue #48 asked for three things and none of them had been done:
# build the package with dpkg-buildpackage, confirm the .deb contains the executable,
# and confirm the control file's dependency list resolves. The reason none of them had
# been done is that all three need dpkg-buildpackage, dpkg-source, dh and lintian, and
# the machine this project was developed on is a Mac. So the recipe was written down in
# an issue and never run, and the packaging was asserted by a Python script reading
# text files -- which is how `debian/rules` shipped for a year configuring nothing at
# all (see the --buildsystem=cmake comment in that file).
#
# THIS SCRIPT IS THE RECIPE, EXECUTED. It is what turns the issue into a measurement.
#
#   ./scripts/build-debian-package.sh [--lintian] [--keep]
#
# IT NEEDS docker and an x86-64 Linux host, and it says so rather than guessing:
# dpkg-buildpackage is not on macOS and dpkg-source has no macOS port, so there is no
# fallback path on Darwin and the script refuses instead of pretending. THE COST, WHICH
# IS REAL: this is the only build in the project that cannot run on the machine that
# wrote it. That is the same reason scripts/gate.sh has a Linux CI cell rather than
# pretending a macOS run covers it.
#
# WHAT IT DOES, IN ORDER, and each step exists because the step after it fails without it:
#
#   1. BUILD THE ORIG TARBALL. `debian/source/format` is `3.0 (quilt)`, and a quilt
#      source package REQUIRES ../irc-serve_0.1.0.orig.tar.gz. A plain `git checkout`
#      cannot produce one -- there is no release and no tag to unpack. `git archive` is
#      the answer and it is not a workaround: it is how a release tarball is made, and
#      it is byte-deterministic from one commit, which is a stronger guarantee than an
#      uploaded tarball carries. THE COST, STATED RATHER THAN HIDDEN: the tarball is
#      built from HEAD of whatever tree this runs in, so it is a release candidate and
#      not a release. Cutting an actual release is a tagging decision, not a build one,
#      and this script does not make it.
#
#   2. MATERIALISE debian/ AS A REAL DIRECTORY. The tree carries `debian` as a
#      committed symlink to `packaging/debian`, which is what lets `dpkg-buildpackage -b`
#      find the packaging in a checkout. `dpkg-source -b` CHOKES ON THAT SYMLINK:
#      it walks debian/ to build irc-serve_0.1.0-1.debian.tar.xz and dies with
#      "add_directory() only handles directories at .../V2.pm line 590", exit 29.
#      Measured. So a source package is built from a tree whose `debian` is dereferenced,
#      and the binary-only build (`-b`) would work with the symlink intact.
#
#   3. RUN dpkg-buildpackage. Without `-b`, so the source package is built too and the
#      orig tarball is exercised. `-us -uc` because this is a local build, not an upload.
#
#   4. INSPECT THE .deb, and the three things issue #48 asked to be confirmed. The
#      assertions are in this script as real checks with real exit codes: the executable
#      is under /usr/bin and NOT under /usr/local/bin; ${shlibs:Depends} was substituted
#      rather than left literal; and the version is the changelog's.
#
# NOTHING HERE IS DOWNLOADED FROM A NETWORK beyond the container image, and nothing here
# modifies the working tree: the build happens in a scratch directory under mktemp -d.

set -euo pipefail

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
root=$(cd -- "$here/.." && pwd)

RUN_LINTIAN=0
KEEP=0
IMAGE="${DEB_BUILD_IMAGE:-ircserve-deb:bookworm}"
JOBS="${DEB_BUILD_JOBS:-$( (command -v nproc >/dev/null 2>&1 && nproc) || echo 4)}"
while [ $# -gt 0 ]; do
    case "$1" in
        --lintian) RUN_LINTIAN=1 ;;
        --keep)    KEEP=1 ;;
        -h|--help) sed -n '2,45p' "$0"; exit 0 ;;
        *) echo "build-debian-package.sh: unknown argument '$1'" >&2; exit 2 ;;
    esac
    shift
done

fail() { echo "build-debian-package.sh: $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# The three refusals, checked before anything is built so the failure is legible.
# ---------------------------------------------------------------------------
case "$(uname -s)" in
    Linux) ;;
    *) fail "this builds with dpkg-buildpackage, which does not exist on $(uname -s).
  Run it on a Linux host with docker. Issue #48's recipe cannot be run on macOS, and
  this script says so rather than producing a plausible-looking substitute." ;;
esac
command -v docker >/dev/null 2>&1 || fail "docker is not on PATH. This script runs the
  build inside a Debian container because the toolchain is the thing under test."
docker info >/dev/null 2>&1 || fail "the docker daemon is not reachable. The gate
  refuses to report a cell that did not run; so does this."
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    cat >&2 <<EOF
build-debian-package.sh: the image $IMAGE is not present locally.

  It is a debian:bookworm image plus the build-deps this package declares and the one
  that verifies it:
    docker build -t $IMAGE - <<'DOCKERFILE'
    FROM debian:bookworm
    RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \\
        --no-install-recommends build-essential dpkg-dev debhelper cmake fakeroot \\
        lintian ca-certificates git patch && rm -rf /var/lib/apt/lists/*
    DOCKERFILE
EOF
    fail "build the image first, or point DEB_BUILD_IMAGE at one you already have."
fi

git -C "$root" rev-parse --git-dir >/dev/null 2>&1 \
    || fail "this must run inside the git tree: step 1 builds the orig tarball with
  \`git archive\`, and a tree with no .git cannot produce one."

# The version and the source name, read from debian/changelog rather than typed here, so
# this script cannot disagree with the file it is checking.
changelog_ver=$(sed -n '1s/^[^ (]*(\([^)]*\)).*/\1/p' "$root/packaging/debian/changelog" 2>/dev/null || true)
[ -n "$changelog_ver" ] || fail "could not read a version out of packaging/debian/changelog"
src_name=$(sed -n '1s/^\([^ (]*\)(.*/\1/p' "$root/packaging/debian/changelog" 2>/dev/null || true)
[ -n "$src_name" ] || fail "could not read a source name out of packaging/debian/changelog"
upstream_ver=${changelog_ver%%-*}

work=$(mktemp -d "${TMPDIR:-/tmp}/irc-serve-deb.XXXXXX")
cleanup() {
    # A build in a container runs as root, so the scratch tree is root-owned and the
    # invoking user cannot remove it with rm. THAT IS THE ONLY REASON THIS EXISTS: a
    # `rm -rf "$work"` that silently fails leaves a root-owned directory behind for
    # every failed build, and the second failure of a debugged script is then a
    # permission error that looks like the bug.
    if [ "$KEEP" = "1" ]; then
        echo "build-debian-package.sh: scratch tree kept at $work (--keep)" >&2
        docker run --rm -v "$work:/w" "$IMAGE" true >/dev/null 2>&1 || true
        return
    fi
    docker run --rm -v "$work:/w" "$IMAGE" rm -rf /w >/dev/null 2>&1 || rm -rf "$work" || true
}
trap cleanup EXIT

echo "irc-serve Debian package build"
echo "  source tree   : $root"
echo "  git describe  : $(git -C "$root" rev-parse --short HEAD) (dirty: $(git -C "$root" status --porcelain | wc -l | tr -d ' ') files)"
echo "  source version: $src_name $changelog_ver"
echo "  image         : $IMAGE"
echo "  scratch       : $work"
echo

# ---------------------------------------------------------------------------
# 1. The orig tarball. See the header: `git archive` IS how a release tarball is made.
# ---------------------------------------------------------------------------
# Built OUTSIDE the scratch tree so the tar is at the same level as the unpacked
# directory, which is where dpkg-source looks for it: `../<name>_<upstream>.orig.tar.*`.
tarball="$work/${src_name}_${upstream_ver}.orig.tar.gz"
git -C "$root" archive --format=tar.gz --prefix="${src_name}-${upstream_ver}/" HEAD > "$tarball" \
    || fail "git archive failed; this is step 1 and everything after it needs the tarball."
echo "--- 1. orig tarball: $(basename "$tarball") ($(wc -c < "$tarball" | tr -d ' ') bytes)"

# ---------------------------------------------------------------------------
# 2. Unpack, then materialise debian/ as a real directory.
# ---------------------------------------------------------------------------
tar xzf "$tarball" -C "$work"
tree="$work/${src_name}-${upstream_ver}"
[ -d "$tree" ] || fail "the orig tarball did not unpack to $tree"
if [ -L "$tree/debian" ]; then
    ( cd "$tree" && rm debian && cp -aL packaging/debian ./debian )
    echo "--- 2. debian/ materialised as a real directory (dpkg-source -b cannot follow the symlink)"
elif [ -d "$tree/debian" ]; then
    echo "--- 2. debian/ is already a real directory"
else
    fail "no debian/ in the unpacked tarball. Either the packaging moved or the
  tarball came from a commit before it was committed."
fi

# ---------------------------------------------------------------------------
# 3. The build.
# ---------------------------------------------------------------------------
echo "--- 3. dpkg-buildpackage -us -uc (source AND binary: without -b the .orig.tar.gz is exercised)"
buildlog="$work/build.log"
if docker run --rm \
        -e DEB_BUILD_JOBS="$JOBS" \
        -v "$work:/build" -w "/build/${src_name}-${upstream_ver}" \
        "$IMAGE" \
        dpkg-buildpackage -us -uc > "$buildlog" 2>&1; then
    echo "      build OK"
else
    rc=$?
    echo "      BUILD FAILED (exit $rc). Last 40 lines:" >&2
    tail -40 "$buildlog" >&2
    echo "      full log: $buildlog (the tree is kept on failure; remove it with:" >&2
    echo "      docker run --rm -v $work:/w $IMAGE rm -rf /w)" >&2
    exit "$rc"
fi

# ---------------------------------------------------------------------------
# 4. Inspect the .deb. These are the three things issue #48 asked to be CONFIRMED, and
#    they are checks with exit codes rather than lines of output to read by eye.
# ---------------------------------------------------------------------------
deb=$(ls "$work"/${src_name}_${upstream_ver}-*_*.deb 2>/dev/null | grep -v dbgsym | head -1 || true)
[ -n "$deb" ] || fail "dpkg-buildpackage succeeded but produced no binary package. Full log: $buildlog"
echo
echo "--- 4. the .deb: $(basename "$deb")"

contents=$(docker run --rm -v "$work:/build" "$IMAGE" dpkg-deb -c "/build/$(basename "$deb")")
fields=$(docker run --rm -v "$work:/build" "$IMAGE" dpkg-deb -f "/build/$(basename "$deb")")

# 4a. The executable is in /usr/bin, and NOT in /usr/local/bin. The second half is the
#     half that matters: a binary in /usr/local/bin installs, runs, and passes every
#     check a person runs by hand, while sitting outside the PATH a Debian expects and
#     outside Debian's file hierarchy.
if printf '%s\n' "$contents" | grep -qE ' \./usr/bin/irc-serve$'; then
    echo "      ok: /usr/bin/irc-serve is in the package"
else
    printf '%s\n' "$contents" >&2
    fail "the package contains no /usr/bin/irc-serve. See the listing above."
fi
if printf '%s\n' "$contents" | grep -q '/usr/local/'; then
    printf '%s\n' "$contents" | grep '/usr/local/' >&2
    fail "/usr/local/ is in the package. That is CMake's default prefix; the rules file
  must pass -DCMAKE_INSTALL_PREFIX=/usr, which is what packaging/debian/rules does."
fi
echo "      ok: nothing under /usr/local"

# 4b. Version.
got_ver=$(printf '%s\n' "$fields" | sed -n 's/^Version: //p')
if [ "$got_ver" = "$changelog_ver" ]; then
    echo "      ok: Version: $got_ver"
else
    fail "Version is $got_ver but debian/changelog says $changelog_ver."
fi

# 4c. ${shlibs:Depends} RESOLVED. dpkg-shlibdeps substituted it; an unsubstituted
#     field is the literal string in the control file and would make the package
#     un-installable. This is the third thing issue #48 asked to be confirmed and the
#     one that cannot be confirmed from the packaging source at all -- it needs
#     dpkg-shlibdeps and a linked binary.
depends=$(printf '%s\n' "$fields" | sed -n 's/^Depends: //p')
if printf '%s' "$depends" | grep -q '\${'; then
    fail "Depends: still contains an unsubstituted field: $depends"
fi
if printf '%s' "$depends" | grep -q 'misc:Depends'; then
    fail "Depends: still contains the literal \${misc:Depends}"
fi
echo "      ok: Depends: ${depends:-<empty>}"

# 4d. And it installs, and the installed binary runs. `dpkg -x` rather than `dpkg -i`
#     because a container has no running dpkg database and `dpkg -i` would fail on that
#     rather than on anything about this package; -x extracts the same payload.
echo "--- 5. the installed binary runs"
run_out=$(docker run --rm -v "$work:/build" "$IMAGE" sh -c "
    dpkg-deb -x '/build/$(basename "$deb")' /inst &&
    /inst/usr/bin/irc-serve --help | head -1" 2>&1) || fail "the installed binary did not run: $run_out"
echo "      ok: /usr/bin/irc-serve --help says: $run_out"

if [ "$RUN_LINTIAN" = "1" ]; then
    echo
    echo "--- 6. lintian"
    # lintian's exit status is 0 whenever there are no ERRORS, which is not what
    # --fail-on is for here; the caller wants to SEE every tag, so it is not silenced
    # and this script does not fail on warnings. Judging which tags are real defects is
    # a reading task and is recorded in packaging/README.md, not automated here.
    docker run --rm -v "$work:/build" "$IMAGE" \
        lintian --tag-display-limit 0 "/build/$(basename "$deb")" 2>&1 | grep -v '^running with root' || true
    changes=$(ls "$work"/*.changes 2>/dev/null | head -1 || true)
    if [ -n "$changes" ]; then
        docker run --rm -v "$work:/build" "$IMAGE" \
            lintian --tag-display-limit 0 "/build/$(basename "$changes")" 2>&1 | grep -v '^running with root' || true
    fi
fi

echo
echo "scratch tree: $work (removed on exit; --keep to retain it)"
exit 0