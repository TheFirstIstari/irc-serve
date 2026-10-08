# packaging/ -- irc-serve for Debian, Arch and Homebrew

**Nothing in this directory has been built.** The machine this packaging was written
on is macOS, which has no `dpkg-buildpackage`, no `dpkg-source`, no `dh`, no
`makepkg` and no `brew`. What was verified is listed under "What was verified" below,
and what was not is listed under "What is NOT verified". Issue **#48** stays open
until a real Debian build runs; this file does not close it.

## What is here

| Path | What it is |
| --- | --- |
| `debian/` | A binary package for Debian: `control`, `rules`, `changelog`, `copyright`, `source/format`, `patches/series` |
| `arch/PKGBUILD` | An Arch Linux package definition. Not in the AUR -- it is in the source tree. |
| `homebrew/irc-serve.rb` | A Homebrew formula. Not in a tap -- `brew tap-new` it, see below. |

## The build command for each format

```sh
# Debian: BINARY-ONLY. See "Why binary-only" and "The ./debian problem" below -- the
# two commands there are not optional extras, and running the second one without the
# first finds no packaging at all.
ln -s packaging/debian debian
dpkg-buildpackage -b -us -uc
rm debian

# Arch: from the directory holding the PKGBUILD. NEEDS NETWORK ACCESS, because the
# source line is a git branch rather than a tarball (the project has no releases).
makepkg -sfi

# Homebrew: a formula in the source tree is not a tap, so make it one first.
brew tap-new TheFirstIstari/irc-serve packaging/homebrew
brew install --HEAD irc-serve
brew test --HEAD irc-serve
```

Each command is what a maintainer of that distribution would run. **None of them has
been executed.**

## The `./debian` problem, and why the symlink above is not tidiness

`dpkg-buildpackage` does not look for a packaging directory anywhere but the current
one. In dpkg's own `scripts/dpkg-buildpackage.pl` the list is a literal:

    my @debian_rules = ('debian/rules');

There is no option, no environment variable and no `-C` that relocates it, and
`dpkg-source` is the same (`$dir` defaults to `.`). This repository keeps its
packaging at `packaging/debian`, so from the repository root `dpkg-buildpackage`
finds **no packaging at all** -- and the error it prints names `debian/rules`, not
the directory, so the message points at a file that exists somewhere else in the tree.

Three ways out, and this is issue #48's item 3 and an open decision rather than a
settled one:

1. **A symlink**, which is what the command above does. It is what this tree's layout
   needs today and it is not committed: a `debian` symlink at the repository root
   would be a second path to the same files, and `dpkg-source` would want to know
   whether to ship it inside the `.debian.tar`.
2. **A root `debian/` directory** holding the real files, with `packaging/debian`
   becoming a pointer instead. That reverses the current arrangement.
3. **A build tree**: copy or `git worktree` the checkout somewhere and place or link
   `debian/` there, keeping the source tree itself free of packaging paths.

Whichever is chosen, `scripts/check-packaging.py` reads `packaging/debian/...` and
would need its paths updated to match. That is recorded here rather than decided
here, because it changes where every other packaging tool has to look.

## The version, and how the three formats get it

`IRC_SERVE_VERSION` in `src/core/server.h` is the project's single version
definition. `CMakeLists.txt` parses it into `project(irc-serve VERSION ...)`, so the
binary reports it in `002`, `004`, `PONG`, the `FEDERATE` handshake and the startup
line. The three packaging formats then do three different things with it, because
each format gives them a different tool to do it with:

| Format | Mechanism | File |
| --- | --- | --- |
| CMake | `file(READ ...)` + `string(REGEX MATCH ...)`, at configure time | `CMakeLists.txt` |
| Debian | a changelog is a **record**, so it is written by hand and *checked* against the header | `debian/changelog` |
| Arch | `pkgver=$(sed -n ... src/core/server.h)`, executed by makepkg | `arch/PKGBUILD` |
| Homebrew | cannot be derived -- see below -- so it is *checked* against the header | `homebrew/irc-serve.rb` |

Why Debian and Homebrew check rather than derive:

* **Debian.** A changelog records what was uploaded and when. Computing one would
  destroy the only thing it is for. It has to agree with the header, which is what
  `tests/integration/test_version_truth.c` and `scripts/check-packaging.py` both
  assert.
* **Homebrew.** A formula is Ruby evaluated by `brew`, and `version` is needed
  *before* anything is downloaded -- there is no source tree to read a header out
  of. The formula's `test` block asserts the installed binary reports the same
  version the formula claims, which is the check with teeth: it runs against what
  `brew` actually installed.

## Why `3.0 (quilt)` and not `3.0 (native)`

`3.0 (quilt)`, and the argument is not a preference:

* `3.0 (native)` **requires** an upstream version with no Debian revision. The
  changelog says `0.1.0-1`, and `dpkg-buildpackage` refuses a native package whose
  version carries one.
* `3.0 (quilt)` accepts a revision, so `0.1.0-1` stands as written.
* Dropping the revision to get `0.1.0` is not available. `tests/integration/
  test_version_truth.c` builds the expected changelog line as `"irc-serve (0.1.0-"`
  -- with a trailing hyphen -- so a changelog reading `irc-serve (0.1.0)` fails a
  test that is currently green. The revision is load-bearing for the test suite.

The cost, stated plainly: `3.0 (quilt)` is a **source** package format and it
expects an upstream tarball beside the package (`irc-serve_0.1.0.orig.tar.gz`). This
project has no releases, so there is no such tarball and a full
`dpkg-buildpackage -b -us -uc` **cannot** be satisfied from this tree. A
**binary-only** build from a git checkout works without it, because `-b` never looks
for the `.orig.tar.gz`. That is the command above. When a release tarball is cut,
the fix is one line of `debian/watch` and nothing here changes.

What this file prevented: with no `debian/source/format` at all, `dpkg-source` assumes
`1.0`, which is a **native** format, and the `0.1.0-1` changelog then contradicts it.

## `debian/source/format` holds exactly one line, and that is not negotiable

`Dpkg::Source::Format::parse()` reads **one line** from that file and validates it
against `^(\d+)(?:\.(\d+))?(?:\s+\(([a-z0-9]+)\))?$`. A comment block above the value
does not parse as a format; it fails with
`source package format '# ...' is invalid`. So the reasoning for the format lives
**here**, in a file `dpkg` does not read, and `debian/source/format` holds nothing
but `3.0 (quilt)`.

## The license

GNU Affero General Public License v3 or later, `AGPL-3.0-or-later`.

* `LICENSE` at the repository root is the AGPL v3 text verbatim.
* `NOTICE` says "either version 3 of the License, or (at your option) any later
  version", which is why the identifier is the SPDX *or later* form.
* `debian/copyright`'s `License:` field, `arch/PKGBUILD`'s `license=(...)` and the
  formula's `license "..."` all carry that one string, and
  `scripts/check-packaging.py` asserts all three agree with each other and with
  `LICENSE`.

The Arch PKGBUILD used to say `license=('custom:Unlicensed')` under a comment
claiming the repository had no LICENSE file. That was true when it was written and
stopped being true when `LICENSE` landed; nothing caught it, because the packaging
check only ever read the `pkgver` line. That is why the check now reads the license.

## No transport encryption in any of these packages

All three configure with `-DWITH_TLS=OFF`, which is the source default, stated
explicitly so that a change to that default becomes a diff in the packaging rather
than a surprise in a user's build log. The consequence: **the packaged binary has no
transport encryption**, and no packaging format below depends on OpenSSL. Turning it
on is `-DWITH_TLS=ON` plus a dependency (`libssl-dev` on Debian, `openssl` on Arch,
`depends_on "openssl"` in the formula).

## What was verified, and how

Verified on macOS, without any of the builders:

* `packaging/debian/rules` is valid make: every target reaches `dh <target>` under
  `make -n` with a stub `dh` on `PATH`, and every `override_` it declares is a target
  debhelper 13 actually defines (an `override_` for a target `dh` lacks is silently
  ignored, so a typo there reads as policy and does nothing).
* `packaging/arch/PKGBUILD`'s `pkgver` derivation **executes** and produces `0.1.0`.
  It is executed rather than read, because a BSD-vs-GNU `sed` difference produces an
  empty match rather than an error.
* `packaging/arch/PKGBUILD` is valid shell: `bash -n` passes.
* `packaging/homebrew/irc-serve.rb` is valid Ruby: `ruby -c` reports `Syntax OK`.
* `debian/copyright` parses as DEP-5, and `debian/source/format` is one of the two
  valid 3.0 values.
* All three formats name the same license, and all three agree on the version.
* The CMake flags in all three files are compared against each other, so they cannot
  drift apart quietly.

All of the above is `scripts/check-packaging.py`, which runs in `scripts/gate.sh` as
a source-wide check. **A green run of it is not a built package.** It is the part of
the verification that can run where the work happens.

## What is NOT verified

Stated plainly rather than left to be discovered:

* **No `.deb` has ever been produced.** `dpkg-buildpackage` has not been run.
* **`dpkg-buildpackage` finds no packaging from the repository root**, because the
  packaging is at `packaging/debian` and dpkg only ever looks for `./debian`. See "The
  `./debian` problem" above; the fix is not chosen.
* **`dpkg-source -b` has not been run**, so the source package is unproven. As
  explained above, it is expected to fail for want of an upstream tarball.
* **What a produced `.deb` would contain** is unverified: the executable's presence
  from `cmake --install`, its `${shlibs:Depends}` substitution (which needs
  `dpkg-shlibdeps` and the built binary), and the file list.
* **`lintian` has not been run**, so Debian POLICY compliance is unknown.
* **`makepkg` has not been run.** `PKGBUILD`'s `source` line is a git branch, so
  `makepkg` additionally needs network access, and `arch=('aarch64')` is a claim
  about this source compiling there rather than a measurement.
* **`brew install` and `brew test` have not been run.** The formula's `test` block is
  verified only to be valid Ruby with the right assertions in it.
* **`override_dh_auto_test` running `ctest` in a Debian build environment is
  unverified.** The suite binds ports and spawns nodes, and a Debian build
  environment may not allow that.

Issue #48 is the tracker for the Debian side of this list, and it stays open.