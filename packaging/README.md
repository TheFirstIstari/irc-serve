# packaging/ -- irc-serve for Debian, Arch and Homebrew

**Nothing in this directory has been built.** The machine this packaging was written
on is macOS, which has no `dpkg-buildpackage`, no `dpkg-source`, no `dh`, no
`makepkg` and no `brew`. What was verified is listed under "What was verified" below,
and what was not is listed under "What is NOT verified". Issue **#48** stays open
until a real Debian build runs; this file does not close it.

The Debian packaging lives at `packaging/debian/` and is reachable from the
repository root as **`debian/`**, which is a committed symlink. See "The `./debian`
problem" below for why that is the layout and what it costs.

## What is here

| Path | What it is |
| --- | --- |
| `debian/` | A binary package for Debian: `control`, `rules`, `changelog`, `copyright`, `source/format`, `patches/series` |
| `arch/PKGBUILD` | An Arch Linux package definition. Not in the AUR -- it is in the source tree. |
| `homebrew/irc-serve.rb` | A Homebrew formula. Not in a tap -- `brew tap-new` it, see below. |

## The build command for each format

```sh
# Debian: BINARY-ONLY. See "Why 3.0 (quilt) and not 3.0 (native)" below --
# `dpkg-buildpackage -b` never
# looks for the .orig.tar.gz that `3.0 (quilt)` wants and that this project cannot
# produce. There is no `ln -s` here: `debian` is already a committed symlink.
dpkg-buildpackage -b -us -uc

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

## The `./debian` problem, and the layout this tree settled on

`dpkg-buildpackage` does not look for a packaging directory anywhere but the current
one. In dpkg's own `scripts/dpkg-buildpackage.pl` the list is a literal:

    my @debian_rules = ('debian/rules');

There is no option, no environment variable and no `-C` that relocates it, and
`dpkg-source` is the same (`$dir` defaults to `.`). So a package built from this
repository has to be findable at `./debian`, and the files are at
`packaging/debian`.

**THE LAYOUT IS A COMMITTED SYMLINK, `debian -> packaging/debian`,** and it is
committed rather than made by the build command. That was an open decision with three
options (issue #48's item 3); here is why this one, and what each rejected option
would have cost:

1. **A committed symlink — chosen.** One home for the files (`packaging/debian`, so
   the three distributions sit together and are described by this one README), and the
   path dpkg reads. It is the smallest change that satisfies dpkg's literal, and it
   adds no second copy of anything.
2. **A real root `debian/` holding the files, with `packaging/debian` becoming a
   pointer** — rejected. It reverses the arrangement for no gain, and it splits the
   three distributions across two places: `debian/` at the root and `arch/` and
   `homebrew/` under `packaging/`.
3. **A build tree** (`git worktree`, or a copy with `debian/` placed in it) —
   rejected. It works, and it is the only option that keeps the source tree free of a
   second path at all, but it makes `dpkg-buildpackage` unrunnable from a plain
   checkout: every attempt becomes "check out somewhere else first", and the thing
   that gets skipped is the one that finds no packaging.

### THE COSTS, because there are three and they are not small

* **TWO PATHS TO THE SAME FILES**, which is what a symlink is. The packaging is at
  `packaging/debian/` and equally at `debian/`, and a patch or an edit made through
  one is made to both. That is tolerable precisely because there is one set of bytes:
  `scripts/check-packaging.py` asserts the two paths are the SAME inode
  (`os.path.realpath`) rather than two files that happen to agree today.
* **`dpkg-source` AND THE SOURCE PACKAGE.** The concern that was recorded against
  this option -- "would `dpkg-source` want to ship the symlink inside the
  `.debian.tar`?" -- does not arise for the documented command, because `-b` never
  runs `dpkg-source`. It would arise for a source build, which this project cannot do
  anyway: `3.0 (quilt)` wants `irc-serve_0.1.0.orig.tar.gz` and there are no
  releases. When a release tarball is cut, this is a one-line `debian/watch` away and
  nothing here changes.
* **A TOOL THAT WALKS THE TREE SEES IT TWICE.** Anything globbing `**/debian/**` finds
  the files twice. Nothing in this repository does (`CMakeLists.txt` globs nothing, and
  the check scripts read one path), and `check-packaging.py` reads every Debian file
  through `debian/` -- the path dpkg reads -- so the checks describe what a build
  would actually see.

### WHY THE TARGET IS RELATIVE

`debian -> packaging/debian`, not `debian -> /Users/someone/dev/irc-serve/packaging/debian`.
A committed symlink with an absolute target resolves on exactly one machine and
dangles on every other, including CI's. `scripts/check-packaging.py` asserts the
literal target string, so the difference is a red build rather than a surprise on
someone else's checkout.

### AND IT IS ASSERTED, NOT DESCRIBED

`scripts/check-packaging.py` runs in `scripts/gate.sh` as a source-wide check, and its
first check is the layout: that `debian` exists at the root, that it is a symlink, that
its target is the relative string above, that `packaging/debian` is a real directory,
and that `rules`, `control`, `changelog` and `copyright` are reachable through the
symlink as the same files. A layout that is only described in this file is a layout
that can drift while every other check stays green; this one goes red if the symlink is
deleted, replaced by a real directory, or pointed somewhere else.

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
* **That the symlink is what a real `dpkg-buildpackage` would follow.** The layout is
  asserted by `scripts/check-packaging.py` -- that `debian` exists at the root, is a
  symlink, and that `debian/rules` and `packaging/debian/rules` are the same file --
  but that is a check reading a filesystem, not dpkg reading one. Whether dpkg
  follows a committed symlink, and whether `dh` objects to one, is unverified here
  because this machine has no dpkg at all. This is the one claim in this file that a
  Debian machine settles in about a minute, and it is part of what #48 needs.
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