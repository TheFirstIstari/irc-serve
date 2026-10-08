# packaging/homebrew/irc-serve.rb -- a Homebrew formula for irc-serve, from scratch.
#
# HOW TO USE IT, since a formula in the source tree is not a tap:
#
#     brew tap-new TheFirstIstari/irc-serve packaging/homebrew
#     brew install --HEAD irc-serve
#     brew test --HEAD irc-serve
#
# WHY `head` AND NOT `url` + `sha256`, which is what every formula in homebrew/core
# has and what `brew audit --new --formula` will complain about. Because this project
# has NO RELEASE: the upstream repository's release list is EMPTY, the newest tag is
# v0.7.0-messaging and predates the current source, and the only tag whose name
# looks like this version, v0.1.0-preserved, points at a commit from before the
# CMake build existed. A url + sha256 pair naming any of those would be a formula
# that installs the WRONG TREE under a plausible version, or one that fails to
# download. An INVENTED HASH IS WORSE THAN A MISSING FIELD: it is a checkable lie,
# and `brew install` would fail on it in a way that looks like an upstream problem.
#
# So the source is a git branch, stated as `head`, which is Homebrew's own mechanism
# for "no release artifact" and which makes `brew install --HEAD` work today.
#
# THE COST, plainly: --HEAD tracks main, so an install is not reproducible, and
# `brew install irc-serve` without --HEAD refuses with "no URL". That is the correct
# failure -- it is the tool saying the thing this file says. Converting to a released
# formula is three lines and no code change: tag the tree, put the tarball URL in
# `url`, and put the value `brew fetch --force` prints in `sha256`.
class IrcServe < Formula
  desc "Federated modern-spec IRC server in C"
  homepage "https://github.com/TheFirstIstari/irc-serve"

  # THE ONE VERSION REFERENCE IN THIS FILE, and it is CHECKED rather than trusted --
  # in two places, because a formula that disagrees with the binary it installs is a
  # package claiming a version the program does not have.
  #
  #   1. The `test` block below asserts the INSTALLED BINARY reports this version.
  #      That is the check with teeth: it runs against what brew actually installed,
  #      so a formula whose `version` and whose `head` point at different commits
  #      fails `brew test` rather than looking fine.
  #   2. scripts/check-packaging.py asserts this literal against IRC_SERVE_VERSION in
  #      src/core/server.h, which is the project's single version definition and the
  #      word 002, 004, PONG and the startup line all report.
  #
  # IT CANNOT BE A DERIVATION, and that is worth saying so nobody "fixes" it by
  # shelling out. A Homebrew formula is Ruby evaluated by brew, and `version` is
  # needed BEFORE anything is downloaded, so there is no source tree to read a
  # header out of. packaging/arch/PKGBUILD derives its pkgver with sed because
  # makepkg does run inside the unpacked source; this cannot. Hence the two checks
  # above instead of one sed.
  version "0.1.0"

  # The repository's LICENSE is the AGPL v3 text verbatim and NOTICE says "either
  # version 3 of the License, or (at your option) any later version", so the
  # identifier is the SPDX "or later" form. The same string is in
  # packaging/debian/copyright's License: field and packaging/arch/PKGBUILD's
  # license=(); scripts/check-packaging.py asserts all three agree with LICENSE.
  license "AGPL-3.0-or-later"

  # VCS sources are only ever installed with --HEAD, and Homebrew wants the commit
  # recorded rather than a moving ref wherever it can be pinned. The branch is named
  # rather than left to default to master, because this project's default is main.
  head "https://github.com/TheFirstIstari/irc-serve.git", branch: "main"

  depends_on "cmake" => :build

  def install
    # std_cmake_args, not -DCMAKE_INSTALL_PREFIX=<prefix> typed by hand: it is what
    # sets the prefix to this keg's, and it is what Homebrew's own audit expects.
    # CMAKE_BUILD_TYPE=Release comes AFTER *std_cmake_args on purpose -- a duplicated
    # -D on a CMake command line resolves to the LAST occurrence, so putting ours
    # first would let Homebrew's own value silently win and ship a differently
    # compiled binary than the one this file says it ships.
    #
    # The three -D flags are the project's, and they are the same ones
    # packaging/debian/rules and packaging/arch/PKGBUILD pass:
    #   CMAKE_BUILD_TYPE=Release   a shipping package is a release build
    #   BUILD_TESTING=OFF          the 99-test suite is the project's gate, not a
    #                              formula's job. IT IS NOT THE SUITE, DELIBERATELY:
    #                              the suite spawns nodes and binds ports, and
    #                              `brew install` runs on a user's machine where
    #                              none of that is isolated, so building it would
    #                              add minutes to every install to produce nothing
    #                              the formula ships. Arch's PKGBUILD keeps
    #                              BUILD_TESTING=ON precisely because its check()
    #                              runs ctest and this formula's test does not.
    #   WITH_TLS=OFF               the zero-dependency build, so this formula needs
    #                              no openssl dependency. THE COST, STATED: the
    #                              installed binary has no transport encryption.
    system "cmake", "-S", ".", "-B", "build",
           *std_cmake_args,
           "-DCMAKE_BUILD_TYPE=Release",
           "-DBUILD_TESTING=OFF",
           "-DWITH_TLS=OFF"
    system "cmake", "--build", "build"
    system "cmake", "--install", "build"
  end

  test do
    # A SMOKE CHECK, AND THE SMALLEST ONE WITH TEETH: `irc-serve --help` prints the
    # version as its FIRST line and exits 0, so this asserts two observable facts --
    # the binary that got installed runs, and it reports the version this formula
    # claims. That second half is the one worth having: it fails on a formula whose
    # version and whose binary come from different commits, which is the single
    # defect a --HEAD formula can actually have.
    #
    # IT IS NOT THE TEST SUITE, deliberately. The suite spawns nodes, binds ports
    # and builds a multi-node mesh; `brew test` runs on a user's machine with none of
    # that isolated, so a formula test that ran it would fail in ways that say nothing
    # about whether the package works. No sleep: --help exits on its own and
    # shell_output raises on a non-zero exit, so the command's own exit bounds it.
    output = shell_output("#{bin}/irc-serve --help 2>&1")
    assert_match(/\Airc-serve-\d+\.\d+\.\d+/, output)
    assert_equal "irc-serve-#{version}", output.lines.first.to_s.chomp
  end

  # The one thing a user of this keg cannot find out by running it, and the reason
  # this formula does not depend on openssl.
  caveats <<~EOS
    This formula builds with -DWITH_TLS=OFF, so the installed binary has NO
    transport encryption: peers link in the clear and no `tls` or `sts` capability
    is advertised. For an encrypted deployment build from source with
    -DWITH_TLS=ON against OpenSSL 1.1.1 or later.

    Installed with --HEAD, which tracks the main branch and is therefore not
    reproducible. This project publishes no releases yet, so there is no tagged
    tarball for `brew install` to pin.
  EOS
end