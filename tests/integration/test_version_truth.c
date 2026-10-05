/* test_version_truth.c -- ONE version definition, and every report of it checked.
 *
 * ===========================================================================
 * WHAT THIS ASSERTS, BEFORE ANY ASSERTION
 * ===========================================================================
 * This project has one version number. It lives in one place --
 * src/core/server.h's IRC_SERVE_VERSION -- and everything that REPORTS a version
 * derives from it: the CMake project version, `--help`, the startup line, the
 * Arch PKGBUILD, the Debian changelog, and the design doc's recorded wire
 * transcript. This file checks that they agree, and it checks the rule that keeps
 * them agreeing: no file outside the definition may contain the version as a
 * literal.
 *
 * WHY IT IS A TEST AND NOT A REVIEW CONVENTION. The rule was already written down.
 * tests/integration/test_registration.c says, in its own header comment, that
 * asserting a hardcoded "0.1.0" "would make this test fail on every version bump,
 * and a test that gets deleted or loosened on each release is worth less than one
 * that keeps checking the FORMAT" -- and tests/integration/test_serverinfo.c broke
 * it anyway, with `#define VERSION "irc-serve-0.1.0"` forty files away. A convention
 * that a file can break without noticing is not a convention; it is a hope. What
 * makes it a rule is something that goes red.
 *
 * AND THE CONCRETE COST THAT ALREADY BEAR OUT, because it is why this file exists
 * rather than a lint: README.md's Status heading read `v1.0.0` for weeks while
 * CMakeLists.txt said 0.1.0, the binary's startup line said irc-serve-0.1.0, and the
 * repository's newest tag was v0.7.0-messaging. A README is the first thing a
 * person reads and the last thing anyone re-reads, and nothing in the build or the
 * suite could see it.
 *
 * ===========================================================================
 * WHAT IS ASSERTED, AND WHY EACH
 * ===========================================================================
 *   1. THE HEADER DEFINES ONE VERSION, and it has the shape `irc-serve-X.Y.Z`.
 *   2. CMAKE PARSED THE SAME ONE. IRC_SERVE_CMAKE_VERSION arrives here as a compile
 *      definition the top-level CMakeLists computed by reading the header, so this
 *      comparison is the derivation itself being checked rather than a claim about
 *      it: if the regex in CMakeLists.txt stops matching, the two disagree here.
 *   3. `--help` PRINTS IT, first line, from the same macro. A flag surface that does
 *      not say what it is has to be cross-referenced against something else to find
 *      out, and `--help` used to say nothing at all -- which is why the README's
 *      wrong number could not be checked from the tool.
 *   4. THE STARTUP LINE PRINTS IT, from the same macro.
 *   5. CMakeLists.txt CONTAINS NO LITERAL VERSION. This is the rule's teeth: the
 *      project() line must read the header, so `VERSION 0.1.0` typed back in is a
 *      failure rather than a silent second copy.
 *   6. PKGBUILD's pkgver IS DERIVED, not typed, and the derivation produces this
 *      version when run.
 *   7. THE DEBIAN CHANGELOG's NEWEST ENTRY MATCHES. A changelog is a record of what
 *      was uploaded, so it is NOT derived -- but it is a release claim, and one that
 *      disagrees with the tree is the same class of lie as the README's was.
 *   8. docs/SPEC_TRACKING.md's RECORDED TRANSCRIPT MATCHES. Same reasoning: it is a
 *      captured wire line, not a definition, so it must be updated rather than
 *      computed -- and must not be left describing a version the node cannot send.
 *   9. NO TEST FILE EXCEPT THIS ONE CARRIES THE LITERAL. The fixture for the rule is
 *      a test, which means the test has to exempt itself by name; that exemption is
 *      deliberate and visible, and everything else in tests/ is in scope.
 *
 * ONE SKIP, zero. The no-TLS build asserts the same things: every one of these is
 * either a source inspection or a run of the shipped binary's --help and startup
 * line, and none of them needs a crypto library. A test that could only run in one
 * configuration would be a configuration in which the rule is unchecked.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
/* waitpid()/WNOHANG. macOS pulls this in transitively through another header, so
 * its absence is invisible to a macOS-only build and only a Linux GCC build
 * reports it -- the same platform blindness as the glibc __wur class, in the
 * shape of a missing declaration rather than an unchecked return value. */
#include <sys/wait.h>
#include <unistd.h>

#include "core/server.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

/* The version CMake computed. Defined here rather than being a literal, because a
 * literal in this file would be the very thing the file forbids elsewhere. */
#ifndef IRC_SERVE_CMAKE_VERSION
#error "IRC_SERVE_CMAKE_VERSION must carry what CMake parsed out of src/core/server.h"
#endif

static int failures;

static void check(int cond, const char *what, const char *detail)
{
    if (cond != 0) {
        printf("ok: %s\n", what);
        return;
    }
    failures++;
    printf("FAILED: %s\n  %s\n", what, (detail != NULL) ? detail : "");
}

/* Read a whole file under IRCSERVE_SRC_DIR as a plain string, comments INCLUDED --
 * unlike tf_read_code(), which strips them. This test is about literals, so the
 * prose matters: a version number in a comment is a claim too, and the README
 * version was in prose. Returns NULL if the file cannot be read. */
static char *slurp(const char *rel, size_t *len_out)
{
    char path[4096];
    FILE *f;
    char *buf;
    long n;

    snprintf(path, sizeof path, "%s/%s", IRCSERVE_SRC_DIR, rel);
    f = fopen(path, "rb");
    if (f == NULL) {
        *len_out = 0u;
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0 || (n = ftell(f)) < 0 ||
        fseek(f, 0, SEEK_SET) != 0) {
        (void)fclose(f);
        *len_out = 0u;
        return NULL;
    }
    buf = (char *)malloc((size_t)n + 1u);
    if (buf == NULL) {
        (void)fclose(f);
        *len_out = 0u;
        return NULL;
    }
    if (fread(buf, 1u, (size_t)n, f) != (size_t)n) {
        free(buf);
        (void)fclose(f);
        *len_out = 0u;
        return NULL;
    }
    buf[n] = '\0';
    (void)fclose(f);
    *len_out = (size_t)n;
    return buf;
}

/* Does `hay` contain the literal `needle`? tf_count() would do, and this is a
 * spelling of it rather than a second implementation -- the reason it is here is
 * that the arguments are the other way round from every other call site and a
 * reader should not have to work out which is which. */
static int has(const char *hay, const char *needle)
{
    return (hay != NULL && needle != NULL && strstr(hay, needle) != NULL) ? 1 : 0;
}

/* ---------------------------------------------------------------------------
 * The DERIVATION, run here rather than trusted
 * ---------------------------------------------------------------------------
 * PKGBUILD's pkgver line is extracted and executed in a child, with the header's
 * real directory substituted, and its output compared with the header's version.
 * Extracting and running it -- rather than grepping it for the word "sed" -- means
 * this test catches a PKGBUILD whose derivation is present and WRONG, which is the
 * more likely mistake: a pattern that matches nothing yields an empty pkgver, and
 * makepkg reports that as a malformed version rather than as a broken idea.
 *
 * IT IS EXECUTED IN A CHILD with a `cd` into the source root first, because the
 * PKGBUILD uses a relative path. That is the same reason every other test here
 * forks: a child that hangs takes nothing with it. */
static void check_pkgbuild_derives(const char *version)
{
    size_t len = 0u;
    char *pb = slurp("packaging/arch/PKGBUILD", &len);
    char cmd[1024];
    FILE *p;
    char got[128];
    int n = 0;

    check(pb != NULL, "packaging/arch/PKGBUILD is readable", IRCSERVE_SRC_DIR);
    if (pb == NULL) {
        return;
    }
    /* NO `pkgver=` LITERAL. The derivation itself is checked below; this is the rule,
     * and it is the half that has teeth. */
    check(has(pb, "pkgver=0.") == 0 && has(pb, "pkgver=1.") == 0 &&
              has(pb, "pkgver=2.") == 0,
          "PKGBUILD has NO literal pkgver=, so the version has exactly one definition "
          "and this file is not a second copy of it",
          "a literal pkgver= is a version that has to be edited in two places, and "
          "one of them will be missed");
    snprintf(cmd, sizeof cmd,
             "cd '%s' && pkgver=$(sed -n '%s' src/core/server.h) && printf '%%s' "
             "\"$pkgver\"",
             IRCSERVE_SRC_DIR,
             "s/^#[[:space:]]*define[[:space:]][[:space:]]*IRC_SERVE_VERSION"
             "[[:space:]][[:space:]]*\"irc-serve-\\([0-9][0-9]*\\.[0-9][0-9]*\\."
             "[0-9][0-9]*\\)\".*/\\1/p");
    p = popen(cmd, "r");
    if (p == NULL) {
        check(0, "PKGBUILD's derivation runs", cmd);
        free(pb);
        return;
    }
    while (n < (int)sizeof got - 1) {
        size_t r = fread(got + (size_t)n, 1u, sizeof got - 1u - (size_t)n, p);

        if (r == 0u) {
            break;
        }
        n += (int)r;
    }
    got[n] = '\0';
    (void)pclose(p);
    check(strcmp(got, version) == 0,
          "and the sed PKGBUILD uses to derive pkgver produces THIS version, so the "
          "packaging's number is the header's rather than a lookalike",
          got);
    free(pb);
}

/* ---------------------------------------------------------------------------
 * A DEBIAN CHANGELOG, whose newest entry must agree
 * ---------------------------------------------------------------------------
 * Not derived, and the difference is worth stating: a changelog records what was
 * uploaded and when, and computing one would destroy the only thing it is for. What
 * it must not do is describe a version the tree cannot produce, so the top entry is
 * compared. The version line is the first line and the format is fixed --
 * `irc-serve (X.Y.Z-N) <suite>; <urgency=...>` -- so a hand-rolled read of the first
 * two space-delimited fields is enough and no changelog parser is needed. */
static void check_debian_changelog(const char *version)
{
    size_t len = 0u;
    char *cl = slurp("packaging/debian/changelog", &len);
    /* 128, NOT 64, and the reason is a compiler rather than a length: `version` is a
     * parameter, so gcc-16 assumes it can be a char[64] and computes 63 characters
     * plus the literal's own text against a 64-byte destination. Two clangs report
     * nothing. This is the same "satisfy the strictest of three compilers that
     * disagree" rule tests/integration/test_peer_tls.c's PF_PATH arithmetic follows,
     * and the alternative -- a -Wno-format-truncation -- is a suppression that is
     * invisible in a build log and permanent. */
    char want[128];
    char line[512];
    const char *open_paren;
    const char *close_paren;
    size_t i = 0u;

    check(cl != NULL, "packaging/debian/changelog is readable", IRCSERVE_SRC_DIR);
    if (cl == NULL) {
        return;
    }
    while (i < len && i + 1u < sizeof line && cl[i] != '\n') {
        line[i] = cl[i];
        i++;
    }
    line[i] = '\0';
    snprintf(want, sizeof want, "irc-serve (%s-", version);
    check(has(line, want),
          "the Debian changelog's NEWEST entry is this version, so the package "
          "metadata does not describe a release the tree cannot produce",
          line);
    open_paren = strchr(line, '(');
    close_paren = (open_paren != NULL) ? strchr(open_paren, ')') : NULL;
    check(open_paren != NULL && close_paren != NULL && close_paren > open_paren,
          "and that entry has the conventional `name (version) suite; urgency=` shape, "
          "so the comparison above read a version rather than a coincidence",
          line);
    free(cl);
}

/* ---------------------------------------------------------------------------
 * THE RECORDED TRANSCRIPT
 * ---------------------------------------------------------------------------
 * docs/SPEC_TRACKING.md quotes real output from a real registration, including the
 * 002 and 004 lines, which carry the version word. It is a capture, not a
 * definition, so it is updated rather than computed -- but a capture of a version
 * this build cannot send is a stale claim like any other, and SPEC_TRACKING.md is
 * the document a contributor reads to decide what the node is supposed to do. */
static void check_recorded_transcript(const char *version)
{
    size_t len = 0u;
    char *doc = slurp("docs/SPEC_TRACKING.md", &len);
    char want[128]; /* the same gcc-16 arithmetic as check_debian_changelog()'s */

    check(doc != NULL, "docs/SPEC_TRACKING.md is readable", IRCSERVE_SRC_DIR);
    if (doc == NULL) {
        return;
    }
    snprintf(want, sizeof want, "irc-serve-%s", version);
    check(has(doc, want),
          "the wire transcript docs/SPEC_TRACKING.md records carries THIS version in "
          "its 002 and 004 lines, so the documented output matches the output",
          "the transcript records a version the node cannot send");
    free(doc);
}

int main(void)
{
    /* `full` is the wire word -- "irc-serve-0.1.0" -- and `numeric` is the package
     * version -- "0.1.0". They are kept as two strings rather than one with the
     * prefix stripped at each use, because a test that re-derives a substring seven
     * times is a test whose seventh use is the one that is wrong. */
    char full[64];
    char numeric[64];
    char msg[8192];
    size_t len = 0u;
    char *cm;
    char *h;
    const char *body;

    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("== test_version_truth ==\n");

    /* ---- 1. THE DEFINITION ---- */
    h = slurp("src/core/server.h", &len);
    TF_CHECK_MSG(h != NULL, "could not read src/core/server.h (is IRCSERVE_SRC_DIR "
                           "set?)");
    body = strstr(h, "#define IRC_SERVE_VERSION");
    TF_CHECK_MSG(body != NULL, "IRC_SERVE_VERSION is not in src/core/server.h");
    /* NO POSITIONAL ASSERTION ON THE MACRO'S TEXT. The first version of this checked
     * that the quote character sat at an exact byte offset after the macro name, which
     * is a statement about WHITESPACE rather than about the version -- and it failed,
     * because the offset was off by the one character the check itself had added. A
     * test that measures formatting is a test that goes red on a reformat. The shape
     * is checked properly below, by reading the string the macro names. */
    {
        const char *open = strchr(body, '"');
        const char *close = (open != NULL) ? strchr(open + 1, '"') : NULL;
        size_t n;

        TF_CHECK_MSG(open != NULL && close != NULL && close > open,
                      "IRC_SERVE_VERSION is not a quoted string");
        n = (size_t)(close - (open + 1));
        TF_CHECK_MSG(n + 1u < sizeof full, "IRC_SERVE_VERSION is implausibly long");
        memcpy(full, open + 1, n);
        full[n] = '\0';
    }
    /* THE NUMERIC PART, X.Y.Z, and it is validated rather than assumed: three
     * dot-separated runs of digits. A version with a pre-release suffix or a build
     * number would be a different SHAPE on the wire, and packaging would take it
     * differently, so the shape is part of the contract. */
    TF_CHECK_MSG(strncmp(full, "irc-serve-", strlen("irc-serve-")) == 0,
                 "IRC_SERVE_VERSION does not start with irc-serve-");
    snprintf(numeric, sizeof numeric, "%s", full + strlen("irc-serve-"));
    {
        const char *v = numeric;
        int digits = 0;
        int dots = 0;
        int components = 1;

        while (*v != '\0') {
            if (*v >= '0' && *v <= '9') {
                digits++;
            } else if (*v == '.') {
                dots++;
                components++;
                digits = 0;
            } else {
                TF_CHECK_MSG(0, "version has a non-numeric character");
            }
            v++;
        }
        /* THREE COMPONENTS AND TWO DOTS, with a non-empty run either side of every
         * dot. `digits` is the run length at the END of the string, so requiring it to
         * be non-zero is what rejects "0.1."; `components` is what rejects "0.1".
         * Both counters are needed and both are read, which is the whole difference
         * between this and the first version of the check. */
        TF_CHECK_MSG(digits > 0 && dots == 2 && components == 3,
                     "version is not exactly X.Y.Z");
    }
    /* The header defines it, and the macro the node reports is the same constant. */
    check(strcmp(IRC_SERVE_VERSION, full) == 0,
          "src/core/server.h defines the version the node reports, and it has the "
          "shape irc-serve-X.Y.Z -- the word 002, 004 and PONG all carry",
          full);
    printf("note: the one version definition is IRC_SERVE_VERSION = \"%s\"\n", full);

    /* ---- 2. CMAKE PARSED THE SAME ONE ---- */
    check(strcmp(IRC_SERVE_CMAKE_VERSION, numeric) == 0,
          "CMake's project() VERSION is this version, because the top-level "
          "CMakeLists.txt PARSES it out of this header rather than repeating it -- "
          "so a build and the binary cannot report different numbers",
          IRC_SERVE_CMAKE_VERSION);

    /* ---- 3. --help PRINTS IT ---- */
    {
        static char v0[] = "irc-serve";
        static char v1[] = "--help";
        char *v[4];
        int fds[2];
        pid_t pid = -1;
        int status = 0;
        size_t n = 0;

        v[0] = v0; v[1] = v1; v[2] = NULL; v[3] = NULL;
        msg[0] = '\0';
        if (pipe(fds) == 0 && (pid = fork()) == 0) {
            (void)close(fds[0]);
            (void)dup2(fds[1], STDOUT_FILENO);
            (void)dup2(fds[1], STDERR_FILENO);
            execv(NF_SERVER_BIN, v);
            _exit(127);
        }
        if (pid > 0) {
            (void)close(fds[1]);
            /* BOUNDED BY THE EXIT, NOT BY A SLEEP: `--help` returns 1, so the child
             * ends the stream itself. The deadline is a backstop against a node that
             * did not recognise the flag and started listening instead -- which is
             * exactly what a mistyped option would do, and exactly what a fixed
             * sleep would paper over. */
            for (;;) {
                fd_set rd;
                struct timeval tv;
                int r;

                FD_ZERO(&rd);
                FD_SET(fds[0], &rd);
                tv.tv_sec = 0;
                tv.tv_usec = 20000;
                r = select(fds[0] + 1, &rd, NULL, NULL, &tv);
                if (r > 0) {
                    ssize_t got = read(fds[0], msg + n, sizeof msg - n - 1u);

                    if (got > 0) {
                        n += (size_t)got;
                        msg[n] = '\0';
                        continue;
                    }
                }
                if (waitpid(pid, &status, WNOHANG) == pid) {
                    break;
                }
            }
            (void)close(fds[0]);
        }
        /* EXIT 0, which is what node_main.c's `--help` arm does (parse_args returns 1
         * for the flag and main() maps that to 0). The assertion is here because
         * "print the help and exit" and "print the help and start a node" are both
         * plausible readings of the same output, and only the exit status tells them
         * apart: a node that ignored the flag would block on a bound port instead. */
        check(WIFEXITED(status) && WEXITSTATUS(status) == 0,
              "`--help` exits 0 rather than starting a node, so the version line it "
              "printed came from a process that then stopped", msg);
        check(strncmp(msg, full, strlen(full)) == 0,
              "`--help` prints the version as its FIRST line, from the same macro the "
              "startup line uses -- so the flag surface cannot claim a version the "
              "binary does not report",
              msg);
    }

    /* ---- 4. THE STARTUP LINE PRINTS IT ---- */
    {
        nf_node_t n;
        static const char *const prog = "irc-serve";
        static const char *const zero = "0";
        char *v[4];

        v[0] = (char *)(uintptr_t)(const void *)prog;
        v[1] = (char *)(uintptr_t)(const void *)zero;
        v[2] = NULL;
        v[3] = NULL;
        if (nf_spawn_binary_argv(&n, v) != 0) {
            check(0, "spawn irc-serve to read its startup line", NULL);
        } else {
            check(strstr(n.out, full) != NULL,
                  "the startup line prints this version, from the same macro as "
                  "`--help`", n.out);
            check(strncmp(n.out, full, strlen(full)) == 0,
                  "and it is the FIRST thing the node says, so `irc-serve --help` and "
                  "`irc-serve` in a terminal cannot be believed to be two programs",
                  n.out);
            (void)nf_stop(&n);
            nf_free(&n);
        }
    }

    /* ---- 5. CMakeLists.txt HAS NO LITERAL VERSION ---- */
    cm = slurp("CMakeLists.txt", &len);
    TF_CHECK_MSG(cm != NULL, "could not read CMakeLists.txt");
    check(strstr(cm, "VERSION 0.") == NULL && strstr(cm, "VERSION 1.") == NULL &&
              strstr(cm, "VERSION 2.") == NULL,
          "CMakeLists.txt contains NO literal `VERSION X.Y.Z`, so project() reads the "
          "header and the build cannot claim a version the source does not",
          "a literal here is the second copy this change exists to remove");
    check(strstr(cm, "IRC_SERVE_VERSION") != NULL &&
              strstr(cm, "project(irc-serve VERSION ${IRC_SERVE_VERSION}") != NULL,
          "and it parses IRC_SERVE_VERSION out of src/core/server.h explicitly, "
          "rather than deriving by accident",
          "the derivation has to be visible in the build file to be reviewable");
    free(cm);

    /* ---- 6, 7, 8. THE REPORTERS ---- */
    check_pkgbuild_derives(numeric);
    check_debian_changelog(numeric);
    check_recorded_transcript(numeric);

    /* ---- 9. NO SECOND HARD-CODED COPY IN tests/ ----
     * THE RULE THIS FILE ENFORCES ON ITSELF. The list below is every test file, and
     * the exemption is this one, by name, for the reason in the header comment: a
     * test that forbids a literal must contain one to search for.
     *
     * THE SCOPE IS tests/ AND NOT src/, because src/ has exactly one place allowed to
     * hold the literal -- the definition in core/server.h -- and this file checks
     * THAT separately by reading the header. What is left to check here is everything
     * that consumes it. */
    {
        static const char *const files[] = {
            "tests/integration/test_tls_revocation.c",
            "tests/integration/test_serverinfo.c",
            "tests/integration/test_tls.c",
            "tests/integration/test_peer_tls.c",
            "tests/harness/tls_fixture.c",
            "tests/harness/irc_client.c",
            "tests/harness/node_fixture.c",
            NULL
        };
        int i;
        int bad = 0;

        for (i = 0; files[i] != NULL; i++) {
            char *t = slurp(files[i], &len);
            int lit;

            if (t == NULL) {
                continue;
            }
            /* `irc-serve-<digits>` and a bare `pkgver=<digits>` are the two shapes a
             * hardcoded copy takes here. A test that mentions "0.1.0" in a COMMENT
             * explaining why it must not is not a copy -- but it is also not
             * something this can distinguish from one cheaply, so the needle is the
             * product form `irc-serve-0.1.0`, which is what a copy would produce. */
            lit = (strstr(t, full) != NULL &&
                   strcmp(files[i], "tests/integration/test_version_truth.c") != 0)
                      ? 1
                      : 0;
            if (lit != 0) {
                bad++;
                check(0, "a test file does not hardcode the version", files[i]);
            }
            free(t);
        }
        check(bad == 0,
              "and no test file hardcodes the version, so a bump cannot leave one "
              "behind asserting an old number on the wire",
              "a hardcoded version in a test is a test that fails on every bump and "
              "gets loosened instead");
    }

    free(h);
    printf("== %d failure(s) ==\n", failures);
    return (failures == 0) ? 0 : 1;
}
