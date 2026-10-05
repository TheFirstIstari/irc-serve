# strip-c-comments.awk — blank out C comments and string/char literals, printing
# exactly one output line per input line so reported line numbers still point at
# the real source line.
#
# IT IS STATEFUL ACROSS LINES, and that is the whole point. A block comment opens
# on one line and closes twenty lines later, so a stripper that resets per line
# silently leaves everything in between intact -- and this tree has such a
# comment: tests/integration/test_tls.c explains the (void)read() defect IN A
# COMMENT THAT QUOTES THE DEFECT, so a naive grep for the very pattern this gate
# looks for matches its own documentation of it. Per-line stripping is how that
# false positive gets in.
#
# Used by scripts/check-wur-discards.sh. See that script for what the result is
# matched against and why this file is not a general-purpose C lexer.

BEGIN { in_block = 0 }
{
  line = $0
  out  = ""
  i    = 1
  n    = length(line)
  while (i <= n) {
    c  = substr(line, i, 1)
    c2 = substr(line, i, 2)

    if (in_block) {
      if (c2 == "*/") { in_block = 0; i += 2 } else { i++ }
      continue
    }

    if (c2 == "/*") { in_block = 1; i += 2; continue }
    if (c2 == "//") { i = n + 1; continue }        # rest of line is comment

    if (c == "\"" || c == "'") {
      # A string or char literal. Blanked rather than kept so that a literal
      # holding the text "(void)read(" cannot register as a call site.
      q = c
      i++
      while (i <= n) {
        if (substr(line, i, 1) == "\\") { i += 2; continue }
        if (substr(line, i, 1) == q) { i++; break }
        i++
      }
      out = out " "
      continue
    }

    out = out c
    i++
  }
  # A line that was wholly or partly inside a block comment keeps its newline so
  # the NEXT line still lands on its own number.
  print out
}