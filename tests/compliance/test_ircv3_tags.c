/* Real IRCv3 message-tag parse tests, exercising ircv3_tags.c. Pins grammar
 * validation, the validate-and-copy roundtrip, '=' in values, empty values,
 * capacity rejection, and NULL/empty/lone-'@' rejection. */
#include <assert.h>
#include <string.h>
#include "ircv3_tags.h"

int main(void) {
    char buf[128];
    int rc;

    /* canonical form roundtrips */
    rc = tags_parse("@label=123;key=val", buf, sizeof buf);
    assert(rc == (int)strlen("@label=123;key=val"));
    assert(strcmp(buf, "@label=123;key=val") == 0);

    rc = tags_parse("@key=value", buf, sizeof buf);
    assert(rc != -1);
    assert(strcmp(buf, "@key=value") == 0);

    /* '=' is legal inside values */
    rc = tags_parse("@a=b=c", buf, sizeof buf);
    assert(rc != -1);
    assert(strcmp(buf, "@a=b=c") == 0);

    rc = tags_parse("@a=x=y;b=z", buf, sizeof buf);
    assert(rc != -1);
    assert(strcmp(buf, "@a=x=y;b=z") == 0);

    /* empty value is legal */
    rc = tags_parse("@a=", buf, sizeof buf);
    assert(rc != -1);
    assert(strcmp(buf, "@a=") == 0);

    /* no '@' prefix is also valid (grammar allows optional '@') */
    rc = tags_parse("k=v;m=n", buf, sizeof buf);
    assert(rc != -1);
    assert(strcmp(buf, "k=v;m=n") == 0);

    /* invalid: lone '@', empty string, and '@' in a key position */
    assert(tags_parse("@", buf, sizeof buf) == -1);
    assert(tags_parse("", buf, sizeof buf) == -1);
    /* '@' prefix followed by ';' (nothing before separator) is invalid */
    assert(tags_parse("a;;b", buf, sizeof buf) == -1);     /* empty pair */
    assert(tags_parse("@;b", buf, sizeof buf) == -1);      /* empty key */
    assert(tags_parse("@a b", buf, sizeof buf) == -1);     /* space in key/value */
    assert(tags_parse("@a x=y", buf, sizeof buf) == -1);   /* space separates pairs => stray token */

    /* NULL arguments rejected */
    assert(tags_parse(NULL, buf, sizeof buf) == -1);
    assert(tags_parse("@a", NULL, sizeof buf) == -1);

    /* capacity too small -> reject, never truncate */
    assert(tags_parse("@a=b", buf, 2) == -1);
    assert(tags_parse("@a=b", buf, 1) == -1);
    assert(tags_parse("@a=b", buf, 0) == -1);
    assert(tags_parse("@a=b", buf, -1) == -1);

    return 0;
}