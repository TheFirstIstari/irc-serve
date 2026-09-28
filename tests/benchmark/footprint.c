/* Real resident-memory peak (RSS) measurement of this process.
 *
 * Uses getrusage(RUSAGE_SELF).ru_maxrss, which is reported in BYTES on
 * macOS/BSD and in KIBIBYTES on Linux; the units are handled explicitly here.
 * The value is a real peak for THIS process (`process=self`), not a 30-run
 * mean and not a deployed-node figure. No threshold is enforced by default;
 * an optional threshold can be supplied via the FOOTPRINT_RSS_MB_THRESHOLD
 * environment variable (in MiB), which makes the test fail if the measured
 * peak exceeds it. Sanitizer builds would inflate RSS and should be evaluated
 * separately, not against this threshold.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>

int main(void) {
    struct rusage ru;
    if (getrusage(RUSAGE_SELF, &ru) != 0) {
        fprintf(stderr, "footprint: getrusage failed\n");
        return 1;
    }

    double rss_mb;
#if defined(__APPLE__)
    /* macOS: ru_maxrss is in bytes */
    rss_mb = (double)ru.ru_maxrss / (1024.0 * 1024.0);
#else
    /* Linux: ru_maxrss is in KiB */
    rss_mb = (double)ru.ru_maxrss / 1024.0;
#endif

    printf("rss_peak: process=self workload=core-init rss=%.2f MiB\n", rss_mb);

    /* Optional, opt-in threshold: FOOTPRINT_RSS_MB_THRESHOLD in MiB. */
    const char* th = getenv("FOOTPRINT_RSS_MB_THRESHOLD");
    if (th != NULL && *th != '\0') {
        double max_mb = atof(th);
        if (max_mb > 0.0 && rss_mb > max_mb) {
            fprintf(stderr, "footprint: RSS %.2f MiB exceeds threshold %.2f MiB\n",
                    rss_mb, max_mb);
            return 1;
        }
    }

    return 0;
}
