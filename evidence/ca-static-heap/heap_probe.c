/* Diagnose the pinned provider's key memory without generating or printing keys, #154. */
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

static long locked_kib(void) {
    FILE *f = fopen("/proc/self/status", "r");
    char line[256];
    long value = -1;
    if (!f) return value;
    while (fgets(line, sizeof line, f))
        if (sscanf(line, "VmLck: %ld kB", &value) == 1) break;
    fclose(f);
    return value;
}

static int protected_mapping(const void *allocation) {
    FILE *f = fopen("/proc/self/smaps", "r");
    char line[1024];
    unsigned long start, end;
    int selected = 0, protected = 0;
    if (!f) return 0;
    while (fgets(line, sizeof line, f)) {
        if (sscanf(line, "%lx-%lx", &start, &end) == 2)
            selected = (unsigned long)allocation >= start && (unsigned long)allocation < end;
        if (selected && strncmp(line, "VmFlags:", 8) == 0) {
            protected = strstr(line, " lo ") != NULL && strstr(line, " dd ") != NULL;
            break;
        }
    }
    fclose(f);
    return protected;
}

int main(void) {
    struct rlimit limit;
    struct timespec before, after;
    long locked_before = locked_kib();
    getrlimit(RLIMIT_MEMLOCK, &limit);
    clock_gettime(CLOCK_MONOTONIC, &before);
    int result = CRYPTO_secure_malloc_init(1 << 20, 32);
    clock_gettime(CLOCK_MONOTONIC, &after);
    printf("uid=%lu memlock_soft=%llu memlock_hard=%llu init_return=%d init_ns=%lld VmLck_before_KiB=%ld VmLck_after_KiB=%ld\n",
        (unsigned long)geteuid(), (unsigned long long)limit.rlim_cur,
        (unsigned long long)limit.rlim_max, result,
        (long long)(after.tv_sec-before.tv_sec)*1000000000 + after.tv_nsec-before.tv_nsec,
        locked_before, locked_kib());
    if (result != 1) {
        puts("key memory refused");
        return 1;
    }
    /* Force every sample allocation resident; no private material exists in this diagnostic. */
    void *blocks[10000];
    for (size_t i = 0; i < 10000; ++i) {
        blocks[i] = OPENSSL_secure_zalloc(32);
        if (!blocks[i]) return 2;
        memset(blocks[i], 0x5a, 32);
        if (!CRYPTO_secure_allocated(blocks[i]) || !protected_mapping(blocks[i])) return 3;
    }
    printf("allocations=10000 secure_used_bytes=%zu locked_pages_dump_excluded=yes VmLck_resident_KiB=%ld\n",
        CRYPTO_secure_used(), locked_kib());
    for (size_t i = 0; i < 10000; ++i) OPENSSL_secure_clear_free(blocks[i], 32);
    printf("secure_used_after_free_bytes=%zu\n", CRYPTO_secure_used());
    return 0;
}
