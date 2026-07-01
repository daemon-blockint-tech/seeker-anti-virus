// yara_stub.c — Stub implementation used when libyara is not yet vendored.
// Provides no-op implementations of the functions yara_jni.cpp expects,
// so the project compiles and links. Replace with real libyara once vendored.

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

int yara_initialize(void) { return 0; }
int yara_finalize(void) { return 0; }

// Stub: always returns 0 rules loaded
int yara_load_rules(const char* rules_text, void** handle) {
    *handle = NULL;
    return 0;
}

// Stub: always returns 0 matches
int yara_scan_bytes(const void* handle, const uint8_t* data, size_t len,
                    int* match_indices, int max_matches) {
    (void)handle; (void)data; (void)len; (void)match_indices; (void)max_matches;
    return 0;
}

void yara_free_rules(void* handle) {
    (void)handle;
}

#ifdef __cplusplus
}
#endif
