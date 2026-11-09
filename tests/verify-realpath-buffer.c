// Host-runnable model of the realpath output-buffer contract. The hook resolves
// into private scratch and calls this helper only after policy decides whether
// to commit that spelling to the caller's buffer.
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../src/ShadowCore.dylib/hooks/Universal/path_rewrite.h"

#define PATH_CAP 128

static char *model_original_realpath(const char *path, char *scratch) {
    size_t len = strlen(path);
    assert(len < PATH_CAP);
    memcpy(scratch, path, len + 1);
    return scratch;
}

static int model_realpath_buffer(char *caller, const char *path, int approved) {
    char scratch[PATH_CAP];
    char *result = model_original_realpath(path, scratch);
    return shdw_realpath_buffer_commit(caller, result, PATH_CAP, approved);
}

int main(void) {
    const char *denied_target = "/private/preboot/UUID/procursus/basebin/hidden.dylib";
    const char *approved_path = "/usr/lib/dyld";
    char caller[PATH_CAP];
    char snapshot[PATH_CAP];

    // A denied resolver result stays in private scratch; the caller receives
    // no target bytes, only the permitted empty-string failure shape. Assert
    // every byte after index 0 is untouched: `strstr` stops at the NUL and
    // cannot see a retained suffix.
    memset(caller, 'C', sizeof(caller));
    caller[sizeof(caller) - 1] = '\0';
    memcpy(snapshot, caller, sizeof(caller));
    assert(model_realpath_buffer(caller, denied_target, 0) == 0);
    assert(caller[0] == '\0');
    assert(memcmp(caller + 1, snapshot + 1, sizeof(caller) - 1) == 0);

    // Approved output is copied exactly, including its terminator.
    memset(caller, 'C', sizeof(caller));
    assert(model_realpath_buffer(caller, approved_path, 1) == 1);
    assert(strcmp(caller, approved_path) == 0);
    assert(caller[strlen(approved_path) + 1] == 'C');

    // An unterminated source is rejected before any partial copy is made; the
    // bytes after the cleared index 0 must remain exactly as they were.
    char short_caller[8] = "stale";
    char short_snapshot[8];
    memcpy(short_snapshot, short_caller, sizeof(short_caller));
    char unterminated[8];
    memset(unterminated, 'T', sizeof(unterminated));
    assert(shdw_realpath_buffer_commit(short_caller, unterminated,
                                       sizeof(short_caller), 1) == 0);
    assert(short_caller[0] == '\0');
    assert(memcmp(short_caller + 1, short_snapshot + 1,
                  sizeof(short_caller) - 1) == 0);

    puts("verify-realpath-buffer: all assertions passed");
    return 0;
}
