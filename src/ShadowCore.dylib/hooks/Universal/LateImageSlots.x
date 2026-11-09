#import "UniversalHooks.h"
#import "../../SHDWHookSession.h"

#include "late_image_slots.h"

// Late-image import-slot rebind. The walk itself (late_image_slots.h) is pure
// C over the image's load commands; this file supplies the two host bindings:
// the journal lookup and the protected store.
//
// HookKit cannot do this: its caller-image scope is a snapshot taken when the
// plan was analyzed, so a header that dyld added afterwards answers "the image
// imports no such symbol" for imports that are plainly there, and shared-cache
// images refuse EXACT_HEADER scope outright. Reading LC_DYLD_INFO /
// LC_DYLD_CHAINED_FIXUPS from the image sidesteps the snapshot entirely.

// Bind records spell C symbols with their Mach-O leading underscore; the spec
// journal keeps the installer's spelling (`sysctl`, `_dyld_get_image_name`).
// The `$DARWIN_EXTSN` variant (`_realpath$DARWIN_EXTSN`) resolves to the same
// function dyld binds for `realpath`, so the suffix is cut before lookup.
static void* shdw_late_lookup(const char* symbol, void* ctx) {
    (void)ctx;
    void* replacement = SHDWRebindJournalReplacement(symbol);
    if(!replacement && symbol[0] == '_') {
        replacement = SHDWRebindJournalReplacement(symbol + 1);
    }
    if(!replacement) {
        const char* dollar = strchr(symbol, '$');
        if(dollar) {
            char name[192];
            size_t len = (size_t)(dollar - symbol);
            if(len < sizeof name) {
                memcpy(name, symbol, len);
                name[len] = 0;
                replacement = SHDWRebindJournalReplacement(name);
                if(!replacement && name[0] == '_') {
                    replacement = SHDWRebindJournalReplacement(name + 1);
                }
            }
        }
    }
    return replacement;
}

static uint32_t shdw_late_store(uintptr_t slot, void* replacement, void* ctx) {
    (void)ctx;
    return SHDWRebindClaimSlot(slot, (uintptr_t)replacement) ? 1 : 0;
}

uint32_t SHDWRebindLateImageSlots(const void* imageHeader) {
    if(!imageHeader) {
        return 0;
    }
    return shdw_late_image_rebind(imageHeader, shdw_late_lookup, shdw_late_store,
                                  NULL);
}
