#import "UniversalHooks.h"
#import "../../SHDWHookSession.h"

#include <mach-o/dyld.h>
#include <string.h>
#include <stdlib.h>

// Rebind-spec journal + event-driven repair (anti-fishhook).
//
// Two journals work together:
//   * the SLOT journal (SHDWHookSession.m, rebind_slots.h core) records every
//     import-slot address a rebind wrote, with the expected replacement.
//     Repair is check-then-store — no HookKit involvement, so it cannot hit
//     the "repeat request invalidates the plan" hazard and needs no session.
//   * this SPEC journal records every (symbol, replacement) pair installers
//     requested. It exists for late-loaded images: a global rebind only
//     covers imports bound at install time, so an image dlopen'd afterwards
//     gets its own slots rewritten from the journal (LateImageSlots.x walks
//     the image's bind records; HookKit's caller-image scope cannot see a
//     header that did not exist when its plan was analyzed).
//
// Both journals only grow on installer paths. The late walk journals every
// cell it writes back into the SLOT journal, so repair and the vm_protect
// guard cover late images exactly like install-time rebinds.
//
// Triggers (event-only, no timer): dyld add-image (slots sync + late-image
// walk sync), detector escalation entry (slots sync), vm_protect-guard deny
// (trip + coalesced async slots repair).

#define SHDW_REBIND_SPECS_MAX 320

typedef struct {
    char* name;
    void* replacement;
    // Caller-owned original cell, or NULL. Must be process-lifetime: replay
    // dereferences it on later image loads, after the installer returned.
    void** originalCell;
} shdw_rebind_spec_t;

static shdw_rebind_spec_t gSHDWRebindSpecs[SHDW_REBIND_SPECS_MAX];
static uint32_t gSHDWRebindSpecCount;
static uint32_t gSHDWRebindSpecOverflowed;

void SHDWRebindJournalNote(const char* symbolName, void* replacement, void** originalCell) {
    if(!symbolName || !symbolName[0] || !replacement) {
        return;
    }
    uint32_t count = __atomic_load_n(&gSHDWRebindSpecCount, __ATOMIC_ACQUIRE);
    for(uint32_t i = 0; i < count; i++) {
        if(gSHDWRebindSpecs[i].replacement == replacement &&
           strcmp(gSHDWRebindSpecs[i].name, symbolName) == 0) {
            return;
        }
    }
    if(count >= SHDW_REBIND_SPECS_MAX) {
        if(!__atomic_exchange_n(&gSHDWRebindSpecOverflowed, 1, __ATOMIC_ACQ_REL)) {
            NSLog(@"[Shadow] rebind spec journal full (%u) — new-image replay will miss %s",
                  count, symbolName);
        }
        return;
    }
    char* copy = strdup(symbolName);
    if(!copy) {
        return;
    }
    gSHDWRebindSpecs[count] = (shdw_rebind_spec_t){ copy, replacement, originalCell };
    __atomic_store_n(&gSHDWRebindSpecCount, count + 1, __ATOMIC_RELEASE);
}

void* SHDWRebindJournalReplacement(const char* symbolName) {
    if(!symbolName || !symbolName[0]) {
        return NULL;
    }
    void* replacement = NULL;
    uint32_t count = __atomic_load_n(&gSHDWRebindSpecCount, __ATOMIC_ACQUIRE);
    for(uint32_t i = 0; i < count; i++) {
        if(strcmp(gSHDWRebindSpecs[i].name, symbolName) == 0) {
            replacement = gSHDWRebindSpecs[i].replacement;
        }
    }
    return replacement;
}

// A dlsym'd replacement is a valid code pointer living in ShadowCore; the
// address-attribution queries answer "which image owns this" with the
// original's image so a caller that resolves a symbol and then attributes the
// result sees the same provenance dladdr reports. NULL when the replacement
// was not journaled or the installer never captured an original.
void* SHDWRebindOriginalForReplacement(const void* replacement) {
    if(!replacement) {
        return NULL;
    }
    uint32_t count = __atomic_load_n(&gSHDWRebindSpecCount, __ATOMIC_ACQUIRE);
    for(uint32_t i = 0; i < count; i++) {
        if(gSHDWRebindSpecs[i].replacement != replacement) {
            continue;
        }
        void** cell = gSHDWRebindSpecs[i].originalCell;
        void* original = cell ? __atomic_load_n(cell, __ATOMIC_ACQUIRE) : NULL;
        if(original) {
            return original;
        }
    }
    return NULL;
}

// Exported (like the header declares): the detector-gated loader path
// resolves it from outside this image. `session` is unused — the walk reads
// the image, never HookKit — and kept for the existing call sites.
__attribute__((visibility("default")))
void SHDWRebindRepairImage(SHDWHookSession* session, const void* imageHeader) {
    (void)session;
    SHDWRebindLateImageSlots(imageHeader);
}

// Called synchronously from the add-image notification for every image dyld
// adds after install: the notification precedes the image's initializers, so
// a detector framework's ctor finds its own imports already rebound.
__attribute__((visibility("default")))
void SHDWRebindRepairLateImage(SHDWHookSession* session, const void* imageHeader) {
    (void)session;
    SHDWRebindLateImageSlots(imageHeader);
}

static uint32_t gSHDWRepairPending;

void SHDWRequestRebindRepair(void) {
    // Coalesced: at most one repair block queued. Runs on main, like the
    // detector escalation, so it never executes on a hook's stack or inside
    // the coordinator's lifecycle queue (whose re-entrancy guard would eat
    // a nested install).
    if(__atomic_exchange_n(&gSHDWRepairPending, 1, __ATOMIC_ACQ_REL)) {
        return;
    }
    dispatch_async(dispatch_get_main_queue(), ^{
        __atomic_store_n(&gSHDWRepairPending, 0, __ATOMIC_RELEASE);
        SHDWRebindRepairSlots();
    });
}

void SHDWRequestRebindRepairImage(const void* imageHeader) {
    if(!imageHeader) {
        return;
    }
    dispatch_async(dispatch_get_main_queue(), ^{
        // The image may have unloaded while queued; HookKit on a stale
        // EXACT_HEADER is at best a refusal, so re-resolve first.
        BOOL stillMapped = NO;
        uint32_t n = _dyld_image_count();
        for(uint32_t i = 0; i < n; i++) {
            if(_dyld_get_image_header(i) == (const struct mach_header*)imageHeader) {
                stillMapped = YES;
                break;
            }
        }
        if(!stillMapped) {
            return;
        }
        SHDWRebindLateImageSlots(imageHeader);
    });
}
