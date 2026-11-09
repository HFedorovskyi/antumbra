#import "UniversalHooks.h"
#import "../Diag.h"

#ifndef VM_MAP_READ_NULL
typedef vm_map_t vm_map_read_t;
#endif

extern int shdw_diag_mem_trace;
// Memory-query entrypoints are integrity-checked at their text by some
// sandboxed apps: a single patched instruction in libsystem_kernel is enough
// for a text comparison to fail, while rewriting only the importing image's
// own slots leaves the system function byte- and address-identical. Default is
// therefore the import-slot lane. 0 = entrypoint-first, 1 = import-slot only,
// 2 = both (diagnostics; the text patch is what such checks catch).
int shdw_diag_mem_lane = 1;

// Diagnostic lane (pref: Debug_MemOpaquePass): present headerless exec
// regions to external walkers instead of skipping them, matching the
// stock region geometry of an image body.
int shdw_diag_mem_opaque_pass = 0;

// Diagnostic lane (pref Debug_MemTrace): one line per region handed to an
// external caller and one per policy decision (skip/point). Budgeted so a
// full address-space walk cannot flood the log; off in production.
static int shdw_mem_trace_budget = 4096;

// Diagnostic lane (pref Debug_MemShare): one-shot snapshot at ctor of the
// share_mode/page-accounting of every dyld image's __TEXT, walked region by
// region so page-granular COW splits are visible. Data-only: it calls the
// raw kernel entry, never our own hook, and changes nothing.
// Pref Debug_MemShareTrace: the same fields for every submap-info region an
// external caller asks for, i.e. exactly what a detector is handed.
int shdw_diag_mem_share = 0;
int shdw_diag_mem_share_trace = 0;
// Pref Debug_MemShareRaw: for the passive lane, log the 12 raw words the
// kernel filled instead of the decoded fields. Used once to pin the exact
// layout the kernel uses for a 12-word submap reply.
int shdw_diag_mem_share_raw = 0;
static int shdw_share_trace_budget = 4096;
static int shdw_share_dump_budget = 4096;

static const char* shdw_sm_name(unsigned int sm) {
    switch(sm) {
        case SM_COW: return "COW";
        case SM_PRIVATE: return "PRIVATE";
        case SM_EMPTY: return "EMPTY";
        case SM_SHARED: return "SHARED";
        case SM_TRUESHARED: return "TRUESHARED";
        case SM_PRIVATE_ALIASED: return "PRIV_ALIASED";
        case SM_SHARED_ALIASED: return "SHARED_ALIASED";
        case SM_LARGE_PAGE: return "LARGE_PAGE";
        default: return "?";
    }
}

static void shdw_mem_trace(const char *api, uintptr_t caller, uintptr_t query,
                           uintptr_t base, uintptr_t size, int prot, int maxprot,
                           int restricted, const char *action) {
    if(!shdw_diag_mem_trace || shdw_mem_trace_budget <= 0) {
        return;
    }

    shdw_mem_trace_budget--;
    char who[256];
    shdw_diag_describe(who, sizeof who, (void *) caller);
    shdw_diag_log("memtrace %s caller=%s q=%p base=%p size=%#lx prot=%d/%d restr=%d act=%s",
                  api, who, (void *) query, (void *) base,
                  (unsigned long) size, prot, maxprot, restricted, action);
}

// share_mode tells the caller how the backing object is mapped: SM_SHARED
// pages of the dyld shared cache stay file-backed and read-only, while an
// inline hook that writes a cache page first makes that page private and
// COW, which the kernel then reports as a split region with a different
// share_mode. A stock process never shows private/COW code pages of a
// system library; a jailbroken one does as soon as any tweak hooks a
// function in it. Logged for both the passive (detector-facing) and the
// ctor snapshot (whole-process) lanes.
static void shdw_share_trace(const char *api, uintptr_t caller, uintptr_t base,
                             uintptr_t size, mach_msg_type_number_t count,
                             mach_msg_type_number_t entryCount, const void *info) {
    if(!shdw_diag_mem_share_trace || shdw_share_trace_budget <= 0 || !info) {
        return;
    }

    if(shdw_diag_mem_share_raw) {
        const natural_t *w = info;
        unsigned int n = count < 12 ? (unsigned int) count : 12;
        shdw_share_trace_budget--;
        shdw_diag_log("SHRRAW %s caller=%p base=%p size=%#lx in=%u out=%u w0..7=%#x,%#x,%#x,%#x,%#x,%#x,%#x,%#x w8..11=%#x,%#x,%#x,%#x",
                      api, (void *) caller, (void *) base, (unsigned long) size,
                      (unsigned) entryCount, (unsigned) count,
                      n > 0 ? w[0] : 0, n > 1 ? w[1] : 0, n > 2 ? w[2] : 0,
                      n > 3 ? w[3] : 0, n > 4 ? w[4] : 0, n > 5 ? w[5] : 0,
                      n > 6 ? w[6] : 0, n > 7 ? w[7] : 0, n > 8 ? w[8] : 0,
                      n > 9 ? w[9] : 0, n > 10 ? w[10] : 0, n > 11 ? w[11] : 0);
        return;
    }

    if((size_t) count * sizeof(natural_t) <
       offsetof(vm_region_submap_info_data_64_t, share_mode) + 1) {
        shdw_share_trace_budget--;
        shdw_diag_log("SHRTRACE %s caller=%p base=%p size=%#lx in=%u count=%u fields=<short>",
                      api, (void *) caller, (void *) base, (unsigned long) size,
                      (unsigned) entryCount, (unsigned) count);
        return;
    }

    const vm_region_submap_info_data_64_t *s = info;
    shdw_share_trace_budget--;
    char who[192];
    shdw_diag_describe(who, sizeof who, (void *) caller);
    shdw_diag_log("SHRTRACE %s caller=%s base=%p size=%#lx count=%u prot=%d/%d sm=%s(%u) tag=%#x res=%u spriv=%u dirt=%u subm=%d",
                  api, who, (void *) base, (unsigned long) size, (unsigned) count,
                  (int) s->protection, (int) s->max_protection,
                  shdw_sm_name(s->share_mode), (unsigned) s->share_mode,
                  (unsigned) s->user_tag, (unsigned) s->pages_resident,
                  (unsigned) s->pages_shared_now_private,
                  (unsigned) s->pages_dirtied, (int) s->is_submap);
}

// Writable executable text (pref Debug_MemTextMax). Dopamine's debug-signed
// launch maps every bundled framework's __TEXT with max_protection rwx, while
// a stock launch maps it r-x and keeps only the main executable at 5/5. A
// region walker that treats a run-writable code page as tamper evidence sees
// a jailbreak tell. Clear VM_PROT_WRITE from the reported max_protection of
// every executable region handed to an external caller; protection itself is
// already r-x and is left alone.
int shdw_diag_mem_textmax = 0;
static int shdw_textmax_budget = 256;

static void shdw_textmax_fix(const char *api, uintptr_t caller, uintptr_t base,
                             uintptr_t size, vm_region_info_t info,
                             mach_msg_type_number_t count) {
    if(!shdw_diag_mem_textmax || !info || count < 4) {
        return;
    }

    natural_t *w = (natural_t *) info;
    if(!(w[0] & VM_PROT_EXECUTE) || !(w[1] & VM_PROT_WRITE)) {
        return;
    }

    natural_t old = w[1];
    w[1] &= ~(natural_t) VM_PROT_WRITE;

    if(shdw_textmax_budget > 0) {
        shdw_textmax_budget--;
        shdw_diag_log("TEXTMAX %s caller=%p base=%p size=%#lx prot=%u max=%u->%u",
                      api, (void *) caller, (void *) base, (unsigned long) size,
                      (unsigned) w[0], (unsigned) old, (unsigned) w[1]);
    }
}

// Extended-info lane (prefs Debug_MemExtInfo / Debug_MemExtDirt). OZ asks
// vm_region_64 with flavor 9 on its own __TEXT base twice per launch (callers
// OZ+0x38dbe4 and OZ+0x596808) and consumes the reply; flavor 9 is the only
// flavor carrying pages_shared_now_private / pages_dirtied / share_mode, i.e.
// the exact COW fingerprint that inline-hook pages leave behind and that no
// other lane touches. Log the raw words for external callers, and under
// Debug_MemExtDirt report zero private/dirtied pages so the reply looks like a
// clean file-backed text mapping.
int shdw_diag_mem_extinfo = 0;
int shdw_diag_mem_extdirt = 0;
static int shdw_extinfo_budget = 64;

static void shdw_extinfo_probe(const char *api, uintptr_t caller, uintptr_t base,
                               uintptr_t size, vm_region_flavor_t flavor,
                               vm_region_info_t info, mach_msg_type_number_t count) {
    if((!shdw_diag_mem_extinfo && !shdw_diag_mem_extdirt) || !info || count < 8) {
        return;
    }

    natural_t *w = (natural_t *) info;

    if(shdw_diag_mem_extinfo && shdw_extinfo_budget > 0) {
        shdw_extinfo_budget--;
        shdw_diag_log("EXTINFO %s caller=%p base=%p size=%#lx flav=%d cnt=%u "
                      "w0=%u w1=%u w2=%u w3=%u w4=%u w5=%u w6=%#x w7=%#x w8=%#x w9=%#x w10=%#x",
                      api, (void *) caller, (void *) base, (unsigned long) size,
                      (int) flavor, (unsigned) count,
                      (unsigned) w[0], (unsigned) w[1], (unsigned) w[2], (unsigned) w[3],
                      (unsigned) w[4], (unsigned) w[5], (unsigned) w[6], (unsigned) w[7],
                      (unsigned) w[8], (unsigned) w[9], (unsigned) w[10]);
    }

    if(shdw_diag_mem_extdirt) {
        natural_t old3 = w[3], old5 = w[5];
        w[3] = 0;  // pages_shared_now_private
        w[5] = 0;  // pages_dirtied
        if(shdw_extinfo_budget > 0) {
            shdw_extinfo_budget--;
            shdw_diag_log("EXTDIRT %s caller=%p base=%p size=%#lx spriv=%u->0 dirt=%u->0",
                          api, (void *) caller, (void *) base, (unsigned long) size,
                          (unsigned) old3, (unsigned) old5);
        }
    }
}

// Split-page normalization (pref Debug_MemSplit). An inline hook installed by
// the substrate writes a code page of the dyld shared cache in place, so the
// kernel reports that page as a separate region with share_mode SM_COW and a
// writable max_protection, while every untouched fragment of the same cache
// mapping reports SM_PRIVATE/is_submap=1 and r--/r-- . A region walk that
// looks at those fields therefore sees a jailbreak tell. For external callers
// rewrite such a page to the fields of its nearest clean cache fragment, so
// the walk sees a homogeneous shared-cache mapping. The page's geometry
// (start/size) cannot be merged without knowing the cache file extent, so
// only the reported properties are normalized.
int shdw_diag_mem_split = 0;
static int shdw_split_fix_budget = 512;

typedef kern_return_t (*shdw_short_recurse_t)(vm_map_read_t target_task, vm_address_t* address,
                                              vm_size_t* size, natural_t* nesting_depth,
                                              vm_region_recurse_info_t info,
                                              mach_msg_type_number_t* infoCnt);

static int shdw_split_clean(const vm_region_submap_short_info_data_64_t* s) {
    return s->is_submap && s->share_mode == SM_PRIVATE &&
           !(s->max_protection & VM_PROT_WRITE);
}

// Find the nearest clean fragment of the same cache mapping by walking one
// page at a time in both directions (the scan is bounded; a hooked page is
// adjacent to clean fragments in practice).
static int shdw_split_template(shdw_short_recurse_t raw, uintptr_t base,
                               vm_region_submap_short_info_data_64_t* out,
                               uintptr_t* regionStart) {
    for(int dir = 0; dir < 2; dir++) {
        uintptr_t probe = base;
        for(int i = 0; i < 64; i++) {
            if(dir == 0) {
                if(probe < 0x4000) {
                    break;
                }
                probe -= 0x4000;
            } else {
                probe += 0x4000;
            }

            vm_address_t a = (vm_address_t) probe;
            vm_size_t sz = 0;
            natural_t depth = 0;
            vm_region_submap_short_info_data_64_t t;
            mach_msg_type_number_t c = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
            if(raw(mach_task_self(), &a, &sz, &depth,
                   (vm_region_recurse_info_t) &t, &c) != KERN_SUCCESS) {
                break;
            }
            if(c < VM_REGION_SUBMAP_SHORT_INFO_COUNT_64) {
                break;
            }
            if(shdw_split_clean(&t)) {
                *out = t;
                *regionStart = (uintptr_t) a;
                return 1;
            }
        }
    }
    return 0;
}

// Returns 1 when the caller's short submap reply was rewritten. Only the
// short flavor carries share_mode at the offset a hook page trips; the long
// flavor is left alone (no detector observed requesting it).
static int shdw_split_fix(uintptr_t base, uintptr_t size, vm_region_info_t info,
                          mach_msg_type_number_t count, uintptr_t caller) {
    if(!shdw_diag_mem_split || !info || count != VM_REGION_SUBMAP_SHORT_INFO_COUNT_64) {
        return 0;
    }

    vm_region_submap_short_info_data_64_t* s = (vm_region_submap_short_info_data_64_t*) info;
    if(shdw_split_clean(s) || !(s->max_protection & VM_PROT_WRITE)) {
        return 0;
    }

    if(shdw_split_fix_budget > 0) {
        shdw_split_fix_budget--;
        shdw_diag_log("SPLITCAND base=%p size=%#lx caller=%p sm=%u prot=%d/%d subm=%d off=%#lx",
                      (void *) base, (unsigned long) size, (void *) caller,
                      (unsigned) s->share_mode, (int) s->protection,
                      (int) s->max_protection, (int) s->is_submap,
                      (unsigned long) s->offset);
    }

    shdw_short_recurse_t raw = (shdw_short_recurse_t) shdw_diag_raw_dlsym("vm_region_recurse_64");
    if(!raw) {
        shdw_diag_log("SPLITNO base=%p reason=no-raw", (void *) base);
        return 0;
    }

    vm_region_submap_short_info_data_64_t t;
    uintptr_t rs = 0;
    if(!shdw_split_template(raw, base, &t, &rs)) {
        shdw_diag_log("SPLITNO base=%p reason=no-template", (void *) base);
        return 0;
    }

    // The template's offset is the file offset of its region start; the
    // queried page sits at the same file offset plus its distance from that
    // start. This needs no knowledge of the cache base address.
    int64_t offset = (int64_t) (uintptr_t) t.offset + ((int64_t) base - (int64_t) rs);
    if(offset < 0) {
        shdw_diag_log("SPLITNO base=%p reason=neg-offset rs=%p off=%#lx",
                      (void *) base, (void *) rs, (unsigned long) t.offset);
        return 0;
    }

    unsigned int oldShare = s->share_mode;
    *s = t;
    s->offset = (memory_object_offset_t) offset;

    if(shdw_split_fix_budget > 0) {
        shdw_split_fix_budget--;
        shdw_diag_log("SPLITFIX base=%p size=%#lx caller=%p sm=%u->%u off=%#lx max=%d/%d",
                      (void *) base, (unsigned long) size, (void *) caller,
                      oldShare, (unsigned) s->share_mode,
                      (unsigned long) s->offset, (int) s->protection,
                      (int) s->max_protection);
    }
    return 1;
}

// Executable images always begin with a Mach-O header; an executable region
// that does not is a page carved out of an image body (per-page protections,
// code pages of a live-protected framework) or a private stub arena. A region
// walker that treats every executable region start as an image start then
// reads a headerless page and reports a corrupt image. Present only real image
// starts as executable regions; the rest of an image body is not something a
// stock self-inspection loop needs to see as its own region.
// Applies to the SEQUENTIAL lane only (vm_region_recurse_64,
// mach_vm_region_recurse). A point query (vm_region_64, mach_vm_region) is a
// "which region contains this address" lookup whose contract is that the
// returned start is <= the query; skipping there hands back a start BEYOND
// the query and lets a caller that steps by the returned size see a false hole
// where a contiguous image body sits.
static int shdw_mem_is_image_header(uintptr_t start, int prot) {
    if(!(prot & VM_PROT_READ)) {
        return 1;  // cannot classify without reading: leave the region alone
    }

    uint32_t magic = 0;
    memcpy(&magic, (const void *) start, sizeof magic);
    return magic == 0xfeedface || magic == 0xfeedfacf ||
           magic == 0xcefaedfe || magic == 0xcffaedfe;
}

// vm_region policy: a returned region whose start address lies inside a
// restricted image interval is SKIPPED — the original is re-called to
// advance to the next region — instead of having its protection bits
// rewritten. Mutating VM_PROT_EXECUTE (the old blanket-NX) contradicts the
// region's max_protection and fingerprints the hook; skipping restricted
// intervals removes the mapping enumeration leak while leaving every other
// region byte-identical to stock. Regions that cannot be classified pass
// through UNCHANGED (protection is never mutated).
// A targeted probe reads the protection of the region that BACKS a specific
// function it names (detect_jb_payload passes &vm_region_64 as the search
// address and flags protection != VM_PROT_READ). Under Shadow the named symbol
// is rebound into ShadowCore, so the query lands in a restricted image. Neither
// answer is right: returning ShadowCore's executable __TEXT reveals injection
// (protection has EXECUTE), and skipping to the next region leaks a neighbouring
// mapping's protection. A stock process would find that function in a system
// library whose region reports VM_PROT_READ. So when an external caller's query
// address falls INSIDE a restricted region (a targeted point query, not the
// start-of-region step an enumeration loop makes), keep the region but present
// the stock read-only protection and drop the object name — the mapping looks
// like an ordinary system __TEXT instead of an injected or skipped region.
// A signed image's __TEXT is not writable on a device with code-signing
// enforcement: a vm_protect/mprotect that adds write access to it fails. On a
// device where enforcement is off the same call succeeds, which is a direct
// runtime fingerprint on either the loader or the kernel. Emulate the stock
// answer for external callers; anonymous pages (JIT, allocations) keep their
// real answer.
static int shdw_range_overlaps_image_text(uintptr_t addr, size_t size) {
    if(size == 0) {
        size = 1;
    }
    uintptr_t end = addr + size;
    uint32_t count = _dyld_image_count();
    for(uint32_t i = 0; i < count; i++) {
        const struct mach_header_64* mh = (const struct mach_header_64*) _dyld_get_image_header(i);
        if(!mh || mh->magic != MH_MAGIC_64) {
            continue;
        }
        uintptr_t slide = (uintptr_t) _dyld_get_image_vmaddr_slide(i);
        const struct load_command* lc = (const struct load_command*) (mh + 1);
        for(uint32_t j = 0; j < mh->ncmds; j++) {
            if(lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64* sc = (const struct segment_command_64*) lc;
                if(!strcmp(sc->segname, "__TEXT")) {
                    uintptr_t start = slide + (uintptr_t) sc->vmaddr;
                    if(addr < start + (uintptr_t) sc->vmsize && end > start) {
                        return 1;
                    }
                }
            }
            lc = (const struct load_command*) ((const char*) lc + lc->cmdsize);
        }
    }
    return 0;
}

static kern_return_t (*original_vm_protect)(vm_map_t target_task, vm_address_t address, vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection);
static kern_return_t replaced_vm_protect(vm_map_t target_task, vm_address_t address, vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection) {
    uintptr_t caller = (uintptr_t) __builtin_extract_return_addr(__builtin_return_address(0));
    BOOL external = isCallerExternal();

    shdw_diag_trace_image_entry(__builtin_return_address(0),
                                "vm_protect addr=%p size=%lu prot=%d setmax=%d",
                                (void*)(uintptr_t)address, (unsigned long)size,
                                (int)new_protection, (int)set_maximum);

    if(external && target_task == mach_task_self() && (new_protection & VM_PROT_WRITE) &&
       shdw_range_overlaps_image_text((uintptr_t) address, (size_t) size)) {
        shdw_mem_trace("vm_protect", caller, (uintptr_t) address, (uintptr_t) address,
                       (uintptr_t) size, (int) new_protection, -1, -1, "deny-text");
        return KERN_PROTECTION_FAILURE;
    }

    return original_vm_protect(target_task, address, size, set_maximum, new_protection);
}

static int (*original_mprotect)(void* addr, size_t len, int prot);
static int replaced_mprotect(void* addr, size_t len, int prot) {
    uintptr_t caller = (uintptr_t) __builtin_extract_return_addr(__builtin_return_address(0));
    BOOL external = isCallerExternal();

    shdw_diag_trace_image_entry(__builtin_return_address(0),
                                "mprotect addr=%p len=%lu prot=%d",
                                addr, (unsigned long)len, prot);

    if(external && (prot & PROT_WRITE) && shdw_range_overlaps_image_text((uintptr_t) addr, len)) {
        shdw_mem_trace("mprotect", caller, (uintptr_t) addr, (uintptr_t) addr,
                       (uintptr_t) len, prot, -1, -1, "deny-text");
        errno = EACCES;
        return -1;
    }

    return original_mprotect(addr, len, prot);
}

static kern_return_t (*original_vm_region_64)(vm_map_read_t target_task, vm_address_t* address, vm_size_t* size, vm_region_flavor_t flavor, vm_region_info_t info, mach_msg_type_number_t* infoCnt, mach_port_t* object_name);
static kern_return_t replaced_vm_region_64(vm_map_read_t target_task, vm_address_t* address, vm_size_t* size, vm_region_flavor_t flavor, vm_region_info_t info, mach_msg_type_number_t* infoCnt, mach_port_t* object_name) {
    shdw_diag_trace_image_entry(__builtin_return_address(0), "vm_region_64 addr=%p flavor=%d", (void*)(address ? (uintptr_t)*address : 0), (int)flavor);
    vm_address_t queryAddr = address ? *address : 0;
    uintptr_t caller = (uintptr_t) __builtin_extract_return_addr(__builtin_return_address(0));
    BOOL external = isCallerExternal();
    for(;;) {
        kern_return_t result = original_vm_region_64(target_task, address, size, flavor, info, infoCnt, object_name);

        int prot = -1, maxprot = -1;
        if(result == KERN_SUCCESS && flavor == VM_REGION_BASIC_INFO_64 && infoCnt &&
           *infoCnt >= VM_REGION_BASIC_INFO_COUNT_64) {
            vm_region_basic_info_64_t basic = (vm_region_basic_info_64_t) info;
            prot = (int) basic->protection;
            maxprot = (int) basic->max_protection;
        }

        if(result != KERN_SUCCESS) {
            if(external) {
                shdw_mem_trace("vm_region_64", caller, queryAddr, 0, 0, -1, -1, -1, "fail");
            }
            return result;
        }

        BOOL restricted = external && shdw_addr_is_restricted((void *) *address);
        BOOL opaque = external && !restricted && !shdw_diag_mem_opaque_pass &&
                      prot > 0 && (prot & VM_PROT_EXECUTE) &&
                      !shdw_mem_is_image_header((uintptr_t) *address, prot);
        if(external) {
            shdw_mem_trace("vm_region_64", caller, queryAddr, (uintptr_t) *address,
                           (uintptr_t) *size, prot, maxprot, restricted ? 1 : 0,
                           opaque ? "opaque-pass" : "seen");
        }
        if(external && !restricted && flavor == 9) {
            shdw_extinfo_probe("vm_region_64", caller, (uintptr_t) *address,
                               (uintptr_t) *size, flavor, info, infoCnt ? *infoCnt : 0);
        }
        if(external && !restricted) {
            shdw_textmax_fix("vm_region_64", caller, (uintptr_t) *address,
                             (uintptr_t) *size, info, infoCnt ? *infoCnt : 0);
        }

        // Point-query contract: the containing region is always reported. An
        // opaque executable page stays visible here (see the helper comment).
        if(!restricted) {
            return result;
        }

        // Targeted point query: the caller's search address lies STRICTLY
        // inside the restricted region just returned (queryAddr > region start).
        // An enumeration loop instead steps to successive region starts, where
        // queryAddr == region start; excluding equality leaves enumeration on
        // the skip path so mappings are still hidden, while a point query at a
        // function address gets the stock read-only mapping. Present it as a
        // read-only system __TEXT rather than skipping (which would leak the
        // next region's protection) or exposing ShadowCore's executable text.
        if(flavor == VM_REGION_BASIC_INFO_64 && infoCnt && *infoCnt >= VM_REGION_BASIC_INFO_COUNT_64 &&
           *address < queryAddr && queryAddr < *address + *size) {
            vm_region_basic_info_64_t basic = (vm_region_basic_info_64_t) info;
            basic->protection = VM_PROT_READ;
            basic->max_protection = VM_PROT_READ;
            if(object_name && *object_name != MACH_PORT_NULL) {
                mach_port_deallocate(mach_task_self(), *object_name);
                *object_name = MACH_PORT_NULL;
            }
            shdw_mem_trace("vm_region_64", caller, queryAddr, (uintptr_t) *address,
                           (uintptr_t) *size, VM_PROT_READ, VM_PROT_READ, restricted ? 1 : 0,
                           "point");
            return result;
        }

        // Restricted region: drop the object-name send right this skipped
        // call returned (it is ours to deallocate) and advance the search
        // address past the region. vm_region_64 does NOT advance *address
        // itself — on success it returns the region CONTAINING the input
        // address with *address set to that region's START, and callers
        // advance by the returned size (the step every stock iteration loop
        // takes). Without the advance the re-call returns the same region
        // forever.
        if(object_name && *object_name != MACH_PORT_NULL) {
            mach_port_deallocate(mach_task_self(), *object_name);
            *object_name = MACH_PORT_NULL;
        }

        shdw_mem_trace("vm_region_64", caller, queryAddr, (uintptr_t) *address,
                       (uintptr_t) *size, prot, maxprot, restricted ? 1 : 0,
                       "skip");
        *address += *size;
    }
}

static kern_return_t (*original_vm_region_recurse_64)(vm_map_read_t target_task, vm_address_t* address, vm_size_t* size, natural_t* nesting_depth, vm_region_recurse_info_t info, mach_msg_type_number_t* infoCnt);
static kern_return_t replaced_vm_region_recurse_64(vm_map_read_t target_task, vm_address_t* address, vm_size_t* size, natural_t* nesting_depth, vm_region_recurse_info_t info, mach_msg_type_number_t* infoCnt) {
    vm_address_t queryAddr = address ? *address : 0;
    uintptr_t caller = (uintptr_t) __builtin_extract_return_addr(__builtin_return_address(0));
    BOOL external = isCallerExternal();

    shdw_diag_trace_image_entry(__builtin_return_address(0),
                                "vm_region_recurse_64 addr=%p",
                                (void*)queryAddr);
    for(;;) {
        mach_msg_type_number_t entryCnt = infoCnt ? *infoCnt : 0;
        kern_return_t result = original_vm_region_recurse_64(target_task, address, size, nesting_depth, info, infoCnt);

        int prot = -1, maxprot = -1;
        if(result == KERN_SUCCESS && info && infoCnt && *infoCnt >= 4) {
            // Every recurse info flavor (selected by infoCnt) begins with
            // protection and max_protection.
            vm_region_submap_info_64_t submap = (vm_region_submap_info_64_t) info;
            prot = (int) submap->protection;
            maxprot = (int) submap->max_protection;
        }
        if(result == KERN_SUCCESS && external) {
            shdw_split_fix((uintptr_t) *address, (uintptr_t) *size, info,
                           infoCnt ? *infoCnt : 0, caller);
            shdw_share_trace("vm_region_recurse_64", caller, (uintptr_t) *address,
                             (uintptr_t) *size, infoCnt ? *infoCnt : 0, entryCnt, info);
        }

        if(result != KERN_SUCCESS) {
            if(external) {
                shdw_mem_trace("vm_region_recurse_64", caller, queryAddr, 0, 0, -1, -1, -1, "fail");
            }
            return result;
        }

        BOOL restricted = external && shdw_addr_is_restricted((void *) *address);
        BOOL opaque = external && !restricted && !shdw_diag_mem_opaque_pass &&
                      prot > 0 && (prot & VM_PROT_EXECUTE) &&
                      !shdw_mem_is_image_header((uintptr_t) *address, prot);
        if(external) {
            shdw_mem_trace("vm_region_recurse_64", caller, queryAddr, (uintptr_t) *address,
                           (uintptr_t) *size, prot, maxprot, restricted ? 1 : 0,
                           opaque ? "opaque-seen" : "seen");
        }
        if(external && !restricted) {
            shdw_textmax_fix("vm_region_recurse_64", caller, (uintptr_t) *address,
                             (uintptr_t) *size, info, infoCnt ? *infoCnt : 0);
        }

        if(!restricted && !opaque) {
            return result;
        }

        // No *address auto-advance in this API: skip past the restricted
        // region manually (see replaced_vm_region_64).
        shdw_mem_trace("vm_region_recurse_64", caller, queryAddr, (uintptr_t) *address,
                       (uintptr_t) *size, prot, maxprot, restricted ? 1 : 0,
                       opaque ? "skip-opaque" : "skip");
        *address += *size;
    }
}

// mach_vm_region/mach_vm_region_recurse: the mach_vm_* twins of the two
// hooks above — same enumeration semantics over 64-bit address/size types,
// same skip policy (a returned region inside a restricted interval is
// SKIPPED and the original re-called to advance). The SDK's mach_vm.h is a
// stub, so the prototypes are declared here. NOTE: mach_vm_region takes the
// flavor BY VALUE (the ABI requires a value, not a pointer — a pointer
// earlier revision was an ABI bug: the hook passed a pointer where the
// kernel expects the int flavor, so the original call returned
// KERN_INVALID_ARGUMENT and the hiding never engaged, and callers of
// mach_vm_region got an error instead of region info).
extern kern_return_t mach_vm_region(vm_map_read_t target_task, mach_vm_address_t* address, mach_vm_size_t* size, vm_region_flavor_t flavor, vm_region_info_t info, mach_msg_type_number_t* infoCnt, mach_port_t* object_name);
static kern_return_t (*original_mach_vm_region)(vm_map_read_t target_task, mach_vm_address_t* address, mach_vm_size_t* size, vm_region_flavor_t flavor, vm_region_info_t info, mach_msg_type_number_t* infoCnt, mach_port_t* object_name);
static kern_return_t replaced_mach_vm_region(vm_map_read_t target_task, mach_vm_address_t* address, mach_vm_size_t* size, vm_region_flavor_t flavor, vm_region_info_t info, mach_msg_type_number_t* infoCnt, mach_port_t* object_name) {
    shdw_diag_trace_image_entry(__builtin_return_address(0), "mach_vm_region addr=%p flavor=%d", (void*)(address ? (uintptr_t)*address : 0), (int)flavor);
    mach_vm_address_t queryAddr = address ? *address : 0;
    uintptr_t caller = (uintptr_t) __builtin_extract_return_addr(__builtin_return_address(0));
    BOOL external = isCallerExternal();
    for(;;) {
        kern_return_t result = original_mach_vm_region(target_task, address, size, flavor, info, infoCnt, object_name);

        int prot = -1, maxprot = -1;
        if(result == KERN_SUCCESS && flavor == VM_REGION_BASIC_INFO_64 && infoCnt &&
           *infoCnt >= VM_REGION_BASIC_INFO_COUNT_64) {
            vm_region_basic_info_64_t basic = (vm_region_basic_info_64_t) info;
            prot = (int) basic->protection;
            maxprot = (int) basic->max_protection;
        }

        if(result != KERN_SUCCESS) {
            if(external) {
                shdw_mem_trace("mach_vm_region", caller, (uintptr_t) queryAddr, 0, 0, -1, -1, -1, "fail");
            }
            return result;
        }

        BOOL restricted = external && shdw_addr_is_restricted((void *) (uintptr_t) *address);
        BOOL opaque = external && !restricted && !shdw_diag_mem_opaque_pass &&
                      prot > 0 && (prot & VM_PROT_EXECUTE) &&
                      !shdw_mem_is_image_header((uintptr_t) *address, prot);
        if(external) {
            shdw_mem_trace("mach_vm_region", caller, (uintptr_t) queryAddr,
                           (uintptr_t) *address, (uintptr_t) *size, prot, maxprot,
                           restricted ? 1 : 0, opaque ? "opaque-pass" : "seen");
        }
        if(external && !restricted) {
            shdw_textmax_fix("mach_vm_region", caller, (uintptr_t) *address,
                             (uintptr_t) *size, info, infoCnt ? *infoCnt : 0);
        }

        // Point-query contract: the containing region is always reported (see
        // the helper comment above).
        if(!restricted) {
            return result;
        }

        // Restricted region: drop the object-name send right this skipped
        // call returned (it is ours to deallocate) and advance to the next
        // region — same loop discipline as the vm_region_64 hook above
        // (mach_vm_region likewise does not advance *address on return).
        if(object_name && *object_name != MACH_PORT_NULL) {
            mach_port_deallocate(mach_task_self(), *object_name);
            *object_name = MACH_PORT_NULL;
        }

        shdw_mem_trace("mach_vm_region", caller, (uintptr_t) queryAddr,
                       (uintptr_t) *address, (uintptr_t) *size, prot, maxprot,
                       restricted ? 1 : 0, "skip");
        *address += *size;
    }
}

extern kern_return_t mach_vm_region_recurse(vm_map_read_t target_task, mach_vm_address_t* address, mach_vm_size_t* size, natural_t* nesting_depth, vm_region_recurse_info_t info, mach_msg_type_number_t* infoCnt);
static kern_return_t (*original_mach_vm_region_recurse)(vm_map_read_t target_task, mach_vm_address_t* address, mach_vm_size_t* size, natural_t* nesting_depth, vm_region_recurse_info_t info, mach_msg_type_number_t* infoCnt);
static kern_return_t replaced_mach_vm_region_recurse(vm_map_read_t target_task, mach_vm_address_t* address, mach_vm_size_t* size, natural_t* nesting_depth, vm_region_recurse_info_t info, mach_msg_type_number_t* infoCnt) {
    mach_vm_address_t queryAddr = address ? *address : 0;
    uintptr_t caller = (uintptr_t) __builtin_extract_return_addr(__builtin_return_address(0));
    BOOL external = isCallerExternal();
    for(;;) {
        mach_msg_type_number_t entryCnt = infoCnt ? *infoCnt : 0;
        kern_return_t result = original_mach_vm_region_recurse(target_task, address, size, nesting_depth, info, infoCnt);

        int prot = -1, maxprot = -1;
        if(result == KERN_SUCCESS && info && infoCnt && *infoCnt >= 4) {
            vm_region_submap_info_64_t submap = (vm_region_submap_info_64_t) info;
            prot = (int) submap->protection;
            maxprot = (int) submap->max_protection;
        }
        if(result == KERN_SUCCESS && external) {
            shdw_split_fix((uintptr_t) *address, (uintptr_t) *size, info,
                           infoCnt ? *infoCnt : 0, caller);
            shdw_share_trace("mach_vm_region_recurse", caller, (uintptr_t) *address,
                             (uintptr_t) *size, infoCnt ? *infoCnt : 0, entryCnt, info);
        }

        if(result != KERN_SUCCESS) {
            if(external) {
                shdw_mem_trace("mach_vm_region_recurse", caller, (uintptr_t) queryAddr, 0, 0, -1, -1, -1, "fail");
            }
            return result;
        }

        BOOL restricted = external && shdw_addr_is_restricted((void *) (uintptr_t) *address);
        BOOL opaque = external && !restricted && !shdw_diag_mem_opaque_pass &&
                      prot > 0 && (prot & VM_PROT_EXECUTE) &&
                      !shdw_mem_is_image_header((uintptr_t) *address, prot);
        if(external) {
            shdw_mem_trace("mach_vm_region_recurse", caller, (uintptr_t) queryAddr,
                           (uintptr_t) *address, (uintptr_t) *size, prot, maxprot,
                           restricted ? 1 : 0, opaque ? "opaque-seen" : "seen");
        }
        if(external && !restricted) {
            shdw_textmax_fix("mach_vm_region_recurse", caller, (uintptr_t) *address,
                             (uintptr_t) *size, info, infoCnt ? *infoCnt : 0);
        }

        if(!restricted && !opaque) {
            return result;
        }

        // No *address auto-advance in this API: skip past the restricted
        // region manually (see replaced_vm_region_64).
        shdw_mem_trace("mach_vm_region_recurse", caller, (uintptr_t) queryAddr,
                       (uintptr_t) *address, (uintptr_t) *size, prot, maxprot,
                       restricted ? 1 : 0, opaque ? "skip-opaque" : "skip");
        *address += *size;
    }
}

typedef kern_return_t (*shdw_recurse_raw_t)(vm_map_read_t target_task, vm_address_t* address,
                                            vm_size_t* size, natural_t* nesting_depth,
                                            vm_region_recurse_info_t info,
                                            mach_msg_type_number_t* infoCnt);

static shdw_recurse_raw_t shdw_share_raw_recurse(void) {
    if(original_vm_region_recurse_64) {
        return original_vm_region_recurse_64;
    }
    return (shdw_recurse_raw_t) shdw_diag_raw_dlsym("vm_region_recurse_64");
}

static int shdw_share_image_text(const struct mach_header_64* mh, uintptr_t slide,
                                 uintptr_t* start, uintptr_t* size) {
    if(!mh || mh->magic != MH_MAGIC_64) {
        return 0;
    }

    const struct load_command* lc = (const struct load_command*) (mh + 1);
    for(uint32_t j = 0; j < mh->ncmds; j++) {
        if(lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64* sc = (const struct segment_command_64*) lc;
            if(!strcmp(sc->segname, "__TEXT")) {
                *start = slide + (uintptr_t) sc->vmaddr;
                *size = (uintptr_t) sc->vmsize;
                return 1;
            }
        }
        lc = (const struct load_command*) ((const char*) lc + lc->cmdsize);
    }
    return 0;
}

// One-shot ctor snapshot (pref Debug_MemShare): the __TEXT of every loaded
// image, walked region by region with the submap flavor so share_mode and
// the page counters are visible. A stock process reports the dyld-cache
// code pages as SM_SHARED with pages_shared_now_private 0; a process whose
// tweak wrote a page reports a split region with SM_COW/SM_PRIVATE and a
// non-zero private count for exactly the hooked page. Data-only.
void shdw_mem_share_dump(void) {
    if(!shdw_diag_enabled || !shdw_diag_mem_share) {
        return;
    }

    shdw_recurse_raw_t raw = shdw_share_raw_recurse();
    if(!raw) {
        shdw_diag_log("IMGSHARE no raw recurse entry");
        return;
    }

    uint32_t count = _dyld_image_count();
    int images = 0;
    int splits = 0;
    for(uint32_t i = 0; i < count; i++) {
        const struct mach_header_64* mh = (const struct mach_header_64*) _dyld_get_image_header(i);
        uintptr_t slide = (uintptr_t) _dyld_get_image_vmaddr_slide(i);
        uintptr_t start = 0, size = 0;
        if(!shdw_share_image_text(mh, slide, &start, &size) || !size) {
            continue;
        }

        images++;
        const char* name = _dyld_get_image_name(i);
        uintptr_t cur = start;
        uintptr_t end = start + size;
        int segs = 0;
        while(cur < end && segs < 32 && shdw_share_dump_budget > 0) {
            vm_address_t addr = (vm_address_t) cur;
            vm_size_t rsize = 0;
            natural_t depth = 0;
            vm_region_submap_info_data_64_t info;
            mach_msg_type_number_t ic = VM_REGION_SUBMAP_INFO_COUNT_64;
            kern_return_t kr = raw(mach_task_self(), &addr, &rsize, &depth,
                                   (vm_region_recurse_info_t) &info, &ic);
            if(kr != KERN_SUCCESS) {
                shdw_diag_log("IMGSHARE i=%u %s text=%p+%#lx walk=ERR kr=%d",
                              i, name ? name : "?", (void *) start,
                              (unsigned long) size, (int) kr);
                break;
            }

            shdw_share_dump_budget--;
            segs++;
            shdw_diag_log("IMGSHARE i=%u seg=%d %s text=%p+%#lx reg=%p+%#lx prot=%d/%d sm=%s(%u) tag=%#x res=%u spriv=%u dirt=%u subm=%d obj=%#x",
                          i, segs - 1, name ? name : "?", (void *) start,
                          (unsigned long) size, (void *) (uintptr_t) addr,
                          (unsigned long) rsize, (int) info.protection,
                          (int) info.max_protection,
                          shdw_sm_name(info.share_mode), (unsigned) info.share_mode,
                          (unsigned) info.user_tag, (unsigned) info.pages_resident,
                          (unsigned) info.pages_shared_now_private,
                          (unsigned) info.pages_dirtied, (int) info.is_submap,
                          (unsigned) info.object_id);

            uintptr_t next = (uintptr_t) addr + (uintptr_t) rsize;
            if(next <= cur) {
                break;
            }
            cur = next;
        }

        if(segs > 1) {
            splits++;
        }
        if(shdw_share_dump_budget <= 0) {
            shdw_diag_log("IMGSHARE budget exhausted at i=%u", i);
            break;
        }
    }

    shdw_diag_log("IMGSHARE done images=%d splits=%d", images, splits);
}

// Symbol policy for the mem C-function group (see dyld.x's
// shdw_sym_policy_table). A member is substituted for external dlsym callers
// ONLY when its hook had to be installed through the import-slot lane: that
// lane leaves the caller's slot holding the replacement, so dlsym must hand
// back the same address or a GOT-vs-dlsym comparison sees a mismatch. When the
// entrypoint lane installed (a text patch on the shared-cache function), the
// import slots and the exported symbol keep their genuine libsystem_kernel
// address and the patched prologue redirects control instead: no substitution,
// so dlsym, dladdr and the caller's own slot all still name the system
// function while the replacement still runs.
typedef struct {
    const char* name;
    void* replacement;
    void* const* original;
    BOOL entrypointLane;
    BOOL substituteSymbol;
} shdw_mem_sym_policy_entry_t;

static shdw_mem_sym_policy_entry_t shdw_mem_sym_policy_table[] = {
    { "mach_vm_region", (void*)&replaced_mach_vm_region, (void* const*)&original_mach_vm_region, NO, YES },
    { "mach_vm_region_recurse", (void*)&replaced_mach_vm_region_recurse, (void* const*)&original_mach_vm_region_recurse, NO, YES },
    { "vm_region_64", (void*)&replaced_vm_region_64, (void* const*)&original_vm_region_64, NO, YES },
    { "vm_region_recurse_64", (void*)&replaced_vm_region_recurse_64, (void* const*)&original_vm_region_recurse_64, NO, YES },
    { "vm_protect", (void*)&replaced_vm_protect, (void* const*)&original_vm_protect, NO, YES },
    { "mprotect", (void*)&replaced_mprotect, (void* const*)&original_mprotect, NO, YES },
};

static shdw_mem_sym_policy_entry_t* shdw_mem_policy_row(const char* name) {
    if(!name) {
        return NULL;
    }
    for(size_t i = 0; i < sizeof(shdw_mem_sym_policy_table) / sizeof(shdw_mem_sym_policy_table[0]); i++) {
        if(strcmp(name, shdw_mem_sym_policy_table[i].name) == 0) {
            return &shdw_mem_sym_policy_table[i];
        }
    }
    return NULL;
}

static void shdw_install_memory_hook(SHDWHookSession* hooks, void* target,
                                     void* replacement, void** original,
                                     NSString* symbol) {
    shdw_mem_sym_policy_entry_t* row = shdw_mem_policy_row(symbol.UTF8String);
    BOOL entrypointInstalled = NO;
    BOOL substitute = YES;

    if(shdw_diag_mem_lane == 1) {
        [hooks hookRebindSymbol:symbol
                withReplacement:replacement
                       outOldPtr:original];
        // The import slots now hold the replacement, so dlsym must hand the
        // same address back; exporting the raw libsystem_kernel entry gives
        // any dlsym caller a pointer that never reaches the hook.
    } else if(shdw_diag_mem_lane == 2) {
        entrypointInstalled = [hooks hookFunction:target
                                 withReplacement:replacement
                                        outOldPtr:original];
        [hooks hookRebindSymbol:symbol
                withReplacement:replacement
                       outOldPtr:entrypointInstalled ? NULL : original];
    } else {
        entrypointInstalled = [hooks hookFunction:target
                                 withReplacement:replacement
                                        outOldPtr:original];
        // Only a caller whose import slot still holds the genuine address
        // needs the slot rewritten: that happens when the text patch could
        // not install. Rebinding on top of a successful entrypoint patch
        // would move the exported function's address out of
        // libsystem_kernel for every observer.
        if(!entrypointInstalled) {
            [hooks hookRebindSymbol:symbol
                    withReplacement:replacement
                           outOldPtr:original];
        } else {
            substitute = NO;
        }
    }

    if(row) {
        row->entrypointLane = entrypointInstalled;
        row->substituteSymbol = substitute;
    }
}

void shdw_universal_memory(SHDWHookSession* hooks) {
    shdw_install_memory_hook(hooks, vm_region_64, replaced_vm_region_64,
                             (void **) &original_vm_region_64, @"vm_region_64");
    shdw_install_memory_hook(hooks, vm_region_recurse_64, replaced_vm_region_recurse_64,
                             (void **) &original_vm_region_recurse_64, @"vm_region_recurse_64");
    shdw_install_memory_hook(hooks, mach_vm_region, replaced_mach_vm_region,
                             (void **) &original_mach_vm_region, @"mach_vm_region");
    shdw_install_memory_hook(hooks, mach_vm_region_recurse, replaced_mach_vm_region_recurse,
                             (void **) &original_mach_vm_region_recurse, @"mach_vm_region_recurse");
    shdw_install_memory_hook(hooks, vm_protect, replaced_vm_protect,
                             (void **) &original_vm_protect, @"vm_protect");
    shdw_install_memory_hook(hooks, mprotect, replaced_mprotect,
                             (void **) &original_mprotect, @"mprotect");

    if(!original_vm_protect) {
        original_vm_protect = (kern_return_t (*)(vm_map_t, vm_address_t, vm_size_t, boolean_t, vm_prot_t)) shdw_diag_raw_dlsym("vm_protect");
    }
    if(!original_mprotect) {
        original_mprotect = (int (*)(void*, size_t, int)) shdw_diag_raw_dlsym("mprotect");
    }
}

void* shdw_sym_policy_lookup_mem(const char* name) {
    shdw_mem_sym_policy_entry_t* row = shdw_mem_policy_row(name);
    if(!row) {
        return NULL;
    }

    // The symbol keeps its genuine libsystem_kernel address unless this row
    // had to be installed through the import-slot lane (see the table note).
    if(!row->substituteSymbol) {
        return NULL;
    }

    if(row->original && *row->original == NULL) {
        return NULL;  // symbol not installed
    }

    return row->replacement;
}

// Reverse of the policy lookup: given a replacement address (what dlsym or a
// rebound import slot hands a caller for a hooked vm_region export), return
// the original libsystem_kernel function so dladdr() on it resolves to the
// genuine system image (a function-origin check). Mirrors
// shdw_sym_original_for_replacement_libc.
void* shdw_sym_original_for_replacement_mem(const void* addr) {
    if(!addr) {
        return NULL;
    }
    for(size_t i = 0; i < sizeof(shdw_mem_sym_policy_table) / sizeof(shdw_mem_sym_policy_table[0]); i++) {
        if(shdw_mem_sym_policy_table[i].replacement == addr) {
            if(!shdw_mem_sym_policy_table[i].original || !*shdw_mem_sym_policy_table[i].original) {
                return NULL;
            }
            return *shdw_mem_sym_policy_table[i].original;
        }
    }
    return NULL;
}
