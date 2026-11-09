#import "AdapterHooks.h"

#include <dlfcn.h>
#include <fcntl.h>
#include <libkern/OSCacheControl.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <mach/vm_region.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

// PureLiveSDK (bank face-liveness SDK) + FaceTecSDK (its 3D face engine).
// Both run obfuscated Swift/C++ verifiers; the only sound anchors are the
// instruction bodies. Rows are keyed by the image LC_UUID and guarded by an
// 8-byte prologue, so an unknown app build installs nothing and behaves
// exactly as it would without Shadow.
//
// Kill chain (verified on Wise 9.116 / PureLiveSDK c8db8ceb, FaceTecSDK
// 67e0fb93, iOS 18.6.2 / Dopamine 3.0):
//   1. PureLive once-initializers seal poison values into slot60 and slotVERD
//      (0xfe14, 0x21da4, 0x12f88, 0x6c3510). check60/VERD then compare the
//      slot against its expected constant, mismatch -> brk #1 (0x45e0) or
//      abort2 (0x6ba858).
//   2. The dirty path then reseals slotVERD (0x6db9f0) and reads the
//      jailbreak verdict byte [0x1075208]; bit0 set -> abort2.
//   3. PureLive also forces the two clean-gate results (0x36ad8, 0x1587c);
//      with the slots left legitimate this makes every verifier gate pass.
//   4. Last layer: FaceTec's own 237248-byte self-compare (handler at
//      0x342044/0x347ed8) exits early at idx 23488 and sets the mismatch flag
//      that poisons the worker thread (SIGSEGV at pc=0x1c). Forcing the flag
//      word to 0 at 0x347ee4 removes that decision.
//
// OZLivenessSDK (Regula, bundled with bcc) is the same shape: one validator
// function at 0x38d980 funnels every sub-check into
//   0x38ee70  and w8,w8,#1
//   0x38ee74  cbnz w8, <next check>
//   ...       b <poison 0x38da60: writes 0xc into saved fp/LR, brk #1>
// so bit0 clear means "dirty" and the poison runs. Forcing w8=1 selects the
// non-poison branch for all five sub-checks at once.
//
// All rows are "disable-style": they force a detector's result to clean, so,
// like MobileProtect's verdict forcing, they install only in aggressive mode.
typedef struct {
    uint32_t offset;
    uint8_t prologue[8];
    uint32_t replacement;
} shdw_pl_patch_t;

typedef struct {
    const char* imageSuffix;
    uint8_t uuid[16];
    const shdw_pl_patch_t* patches;
    unsigned patchCount;
    uint8_t svcImageGuard;    // skip raw-svc rewrites inside this image
    uint8_t svcProcessGuard;  // process hashes its own text: keep svc lane native
} shdw_pl_image_t;

static const shdw_pl_patch_t shdw_pl_purelive_patches[] = {
    // str x8,[x9] sealing slot60 -> nop
    { 0xfe14,   { 0x28, 0x01, 0x00, 0xf9, 0x28, 0x83, 0x00, 0xd0 }, 0xd503201fu },
    // str x8,[x9] sealing slotVERD -> nop
    { 0x21da4,  { 0x28, 0x01, 0x00, 0xf9, 0xa8, 0x82, 0x00, 0x90 }, 0xd503201fu },
    // str x8,[x9] reseal2 (slot60) -> nop
    { 0x12f88,  { 0x28, 0x01, 0x00, 0xf9, 0x68, 0x49, 0x00, 0xb0 }, 0xd503201fu },
    // str x8,[x9] reseal-store (slot60) -> nop
    { 0x6c3510, { 0x28, 0x01, 0x00, 0xf9, 0x88, 0x4d, 0x00, 0xd0 }, 0xd503201fu },
    // tbz w8,#0 -> abort2; force the non-abort path
    { 0x6dba04, { 0x48, 0x00, 0x00, 0x36, 0x84, 0x7b, 0xff, 0x17 }, 0x14000002u },
    // gate1: cset w28,.. -> mov w28,#1
    { 0x36ad8,  { 0x1c, 0xfc, 0x7f, 0xd3, 0x55, 0xe7, 0x90, 0x52 }, 0xd280003cu },
    // gate2: cset w28,eq -> mov w28,#1
    { 0x1587c,  { 0xfc, 0x17, 0x9f, 0x1a, 0xb5, 0x9d, 0x8b, 0x52 }, 0x5280003cu },
};

static const shdw_pl_patch_t shdw_pl_facetec_patches[] = {
    // cset w8,lo -> mov w8,#0 (self-compare mismatch flag)
    { 0x347ee4, { 0xe8, 0x27, 0x9f, 0x1a, 0x08, 0x01, 0x00, 0x12 }, 0x52800008u },
};

// LAB: Debug_ExcWatch observes OZ's own VM through hardware breakpoints, so
// this build must run an image whose __text is byte-identical to the bundle
// (the earlier lab rows below all trip OZ's own text self-check).
#define SHDW_PL_OZ_CLEAN 1

static const shdw_pl_patch_t shdw_pl_ozliveness_patches[] = {
#if !SHDW_PL_OZ_CLEAN
    // The VM resolves its own once-cells before the integrity gadgets read
    // them: 0x105b860/868 go from the load-time trampolines (0x51d28/0x51c80)
    // to OZ+0x9e028c, so `cmp x20,x22` fails and the gadget calls the report
    // stub 0xf5c858(0xfe,0x72) which arms the (4,0xc) verdict. Force the
    // equality (healthy) state so the gadget returns without the report.
    { 0x2baa0c, { 0xe8, 0x06, 0x9f, 0x1a, 0xe8, 0x0f, 0x00, 0xb9 }, 0x528000a8u }, // csinc w8,w23,wzr,eq -> mov w8,#5 (gadget B)
    { 0x3216fc, { 0xe8, 0x16, 0x97, 0x1a, 0xe8, 0x0f, 0x00, 0xb9 }, 0x52800048u }, // cinc w8,w23,eq -> mov w8,#2 (gadget A)
    // Lab: the shared VM abort at 0x5fd408 compares x19 (once-slot value)
    // against a pointer computed from the step record and poisons the frame on
    // mismatch. Force the compare equal to test whether this block is the kill
    // switch that produces the 0xc return.
    { 0x5fd3fc, { 0x7f, 0x02, 0x09, 0xeb, 0x4d, 0x05, 0x9f, 0x1a }, 0xeb13027fu }, // cmp x19,x9 -> cmp x19,x19
#endif
};

// Diagnostic (pref: Debug_OzTag): the only other native producers of a literal
// 0xc in OZ __text are these six `mov w30,#0xc` VM switch initialisers. Each is
// retagged with a unique value so a poisoned virtual frame that carries 0xc
// names the initialiser it came from. Installed instead of the rows above.
static const shdw_pl_patch_t shdw_pl_oztag_patches[] = {
    { 0xfc084,  { 0x9e, 0x01, 0x80, 0x52, 0x0e, 0x00, 0x00, 0x90 }, 0x5280583eu }, // 0xc -> 0x2c1
    { 0x1115e8, { 0x9e, 0x01, 0x80, 0x52, 0xae, 0x53, 0x00, 0xd1 }, 0x5280585eu }, // 0xc -> 0x2c2
    { 0x270270, { 0x9e, 0x01, 0x80, 0x52, 0x8e, 0x5e, 0x80, 0x52 }, 0x5280587eu }, // 0xc -> 0x2c3
    { 0x322c28, { 0x9e, 0x01, 0x80, 0x52, 0x2c, 0x54, 0x80, 0x92 }, 0x5280589eu }, // 0xc -> 0x2c4
    { 0x352cac, { 0x9e, 0x01, 0x80, 0x52, 0x58, 0x01, 0x80, 0x52 }, 0x528058beu }, // 0xc -> 0x2c5
    { 0x5cfeac, { 0x9e, 0x01, 0x80, 0x52, 0x0b, 0x00, 0x00, 0xb0 }, 0x528058deu }, // 0xc -> 0x2c6
    // Lab: the verdict state machine at 0x5fd408 poisons the caller's frame
    // record before its `brk #1`: 0x5fd468 stores 0x10 at [fp+8] (saved LR) and
    // 0x5fd470 stores 4 at [fp] (saved FP), which is what turns the return into
    // pc=lr=0xc. NOP both stores so the frame stays intact; the trap handler
    // already skips the trailing brk.
    { 0x5fd468, { 0x2a, 0x01, 0x00, 0xf9, 0x89, 0x00, 0x80, 0x52 }, 0xd503201fu },
    { 0x5fd470, { 0x09, 0x01, 0x00, 0xf9, 0x20, 0x00, 0x20, 0xd4 }, 0xd503201fu },
    // The 0xc poison is produced inside OZ's once-body at 0x596034 (the cryptid
    // run faults at 0x5964e4 in the same body). Skipping the body with a bare
    // `ret` releases the once token without running that checker; x19..x28 and
    // x30 stay untouched because the prologue never executed.
    { 0x596034, { 0xff, 0x43, 0x04, 0xd1, 0xfc, 0x6f, 0x0b, 0xa9 }, 0xd65f03c0u },
};

static const shdw_pl_image_t shdw_pl_images[] = {
    {   // PureLiveSDK bundled with Wise 9.116 (17444)
        .imageSuffix = "/PureLiveSDK.framework/PureLiveSDK",
        .uuid = {
            0x1d, 0xf2, 0xb2, 0x56, 0x70, 0x76, 0x31, 0x12,
            0x87, 0x3b, 0x19, 0x91, 0xb6, 0x67, 0x91, 0xda,
        },
        .patches = shdw_pl_purelive_patches,
        .patchCount = sizeof(shdw_pl_purelive_patches) / sizeof(shdw_pl_purelive_patches[0]),
        .svcImageGuard = 1,
        .svcProcessGuard = 1,
    },
    {   // FaceTecSDK bundled with Wise 9.116 (17444)
        .imageSuffix = "/FaceTecSDK.framework/FaceTecSDK",
        .uuid = {
            0xab, 0x90, 0x39, 0x1b, 0x3e, 0x01, 0x33, 0xdc,
            0x9f, 0xcd, 0x47, 0x41, 0xba, 0x60, 0x43, 0xe7,
        },
        .patches = shdw_pl_facetec_patches,
        .patchCount = sizeof(shdw_pl_facetec_patches) / sizeof(shdw_pl_facetec_patches[0]),
        .svcImageGuard = 1,
        .svcProcessGuard = 1,
    },
    {   // OZLivenessSDK bundled with bcc (kz.bcc.starbanking)
        .imageSuffix = "/OZLivenessSDK.framework/OZLivenessSDK",
        .uuid = {
            0x97, 0xeb, 0xc9, 0x37, 0x74, 0x2f, 0x3c, 0x77,
            0xaa, 0x98, 0xca, 0xd1, 0xa5, 0x5e, 0x41, 0xa4,
        },
        .patches = shdw_pl_ozliveness_patches,
        .patchCount = sizeof(shdw_pl_ozliveness_patches) / sizeof(shdw_pl_ozliveness_patches[0]),
        .svcImageGuard = 1,
        .svcProcessGuard = 0,
    },
};
#define SHDW_PL_IMAGE_COUNT (sizeof(shdw_pl_images) / sizeof(shdw_pl_images[0]))

static _Atomic unsigned shdw_pl_done_mask = 0;
static pthread_mutex_t shdw_pl_lock = PTHREAD_MUTEX_INITIALIZER;
static uint8_t* shdw_pl_oz_base = NULL;

// Bring-up channel: the diag log drops lines from inside the scan, so this
// writes straight to a file and nothing else can filter it.
static _Atomic int shdw_pl_dbg_fd = -2;

static void shdw_pl_dbg_open(void) {
    int expected = -2;
    if(!atomic_compare_exchange_strong(&shdw_pl_dbg_fd, &expected, -3)) return;

    int fd = open("/tmp/shdwpl.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
    if(fd < 0) {
        const char* home = getenv("HOME");
        char path[512];
        if(home) {
            snprintf(path, sizeof(path), "%s/Library/Caches/shdwpl.log", home);
            fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
        }
    }
    atomic_store(&shdw_pl_dbg_fd, fd < 0 ? -1 : fd);
}

static void shdw_pl_dbg(const char* fmt, ...) {
    if(atomic_load(&shdw_pl_dbg_fd) == -2) shdw_pl_dbg_open();
    int fd = atomic_load(&shdw_pl_dbg_fd);
    if(fd < 0) return;

    char buf[512];
    va_list args;
    va_start(args, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    if(n <= 0) return;
    if(n > (int)sizeof(buf) - 1) n = (int)sizeof(buf) - 1;
    write(fd, buf, (size_t)n);
}

// The dyld accessors Shadow installs filter what external callers see, and
// ShadowCore's own calls are classified as external for adapter code, so the
// scan runs inside the internal-read scope to see the real image list.

static const uint8_t* shdw_pl_imageUUID(const struct mach_header* header) {
    if(!header || header->magic != MH_MAGIC_64) return NULL;

    const struct load_command* command = (const void*)((const struct mach_header_64*)header + 1);
    const uint8_t* end = (const uint8_t*)command + header->sizeofcmds;
    for(uint32_t i = 0; i < header->ncmds; i++) {
        if((const uint8_t*)command + sizeof(*command) > end ||
           command->cmdsize < sizeof(*command) || (const uint8_t*)command + command->cmdsize > end) return NULL;
        if(command->cmd == LC_UUID && command->cmdsize >= sizeof(struct uuid_command)) {
            return ((const struct uuid_command*)command)->uuid;
        }
        command = (const void*)((const uint8_t*)command + command->cmdsize);
    }
    return NULL;
}

static const shdw_pl_image_t* shdw_pl_find_image(const struct mach_header* header) {
    const uint8_t* uuid = shdw_pl_imageUUID(header);
    if(!uuid) return NULL;

    for(unsigned v = 0; v < SHDW_PL_IMAGE_COUNT; v++) {
        if(memcmp(uuid, shdw_pl_images[v].uuid, sizeof(shdw_pl_images[v].uuid)) == 0) {
            return &shdw_pl_images[v];
        }
    }
    return NULL;
}

// Universal_Syscall rewrites raw svc sites in every loaded image. PureLiveSDK
// and FaceTecSDK hash their own __TEXT, so a rewrite anywhere inside these
// images is itself the trip wire. svc_patch.x resolves this through a weak
// symbol, so the guard needs no header and no link dependency.
int shdw_purelive_guard_image(const struct mach_header* header) {
    const shdw_pl_image_t* image = shdw_pl_find_image(header);
    return image && image->svcImageGuard ? 1 : 0;
}

// __TEXT is code-signed with max_protection r-x; VM_PROT_COPY forces a private
// copy-on-write mapping so the site can be rewritten without touching the
// shared clean pages. The COW is taken over the whole segment on purpose: a
// single-page COW splits the Mach region at the patched page, and OZ's own
// region walk compares the mapping size at its image base against __TEXT
// vmsize (crash at OZ+0x596828 when it shrinks).
static BOOL shdw_pl_segment(const struct mach_header* header, uint32_t offset, uint64_t* vmaddr, uint64_t* vmsize) {
    if(!header || header->magic != MH_MAGIC_64) return NO;

    const struct mach_header_64* header64 = (const void*)header;
    const struct load_command* command = (const void*)(header64 + 1);
    const uint8_t* end = (const uint8_t*)command + header->sizeofcmds;
    for(uint32_t i = 0; i < header->ncmds; i++) {
        if((const uint8_t*)command + sizeof(*command) > end ||
           command->cmdsize < sizeof(*command) || (const uint8_t*)command + command->cmdsize > end) return NO;
        if(command->cmd == LC_SEGMENT_64 && command->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64* segment = (const void*)command;
            if(offset >= segment->vmaddr && offset < segment->vmaddr + segment->vmsize) {
                *vmaddr = segment->vmaddr;
                *vmsize = segment->vmsize;
                return YES;
            }
        }
        command = (const void*)((const uint8_t*)command + command->cmdsize);
    }
    return NO;
}

static uint64_t shdw_pl_region_size(const void* address) {
    vm_address_t addr = (vm_address_t)address;
    vm_size_t size = 0;
    natural_t depth = 0;
    vm_region_submap_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
    if(vm_region_recurse_64(mach_task_self(), &addr, &size, &depth,
                            (vm_region_recurse_info_t)&info, &count) != KERN_SUCCESS) return 0;
    return (uint64_t)size;
}

static BOOL shdw_pl_write(uint8_t* base, uint32_t offset, uint32_t replacement) {
    uint8_t* site = base + offset;
    uint64_t vmaddr = 0, vmsize = 0;

    if(!shdw_pl_segment((const struct mach_header*)base, offset, &vmaddr, &vmsize) || !vmsize) {
        shdw_pl_dbg("seg lookup fail off=0x%x\n", offset);
        return NO;
    }

    uint8_t* segment = base + vmaddr;
    uint64_t before = shdw_pl_region_size(base);

    if(vm_protect(mach_task_self(), (vm_address_t)segment, (vm_size_t)vmsize, FALSE,
                  VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY) != KERN_SUCCESS) {
        shdw_pl_dbg("seg prot fail site=%p len=0x%llx\n", (const void*)site, (unsigned long long)vmsize);
        shdw_diag_log("adapter pl prot fail site=%p", site);
        return NO;
    }

    *(volatile uint32_t*)site = replacement;
    sys_icache_invalidate(site, sizeof(uint32_t));

    vm_protect(mach_task_self(), (vm_address_t)segment, (vm_size_t)vmsize, FALSE,
               VM_PROT_READ | VM_PROT_EXECUTE);

    uint64_t after = shdw_pl_region_size(base);
    shdw_pl_dbg("seg patch off=0x%x site=%p seg=0x%llx+0x%llx region=0x%llx->0x%llx\n",
                offset, (const void*)site, (unsigned long long)vmaddr,
                (unsigned long long)vmsize, (unsigned long long)before, (unsigned long long)after);
    return YES;
}

// Lab A/B (bcc): OZLivenessSDK ships with LC_ENCRYPTION_INFO cryptid=0 — a
// decrypted copy — while a stock App Store install carries cryptid=1. A
// tamper check that reads its own Mach-O header sees the piracy marker, not
// the jailbreak. Present the App Store value in the in-memory header (the
// kernel consumed the field at exec; nothing re-reads it) and watch whether
// the 0xc verdict clears.
static void shdw_pl_oz_cryptid(uint8_t* base) {
    if(!base || *(const uint32_t*)base != MH_MAGIC_64) return;

    const struct mach_header_64* header = (const void*)base;
    const struct load_command* command = (const void*)(header + 1);
    const uint8_t* end = (const uint8_t*)command + header->sizeofcmds;

    for(uint32_t i = 0; i < header->ncmds; i++) {
        if((const uint8_t*)command + sizeof(*command) > end ||
           command->cmdsize < sizeof(*command) ||
           (const uint8_t*)command + command->cmdsize > end) return;
        if(command->cmd == LC_ENCRYPTION_INFO || command->cmd == LC_ENCRYPTION_INFO_64) {
            // cryptid is the fifth uint32: cmd, cmdsize, cryptoff, cryptsize, cryptid.
            uint32_t offset = (uint32_t)((const uint8_t*)command - base) + 16;
            uint32_t current = *(volatile uint32_t*)(base + offset);
            uint64_t before = shdw_pl_region_size(base);
            BOOL wrote = NO;  // control: 0 = report only, 1 = write cryptid 1
            // shdw_pl_dbg, not shdw_diag_log: image callbacks run nested inside a
            // hooked dlopen whose own trace holds the diag reentrancy guard, so
            // diag lines from this context are silently dropped.
            shdw_pl_dbg("OZCRYPTID cryptid=%u->%u off=0x%x region=0x%llx->0x%llx\n",
                        current, wrote ? 1u : current, offset,
                        (unsigned long long)before,
                        (unsigned long long)shdw_pl_region_size(base));
            return;
        }
        command = (const void*)((const uint8_t*)command + command->cmdsize);
    }
}

static BOOL shdw_pl_apply_list(uint8_t* base, const shdw_pl_patch_t* patches, unsigned count, unsigned* applied, unsigned* skipped) {
    for(unsigned p = 0; p < count; p++) {
        const shdw_pl_patch_t* patch = &patches[p];
        uint8_t* site = base + patch->offset;
        if(memcmp(site, patch->prologue, 8) != 0) {
            shdw_pl_dbg("prologue mismatch off=0x%x site=%p\n", patch->offset, (const void*)site);
            (*skipped)++;
            continue;
        }
        if(shdw_pl_write(base, patch->offset, patch->replacement)) {
            (*applied)++;
        } else {
            (*skipped)++;
        }
    }
    return *skipped == 0;
}

static BOOL shdw_pl_apply(const shdw_pl_image_t* image, uint8_t* base, unsigned* applied, unsigned* skipped) {
    return shdw_pl_apply_list(base, image->patches, image->patchCount, applied, skipped);
}

static void shdw_pl_scan(void);

// Applies the row straight from the header dyld hands us: no enumeration, so
// the filtered mirror cannot hide the image.
static void shdw_pl_probe_slots(const char* tag) {
    if(!shdw_pl_oz_base) return;
    const uintptr_t base = (uintptr_t)shdw_pl_oz_base;
    uint64_t slot860 = *(volatile uint64_t*)(base + 0x105b860);
    uint64_t slot868 = *(volatile uint64_t*)(base + 0x105b868);
    uint64_t keyA = *(volatile uint32_t*)(base + 0x10930c8);
    uint64_t keyB = *(volatile uint32_t*)(base + 0x1092b70);
    uint64_t keyW = *(volatile uint32_t*)(base + 0x1097688);

    shdw_enter_internal();
    Dl_info info;
    memset(&info, 0, sizeof(info));
    int ok = dladdr((const void*)(uintptr_t)slot868, &info);
    shdw_exit_internal();

    shdw_pl_dbg("probe %s slot860=%p slot868=%p ok=%d img=%s sym=%s "
                "keyA=%#llx keyB=%#llx keyW=%#llx\n", tag,
                (const void*)(uintptr_t)slot860, (const void*)(uintptr_t)slot868,
                ok, ok && info.dli_fname ? info.dli_fname : "?",
                ok && info.dli_sname ? info.dli_sname : "?",
                (unsigned long long)keyA, (unsigned long long)keyB,
                (unsigned long long)keyW);
}

static void shdw_pl_apply_header(const struct mach_header* header) {
    const shdw_pl_image_t* image = shdw_pl_find_image(header);
    if(!image) return;

    unsigned v = (unsigned)(image - shdw_pl_images);
    if(atomic_load_explicit(&shdw_pl_done_mask, memory_order_relaxed) & (1u << v)) return;

    if(image->imageSuffix && strstr(image->imageSuffix, "OZLivenessSDK")) {
        shdw_pl_oz_base = (uint8_t*)header;
    }
    shdw_pl_probe_slots("apply");

    pthread_mutex_lock(&shdw_pl_lock);
    unsigned applied = 0, skipped = 0;
    // Lab build: OZ image is loaded before Shadow's prefs parse, so the tag
    // lane cannot be pref-gated. Force it here and keep the regular rows too.
#if SHDW_PL_OZ_CLEAN
    BOOL tagged = NO;
#else
    BOOL tagged = image->imageSuffix &&
                  strstr(image->imageSuffix, "OZLivenessSDK") != NULL;
#endif
    if(tagged) {
        shdw_pl_oz_cryptid((uint8_t*)header);
    }
    BOOL clean = shdw_pl_apply(image, (uint8_t*)header, &applied, &skipped);
    if(tagged) {
        clean = shdw_pl_apply_list((uint8_t*)header, shdw_pl_oztag_patches,
                                   sizeof(shdw_pl_oztag_patches) / sizeof(shdw_pl_oztag_patches[0]),
                                   &applied, &skipped) && clean;
    }
    if(clean) {
        atomic_fetch_or_explicit(&shdw_pl_done_mask, 1u << v, memory_order_release);
    }
    pthread_mutex_unlock(&shdw_pl_lock);

    shdw_pl_dbg("apply %s header=%p applied=%u skipped=%u%s\n",
                image->imageSuffix, (const void*)header, applied, skipped,
                tagged ? " tag" : "");
    shdw_diag_log("adapter pl %s applied=%u skipped=%u%s", image->imageSuffix, applied, skipped,
                  tagged ? " tag" : "");
    NSLog(@"[Shadow][PureLive] %s applied=%u skipped=%u", image->imageSuffix, applied, skipped);
}

static void shdw_pl_install(void) {
    shdw_pl_dbg("install aggressive=%d done=0x%x\n", shdw_detector_aggressive ? 1 : 0,
                atomic_load_explicit(&shdw_pl_done_mask, memory_order_acquire));
    if(!shdw_detector_aggressive) return;
    shdw_pl_scan();
    shdw_pl_probe_slots("tick");
}

// Shadow filters the dyld accessors for anything outside its own image ranges,
// and adapter code counts as external. The internal-read scope is the
// thread-local truth signal the dyld unit consults, so this walk sees the real
// list without exposing anything to the app.
static void shdw_pl_scan(void) {
    if(atomic_load_explicit(&shdw_pl_done_mask, memory_order_acquire) == (1u << SHDW_PL_IMAGE_COUNT) - 1u) {
        return;
    }

    uint32_t filtered = _dyld_image_count();
    shdw_enter_internal();
    uint32_t count = _dyld_image_count();
    unsigned matches = 0;
    shdw_pl_dbg("scan filtered=%u count=%u\n", filtered, count);
    for(uint32_t i = 0; i < count; i++) {
        const struct mach_header* header = _dyld_get_image_header(i);
        const shdw_pl_image_t* image = shdw_pl_find_image(header);
        if(image) {
            matches++;
            shdw_pl_dbg("scan match i=%u header=%p %s\n", i, (const void*)header, image->imageSuffix);
            shdw_pl_apply_header(header);
        } else if(i < 16) {
            shdw_pl_dbg("scan head i=%u header=%p\n", i, (const void*)header);
        }
    }
    shdw_exit_internal();
    shdw_pl_dbg("scan done matches=%u done=0x%x\n", matches,
                atomic_load_explicit(&shdw_pl_done_mask, memory_order_acquire));
}

void shdw_adapter_purelive(SHDWHookSession* hooks) {
    (void)hooks;
    shdw_pl_dbg("adapter called\n");
    shdw_pl_install();

    // A host that dlopens the SDK later would miss the ctor pass; the sites
    // stay inert until the verifier runs, so late retries are safe.
    if(atomic_load_explicit(&shdw_pl_done_mask, memory_order_acquire) == (1u << SHDW_PL_IMAGE_COUNT) - 1u) {
        return;
    }

    static const int64_t delays[] = { 1, 3, 8 };
    for(unsigned i = 0; i < sizeof(delays) / sizeof(delays[0]); i++) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, delays[i] * NSEC_PER_SEC),
                       dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
            shdw_pl_install();
        });
    }
}

// Process-level answer for the svc lane: verified that skipping only the
// PureLive/FaceTec images is not enough (EFRSDK's 177 rewritten svc sites make
// the detector raise a Mach exception that ellekit turns into exit(1)), so a
// PureLive process must keep its raw svc sites native everywhere.
static _Atomic int shdw_pl_present = 0;

int shdw_purelive_process_guard(void) {
    return atomic_load_explicit(&shdw_pl_present, memory_order_acquire);
}

// PureLive seals its own state during framework initializers, so the patches
// must land when the image is mapped, not when the plugin plan is built.
static void shdw_pl_image_added(const struct mach_header* header, intptr_t slide) {
    (void)slide;
    shdw_pl_dbg("image_added header=%p\n", (const void*)header);
    const shdw_pl_image_t* image = shdw_pl_find_image(header);
    if(image && image->svcProcessGuard) {
        atomic_store_explicit(&shdw_pl_present, 1, memory_order_release);
    }
    shdw_pl_apply_header(header);
    shdw_pl_scan();
}

__attribute__((constructor)) static void shdw_pl_ctor(void) {
    shdw_pl_dbg("ctor enter\n");
    _dyld_register_func_for_add_image(shdw_pl_image_added);
    shdw_pl_dbg("ctor registered\n");
}
