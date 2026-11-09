#import "AdapterHooks.h"

#include <mach-o/dyld.h>
#include <objc/runtime.h>
#include <stdatomic.h>
#include <string.h>

// Dynatrace MobileProtect: the checks are obfuscated Swift and the SDK calls
// its own kill path directly, so the sound anchors are the function bodies.
// Rows are keyed by the image LC_UUID and guarded by an 8-byte prologue; an
// unknown UUID installs nothing (fail-safe, the app then behaves exactly as it
// would without this adapter).
//
// 8ef8d763 keeps ObjC metadata for most classes, but Swift calls
// -terminateApp:withReason: directly (bl to the symbol, no selector in the
// method list), so the message lane can not bind it. The structural lane is
// only a fast path for builds whose selectors survive; the UUID row is what
// covers the installed build.
//
// Kill chain (verified on 8ef8d763): a detection is reported, the blocker is
// consulted, and -[DTProtectionItem terminateApp:withReason:] posts an app
// notification and invokes the reason block it was handed. In the 8ef8d763
// build that block
// (___66-[DTJailbreaks determineIfJailbrokenAndReportEvents:withCallback:]
// _block_invoke_2, 0x212e0) is a raw-syscall killer: ptrace, kill(SIGKILL),
// exit(1), `brk #0x4d50`. Neutralizing the terminate method stops the block
// from ever running, so the syscall chain is unreachable.
//
// Coverage split:
//   * natural (always on): the termination trap itself is neutralized. The
//     SDK still detects and still reports, the app simply never dies.
//   * aggressive only: verdict forcing (isJailbroken / determine...), the
//     hook scanner and the block policy. These override a detector's result
//     rather than shaping a stock environment, so they stay opt-in.
typedef struct {
    uint8_t uuid[16];
    uint32_t terminateOffset;
    uint8_t terminatePrologue[8];
    uint32_t isJailbrokenOffset;
    uint8_t isJailbrokenPrologue[8];
    uint32_t determineOffset;
    uint8_t determinePrologue[8];
    uint32_t hookCheckOffset;
    uint8_t hookCheckPrologue[8];
    uint32_t shouldBlockOffset;
    uint8_t shouldBlockPrologue[8];
    uint32_t shouldBlockFromCallerOffset;
    uint8_t shouldBlockFromCallerPrologue[8];
} shdw_mp_version_t;

static const shdw_mp_version_t shdw_mp_versions[] = {
    {   // MobileProtect bundled with PayPal 10.10.0 (oslo.app), installed build
        .uuid = {
            0x8e, 0xf8, 0xd7, 0x63, 0xf1, 0x80, 0x39, 0x74,
            0xb3, 0xa8, 0x30, 0xc9, 0x8d, 0x24, 0x67, 0x5c,
        },
        .terminateOffset = 0x34d4c,
        .terminatePrologue = { 0xff, 0x43, 0x01, 0xd1, 0xf6, 0x57, 0x02, 0xa9 },
        .isJailbrokenOffset = 0x1ecf8,
        .isJailbrokenPrologue = { 0xe3, 0x03, 0x02, 0xaa, 0x02, 0x00, 0x80, 0x52 },
        .determineOffset = 0x1ed04,
        .determinePrologue = { 0xe9, 0x23, 0xb9, 0x6d, 0xfc, 0x6f, 0x01, 0xa9 },
        // No standalone hook scanner in this build: offset 0 with an all-zero
        // prologue never matches real code, so the row stays inert.
        .hookCheckOffset = 0,
        .hookCheckPrologue = { 0 },
        .shouldBlockOffset = 0x34678,
        .shouldBlockPrologue = { 0xf6, 0x57, 0xbd, 0xa9, 0xf4, 0x4f, 0x01, 0xa9 },
        .shouldBlockFromCallerOffset = 0x346e8,
        .shouldBlockFromCallerPrologue = { 0xf6, 0x57, 0xbd, 0xa9, 0xf4, 0x4f, 0x01, 0xa9 },
    },
    {   // MobileProtect bundled with PayPal 663 (oslo.app)
        .uuid = {
            0x17, 0xd5, 0xba, 0xf1, 0xad, 0x37, 0x3a, 0xa2,
            0xae, 0xee, 0x82, 0x1a, 0x44, 0xa0, 0x93, 0xe3,
        },
        .terminateOffset = 0x33798,
        .terminatePrologue = { 0xff, 0x43, 0x02, 0xd1, 0xf8, 0x5f, 0x05, 0xa9 },
        .isJailbrokenOffset = 0x1df20,
        .isJailbrokenPrologue = { 0xe3, 0x03, 0x02, 0xaa, 0x02, 0x00, 0x80, 0x52 },
        .determineOffset = 0x1df2c,
        .determinePrologue = { 0xe9, 0x23, 0xb9, 0x6d, 0xfc, 0x6f, 0x01, 0xa9 },
        .hookCheckOffset = 0x24b64,
        .hookCheckPrologue = { 0xfc, 0x6f, 0xba, 0xa9, 0xfa, 0x67, 0x01, 0xa9 },
        .shouldBlockOffset = 0x330c4,
        .shouldBlockPrologue = { 0xf6, 0x57, 0xbd, 0xa9, 0xf4, 0x4f, 0x01, 0xa9 },
        .shouldBlockFromCallerOffset = 0x33134,
        .shouldBlockFromCallerPrologue = { 0xf6, 0x57, 0xbd, 0xa9, 0xf4, 0x4f, 0x01, 0xa9 },
    },
};
#define SHDW_MP_VERSION_COUNT (sizeof(shdw_mp_versions) / sizeof(shdw_mp_versions[0]))

static void (*shdw_mp_originalTerminate)(id, SEL, id, id) = NULL;
static void (*shdw_mp_originalTerminateNoReason)(id, SEL) = NULL;
static BOOL (*shdw_mp_originalIsJailbroken)(id, SEL, id) = NULL;
static void (*shdw_mp_originalDetermine)(id, SEL, BOOL, id) = NULL;
static BOOL (*shdw_mp_originalHookCheck)(const char*, const char*) = NULL;
static BOOL (*shdw_mp_originalShouldBlock)(id, SEL) = NULL;
static BOOL (*shdw_mp_originalShouldBlockFromCaller)(id, SEL, id) = NULL;
static BOOL (*shdw_mp_originalShouldBlockDataType)(id, SEL, id, id) = NULL;

static _Atomic BOOL shdw_mp_installed = NO;

static void shdw_mp_terminate(id self, SEL command, id reason, id extra) {
    (void)self; (void)command; (void)reason; (void)extra;
}

static void shdw_mp_terminateNoReason(id self, SEL command) {
    (void)self; (void)command;
}

static BOOL shdw_mp_isJailbroken(id self, SEL command, id callback) {
    (void)self; (void)command;
    if(callback) {
        ((void (^)(BOOL))callback)(NO);
    }
    return NO;
}

static void shdw_mp_determine(id self, SEL command, BOOL reportEvents, id callback) {
    (void)self; (void)command; (void)reportEvents;
    if(callback) {
        ((void (^)(BOOL))callback)(NO);
    }
}

static BOOL shdw_mp_hookCheck(const char* image, const char* symbol) {
    (void)image; (void)symbol;
    return NO;
}

static BOOL shdw_mp_shouldBlock(id self, SEL command) {
    (void)self; (void)command;
    return NO;
}

static BOOL shdw_mp_shouldBlockFromCaller(id self, SEL command, id caller) {
    (void)self; (void)command; (void)caller;
    return NO;
}

static BOOL shdw_mp_shouldBlockDataType(id self, SEL command, id type, id caller) {
    (void)self; (void)command; (void)type; (void)caller;
    return NO;
}

static const shdw_mp_version_t* shdw_mp_versionForHeader(const struct mach_header* header) {
    if(!header || header->magic != MH_MAGIC_64) return NULL;

    const struct load_command* command = (const void*)((const struct mach_header_64*)header + 1);
    const uint8_t* end = (const uint8_t*)command + header->sizeofcmds;
    for(uint32_t i = 0; i < header->ncmds; i++) {
        if((const uint8_t*)command + sizeof(*command) > end ||
           command->cmdsize < sizeof(*command) || (const uint8_t*)command + command->cmdsize > end) return NULL;
        if(command->cmd == LC_UUID && command->cmdsize >= sizeof(struct uuid_command)) {
            const uint8_t* uuid = ((const struct uuid_command*)command)->uuid;
            for(unsigned v = 0; v < SHDW_MP_VERSION_COUNT; v++) {
                if(memcmp(uuid, shdw_mp_versions[v].uuid, sizeof(shdw_mp_versions[v].uuid)) == 0) {
                    return &shdw_mp_versions[v];
                }
            }
            return NULL;
        }
        command = (const void*)((const uint8_t*)command + command->cmdsize);
    }
    return NULL;
}

static const shdw_mp_version_t* shdw_mp_get_version(const struct mach_header** outHeader) {
    for(uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char* name = _dyld_get_image_name(i);
        if(!name || !strstr(name, "/MobileProtect.framework/MobileProtect")) continue;
        const struct mach_header* header = _dyld_get_image_header(i);
        const shdw_mp_version_t* version = shdw_mp_versionForHeader(header);
        if(!version) continue;
        if(outHeader) *outHeader = header;
        return version;
    }
    return NULL;
}

static BOOL shdw_mp_hookAt(SHDWHookSession* hooks, uint8_t* base, uint32_t offset,
                           const uint8_t prologue[8], void* replacement, void** original) {
    uint8_t* target = base + offset;
    if(memcmp(target, prologue, 8) != 0) return NO;
    return [hooks hookFunction:target withReplacement:replacement outOldPtr:original];
}

static BOOL shdw_mp_hookSelector(SHDWHookSession* hooks, const char* className,
                                 const char* selectorName, void* replacement,
                                 void** original) {
    Class cls = objc_getClass(className);
    if(!cls) return NO;

    SEL selector = sel_registerName(selectorName);
    if(!class_getInstanceMethod(cls, selector)) return NO;

    return [hooks hookMessageInClass:cls
                      withSelector:selector
                   withReplacement:replacement
                         outOldPtr:original];
}

// Fast path: binds the termination trap by selector on builds that still
// expose it. Returns NO when the class or selectors are gone, which is the
// case for the installed build; the UUID row then takes over.
static BOOL shdw_mp_installStructural(SHDWHookSession* hooks) {
    if(!objc_getClass("DTProtectionItem")) return NO;

    BOOL installed = shdw_mp_hookSelector(hooks, "DTProtectionItem", "terminateApp:withReason:",
                                          (void*)shdw_mp_terminate,
                                          (void**)&shdw_mp_originalTerminate);
    installed = shdw_mp_hookSelector(hooks, "DTProtectionItem", "terminateApp",
                                     (void*)shdw_mp_terminateNoReason,
                                     (void**)&shdw_mp_originalTerminateNoReason) || installed;
    if(!installed) return NO;

    if(shdw_detector_aggressive) {
        shdw_mp_hookSelector(hooks, "DTJailbreaks", "isJailbroken:",
                             (void*)shdw_mp_isJailbroken,
                             (void**)&shdw_mp_originalIsJailbroken);
        shdw_mp_hookSelector(hooks, "DTJailbreaks",
                             "determineIfJailbrokenAndReportEvents:withCallback:",
                             (void*)shdw_mp_determine,
                             (void**)&shdw_mp_originalDetermine);
        shdw_mp_hookSelector(hooks, "DTProtectionItem", "shouldBlock",
                             (void*)shdw_mp_shouldBlock,
                             (void**)&shdw_mp_originalShouldBlock);
        shdw_mp_hookSelector(hooks, "DTProtectionItem", "shouldBlockFromCaller:",
                             (void*)shdw_mp_shouldBlockFromCaller,
                             (void**)&shdw_mp_originalShouldBlockFromCaller);
        shdw_mp_hookSelector(hooks, "DTMobileProtectConfiguration",
                             "shouldBlockDataType:fromCaller:",
                             (void*)shdw_mp_shouldBlockDataType,
                             (void**)&shdw_mp_originalShouldBlockDataType);
    }

    return YES;
}

static BOOL shdw_mp_installTable(SHDWHookSession* hooks) {
    const struct mach_header* header = NULL;
    const shdw_mp_version_t* version = shdw_mp_get_version(&header);
    if(!version) return NO;

    uint8_t* base = (uint8_t*)header;
    BOOL installed = shdw_mp_hookAt(hooks, base, version->terminateOffset, version->terminatePrologue,
                                    (void*)shdw_mp_terminate, (void**)&shdw_mp_originalTerminate);

    if(shdw_detector_aggressive) {
        installed = shdw_mp_hookAt(hooks, base, version->isJailbrokenOffset, version->isJailbrokenPrologue,
                                   (void*)shdw_mp_isJailbroken, (void**)&shdw_mp_originalIsJailbroken) || installed;
        installed = shdw_mp_hookAt(hooks, base, version->determineOffset, version->determinePrologue,
                                   (void*)shdw_mp_determine, (void**)&shdw_mp_originalDetermine) || installed;
        installed = shdw_mp_hookAt(hooks, base, version->hookCheckOffset, version->hookCheckPrologue,
                                   (void*)shdw_mp_hookCheck, (void**)&shdw_mp_originalHookCheck) || installed;
        installed = shdw_mp_hookAt(hooks, base, version->shouldBlockOffset, version->shouldBlockPrologue,
                                   (void*)shdw_mp_shouldBlock, (void**)&shdw_mp_originalShouldBlock) || installed;
        installed = shdw_mp_hookAt(hooks, base, version->shouldBlockFromCallerOffset,
                                   version->shouldBlockFromCallerPrologue,
                                   (void*)shdw_mp_shouldBlockFromCaller,
                                   (void**)&shdw_mp_originalShouldBlockFromCaller) || installed;
    }

    return installed;
}

static void shdw_mp_install(SHDWHookSession* hooks) {
    if(atomic_load_explicit(&shdw_mp_installed, memory_order_acquire)) {
        return;
    }

    BOOL structural = shdw_mp_installStructural(hooks);
    BOOL installed = structural || shdw_mp_installTable(hooks);

    if(installed) {
        shdw_diag_log("adapter mp lane=%s aggressive=%d",
                      structural ? "objc" : "uuid", shdw_detector_aggressive ? 1 : 0);
        atomic_store_explicit(&shdw_mp_installed, YES, memory_order_release);
    } else {
        shdw_diag_log("adapter mp miss image=%d", shdw_mp_get_version(NULL) != NULL);
    }
}

void shdw_adapter_mobileprotect(SHDWHookSession* hooks) {
    shdw_mp_install(hooks);

    // The framework is a launch dependency on the apps observed so far, but a
    // host that dlopens it later would otherwise never get the trap covered.
    if(atomic_load_explicit(&shdw_mp_installed, memory_order_acquire)) {
        return;
    }

    static const int64_t delays[] = { 1, 3, 8 };
    for(unsigned i = 0; i < sizeof(delays) / sizeof(delays[0]); i++) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, delays[i] * NSEC_PER_SEC),
                       dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
            shdw_mp_install(hooks);
        });
    }
}
