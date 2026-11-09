#import "AdapterHooks.h"

#include <objc/runtime.h>
#include <stdatomic.h>

// TransaktSDK (Netcetera; the launch gate of S-ID and S-pushTAN) caches its
// three security verdicts as __DATA bytes that only ever move 0 -> 1 behind
// one-shot guards, and -isSecure returns !flag. The root probe that flips the
// flag runs in ixGuard's obfuscated dispatch: it never touches the image's
// __got / __la_symbol_ptr (traced: only dlsym(kCFCoreFoundationVersionNumber)
// before the flip, getenv(OPENSSL_CONF) and uname after), so there is no libc
// surface for the Universal lanes to answer. The readable verdict surface is
// five ObjC -isSecure methods plus TKTSecurityCheckHandler -didPassChecks;
// answering those clean removes the "Dieses Gerät ist jailbroken" plate, and
// the server-facing -[TransaktProtocolHandshakeDto isJailBroken] then reads a
// clean answer of its own (verified on S-ID 2.10.0).
//
// Disable-style by nature, but default-on: the SDK is the launch gate, so an
// app-scoped opt-in would just leave the host app unusable. The adapter arms
// only once a TransaktSDK class exists, so processes without the SDK are
// untouched.
//
// The verdict cache itself is still the more robust lever (no method names to
// chase), but its addresses are image-build specific:
//   flags root 0x65de40 / debugger 0x65e200 / codeint 0x65db88,
//   one-shot guards 0x667d12 / 0x667d11 / 0x667d10,
//   writers 0x1ec2dc / 0x1ec310 / 0x1ec344.
// Writing 1 into the guards at ctor keeps every flag at 0 for the process
// lifetime (the setter only stores the flag when the guard's old value is not
// 1). Kept here as a note for a future UUID-keyed version row.

static _Atomic BOOL shdw_transakt_installed = NO;

static BOOL shdw_transakt_isSecure(id self, SEL command) {
    (void)self;
    (void)command;
    return YES;
}

static BOOL shdw_transakt_didPass(id self, SEL command) {
    (void)self;
    (void)command;
    return YES;
}

static const char* const shdw_transakt_secureClasses[] = {
    "TransaktSDK.TKTCompromisedFileCheck",
    "TransaktSDK.TKTIXGuardRootCheck",
    "TransaktSDK.TKTIXGuardCodeIntegrityCheck",
    "TransaktSDK.TKTDebuggerCheck",
    "TransaktSDK.TKTIXGuardDebuggerCheck",
};

static void shdw_transakt_install(SHDWHookSession* hooks) {
    if(atomic_load_explicit(&shdw_transakt_installed, memory_order_acquire)) {
        return;
    }

    // Every class below comes from the same framework image, so the root check
    // is a sound presence probe for the whole set.
    Class rootCheck = objc_getClass("TransaktSDK.TKTIXGuardRootCheck");
    if(!rootCheck) {
        return;
    }

    SEL isSecure = sel_registerName("isSecure");
    int hooked = 0;
    for(unsigned i = 0;
        i < sizeof(shdw_transakt_secureClasses) / sizeof(shdw_transakt_secureClasses[0]); i++) {
        Class checkClass = objc_getClass(shdw_transakt_secureClasses[i]);
        if(!checkClass || !class_getInstanceMethod(checkClass, isSecure)) {
            continue;
        }
        void* original = NULL;
        if([hooks hookMessageInClass:checkClass
                        withSelector:isSecure
                     withReplacement:(void*)shdw_transakt_isSecure
                           outOldPtr:&original]) {
            hooked++;
        }
    }

    Class handler = objc_getClass("TKTSecurityCheckHandler");
    SEL didPass = sel_registerName("didPassChecks");
    if(handler && class_getInstanceMethod(handler, didPass)) {
        void* original = NULL;
        if([hooks hookMessageInClass:handler
                        withSelector:didPass
                     withReplacement:(void*)shdw_transakt_didPass
                           outOldPtr:&original]) {
            hooked++;
        }
    }

    if(hooked) {
        atomic_store_explicit(&shdw_transakt_installed, YES, memory_order_release);
    }
}

void shdw_adapter_transakt(SHDWHookSession* hooks) {
    shdw_transakt_install(hooks);
    if(atomic_load_explicit(&shdw_transakt_installed, memory_order_acquire)) {
        return;
    }

    // A host that dlopens the SDK after launch would otherwise stay uncovered.
    static const int64_t delays[] = { 1, 2, 4, 8 };
    for(unsigned i = 0; i < sizeof(delays) / sizeof(delays[0]); i++) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, delays[i] * NSEC_PER_SEC),
                       dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
            shdw_transakt_install(hooks);
        });
    }
}
