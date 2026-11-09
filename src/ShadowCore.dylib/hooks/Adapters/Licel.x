#import "AdapterHooks.h"

#include <mach-o/dyld.h>
#include <objc/runtime.h>
#include <stdatomic.h>
#include <string.h>

// Licel iOS Runtime (ios_runtime.framework) takes over UIApplication.delegate
// with a class it creates at runtime via objc_allocateClassPair. On builds
// where its launch hand-off breaks, the app's own delegate never runs and the
// SDK's gate UI stays on screen. A delegate class with no backing image is
// exactly that runtime-created proxy; keeping the app's compiled delegate
// preserves the stock launch path. Gated on the runtime image being present,
// so apps without the SDK are untouched.

static void (*shdw_licel_originalSetDelegate)(id, SEL, id) = NULL;
static _Atomic BOOL shdw_licel_armed = NO;

static BOOL shdw_licel_image_loaded(void) {
    for(uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char* name = _dyld_get_image_name(i);
        if(name && strstr(name, "/ios_runtime.framework/ios_runtime")) {
            return YES;
        }
    }
    return NO;
}

static void shdw_licel_setDelegate(id self, SEL command, id delegate) {
    if(delegate && !class_getImageName(object_getClass(delegate))) {
        return;
    }
    if(shdw_licel_originalSetDelegate) {
        shdw_licel_originalSetDelegate(self, command, delegate);
    }
}

static BOOL shdw_licel_attempt(SHDWHookSession* session) {
    if(atomic_load_explicit(&shdw_licel_armed, memory_order_acquire)) {
        return YES;
    }
    if(!shdw_licel_image_loaded()) {
        return NO;
    }

    Class appClass = objc_getClass("UIApplication");
    SEL selector = sel_registerName("setDelegate:");
    if(!appClass || !class_getInstanceMethod(appClass, selector)) {
        return NO;
    }

    if([session hookMessageInClass:appClass
                      withSelector:selector
                   withReplacement:(void*)shdw_licel_setDelegate
                         outOldPtr:(void**)&shdw_licel_originalSetDelegate]) {
        atomic_store_explicit(&shdw_licel_armed, YES, memory_order_release);
    }
    return YES;
}

void shdw_adapter_licel(SHDWHookSession* hooks) {
    [hooks performWhenTargetAvailable:^BOOL(SHDWHookSession* session) {
        return shdw_licel_attempt(session);
    }];
}
