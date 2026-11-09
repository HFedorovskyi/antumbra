#import "UniversalHooks.h"

#import <IOKit/IOKitLib.h>

// IOKit service-probing coverage. Detectors probe the IOKit registry for
// jailbreak-related kernel services / user clients (e.g. IOServiceMatching
// on a known JB service name, or IOServiceOpen on a JB user client). The
// matching dict is inspected for the requested service/class name; a
// JB-indicator name trips the behavioral detector and the probe is answered
// with "no such service" (kIOReturnNotFound / empty iterator) for external
// callers. Only VERIFIED jailbreak service names match — the same
// conservative stance as shdw_bootstrap_service_restricted in mach.x.
static BOOL shdw_iokit_service_name_restricted(const char* name) {
    if(!name || !name[0]) {
        return NO;
    }

    return strcmp(name, "AppleARMBackdoor") == 0
        || strncmp(name, "pongo", 5) == 0
        || strstr(name, "jailbreak") != NULL
        || strstr(name, "jbroot") != NULL;
}

// Inspects an IOServiceMatching/IOServiceNameMatching dict for a restricted
// service/class name. IOServiceMatching sets kIOClassKey; IOServiceNameMatching
// nests the name under kIOPropertyMatchKey -> "IOPropertyName".
static BOOL shdw_iokit_matching_restricted(CFDictionaryRef matching) {
    if(!matching) {
        return NO;
    }

    CFStringRef cls = CFDictionaryGetValue(matching, CFSTR(kIOClassKey));

    if(cls && CFGetTypeID(cls) == CFStringGetTypeID()) {
        char buf[256];

        if(CFStringGetCString(cls, buf, sizeof(buf), kCFStringEncodingUTF8) && shdw_iokit_service_name_restricted(buf)) {
            return YES;
        }
    }

    CFDictionaryRef propMatch = CFDictionaryGetValue(matching, CFSTR(kIOPropertyMatchKey));

    if(propMatch && CFGetTypeID(propMatch) == CFDictionaryGetTypeID()) {
        CFStringRef name = CFDictionaryGetValue(propMatch, CFSTR("IOPropertyName"));

        if(name && CFGetTypeID(name) == CFStringGetTypeID()) {
            char buf[256];

            if(CFStringGetCString(name, buf, sizeof(buf), kCFStringEncodingUTF8) && shdw_iokit_service_name_restricted(buf)) {
                return YES;
            }
        }
    }

    return NO;
}

// Resolves a service object's class name for the IOServiceOpen deny path.
// IORegistryEntryCreateCFProperty is not hooked, so no recursion; the lookup
// only runs for external callers on the deny path.
static CFTypeRef (*original_IORegistryEntryCreateCFProperty)(io_service_t service, CFStringRef key, CFAllocatorRef allocator, IOOptionBits options);

static BOOL shdw_iokit_service_restricted(io_service_t service) {
    // Unset until the lane installs or a detector's dlsym adopts it; without
    // the original there is nothing to chain to, so classify nothing.
    if(!service || !original_IORegistryEntryCreateCFProperty) {
        return NO;
    }

    CFStringRef cls = original_IORegistryEntryCreateCFProperty(service, CFSTR(kIOClassKey), kCFAllocatorDefault, 0);

    if(!cls) {
        return NO;
    }

    BOOL restricted = NO;

    if(CFGetTypeID(cls) == CFStringGetTypeID()) {
        char buf[256];

        if(CFStringGetCString(cls, buf, sizeof(buf), kCFStringEncodingUTF8)) {
            restricted = shdw_iokit_service_name_restricted(buf);
        }
    }

    CFRelease(cls);
    return restricted;
}

static kern_return_t (*original_IOServiceGetMatchingServices)(mach_port_t masterPort, CFDictionaryRef matching, io_iterator_t* existing);

// Stock no-match shape for IOServiceGetMatchingServices: kIOReturnSuccess
// with an EMPTY iterator (never kIOReturnNotFound — a stock device answers
// "no such service" with success + an iterator that yields nothing, and a
// caller branching off the error path would see the divergence).
static kern_return_t shdw_iokit_empty_iterator(io_iterator_t* existing) {
    if(!existing) {
        return kIOReturnSuccess;
    }

    // Match against a service name that can never exist; the kernel answers
    // success with an empty iterator.
    CFMutableDictionaryRef none = IOServiceMatching("__shadow_no_such_service__");

    if(none) {
        kern_return_t kr = original_IOServiceGetMatchingServices(MACH_PORT_NULL, none, existing);
        CFRelease(none);

        if(kr == kIOReturnSuccess && existing) {
            return kr;
        }
    }

    *existing = 0;
    return kIOReturnSuccess;
}

static kern_return_t replaced_IOServiceGetMatchingServices(mach_port_t masterPort, CFDictionaryRef matching, io_iterator_t* existing) {
    if(isCallerExternal() && shdw_iokit_matching_restricted(matching)) {
        shdw_detector_detected("iokit");
        return shdw_iokit_empty_iterator(existing);
    }

    return original_IOServiceGetMatchingServices(masterPort, matching, existing);
}

static io_service_t (*original_IOServiceGetMatchingService)(mach_port_t masterPort, CFDictionaryRef matching);
static io_service_t replaced_IOServiceGetMatchingService(mach_port_t masterPort, CFDictionaryRef matching) {
    if(isCallerExternal() && shdw_iokit_matching_restricted(matching)) {
        shdw_detector_detected("iokit");
        return 0;
    }

    return original_IOServiceGetMatchingService(masterPort, matching);
}

static kern_return_t (*original_IOServiceOpen)(io_service_t service, task_port_t owningTask, uint32_t type, io_connect_t* connect);
static kern_return_t replaced_IOServiceOpen(io_service_t service, task_port_t owningTask, uint32_t type, io_connect_t* connect) {
    if(isCallerExternal() && shdw_iokit_service_restricted(service)) {
        shdw_detector_detected("iokit");

        if(connect) {
            *connect = 0;
        }

        // Stock shape for an existing service that exposes no openable user
        // client: kIOReturnUnsupported. kIOReturnNotFound would contradict
        // the service object the caller just matched and holds in hand.
        return kIOReturnUnsupported;
    }

    return original_IOServiceOpen(service, owningTask, type, connect);
}

// Property-table exfiltration without a matching-dict probe: a detector
// holding a service object (matched by class, or iterated from the root)
// reads its properties for jailbreak strings (IOPropertyName, version,
// bundle identifiers). IORegistryEntryCreateCFProperty is already used
// internally by shdw_iokit_service_restricted above, so only filter when
// the RESULT carries a restricted string — never the whole table (a NULL
// whole-table answer for a live service contradicts the handle in hand).
// Only VERIFIED jailbreak tokens match (same stance as the service-name
// gate); stock property values pass through byte-identical.
static BOOL shdw_iokit_property_value_restricted(CFTypeRef value) {
    if(!value) return NO;
    CFTypeID stringID = CFStringGetTypeID();
    if(CFGetTypeID(value) == stringID) {
        char buf[256];
        if(CFStringGetCString((CFStringRef)value, buf, sizeof(buf), kCFStringEncodingUTF8))
            return shdw_iokit_service_name_restricted(buf);
        return NO;
    }
    if(CFGetTypeID(value) == CFArrayGetTypeID()) {
        CFIndex n = CFArrayGetCount((CFArrayRef)value);
        if(n < 0 || n > 128) return NO;  // malformed: fail open
        for(CFIndex i = 0; i < n; i++)
            if(shdw_iokit_property_value_restricted(CFArrayGetValueAtIndex((CFArrayRef)value, i)))
                return YES;
        return NO;
    }
    if(CFGetTypeID(value) == CFDictionaryGetTypeID()) {
        CFIndex n = CFDictionaryGetCount((CFDictionaryRef)value);
        if(n <= 0 || n > 64) return NO;  // malformed: fail open
        const void* keys[64];
        const void* vals[64];
        CFDictionaryGetKeysAndValues((CFDictionaryRef)value, keys, vals);
        for(CFIndex i = 0; i < n; i++)
            if(shdw_iokit_property_value_restricted(vals[i])) return YES;
        return NO;
    }
    return NO;
}

static CFTypeRef (*original_IORegistryEntryCreateCFProperty)(io_service_t service, CFStringRef key, CFAllocatorRef allocator, IOOptionBits options);
static CFTypeRef replaced_IORegistryEntryCreateCFProperty(io_service_t service, CFStringRef key, CFAllocatorRef allocator, IOOptionBits options) {
    CFTypeRef result = original_IORegistryEntryCreateCFProperty(service, key, allocator, options);
    if(isCallerExternal() && result && shdw_iokit_property_value_restricted(result)) {
        CFRelease(result);
        return NULL;  // stock shape for an absent property
    }
    return result;
}

static kern_return_t (*original_IORegistryEntryCreateCFProperties)(io_service_t service, CFMutableDictionaryRef* properties, CFAllocatorRef allocator, IOOptionBits options);
static kern_return_t replaced_IORegistryEntryCreateCFProperties(io_service_t service, CFMutableDictionaryRef* properties, CFAllocatorRef allocator, IOOptionBits options) {
    kern_return_t kr = original_IORegistryEntryCreateCFProperties(service, properties, allocator, options);
    if(!isCallerExternal() || kr != kIOReturnSuccess || !properties || !*properties) return kr;
    // Strip restricted values key-by-key; an emptied table stays a valid
    // (empty) table — never a NULL table for a live service.
    CFMutableDictionaryRef table = *properties;
    CFIndex n = CFDictionaryGetCount(table);
    if(n <= 0 || n > 256) return kr;  // malformed: fail open
    const void* keys[256];
    const void* vals[256];
    CFDictionaryGetKeysAndValues(table, keys, vals);
    for(CFIndex i = 0; i < n; i++)
        if(shdw_iokit_property_value_restricted(vals[i]))
            CFDictionaryRemoveValue(table, keys[i]);
    return kr;
}

static CFTypeRef (*original_IORegistryEntrySearchCFProperty)(io_service_t service, const io_name_t plane, CFStringRef key, CFAllocatorRef allocator, IOOptionBits options);
static CFTypeRef replaced_IORegistryEntrySearchCFProperty(io_service_t service, const io_name_t plane, CFStringRef key, CFAllocatorRef allocator, IOOptionBits options) {
    CFTypeRef result = original_IORegistryEntrySearchCFProperty(service, plane, key, allocator, options);
    if(isCallerExternal() && result && shdw_iokit_property_value_restricted(result)) {
        CFRelease(result);
        return NULL;
    }
    return result;
}

// --- Phase 4: iterator/notification surfaces. A detector blocked at the
// matching-dict gate falls back to enumerating the registry and filtering
// client-side, or subscribing for arrival notifications. Same
// verified-token gate, same stock shapes:
//   - IOIteratorNext: per-object skip — restricted services are skipped
//     to the next object, never NULL-terminated early (early-NULL reads
//     as end-of-iteration AND hides legitimate later entries; skipping
//     preserves the full visible sequence).
//   - IOObjectConformsTo: BOOL gate on the object's class name.
//   - IOServiceAddMatchingNotification: subscribe-time gate — a
//     restricted matching dict is answered with the empty-iterator shape
//     up front (the notification itself still installs; a later wakeup
//     re-enters IOIteratorNext, which skips per-object).
// The iterators themselves (IORegistryCreateIterator /
// IORegistryEntryCreateIterator) name no service and pass through: every
// entry they yield is classified at the gates above.
static io_object_t (*original_IOIteratorNext)(io_iterator_t iterator);
static io_object_t replaced_IOIteratorNext(io_iterator_t iterator) {
    if(!isCallerExternal()) {
        return original_IOIteratorNext(iterator);
    }

    io_object_t obj;
    while((obj = original_IOIteratorNext(iterator)) != 0) {
        if(!shdw_iokit_service_restricted(obj)) {
            break;
        }
        IOObjectRelease(obj);  // skipped handle belongs to us now
        shdw_detector_detected("iokit");
    }
    return obj;
}

static boolean_t (*original_IOObjectConformsTo)(io_object_t object, const io_name_t className);
static boolean_t replaced_IOObjectConformsTo(io_object_t object, const io_name_t className) {
    if(isCallerExternal() && className && shdw_iokit_service_name_restricted(className)) {
        shdw_detector_detected("iokit");
        return false;
    }
    if(isCallerExternal() && shdw_iokit_service_restricted(object)) {
        shdw_detector_detected("iokit");
        return false;
    }
    return original_IOObjectConformsTo(object, className);
}

static kern_return_t (*original_IOServiceAddMatchingNotification)(IONotificationPortRef notifyPort, const io_name_t notificationType, CFDictionaryRef matching, IOServiceMatchingCallback callback, void* refCon, io_iterator_t* notification);
static kern_return_t replaced_IOServiceAddMatchingNotification(IONotificationPortRef notifyPort, const io_name_t notificationType, CFDictionaryRef matching, IOServiceMatchingCallback callback, void* refCon, io_iterator_t* notification) {
    if(isCallerExternal() && shdw_iokit_matching_restricted(matching)) {
        shdw_detector_detected("iokit");
        // Install the real notification (a later wakeup re-enters
        // IOIteratorNext, which skips per-object), but hand back the
        // empty-iterator shape for the current snapshot.
        kern_return_t kr = original_IOServiceAddMatchingNotification(notifyPort, notificationType, matching, callback, refCon, notification);
        if(kr == kIOReturnSuccess && notification) {
            if(*notification) {
                IOObjectRelease(*notification);
            }
            shdw_iokit_empty_iterator(notification);
        }
        return kr;
    }
    return original_IOServiceAddMatchingNotification(notifyPort, notificationType, matching, callback, refCon, notification);
}

// --- Probe instrumentation: registry-walk census (Debug_ApiTrace only) ---
// A detector that resolves the walk entry points by dlsym (DexProtector in
// Revolut does: GetRootEntry -> GetChildIterator -> Next -> GetClass /
// GetRegistryEntryID) never touches the matching-dict gates above. These
// replacements do not filter; they log the chain and the values handed back
// so the verdict input can be identified. Capped so one walk cannot flood
// the 30000-line apitrace budget.
static int shdw_iokit_probe_lines = 0;
#define SHDW_IOKIT_PROBE_LINE(fmt, ...)                                        \
    do {                                                                       \
        if(shdw_diag_api_trace && shdw_iokit_probe_lines < 600) {              \
            shdw_iokit_probe_lines += 1;                                       \
            shdw_diag_apitrace(__builtin_extract_return_addr(__builtin_return_address(0)), fmt, ##__VA_ARGS__); \
        }                                                                      \
    } while(0)

static io_registry_entry_t (*original_IORegistryGetRootEntry)(mach_port_t masterPort);
static io_registry_entry_t replaced_IORegistryGetRootEntry(mach_port_t masterPort) {
    io_registry_entry_t entry = original_IORegistryGetRootEntry(masterPort);
    if(isCallerExternal()) {
        SHDW_IOKIT_PROBE_LINE("IORegistryGetRootEntry port=0x%x -> 0x%x", (unsigned)masterPort, (unsigned)entry);
    }
    return entry;
}

static kern_return_t (*original_IORegistryEntryGetChildIterator)(io_registry_entry_t entry, const io_name_t plane, io_iterator_t* iterator);
static kern_return_t replaced_IORegistryEntryGetChildIterator(io_registry_entry_t entry, const io_name_t plane, io_iterator_t* iterator) {
    kern_return_t kr = original_IORegistryEntryGetChildIterator(entry, plane, iterator);
    if(isCallerExternal()) {
        SHDW_IOKIT_PROBE_LINE("IORegistryEntryGetChildIterator entry=0x%x plane=%s kr=0x%x iter=0x%x",
                              (unsigned)entry, plane ? plane : "(null)", (unsigned)kr,
                              (unsigned)(iterator ? *iterator : 0));
    }
    return kr;
}

static kern_return_t (*original_IOObjectGetClass)(io_object_t object, io_name_t className);
static kern_return_t replaced_IOObjectGetClass(io_object_t object, io_name_t className) {
    kern_return_t kr = original_IOObjectGetClass(object, className);
    if(isCallerExternal()) {
        SHDW_IOKIT_PROBE_LINE("IOObjectGetClass obj=0x%x kr=0x%x class=%s",
                              (unsigned)object, (unsigned)kr, className ? className : "");
    }
    return kr;
}

static kern_return_t (*original_IORegistryEntryGetRegistryEntryID)(io_registry_entry_t entry, uint64_t* entryID);
static kern_return_t replaced_IORegistryEntryGetRegistryEntryID(io_registry_entry_t entry, uint64_t* entryID) {
    kern_return_t kr = original_IORegistryEntryGetRegistryEntryID(entry, entryID);
    if(isCallerExternal()) {
        SHDW_IOKIT_PROBE_LINE("IORegistryEntryGetRegistryEntryID entry=0x%x kr=0x%x id=0x%llx",
                              (unsigned)entry, (unsigned)kr,
                              entryID ? (unsigned long long)*entryID : 0ULL);
    }
    return kr;
}

// One name table drives both install paths: the ctor install (for apps that
// already map IOKit) and dlsym adoption (for detectors that dlopen the
// framework with a local handle, which no Shadow-side lookup can see).
typedef struct {
    const char* name;
    void* replacement;
    void** original;
} shdw_iokit_install_entry_t;

static const shdw_iokit_install_entry_t shdw_iokit_install_table[] = {
    { "_IOServiceGetMatchingServices", (void*)&replaced_IOServiceGetMatchingServices, (void**)&original_IOServiceGetMatchingServices },
    { "_IOServiceOpen", (void*)&replaced_IOServiceOpen, (void**)&original_IOServiceOpen },
    { "_IOServiceGetMatchingService", (void*)&replaced_IOServiceGetMatchingService, (void**)&original_IOServiceGetMatchingService },
    { "_IORegistryEntryCreateCFProperty", (void*)&replaced_IORegistryEntryCreateCFProperty, (void**)&original_IORegistryEntryCreateCFProperty },
    { "_IORegistryEntryCreateCFProperties", (void*)&replaced_IORegistryEntryCreateCFProperties, (void**)&original_IORegistryEntryCreateCFProperties },
    { "_IORegistryEntrySearchCFProperty", (void*)&replaced_IORegistryEntrySearchCFProperty, (void**)&original_IORegistryEntrySearchCFProperty },
    { "_IOIteratorNext", (void*)&replaced_IOIteratorNext, (void**)&original_IOIteratorNext },
    { "_IOObjectConformsTo", (void*)&replaced_IOObjectConformsTo, (void**)&original_IOObjectConformsTo },
    { "_IOServiceAddMatchingNotification", (void*)&replaced_IOServiceAddMatchingNotification, (void**)&original_IOServiceAddMatchingNotification },
    { "_IORegistryGetRootEntry", (void*)&replaced_IORegistryGetRootEntry, (void**)&original_IORegistryGetRootEntry },
    { "_IORegistryEntryGetChildIterator", (void*)&replaced_IORegistryEntryGetChildIterator, (void**)&original_IORegistryEntryGetChildIterator },
    { "_IOObjectGetClass", (void*)&replaced_IOObjectGetClass, (void**)&original_IOObjectGetClass },
    { "_IORegistryEntryGetRegistryEntryID", (void*)&replaced_IORegistryEntryGetRegistryEntryID, (void**)&original_IORegistryEntryGetRegistryEntryID },
};

// Called from dlsym with the exact address the caller just resolved. Entry
// patching these targets is not an option: HookKit refuses some of them ("entry
// patch would not be a single aligned store"), and when the framework sits
// behind a detector's local dlopen handle no Shadow-side lookup can find them.
// Adopt the address as the original and hand back the wrapper for this very
// dlsym — the caller then invokes Shadow code, which chains to the exact
// function it asked for.
void* shdw_iokit_adopt_dlsym(const char* c_symbol, void* address) {
    if(!c_symbol || !address) {
        return NULL;
    }

    for(size_t i = 0; i < sizeof(shdw_iokit_install_table) / sizeof(shdw_iokit_install_table[0]); i++) {
        const char* name = shdw_iokit_install_table[i].name;

        if(name && name[0] == '_') {
            name += 1;
        }
        if(!name || strcmp(name, c_symbol) != 0) {
            continue;
        }

        void** original = shdw_iokit_install_table[i].original;
        if(original && !*original) {
            *original = address;
        }
        if(original && *original != address) {
            shdw_diag_log("iokitadopt: %s second addr=%p kept=%p", c_symbol, address, *original);
        }
        return shdw_iokit_install_table[i].replacement;
    }

    return NULL;
}

void shdw_universal_iokit(SHDWHookSession* hooks) {
    for(size_t i = 0; i < sizeof(shdw_iokit_install_table) / sizeof(shdw_iokit_install_table[0]); i++) {
        const shdw_iokit_install_entry_t* e = &shdw_iokit_install_table[i];

        if(e->original && *e->original) {
            continue;
        }

        // shdw_resolve_libsystem = dlsym hash lookup; findSymbolInImage:NULL
        // walked all ~600 loaded images and was pathologically slow.
        void* sym = shdw_resolve_libsystem(e->name);

        if(sym) {
            [hooks hookFunction:sym withReplacement:e->replacement outOldPtr:e->original];
        }
    }
}

// Symbol policy for the iokit C-function group (see dyld.x's
// shdw_sym_policy_table): dlsym must resolve every fishhook-rebound iokit
// export to its replacement for external callers, so the GOT-vs-dlsym
// comparison agrees. Guarded by the original pointer: runtime-resolved
// symbols (IOServiceGetMatchingService) only resolve to their replacement
// when actually installed.
typedef struct {
    const char* name;
    void* replacement;
    void* const* original;
} shdw_iokit_sym_policy_entry_t;

static const shdw_iokit_sym_policy_entry_t shdw_iokit_sym_policy_table[] = {
    { "IOServiceGetMatchingServices", (void*)&replaced_IOServiceGetMatchingServices, (void* const*)&original_IOServiceGetMatchingServices },
    { "IOServiceGetMatchingService", (void*)&replaced_IOServiceGetMatchingService, (void* const*)&original_IOServiceGetMatchingService },
    { "IOServiceOpen", (void*)&replaced_IOServiceOpen, (void* const*)&original_IOServiceOpen },
    { "IORegistryEntryCreateCFProperties", (void*)&replaced_IORegistryEntryCreateCFProperties, (void* const*)&original_IORegistryEntryCreateCFProperties },
    { "IORegistryEntryCreateCFProperty", (void*)&replaced_IORegistryEntryCreateCFProperty, (void* const*)&original_IORegistryEntryCreateCFProperty },
    { "IORegistryEntrySearchCFProperty", (void*)&replaced_IORegistryEntrySearchCFProperty, (void* const*)&original_IORegistryEntrySearchCFProperty },
    { "IOIteratorNext", (void*)&replaced_IOIteratorNext, (void* const*)&original_IOIteratorNext },
    { "IOObjectConformsTo", (void*)&replaced_IOObjectConformsTo, (void* const*)&original_IOObjectConformsTo },
    { "IOServiceAddMatchingNotification", (void*)&replaced_IOServiceAddMatchingNotification, (void* const*)&original_IOServiceAddMatchingNotification },
    // Registry-walk entry points: DexProtector resolves these by dlsym, so
    // the import-slot rebind never sees the caller; the policy table does.
    { "IORegistryGetRootEntry", (void*)&replaced_IORegistryGetRootEntry, (void* const*)&original_IORegistryGetRootEntry },
    { "IORegistryEntryGetChildIterator", (void*)&replaced_IORegistryEntryGetChildIterator, (void* const*)&original_IORegistryEntryGetChildIterator },
    { "IOObjectGetClass", (void*)&replaced_IOObjectGetClass, (void* const*)&original_IOObjectGetClass },
    { "IORegistryEntryGetRegistryEntryID", (void*)&replaced_IORegistryEntryGetRegistryEntryID, (void* const*)&original_IORegistryEntryGetRegistryEntryID },
};

void* shdw_sym_policy_lookup_iokit(const char* name) {
    if(!name) {
        return NULL;
    }

    for(size_t i = 0; i < sizeof(shdw_iokit_sym_policy_table) / sizeof(shdw_iokit_sym_policy_table[0]); i++) {
        if(strcmp(name, shdw_iokit_sym_policy_table[i].name) == 0) {
            if(shdw_iokit_sym_policy_table[i].original && *shdw_iokit_sym_policy_table[i].original == NULL) {
                return NULL;  // not installed yet; dlsym adopts it below
            }

            return shdw_iokit_sym_policy_table[i].replacement;
        }
    }

    return NULL;
}

// Reverse of the policy lookup: hooked iokit replacement -> original function,
// so dladdr() on a substituted IORegistryEntry*/IOService* address resolves to
// the genuine system image. Same contract as
// shdw_sym_original_for_replacement_libc.
void* shdw_sym_original_for_replacement_iokit(const void* addr) {
    if(!addr) {
        return NULL;
    }
    for(size_t i = 0; i < sizeof(shdw_iokit_sym_policy_table) / sizeof(shdw_iokit_sym_policy_table[0]); i++) {
        if(shdw_iokit_sym_policy_table[i].replacement == addr) {
            if(!shdw_iokit_sym_policy_table[i].original || !*shdw_iokit_sym_policy_table[i].original) {
                return NULL;
            }
            return *shdw_iokit_sym_policy_table[i].original;
        }
    }
    return NULL;
}
