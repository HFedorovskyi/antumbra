#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#import "../common.h"
#import <Shadow/JBPath.h>
#import "hooks/hooks.h"
#import "hooks/UniversalHooks.h"
#import "hooks/AdapterHooks.h"
#import "policy/PathPolicy.h"

#import <Shadow.h>
#import <Shadow/Settings.h>
#import <libSandy.h>

#include <time.h>

static void shdw_lab_mark(const char* tag);
#include <dlfcn.h>
#include <mach/mach.h>

#import "HookCoordinator.h"
#import "hooks/Diag.h"
#import "../../vendor/apple/dyld_priv.h"

// Set by an exact detector-adapter match or behavioral tripwires.
BOOL shdw_detector_present = NO;

// Emergency kill-switch for the dyld_all_image_infos memory-hiding patch.
BOOL shdw_memory_hiding_enabled = YES;

// Debug bisection switches for the dyld lane; off unless the profile sets them.
BOOL shdw_dyld_no_infos_hiding = NO;
BOOL shdw_dyld_no_spi_inline = NO;
NSString* gShdwDyldSkipRebinds = nil;

// User opt-in (global or per-app, resolved in getPreferencesForIdentifier:):
// when YES, adapters may run disable-style neutralizers that force a detector's
// check result rather than only shaping a stock-looking environment.
BOOL shdw_detector_aggressive = NO;

// Per-app: neutralize the UIScreen capture report so a bank's login gate does
// not treat a mirrored/recorded screen as a security event (Detector_ScreenCap).
BOOL shdw_detector_screencap = NO;

// Per-app: clear the risk bit of the web security-status cookie the app
// publishes into its WKWebView (Detector_XsCookie).
BOOL shdw_detector_xscookie = NO;
// Per-app switch: answer restricted Mach-service probes as a stock device
// does (unknown service) instead of known-but-sandbox-denied.
// Pref: Detector_HideBootstrap.
BOOL shdw_detector_hidebootstrap = NO;

// Diagnostic only: name the presented screen and the code path behind a
// blocking alert (pref: Debug_BannerProbe).
BOOL shdw_debug_bannerprobe = NO;

static BOOL _shdw_watcher_enabled = NO;
static BOOL _shdw_uikit_installed = NO;
static SHDWHookCoordinator* shdw_coordinator_instance = nil;

// Journaled import slots must not outlive the image they live in: repair
// dereferences them, and an unmapped or reused address is a crash or a wild
// store. Registered from the core so the prune runs with the dyld unit
// disabled too.
static void shdw_rebind_prune_image(const struct mach_header* mh, intptr_t vmaddr_slide) {
    if(!mh) {
        return;
    }

    uintptr_t base = 0, end = 0;
    if(shdw_image_span(mh, vmaddr_slide, &base, &end)) {
        SHDWRebindForgetRange(base, end);
    }
}

// UIKit may not exist when the payload is injected at process spawn. Install
// UIKit-class groups only after dyld reports that the framework is loaded.
static void shdw_early_image_add(const struct mach_header* mh, intptr_t vmaddr_slide) {
    (void) vmaddr_slide;

    [SHDWHookCoordinator shdw_requestPendingTargetDrain];

    if(!__atomic_load_n(&_shdw_watcher_enabled, __ATOMIC_ACQUIRE) ||
       __atomic_load_n(&_shdw_uikit_installed, __ATOMIC_ACQUIRE)) {
        return;
    }

    @autoreleasepool {
        const char* path = dyld_image_path_containing_address(mh);

        if(!path || !path[0]) {
            return;
        }

        NSString* image = [[NSString stringWithUTF8String:path] lowercaseString];

        if([image containsString:@"uikit.framework"] &&
           !__atomic_exchange_n(&_shdw_uikit_installed, YES, __ATOMIC_ACQ_REL)) {
            [shdw_coordinator_instance enqueueEvent:SHDWEventUIKitLoaded];
        }
    }
}

void shdw_detector_detected(const char* reason) {
    (void) reason;

    if(!shdw_coordinator_instance) {
        return;
    }

    shdw_detector_present = YES;
    shdw_detector_write_policy_set_enabled(YES);
    [shdw_coordinator_instance escalate];
}

static void shdw_coord_envvars_c(SHDWHookSession* hooks) {
    setenv("SHELL", "/bin/sh", 1);
    shdw_universal_envvars_c(hooks);
    shdw_universal_envpolicy(hooks);
}

static void shdw_coord_symlookup(SHDWHookSession* hooks) {
    shdw_universal_symlookup(hooks);
    shdw_universal_symaddrlookup(hooks);
}

static void shdw_coord_detector_integrity(SHDWHookSession* hooks) {
    [Shadow shdwEnterInternalRead];
    @try {
        shdw_universal_objc_methodimpl_detector(hooks);
        shdw_universal_import_slot_protection(hooks);
    } @finally {
        [Shadow shdwExitInternalRead];
    }
}

static void shdw_coord_filesystem_objc(SHDWHookSession* hooks) {
    shdw_universal_filesystem_objc(hooks);
    shdw_universal_nsfilehandle(hooks);
    shdw_universal_nsfileversion(hooks);
    shdw_universal_nsfilewrapper(hooks);
}

static void shdw_coord_foundation_objc(SHDWHookSession* hooks) {
    shdw_universal_nsarray(hooks);
    shdw_universal_nsdictionary(hooks);
    shdw_universal_nsbundle(hooks);
    shdw_universal_nsstring(hooks);
    shdw_universal_nsurl(hooks);
    shdw_universal_nsdata(hooks);
    shdw_universal_nsthread(hooks);
    shdw_universal_user_defaults(hooks);
    shdw_universal_nstask(hooks);
}

static void shdw_plugin_policy_nop(SHDWHookSession* hooks) { (void)hooks; }

// Must stay in SHDWPluginRegistry() order (Hybrid: verified vs SHDWPluginOrder.inc).
#import <Shadow/SHDWPluginOrder.inc>
static const SHDWPluginInstaller kSHDWPluginInstallers[] = {
    { "Universal_Dyld",                       shdw_universal_dyld },
    { "Universal_Filesystem_C",               shdw_universal_filesystem_c },
    { "Universal_EnvVars_C",                  shdw_coord_envvars_c },
    { "Universal_EnvVars_ObjC",               shdw_universal_nsprocessinfo },
    { "Adapter_DeviceCheck",                   shdw_adapter_devicecheck },
    { "Adapter_FreeRASP",                      shdw_adapter_freerasp },
    { "Universal_MachBootstrap",              shdw_universal_mach_bootstrap },
    { "Universal_IOKit",                      shdw_universal_iokit },
    { "Universal_LowLevelC",                  shdw_universal_low_level_c },
    { "Universal_AntiDebugging",              shdw_universal_antidebugging },
    { "Universal_CodeSigning",                shdw_universal_codesigning },
    { "Universal_ObjC",                       shdw_universal_objc },
    { "Universal_ObjC_MethodImplementation",  shdw_universal_objc_methodimpl },
    { "Universal_Syscall",                    shdw_universal_syscall },
    { "Universal_Memory",                     shdw_universal_memory },
    { "Universal_Sandbox",                    shdw_universal_sandbox },
    { "Universal_HideClasses",                shdw_universal_hide_classes },
    { "Universal_SymbolLookup",               shdw_coord_symlookup },
    { "Universal_DynamicLibrariesExtra",      shdw_universal_dynamic_libraries_extra },
    { "Universal_DetectorIntegrity",          shdw_coord_detector_integrity },
    { "Universal_Filesystem_ObjC",            shdw_coord_filesystem_objc },
    { "Universal_Foundation_ObjC",            shdw_coord_foundation_objc },
    { "Universal_HideApps",                   shdw_universal_hide_apps },
    { "Universal_URLScheme",                  shdw_universal_url_scheme },
    { "Universal_Foundation_UIKit",           shdw_universal_foundation_uikit },
    { "Universal_PasscodeStatus",             shdw_universal_passcode_status },
    { "Adapter_DeviceSecurityKit",             shdw_adapter_devicesecuritykit },
    { "Adapter_IOSSecuritySuite",              shdw_adapter_iossecuritysuite },
    { "Adapter_MobileProtect",                 shdw_adapter_mobileprotect },
    { "Adapter_PureLive",                      shdw_adapter_purelive },
    { "Adapter_Licel",                         shdw_adapter_licel },
    { "Adapter_Transakt",                      shdw_adapter_transakt },
    // Policy plugins — no hook install, evaluated via RestrictionEngine
    { "Policy_Path",                  shdw_plugin_policy_nop },
    { "Policy_Environment",           shdw_plugin_policy_nop },
    { "Policy_Process",               shdw_plugin_policy_nop },
    { "Policy_PseudoSandbox",         shdw_plugin_policy_nop },
};
_Static_assert(sizeof(kSHDWPluginInstallers)/sizeof(kSHDWPluginInstallers[0]) == SHDW_PLUGIN_COUNT, "installer count != SHDW_PLUGIN_COUNT");

static BOOL shdw_bisect_no_ek_handler = NO;

// Ports the jailbreak's launch exception handler installs on this task. Read by
// the sandbox lane's task_get_exception_ports replacement (see
// hooks/Universal/sandbox.x) so external probes see the app's own handler set
// and not the hooking engine's.
mach_port_t shdw_ek_exc_ports[EXC_TYPES_COUNT];
int shdw_ek_exc_port_count = 0;

// Snapshot of the task's current exception handler ports. The caller owns every
// non-null send right returned here.
static mach_msg_type_number_t shdw_exc_query_ports(mach_port_t out[EXC_TYPES_COUNT]) {
    exception_mask_t masks[EXC_TYPES_COUNT];
    exception_behavior_t behaviors[EXC_TYPES_COUNT];
    thread_state_flavor_t flavors[EXC_TYPES_COUNT];
    mach_msg_type_number_t count = EXC_TYPES_COUNT;

    if(task_get_exception_ports(mach_task_self(), EXC_MASK_ALL, masks, &count,
                                out, behaviors, flavors) != KERN_SUCCESS) {
        return 0;
    }

    return count;
}

// Record the handler ports that appear only after EKLaunchExceptionHandler ran.
// A port already present beforehand belongs to the app (its own crash reporter),
// so it is released and never hidden. Recorded ports keep their send right: the
// name stays alive for comparison and cannot be recycled into an app port.
static void shdw_ek_exc_capture(void) {
    mach_port_t before[EXC_TYPES_COUNT] = {0};
    mach_msg_type_number_t beforeCount = shdw_exc_query_ports(before);

    void* ekLaunch = dlsym(RTLD_DEFAULT, "EKLaunchExceptionHandler");
    if(ekLaunch) {
        ((mach_port_t (*)(void))ekLaunch)();
    }

    mach_port_t after[EXC_TYPES_COUNT] = {0};
    mach_msg_type_number_t afterCount = shdw_exc_query_ports(after);

    for(mach_msg_type_number_t i = 0; i < afterCount; i++) {
        BOOL known = NO;
        for(mach_msg_type_number_t j = 0; j < beforeCount; j++) {
            if(after[i] != MACH_PORT_NULL && after[i] == before[j]) {
                known = YES;
                break;
            }
        }

        if(!known && after[i] != MACH_PORT_NULL &&
           shdw_ek_exc_port_count < EXC_TYPES_COUNT) {
            shdw_ek_exc_ports[shdw_ek_exc_port_count++] = after[i];
            continue;
        }

        if(after[i] != MACH_PORT_NULL) {
            mach_port_deallocate(mach_task_self(), after[i]);
        }
    }

    for(mach_msg_type_number_t j = 0; j < beforeCount; j++) {
        if(before[j] != MACH_PORT_NULL) {
            mach_port_deallocate(mach_task_self(), before[j]);
        }
    }

    NSLog(@"[Shadow][exc] ellekit ports=%d", shdw_ek_exc_port_count);
}

static void shdw_coordinator_ctor(NSDictionary<NSString*, id>* prefs) {
    shdw_coordinator_instance =
        [[SHDWHookCoordinator alloc] initWithInstallerTable:kSHDWPluginInstallers
                                                      count:sizeof(kSHDWPluginInstallers) / sizeof(kSHDWPluginInstallers[0])
                                                      prefs:prefs];

    if(!shdw_coordinator_instance) {
        NSLog(@"[Shadow][coordinator] init failed — continuing");
        return;
    }

    // Install synchronously: Shadow must be active before the app's main()
    // runs (the stub loader's whole point). The installers call into
    // ElleKit's substitutor, whose JIT-less exception-based hooking path
    // (brk #1) needs the exception handler up before any brk-patched hook
    // can fire. Pre-initialize it here so those hooks are handled instead of
    // trapping (observed: EXC_BREAKPOINT SIGTRAP during the dyld unit's
    // install when isPathRestricted re-enters a brk-patched function).
    // The ports that initialisation adds are recorded so probes can be shown
    // the app's own handler set instead.
    if(!shdw_bisect_no_ek_handler) {
        shdw_ek_exc_capture();
    }

    [shdw_coordinator_instance installEvent:SHDWEventCtor];

    // Watcher replay runs after the install (it depends on the coordinator's
    // backends being resolved).
    // The UIKit event is also the only way the passcode-status unit can ever
    // be planned (its registry row is pref-less and self-gates on aggressive
    // mode), so aggressive mode alone must arm the watcher: with both
    // URL-scheme and Foundation hiding off, passcode probes would otherwise
    // read the real device state with no log.
    BOOL watcherEnabled = shdw_coordinator_instance
        && (shdw_coordinator_instance.backends.capabilities & SHDWCapMessage)
        && ([prefs[SHDWUniversalURLSchemeID] boolValue] || [prefs[SHDWUniversalFoundationID] boolValue]
            || shdw_detector_aggressive);
    __atomic_store_n(&_shdw_watcher_enabled, watcherEnabled, __ATOMIC_RELEASE);

    if(watcherEnabled) {
        uint32_t count = _dyld_image_count();

        for(uint32_t i = 0; i < count; i++) {
            shdw_early_image_add(_dyld_get_image_header(i), _dyld_get_image_vmaddr_slide(i));
        }
        if(__atomic_load_n(&_shdw_uikit_installed, __ATOMIC_ACQUIRE)) {
            [shdw_coordinator_instance installEvent:SHDWEventUIKitLoaded];
        }
    }

    NSLog(@"completed hooks");
    shdw_lab_mark("ctor-hooks-done");
}

// Lab timing marker: independent of Debug_Diag, append "marker <name>" to
// $HOME/Library/Caches/shdw_bs.log with an epoch timestamp.
static void shdw_lab_mark(const char* tag) {
    const char* home = getenv("HOME");
    if(!home) return;
    char path[PATH_MAX];
    snprintf(path, sizeof path, "%s/Library/Caches/shdw_bs.log", home);
    FILE* f = fopen(path, "a");
    if(!f) return;
    fprintf(f, "%ld %d MARK %s imgs=%d\n", (long)time(NULL), (int)getpid(), tag,
            (int)_dyld_image_count());
    fclose(f);
}

%ctor {
    shdw_lab_mark("ctor-entry");
    @try {
        NSString* bundleIdentifier = [NSBundle mainBundle].bundleIdentifier;

        // Debug bisection switches read straight from the on-disk overlay so
        // they take effect before any ctor side effect runs.
        BOOL shdw_bisect_no_sandy = NO;
        BOOL shdw_bisect_no_early_image = NO;
        BOOL shdw_bisect_no_hide_names = NO;
        {
            NSDictionary* earlyFilePrefs = [NSDictionary dictionaryWithContentsOfFile:@SHADOW_PREFS_PLIST];
            NSDictionary* appEarlyPrefs =
                [earlyFilePrefs[bundleIdentifier] isKindOfClass:[NSDictionary class]]
                    ? earlyFilePrefs[bundleIdentifier]
                    : nil;
            if(appEarlyPrefs) {
                shdw_bisect_no_sandy = [appEarlyPrefs[@"Debug_NoSandy"] boolValue];
                shdw_bisect_no_early_image = [appEarlyPrefs[@"Debug_NoEarlyImage"] boolValue];
                shdw_bisect_no_hide_names = [appEarlyPrefs[@"Debug_NoHideNames"] boolValue];
                shdw_bisect_no_ek_handler = [appEarlyPrefs[@"Debug_NoEKHandler"] boolValue];
            }
        }

        // Registration replays current images while the watcher is disabled;
        // they are replayed once more after preferences and hooks are ready.
        if(!shdw_bisect_no_early_image) {
            _dyld_register_func_for_add_image(shdw_early_image_add);
        }
        _dyld_register_func_for_remove_image(shdw_rebind_prune_image);

        if(!shdw_bisect_no_sandy &&
           kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_11_0) {
            libSandy_applyProfile("ShadowSettings");
        }

        NSDictionary* prefs = [[ShadowSettings sharedInstance] getPreferencesForIdentifier:bundleIdentifier];

        // Diagnostic bisection overlay: for the keys below the on-disk plist
        // wins over the cfprefsd-cached suite domain, so an A/B run can be
        // driven by writing the file and relaunching.
        {
            NSDictionary* filePrefs = [NSDictionary dictionaryWithContentsOfFile:@SHADOW_PREFS_PLIST];
            NSDictionary* appFilePrefs =
                [filePrefs[bundleIdentifier] isKindOfClass:[NSDictionary class]]
                    ? filePrefs[bundleIdentifier]
                    : nil;
            if(appFilePrefs) {
                NSMutableDictionary* merged = prefs ? [prefs mutableCopy]
                                                    : [NSMutableDictionary dictionary];
                for(NSString* key in @[ @"App_Enabled", SHDWDetectorAggressiveID,
                                        SHDWDebugDisabledPluginsID, SHDWDebugDyldNoInfosID,
                                        SHDWDebugDyldNoSpiInlineID, SHDWDebugDyldSkipRebindsID,
                                        SHDWDeepTier2ID, @"Debug_SyscallLane",
                                        @"Debug_MemTrace", @"Debug_Diag",
                                        @"Debug_NoSandy", @"Debug_NoEarlyImage",
                                        @"Debug_NoHideNames", @"Debug_NoEKHandler",
                                        @"Debug_DiagNoSignal", @"Debug_SvcTrace",
                                        @"Debug_ExitProbe", @"Debug_Heartbeat",
                                        @"Debug_PathTrace", @"Debug_ApiTrace",
                                        @"Debug_DyldTruth", @"Debug_StateProbe",
                                        @"Debug_FunnelProbe", @"Debug_SigWatch",
                                        @"Debug_SigRearm", @"Debug_PcSample",
                                        @"Debug_PcDump", @"Debug_PrmDump", @"Debug_CellShim",
                                        @"Debug_SlotWatch",
                                        @"Debug_ExposeSelf", @"Debug_DyldDumpAll", @"Debug_MemOpaquePass",
                                        @"Debug_MemShare", @"Debug_MemShareTrace", @"Debug_MemShareRaw",
                                        @"Debug_MemSplit", @"Debug_MemTextMax",
                                        @"Debug_MemExtInfo", @"Debug_MemExtDirt",
                                        @"Debug_VmFrame", @"Debug_JsonScan", @"Debug_ExcPorts",
                                        @"Debug_ExcCatch", @"Debug_ExcWatch", @"Debug_SvcForge", @"Debug_SpkBrk", @"Debug_SpkFix", @"Debug_SpkStub", @"Debug_SpkSkip", @"Debug_SpkDec", @"Debug_SpkMsg", @"Debug_SpkZero", @"Debug_SpkGate", @"Debug_SpkMem", @"Debug_SpkSvc", @"Debug_SpkForge", @"Debug_SpkEvt", @"Debug_SpkRearm", @"Debug_SpkExit", @"Debug_SpkCache", @"Debug_SpkSample", @"Debug_SpkHash", @"Debug_SpkBt", @"Debug_SpkScene",
                                        @"Detector_OzSandbox", @"Detector_ScreenCap", @"Detector_XsCookie", @"Detector_HideBootstrap", @"Debug_BannerProbe",
                                        @"Debug_CleanEnv", @"Debug_EnvDump", @"Debug_TraceImage", @"Debug_Prov",
                                        @"Debug_DenySubstr",
                                        @"Debug_NoWaitRel",
                                        SHDWUniversalMemoryLevelHidingID,
                                        SHDWUniversalFoundationID,
                                        SHDWUniversalURLSchemeID,
                                        @"Debug_DlsymRaw", @"Debug_OzTable", @"Debug_OzTag", @"Debug_OzRecord", @"Debug_OzVerdictThread", @"Debug_Trace", @"Debug_ExitTrace",
                                        @"Debug_FsAll", @"Debug_ObjcDump", @"Debug_ExitBrk",
                                        @"Debug_OzCall", @"Debug_InSvc", @"Debug_InSvcRange", @"Debug_InSvcEntry",
                                        @"Debug_NoSelfMarkKill",
                                        @"Debug_SvcAppImages" ]) {
                    id value = appFilePrefs[key];
                    if(value != nil) {
                        merged[key] = value;
                    }
                }
                prefs = [merged copy];
            }
        }

        if(!prefs) {
            NSLog(@"[Shadow] warning: preferences not loaded");
            return;
        }

        NSLog(@"%@", prefs);


        if(![prefs[@"App_Enabled"] boolValue]) {
            return;
        }

        // Capture authorization independently of current target readiness.
        shdw_adapter_devicecheck_configure(prefs);
        prefs = shdw_adapter_resolve_preferences(prefs);
        BOOL hasActiveDetectorAdapter = NO;
        for(NSString* key in @[ SHDWAdapterDTTJailbreakDetectionID, SHDWAdapterSafeDeviceID,
                                SHDWAdapterJailMonkeyID ]) {
            hasActiveDetectorAdapter |= [prefs[key] boolValue];
        }
        // Behavioral prearm for image/class-linked detectors whose adapters
        // are always-on (FreeRASP/Talsec, DeviceSecurityKit, IOSSecuritySuite,
        // BAT): their presence at ctor means detector code will run, so arm
        // Tier-2 now. Harness baseline unaffected: the harness links none of
        // these, and SDKFallback deferral is planner-gated, not prearm-gated.
        hasActiveDetectorAdapter |= shdw_adapter_has_known_detector();

        // The adapter's raw-syscall coverage is additive to the universal
        // groups and follows its own switch.
        {
            NSMutableDictionary* effectivePrefs = [prefs mutableCopy];
            if([effectivePrefs[SHDWAdapterFreeRASPID] boolValue]) {
                shdw_adapter_freerasp_prepare_preferences(effectivePrefs);
            }
            if([bundleIdentifier isEqualToString:@"me.jjolano.shadow.harness"]) {
                effectivePrefs[SHDWUniversalHarnessBaselineID] = @YES;
            }
            prefs = [effectivePrefs copy];
        }

        shdw_path_rewrite_configure([prefs[SHDWUniversalPathRewriteID] boolValue]);
        shdw_memory_hiding_enabled = [prefs[SHDWUniversalMemoryLevelHidingID] boolValue];
        shdw_dyld_no_infos_hiding = [prefs[SHDWDebugDyldNoInfosID] boolValue];
        shdw_dyld_no_spi_inline = [prefs[SHDWDebugDyldNoSpiInlineID] boolValue];
        {
            id skip = prefs[SHDWDebugDyldSkipRebindsID];
            gShdwDyldSkipRebinds = [skip isKindOfClass:[NSString class]] ? skip : nil;
        }
        shdw_detector_aggressive = [prefs[SHDWDetectorAggressiveID] boolValue];
        shdw_detector_screencap = [prefs[@"Detector_ScreenCap"] boolValue];
        shdw_detector_xscookie = [prefs[@"Detector_XsCookie"] boolValue];
        shdw_detector_hidebootstrap = [prefs[@"Detector_HideBootstrap"] boolValue];
        shdw_debug_bannerprobe = [prefs[@"Debug_BannerProbe"] boolValue];
        shdw_diag_svc_app_images = [prefs[@"Debug_SvcAppImages"] boolValue] ? 1 : 0;
        {
            id lane = prefs[@"Debug_SyscallLane"];
            if([lane isKindOfClass:[NSString class]]) {
                if([lane isEqualToString:@"svc"]) {
                    shdw_diag_syscall_lane = 1;
                } else if([lane isEqualToString:@"hooks"]) {
                    shdw_diag_syscall_lane = 2;
                }
            }

            {
                id ml = prefs[@"Debug_MemLane"];
                if([ml isKindOfClass:[NSString class]]) {
                    if([ml isEqualToString:@"entry"]) {
                        shdw_diag_mem_lane = 0;
                    } else if([ml isEqualToString:@"rebind"]) {
                        shdw_diag_mem_lane = 1;
                    } else if([ml isEqualToString:@"both"]) {
                        shdw_diag_mem_lane = 2;
                    }
                }
            }

            if([prefs[@"Debug_MemTrace"] boolValue]) {
                shdw_diag_mem_trace = 1;
            }

            if([prefs[@"Debug_MemOpaquePass"] boolValue]) {
                shdw_diag_mem_opaque_pass = 1;
            }

            if([prefs[@"Debug_MemShare"] boolValue]) {
                shdw_diag_mem_share = 1;
                shdw_diag_enabled = 1;
            }

            if([prefs[@"Debug_MemShareTrace"] boolValue]) {
                shdw_diag_mem_share_trace = 1;
                shdw_diag_enabled = 1;
            }

            if([prefs[@"Debug_MemShareRaw"] boolValue]) {
                shdw_diag_mem_share_raw = 1;
            }

            if([prefs[@"Debug_MemSplit"] boolValue]) {
                shdw_diag_mem_split = 1;
                shdw_diag_enabled = 1;
            }

            if([prefs[@"Debug_MemTextMax"] boolValue]) {
                shdw_diag_mem_textmax = 1;
                shdw_diag_enabled = 1;
            }

            if([prefs[@"Debug_MemExtInfo"] boolValue]) {
                shdw_diag_mem_extinfo = 1;
                shdw_diag_enabled = 1;
            }

            if([prefs[@"Debug_MemExtDirt"] boolValue]) {
                shdw_diag_mem_extdirt = 1;
                shdw_diag_enabled = 1;
            }

            if([prefs[@"Debug_VmFrame"] boolValue]) {
                shdw_diag_vmframe = 1;
                shdw_diag_enabled = 1;
            }

            if([prefs[@"Debug_JsonScan"] boolValue]) {
                shdw_diag_jsonscan = 1;
                shdw_diag_enabled = 1;
            }

            if([prefs[@"Debug_ExcPorts"] boolValue]) {
                shdw_diag_excports = 1;
                shdw_diag_enabled = 1;
            }

            if([prefs[@"Debug_ExcCatch"] boolValue]) {
                shdw_diag_exccatch = 1;
                shdw_diag_enabled = 1;
            }

            if([prefs[@"Debug_ExcWatch"] boolValue]) {
                shdw_diag_excwatch = 1;
                shdw_diag_enabled = 1;
            }

            // Production switch for the OZ sandbox-probe forge: the detector
            // asks the kernel whether jailbreak artifacts exist through its own
            // inline __mac_syscall, which no hook can see. Deny those probes
            // the way an unjailbroken device would.
            if([prefs[@"Detector_OzSandbox"] boolValue]) {
                shdw_diag_svcforge = 3;
                shdw_diag_excwatch = 1;
            }

            if([prefs[@"Debug_SpkBrk"] boolValue]) {
                shdw_diag_spkbrk = 1;
                shdw_diag_excwatch = 1;
                shdw_diag_enabled = 1;
            }

            // Same verdict byte, no exception ports and no debug registers:
            // the poller clears it before +0x8ed0c reads it.
            if([prefs[@"Debug_SpkFix"] boolValue]) {
                shdw_diag_spkfix = 1;
                shdw_diag_enabled = 1;
            }

            // Syscall census through the framework's own dispatch stub, armed
            // at the verdict-byte store. No text and no cell writes.
            if([prefs[@"Debug_SpkStub"] boolValue]) {
                shdw_diag_spkstub = 1;
                shdw_diag_excwatch = 1;
                shdw_diag_enabled = 1;
            }

            // Skip the gate entirely: pc moves to the wrapper's epilogue, so
            // neither the exit thunk nor the poisoning stage runs.
            if([prefs[@"Debug_SpkSkip"] boolValue]) {
                shdw_diag_spkskip = 1;
                shdw_diag_excwatch = 1;
                shdw_diag_enabled = 1;
            }

            // Pure observer: two exec breakpoints inside the config decoder.
            // Nothing is written to the framework's state.
            if([prefs[@"Debug_SpkDec"] boolValue]) {
                shdw_diag_spkdec = 1;
                shdw_diag_excwatch = 1;
                shdw_diag_enabled = 1;
            }

            // Pure observer: dump the serialized message behind the tags.
            if([prefs[@"Debug_SpkMsg"] boolValue]) {
                shdw_diag_spkmsg = 1;
                shdw_diag_excwatch = 1;
                shdw_diag_enabled = 1;
            }

            // Byte 0 with no other change: names the zero branch's outcome.
            if([prefs[@"Debug_SpkZero"] boolValue]) {
                shdw_diag_spkzero = 1;
                shdw_diag_excwatch = 1;
                shdw_diag_enabled = 1;
            }

            // Watch-only: resolve the gate's three indirect call targets.
            if([prefs[@"Debug_SpkGate"] boolValue]) {
                shdw_diag_spkgate = 1;
                shdw_diag_excwatch = 1;
                shdw_diag_enabled = 1;
            }

            // One-shot memory dump, read only.
            if([prefs[@"Debug_SpkMem"] boolValue]) {
                shdw_diag_spkmem = 1;
                shdw_diag_excwatch = 1;
                shdw_diag_enabled = 1;
            }

            // Syscall stream of this image, watch only.
            if([prefs[@"Debug_SpkSvc"] boolValue]) {
                shdw_diag_spksvc = 1;
                shdw_diag_excwatch = 1;
                shdw_diag_enabled = 1;
            }

            // Event-5 dispatcher call site, read only.
            if([prefs[@"Debug_SpkEvt"] intValue]) {
                shdw_diag_spkevt = [prefs[@"Debug_SpkEvt"] intValue];
                shdw_diag_spksvc = 1;
                shdw_diag_excwatch = 1;
                shdw_diag_enabled = 1;
            }

            // Compiled exit(1): 1 observes, 2 returns without exiting.
            if([prefs[@"Debug_SpkExit"] intValue]) {
                shdw_diag_spkexit = [prefs[@"Debug_SpkExit"] intValue];
                shdw_diag_spksvc = 1;
                shdw_diag_excwatch = 1;
                shdw_diag_enabled = 1;
            }

            // One-shot: is the dyld cache page SHIELD verifies pristine?
            if([prefs[@"Debug_SpkCache"] boolValue]) {
                shdw_diag_spkcache = 1;
                shdw_diag_enabled = 1;
            }

            // Frame-pointer walks of the ctor thread after the gate.
            if([prefs[@"Debug_SpkBt"] boolValue]) {
                shdw_diag_spkbt = 1;
                shdw_diag_enabled = 1;
            }

            // Replace the stub scene configuration SHIELD hands the session.
            if([prefs[@"Debug_SpkScene"] boolValue]) {
                shdw_diag_spkscene = [prefs[@"Debug_SpkScene"] intValue];
                shdw_diag_enabled = 1;
            }

            // Read-only PC sampler: no debug registers, so SHIELD sees an
            // unperturbed startup. Pref: Debug_SpkSample.
            if([prefs[@"Debug_SpkSample"] boolValue]) {
                shdw_diag_spksample = 1;
                shdw_diag_enabled = 1;
            }

            // Force the file-hash mismatch flag at 0x23cc3c to zero.
            if([prefs[@"Debug_SpkHash"] boolValue]) {
                shdw_diag_spkhash = 1;
                shdw_diag_enabled = 1;
            }

            // Arm debug slots on framework threads created after install.
            if([prefs[@"Debug_SpkRearm"] intValue]) {
                shdw_diag_spkrearm = [prefs[@"Debug_SpkRearm"] intValue];
                shdw_diag_spksvc = 1;
                shdw_diag_enabled = 1;
            }

            // Forge CodeDirectory hash slots at the syscall boundary.
            if([prefs[@"Debug_SpkForge"] intValue]) {
                shdw_diag_spkforge = [prefs[@"Debug_SpkForge"] intValue];
                shdw_diag_spksvc = 1;
                shdw_diag_excwatch = 1;
                shdw_diag_enabled = 1;
            }

            if([prefs[@"Debug_SvcForge"] intValue]) {
                shdw_diag_svcforge = [prefs[@"Debug_SvcForge"] intValue];
                shdw_diag_excwatch = 1;
                // Mode 3 is the production lane: silent, single site.
                if(shdw_diag_svcforge < 3) {
                    shdw_diag_enabled = 1;
                }
            }

            if([prefs[@"Debug_SvcPatchMainExec"] boolValue]) {
                shdw_diag_svc_main_exec = 1;
            }

            if([prefs[@"Debug_Diag"] boolValue]) {
                shdw_diag_enabled = 1;
            }

            if([prefs[@"Debug_NoWaitRel"] boolValue]) {
                shdw_diag_no_waitrel = 1;
            }

            if([prefs[@"Debug_DenySubstr"] isKindOfClass:[NSString class]]) {
                snprintf(shdw_insvc_deny_substr,
                         sizeof shdw_insvc_deny_substr, "%s",
                         [prefs[@"Debug_DenySubstr"] UTF8String]);
            }

            if([prefs[@"Debug_Trace"] boolValue]) {
                shdw_diag_trace_only = 1;
                shdw_diag_enabled = 1;
            }

            if([prefs[@"Debug_ExitTrace"] boolValue]) {
                shdw_diag_exit_trace = 1;
                shdw_diag_trace_only = 1;
                shdw_diag_enabled = 1;
            }

            if([prefs[@"Debug_DiagNoSignal"] boolValue]) {
                shdw_diag_no_signals = 1;
            }

            if([prefs[@"Debug_SvcTrace"] boolValue]) {
                shdw_diag_svc_trace = 1;
            }

            if([prefs[@"Debug_ExitProbe"] boolValue]) {
                shdw_diag_exit_probe = 1;
            }

            if([prefs[@"Debug_ExitBrk"] boolValue]) {
                shdw_diag_exit_brk = 1;
            }

            if([prefs[@"Debug_NoSelfMarkKill"] boolValue]) {
                shdw_diag_no_self_markkill = 1;
            }

            if([prefs[@"Debug_Heartbeat"] boolValue]) {
                shdw_diag_heartbeat = 1;
            }

            if([prefs[@"Debug_SigWatch"] boolValue]) {
                shdw_diag_sigwatch = 1;
            }

            if([prefs[@"Debug_SigRearm"] boolValue]) {
                shdw_diag_sigrearm = 1;
            }

            if([prefs[@"Debug_SlotWatch"] boolValue]) {
                shdw_diag_slotwatch = 1;
            }

            if([prefs[@"Debug_PcSample"] boolValue]) {
                shdw_diag_pcsample = 1;
            }

            if([prefs[@"Debug_PrmDump"] boolValue]) {
                shdw_diag_prm_dump = 1;
                shdw_diag_enabled = 1;
            }

            if([prefs[@"Debug_CellShim"] boolValue]) {
                shdw_cell_shim_on = 1;
                shdw_diag_enabled = 1;
            }

            NSInteger pcd = [prefs[@"Debug_PcDump"] integerValue];
            if(pcd > 0) {
                shdw_diag_pc_dump = (int)pcd;
                shdw_diag_pcsample = 1;
                shdw_diag_enabled = 1;
            }

            if([prefs[@"Debug_PathTrace"] boolValue]) {
                shdw_diag_path_trace = 1;
            }

            if([prefs[@"Debug_FsAll"] boolValue]) {
                shdw_diag_fs_all = 1;
                shdw_diag_path_trace = 1;
            }

            if([prefs[@"Debug_ObjcDump"] boolValue]) {
                shdw_diag_objc_dump = 1;
            }

            if([prefs[@"Debug_ApiTrace"] boolValue]) {
                shdw_diag_api_trace = 1;
            }

            if([prefs[@"Debug_DyldTruth"] boolValue]) {
                shdw_diag_dyld_truth = 1;
            }

            if([prefs[@"Debug_DlsymRaw"] boolValue]) {
                shdw_diag_dlsym_raw = 1;
            }

            if([prefs[@"Debug_OzTable"] boolValue]) {
                shdw_diag_oz_table = 1;
            }

            if([prefs[@"Debug_OzTag"] boolValue]) {
                shdw_diag_oz_tag = 1;
            }

            if([prefs[@"Debug_OzRecord"] boolValue]) {
                shdw_diag_oz_record = 1;
            }

            if([prefs[@"Debug_OzVerdictThread"] boolValue]) {
                shdw_diag_oz_verdict_thread = 1;
            }

            if([prefs[@"Debug_ExposeSelf"] boolValue]) {
                shdw_diag_expose_self = 1;
            }

            if([prefs[@"Debug_DyldDumpAll"] boolValue]) {
                shdw_diag_dyld_dump_all = 1;
            }

            if([prefs[@"Debug_TraceImage"] isKindOfClass:[NSString class]]) {
                NSString* token = prefs[@"Debug_TraceImage"];
                if(token.length && token.length < sizeof(shdw_diag_trace_image)) {
                    strlcpy(shdw_diag_trace_image, token.UTF8String, sizeof(shdw_diag_trace_image));
                    shdw_diag_api_trace = 1;
                }
            }

            if([prefs[@"Debug_EnvDump"] boolValue]) {
                shdw_diag_envdump_flag = 1;
                shdw_diag_enabled = 1;
            }

        }

        // Deep hiding opts into Tier-2 at construction without marking a
        // detector present: the message layer is installed, verdicts stay
        // natural.
        BOOL shdw_deep_tier2 = [prefs[SHDWDeepTier2ID] boolValue];

        Shadow* shadow = [Shadow sharedInstance];
        [shadow shdwConfigurePseudoSandboxMode:[prefs[SHDWUniversalPseudoSandboxModeID] integerValue]];
        shdw_own_ranges_refresh();

        NSLog(@"starting hooks");
        [Shadow shdwEnterInternalRead];
        @try {
            shdw_coordinator_ctor(prefs);
            shdw_lab_mark("coord");

            // Hide any suspicious LC_LOAD_DYLIB names baked into the main
            // executable at link time (e.g. an app linked against
            // Shadow.framework) from a raw Mach-O memory walk.
            if(!shdw_bisect_no_hide_names) {
                shdw_hide_main_image_loadcmd_names();
            }
            // Normalize the decrypted-bundle tell (cryptid=0, MH_PIE clear)
            // on every image under the .app before the protector reads it.
            if([prefs[@"Debug_Prov"] boolValue]) { // SHDW_DEBUG_PROV
                shdw_diag_enabled = 1;
                shdw_image_provenance_normalize();
                shdw_diag_log("PROV done");
            }
            shdw_lab_mark("hidn");

            shdw_diag_install();
            shdw_lab_mark("diag");
            shdw_diag_install_oz_forge();
            shdw_diag_envdump_run();
            shdw_mem_share_dump();
            shdw_lab_mark("env");

            NSString* stateProbe = prefs[@"Debug_StateProbe"];
            if([stateProbe isKindOfClass:[NSString class]] && stateProbe.length) {
                shdw_diag_state_probe(stateProbe.UTF8String);
            }

            NSString* funnelProbe = prefs[@"Debug_FunnelProbe"];
            if([funnelProbe isKindOfClass:[NSString class]] && funnelProbe.length) {
                shdw_diag_funnel_probe(funnelProbe.UTF8String);
            }

            if([prefs[@"Debug_OzCall"] boolValue]) {
                shdw_diag_oz_call_probe("OZLivenessSDK");
            }

            if([prefs[@"Debug_InSvc"] boolValue]) {
                unsigned long long rangeStart = 0;
                unsigned long long rangeEnd = ~0ULL;
                NSString* insvcRange = prefs[@"Debug_InSvcRange"];
                if([insvcRange isKindOfClass:[NSString class]] && insvcRange.length) {
                    sscanf(insvcRange.UTF8String, "%llx:%llx", &rangeStart, &rangeEnd);
                }
                shdw_diag_insvc_probe("OZLivenessSDK", rangeStart, rangeEnd,
                                      [prefs[@"Debug_InSvcEntry"] boolValue]);
            }

            if([prefs[@"Debug_CleanEnv"] boolValue]) {
                const char* before = getenv("DYLD_INSERT_LIBRARIES");
                shdw_diag_log("CLEANENV before=%s", before ? before : "(null)");
                int ur = unsetenv("DYLD_INSERT_LIBRARIES");
                const char* after = getenv("DYLD_INSERT_LIBRARIES");
                shdw_diag_log("CLEANENV after rc=%d value=%s", ur,
                              after ? after : "(null)");
            }

            shdw_diag_log("ctor app=%s enabled=%d aggressive=%d deep=%d lane=%d disabled=%s",
                          bundleIdentifier.UTF8String ?: "?",
                          [prefs[@"App_Enabled"] boolValue], shdw_detector_aggressive,
                          shdw_deep_tier2, shdw_diag_syscall_lane,
                          [prefs[SHDWDebugDisabledPluginsID] UTF8String] ?: "-");
            if ([bundleIdentifier isEqualToString:@"de.starfinanz.Finanzstatus"]) {
                extern void shdw_spk_munged_dump(const char *tag, uint64_t lr_off);
                shdw_spk_munged_dump("ctor", 0x822fecULL);
            }
            {
                NSArray<NSString*>* plan =
                    SHDWPluginPlan(prefs, shdw_coordinator_instance.backends.capabilities,
                                   SHDWEventCtor);
                NSMutableString* joined = [NSMutableString string];
                for(NSString* unit in plan) {
                    if(joined.length) {
                        [joined appendString:@" "];
                    }
                    [joined appendString:unit];
                }
                shdw_diag_log("plan ctor %s", joined.UTF8String ?: "-");
            }

            // Swift source builds and Talsec binaries have no stable direct
            // hook ABI. Prearm framework-independent Tier-2 coverage before
            // detector code can run. Production adapter switches install at
            // construction; the harness keeps its deferred fallback event.
            // Harness sets this false only for its explicit prearmed mode.
            // Prearm the detector-only units before its first real detector
            // runs; normal Harness launches retain the universal baseline.
            // Embedded detectors (harness links Talsec/DeviceSecurityKit/IOSSB
            // frameworks directly) count as an active detector presence, same
            // as the old isolated runners' linked images did.
            BOOL harnessPrearmed = [bundleIdentifier isEqualToString:@"me.jjolano.shadow.harness"] &&
                ![prefs[SHDWUniversalHarnessBaselineID] boolValue];
            BOOL embeddedDetectors = [bundleIdentifier isEqualToString:@"me.jjolano.shadow.harness"];
            BOOL forcedPrearm = [bundleIdentifier hasPrefix:@"me.jjolano.shadow.test."] ||
                bundleIdentifier.length == 0;
            if(hasActiveDetectorAdapter || harnessPrearmed || embeddedDetectors || forcedPrearm) {
                shdw_detector_present = YES;
                shdw_detector_write_policy_set_enabled(YES);
                [shdw_coordinator_instance prearmDetector];
            } else if(shdw_deep_tier2) {
                [shdw_coordinator_instance prearmDetector];
            }
            shdw_lab_mark("prearm");
        } @finally {
            [Shadow shdwExitInternalRead];
        }
    } @catch (NSException* e) {
        NSLog(@"[Shadow] constructor failed: %@ — continuing", e);
        @try {
            NSString* excText = [NSString stringWithFormat:@"name=%@\nreason=%@\ncallStack=%@\n",
                                 [e name], [e reason], [e callStackSymbols]];
            const char* excHome = getenv("HOME");
            char excPath[PATH_MAX] = {0};
            if(excHome && excHome[0]) {
                snprintf(excPath, sizeof excPath, "%s/Library/Caches/shdw_ctor_exc.txt", excHome);
            } else {
                snprintf(excPath, sizeof excPath, "/tmp/shdw_ctor_exc.txt");
            }
            [excText writeToFile:[NSString stringWithUTF8String:excPath]
                      atomically:YES encoding:NSUTF8StringEncoding error:nil];
        } @catch (NSException* e2) {
        }
        return;
    }
}
