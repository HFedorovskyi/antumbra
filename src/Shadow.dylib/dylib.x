#import <Foundation/Foundation.h>
#import <dispatch/dispatch.h>

#import "../common.h"
#import <Shadow/SHDWPlugin.h>
#import <libSandy.h>
#import <dlfcn.h>
#include <mach-o/dyld.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <math.h>
#include <sys/stat.h>

// Same source the framework uses for the executable path (Choicy-derived:
// least side effects possible — see Core+Utilities.m).
extern char*** _NSGetArgv();

// C-only prefilter that must run before any Foundation call. Creating ObjC
// objects without an autorelease pool is fatal in daemons whose tweak ctors
// run during dyld image init (fileproviderd: _objc_fatal from
// AutoreleasePoolPage::push via NSBundle initWithPath).
static BOOL shdw_path_is_app_content(const char* path) {
    if(!path) {
        return NO;
    }

    return strstr(path, ".app/") != NULL || strstr(path, ".appex/") != NULL;
}


#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

// Diagnostic marker, off unless the build passes -DSHADOW_LAB_LOG: a release
// loader must not create per-app files under $HOME.
#ifdef SHADOW_LAB_LOG
static void shdw_lab_log(const char* fmt, ...) {
    const char* home = getenv("HOME");
    char path[PATH_MAX];
    if(home && home[0]) {
        snprintf(path, sizeof path, "%s/Library/Caches/shdw_stub.log", home);
    } else {
        snprintf(path, sizeof path, "/tmp/shdw_stub.log");
    }
    FILE* f = fopen(path, "a");
    if(!f) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fputc('\n', f);
    fclose(f);
}
#else
#define shdw_lab_log(...) ((void)0)
#endif

static BOOL shdw_has_prefix(const char* string, const char* prefix) {
    return string && strncmp(string, prefix, strlen(prefix)) == 0;
}

#ifndef THEOS_PACKAGE_INSTALL_PREFIX
#define THEOS_PACKAGE_INSTALL_PREFIX ""
#endif

#pragma mark - Crash-loop guard

// A launch shorter than this never reached a usable state: the payload applies
// its hook set in the first seconds. The marker is written from this same
// ctor, so the measurement does not depend on the UI or on app cooperation.
static const double kShdwGuardAliveSeconds = 10.0;

// Consecutive short launches before Shadow stands down for that app. Two,
// because a single one can be the app's own state (first-run data, corrupt
// cache); a repeating one is ours.
static const NSInteger kShdwGuardMaxStrikes = 2;

// A pending opt-out request older than this with no answer means shdwbl is not
// running: nothing enforces the opt-out, so blocking injection locally would
// strand the app for good.
static const double kShdwGuardRequestGraceSeconds = 120.0;

// Application Support, not Caches: the system purges Caches under disk
// pressure, and a wiped guard file silently re-arms a crash-looping app.
static NSString* shdw_home_state_path(const char* name) {
    const char* home = getenv("HOME");
    if(!home || !home[0]) {
        return nil;
    }
    return [NSString stringWithFormat:@"%s/Library/Application Support/Shadow/%s",
                                      home, name];
}

static NSMutableDictionary* shdw_read_state(NSString* path) {
    if(!path) {
        return nil;
    }
    id object = [NSDictionary dictionaryWithContentsOfFile:path];
    return [object isKindOfClass:[NSDictionary class]] ? [object mutableCopy]
                                                      : [NSMutableDictionary dictionary];
}

static void shdw_write_state(NSDictionary* state, NSString* path) {
    if(!path) {
        return;
    }
    NSString* directory = [path stringByDeletingLastPathComponent];
    [[NSFileManager defaultManager] createDirectoryAtPath:directory
                              withIntermediateDirectories:YES
                                               attributes:nil
                                                    error:nil];
    [state writeToFile:path atomically:YES];
}

static BOOL shdw_double_is(double value, double expected) {
    return fabs(value - expected) < 0.0005;
}

// Apps killed by the injection surface itself (SHIELD, Licel) stay dead after
// the guard stands Shadow down, because systemhook is still inserted. Hand the
// opt-out to the root daemon (shdwbl) so the next spawn gets no injection.
// Pref: Global_AutoOptOut=0 disables.
static BOOL shdw_auto_optout_enabled(void) {
    NSUserDefaults* defaults = [[NSUserDefaults alloc] initWithSuiteName:@SHADOW_PREFS_PLIST];
    id value = [defaults objectForKey:@"Global_AutoOptOut"];
    if(!value) {
        NSDictionary* filePrefs = [NSDictionary dictionaryWithContentsOfFile:@SHADOW_PREFS_PLIST];
        value = filePrefs[@"Global_AutoOptOut"];
    }
    return value ? [value boolValue] : YES;
}

static void shdw_blacklist_request(const char* executablePath, BOOL add,
                                   NSInteger runPid) {
    if(!executablePath || !executablePath[0] || !shdw_auto_optout_enabled()) {
        return;
    }
    // Sandboxed: only the app's own container is writable. shdwbl scans every
    // app container and authorizes a request only when its owner bundle id
    // matches the requested executable. runPid is the launch that triggered the
    // strike, not this one: shdwbl reads its exit reason from launchd and only
    // applies the opt-out when that run actually crashed.
    NSString* directory = shdw_home_state_path("blacklist-requests");
    [[NSFileManager defaultManager] createDirectoryAtPath:directory
                              withIntermediateDirectories:YES attributes:nil error:nil];
    NSString* exe = [NSString stringWithUTF8String:executablePath];
    NSString* file = [directory stringByAppendingPathComponent:
        [NSString stringWithFormat:@"stub-%d-%@.plist", (int)getpid(),
                                   add ? @"add" : @"remove"]];
    NSDictionary* request = @{ @"exe" : exe, @"action" : add ? @"add" : @"remove",
                               @"pid" : @(runPid) };
    [request writeToFile:file atomically:YES];
    shdw_lab_log("blacklist request %s %s pid=%ld", add ? "add" : "remove",
                 executablePath, (long)runPid);
}

// shdwbl only applies an opt-out when launchd shows the strike run really
// crashed (signals or non-zero exit). Bench kills, force-quits and normal exits
// come back as rc=6 skipped=noncrash in the .result next to the request — a
// refused opt-out must not keep injection skipped locally either.
typedef enum {
    ShdwOptoutApplied,
    ShdwOptoutRefused,
    ShdwOptoutUnanswered,
} ShdwOptoutVerdict;

static ShdwOptoutVerdict shdw_guard_optout_verdict(NSString* path, double requested) {
    NSString* directory = [[path stringByDeletingLastPathComponent]
        stringByAppendingPathComponent:@"blacklist-requests"];
    NSArray* names = [[NSFileManager defaultManager]
        contentsOfDirectoryAtPath:directory error:nil];
    ShdwOptoutVerdict verdict = ShdwOptoutUnanswered;
    for(NSString* name in names) {
        if(![name hasSuffix:@"-add.plist.result"]) {
            continue;
        }
        NSString* file = [directory stringByAppendingPathComponent:name];
        struct stat info;
        if(stat(file.fileSystemRepresentation, &info) != 0 ||
           (requested > 0.0 && (double)info.st_mtime + 1.0 < requested)) {
            continue;
        }
        NSString* body = [NSString stringWithContentsOfFile:file
                                                   encoding:NSUTF8StringEncoding
                                                      error:nil];
        if(!body) {
            continue;
        }
        if([body rangeOfString:@"rc=6"].location != NSNotFound &&
           [body rangeOfString:@"skipped=noncrash"].location != NSNotFound) {
            verdict = ShdwOptoutRefused;
            [[NSFileManager defaultManager] removeItemAtPath:file error:nil];
        } else if(verdict == ShdwOptoutUnanswered) {
            verdict = ShdwOptoutApplied;
        }
    }
    return verdict;
}

// Returns YES when injection must be skipped for this launch. Also records the
// start of the current launch and arms the alive marker.
static BOOL shdw_guard_enter(NSString* path, NSString* bundleIdentifier,
                             const char* executablePath, BOOL userForced) {
    if(!path) {
        return NO;
    }
    NSMutableDictionary* state = shdw_read_state(path);
    if(!state) {
        return NO;
    }

    double now = [NSDate date].timeIntervalSince1970;
    NSInteger strikes = [state[@"strikes"] integerValue];
    NSInteger previousPid = [state[@"pid"] integerValue];
    BOOL blocked = NO;

    if([state[@"disabled"] boolValue]) {
        if(userForced) {
            shdw_lab_log("guard: user re-enabled %s, clearing",
                         bundleIdentifier.UTF8String);
            shdw_blacklist_request(executablePath, NO, 0);
            strikes = 0;
        } else {
            double requested = [state[@"requested"] doubleValue];
            ShdwOptoutVerdict verdict = shdw_guard_optout_verdict(path, requested);
            if(verdict == ShdwOptoutRefused) {
                shdw_lab_log("guard: daemon refused opt-out for %s, re-enabling",
                             bundleIdentifier.UTF8String);
                strikes = 0;
            } else if(verdict == ShdwOptoutUnanswered &&
                      requested > 0.0 &&
                      now - requested > kShdwGuardRequestGraceSeconds) {
                shdw_lab_log("guard: opt-out unanswered for %s, re-enabling",
                             bundleIdentifier.UTF8String);
                strikes = 0;
            } else {
                blocked = YES;
            }
        }
    }

    if(!blocked) {
        double previousStart = [state[@"start"] doubleValue];
        if(previousStart > 0.0) {
            double previousAlive = [state[@"alive"] doubleValue];
            if(previousAlive < previousStart) {
                previousAlive = previousStart;
            }
            double lived = previousAlive - previousStart;
            if(lived < kShdwGuardAliveSeconds) {
                strikes += 1;
                shdw_lab_log("guard: previous run lasted %.1fs, strikes=%ld", lived,
                             (long)strikes);
            } else {
                strikes = 0;
            }
        }
        if(strikes >= kShdwGuardMaxStrikes) {
            blocked = YES;
        }
    }

    if(blocked) {
        state[@"strikes"] = @(strikes);
        state[@"disabled"] = @YES;
        state[@"start"] = @0.0;
        state[@"alive"] = @0.0;
        state[@"pid"] = @0;
        state[@"requested"] = @(now);
        state[@"reason"] = @"repeated short-lived launches";
        state[@"bundle"] = bundleIdentifier ?: @"";
        state[@"exe"] = executablePath ? [NSString stringWithUTF8String:executablePath] : @"";
        shdw_write_state(state, path);
        shdw_lab_log("guard: DISABLED %s after %ld short launches",
                     bundleIdentifier.UTF8String, (long)strikes);
        shdw_blacklist_request(executablePath, YES, previousPid);
        return YES;
    }

    state[@"strikes"] = @(strikes);
    state[@"disabled"] = @NO;
    state[@"start"] = @(now);
    state[@"alive"] = @(now);
    state[@"pid"] = @(getpid());
    state[@"bundle"] = bundleIdentifier ?: @"";
    state[@"exe"] = executablePath ? [NSString stringWithUTF8String:executablePath] : @"";
    shdw_write_state(state, path);

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                                 (int64_t)(kShdwGuardAliveSeconds * NSEC_PER_SEC)),
                   dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        NSMutableDictionary* current = shdw_read_state(path);
        if(current && shdw_double_is([current[@"start"] doubleValue], now) &&
           ![current[@"disabled"] boolValue]) {
            current[@"alive"] = @([NSDate date].timeIntervalSince1970);
            shdw_write_state(current, path);
        }
    });

    return NO;
}

static void shdw_guard_note_core(NSString* path, BOOL loaded, const char* error) {
    if(!path) {
        return;
    }
    NSMutableDictionary* state = shdw_read_state(path);
    if(!state) {
        return;
    }
    state[@"core"] = @(loaded ? 1 : 0);
    state[@"core_error"] = error ? @(error) : @"";
    shdw_write_state(state, path);
}

#pragma mark - Self-check

static BOOL shdw_image_loaded(const char* needle) {
    uint32_t count = _dyld_image_count();
    for(uint32_t i = 0; i < count; i++) {
        const char* name = _dyld_get_image_name(i);
        if(name && strstr(name, needle)) {
            return YES;
        }
    }
    return NO;
}

static const char* shdw_env_or_dash(const char* key) {
    const char* value = getenv(key);
    return value ? value : "-";
}

static NSString* shdw_value_desc(id value) {
    if(!value) {
        return @"absent";
    }
    if([value isKindOfClass:[NSNumber class]]) {
        return [value description];
    }
    if([value isKindOfClass:[NSArray class]]) {
        return [NSString stringWithFormat:@"<array %lu>",
                                          (unsigned long)[value count]];
    }
    return @"<other>";
}

static NSString* shdw_choicy_state(NSString* bundleIdentifier) {
    NSDictionary* root =
        [NSDictionary dictionaryWithContentsOfFile:
                          @"/var/mobile/Library/Preferences/com.opa334.choicyprefs.plist"];
    if(![root isKindOfClass:[NSDictionary class]]) {
        return @"unreadable";
    }
    id apps = root[@"appSettings"];
    if(![apps isKindOfClass:[NSDictionary class]]) {
        return @"none";
    }
    id entry = apps[bundleIdentifier];
    if(![entry isKindOfClass:[NSDictionary class]]) {
        return @"none";
    }
    id value = entry[@"tweakInjectionDisabled"];
    if(!value) {
        return @"disabled=absent";
    }
    return [value boolValue] ? @"disabled=1" : @"disabled=0";
}

static NSString* shdw_blacklist_state(const char* executablePath) {
    NSString* path = [NSString stringWithFormat:@"%s/basebin/config.plist",
                                                THEOS_PACKAGE_INSTALL_PREFIX];
    NSDictionary* config = [NSDictionary dictionaryWithContentsOfFile:path];
    if(![config isKindOfClass:[NSDictionary class]]) {
        return @"unreadable";
    }
    id list = config[@"ProcessBlacklist"];
    if(![list isKindOfClass:[NSArray class]]) {
        return @"none";
    }
    NSString* executable =
        executablePath ? [NSString stringWithUTF8String:executablePath] : @"";
    return [list containsObject:executable] ? @"listed=1" : @"listed=0";
}

// Everything a support reply needs to tell "the detector won" from "Shadow was
// never in the process". Written on every launch, small and append-only.
static void shdw_selfcheck(NSString* bundleIdentifier, const char* executablePath,
                           NSDictionary* appSettings, id globalRaw, id excludedRaw,
                           NSDictionary* guard, BOOL enabled, BOOL excluded,
                           BOOL guardBlocked, NSString* licenseState) {
    NSString* path = shdw_home_state_path("shdw_selfcheck.log");
    if(!path) {
        return;
    }
    NSDictionary* attributes =
        [[NSFileManager defaultManager] attributesOfItemAtPath:path error:nil];
    if(attributes && [attributes fileSize] > 131072) {
        [[NSFileManager defaultManager] removeItemAtPath:path error:nil];
    }

    NSMutableString* line = [NSMutableString string];
    [line appendFormat:@"%.0f bundle=%s exe=%s enabled=%d excluded=%d\n",
                       [NSDate date].timeIntervalSince1970,
                       bundleIdentifier.UTF8String, executablePath, enabled ? 1 : 0,
                       excluded ? 1 : 0];
    [line appendFormat:@"  prefs global=%@ app=%@ app_enabled=%@ app_disabled=%@\n",
                       shdw_value_desc(globalRaw),
                       appSettings ? @"present" : @"absent",
                       shdw_value_desc(appSettings[SHDWAppEnabledID]),
                       shdw_value_desc(appSettings[SHDWAppDisabledID])];
    [line appendFormat:@"  images systemhook=%d ellekit=%d shadowstub=%d\n",
                       shdw_image_loaded("systemhook.dylib") ? 1 : 0,
                       shdw_image_loaded("libellekit") ? 1 : 0,
                       shdw_image_loaded("Shadow.dylib") ? 1 : 0];
    [line appendFormat:@"  env _SafeMode=%s _MSSafeMode=%s DISABLE_TWEAKS=%s\n",
                       shdw_env_or_dash("_SafeMode"), shdw_env_or_dash("_MSSafeMode"),
                       shdw_env_or_dash("DISABLE_TWEAKS")];
    [line appendFormat:@"  choicy=%@ blacklist=%@\n",
                       shdw_choicy_state(bundleIdentifier),
                       shdw_blacklist_state(executablePath)];
    [line appendFormat:@"  guard disabled=%@ strikes=%@ core=%@ core_error=%@ blocked=%d license=%@\n",
                       shdw_value_desc(guard[@"disabled"]),
                       shdw_value_desc(guard[@"strikes"]),
                       shdw_value_desc(guard[@"core"]),
                       guard[@"core_error"] ?: @"-", guardBlocked ? 1 : 0,
                       licenseState ?: @"?"];

    FILE* file = fopen(path.UTF8String, "a");
    if(!file) {
        return;
    }
    fputs(line.UTF8String, file);
    fclose(file);
}

%ctor {
    @autoreleasepool {
        char executablePath[PATH_MAX] = {0};
        uint32_t executablePathSize = sizeof(executablePath);

        if(_NSGetExecutablePath(executablePath, &executablePathSize) != 0) {
            return;
        }

        // Only app content (a .app bundle or an appex nested inside one) is
        // eligible. Platform binaries, daemons and frameworks bail out here,
        // before Foundation is touched at all.
        if(!shdw_path_is_app_content(executablePath)) {
            return;
        }
        shdw_lab_log("enter %s", executablePath);

        // Platform content under /System is decided on the path alone. Those
        // processes can reach a tweak ctor while the ObjC runtime and
        // CoreFoundation are still initializing, so nothing below may run
        // there — including reading NSBundle.
        if(shdw_has_prefix(executablePath, "/System")) {
            return;
        }

        NSString* bundleIdentifierObject = [NSBundle mainBundle].bundleIdentifier;
        // Compared as C strings: a ctor may run before CoreFoundation has
        // rewritten the constant strings compiled into this image, and an
        // NSString argument that still carries the raw class reference traps
        // pointer authentication on arm64e.
        const char* bundleIdentifier = bundleIdentifierObject.UTF8String;
        if(!bundleIdentifier) {
            bundleIdentifier = "";
        }

        // Injected into SpringBoard: nothing to do — the hook_springboard group
        // was removed in v5, and vnode hiding is per-app only (SB holds no lease;
        // the daemon owns recovery).
        if(strcmp(bundleIdentifier, "com.apple.springboard") == 0) {
            return;
        }

        // The verification apps are their own test subjects: they install to
        // /Applications (rooted) or /var/jb/Applications (rootless) — both
        // denied below — so without these exact exceptions they cannot be hooked.
        BOOL isDetectorRunner = shdw_has_prefix(bundleIdentifier, "me.jjolano.shadow.test.");
        BOOL isVerificationApp = strcmp(bundleIdentifier, "me.jjolano.shadow.harness") == 0
            || strcmp(bundleIdentifier, "me.jjolano.dyldprobe") == 0
            || isDetectorRunner;

        // Platform binaries, loaders and the jbroot itself stay unhooked:
        // stability (no detector surface there) + SpringBoard excluded above for
        // the same reason. Verification apps bypass for on-device testing.
        if(!isVerificationApp && (shdw_has_prefix(executablePath, "/Applications")
        || shdw_has_prefix(executablePath, "/System")
        || shdw_has_prefix(executablePath, "/private/preboot")
        || shdw_has_prefix(executablePath, "/var/jb"))) {
            return;
        }

        // Don't load in certain apps
        if(shdw_has_prefix(bundleIdentifier, "com.opa334")
        || shdw_has_prefix(bundleIdentifier, "org.coolstar")
        || shdw_has_prefix(bundleIdentifier, "science.xnu")
        || shdw_has_prefix(bundleIdentifier, "com.apple")
        || shdw_has_prefix(bundleIdentifier, "com.samiiau.loader")
        || shdw_has_prefix(bundleIdentifier, "com.llsc12.palera1nLoader")) {
            return;
        }

        NSLog(@"loaded in app");

        // Load preferences (Foundation-only probe; the payload reads full prefs).
        if(kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_11_0) {
            libSandy_applyProfile("ShadowSettings");
        }

        NSUserDefaults* defaults = [[NSUserDefaults alloc] initWithSuiteName:@SHADOW_PREFS_PLIST];
        NSDictionary* app_settings = bundleIdentifierObject ? [defaults objectForKey:bundleIdentifierObject] : nil;
        // Anything but a dictionary would raise inside SHDWApplicationEnabled's
        // subscript — in this loader's ctor that is an uncaught exception (no @try
        // here), so a hand-edited or foreign plist must not reach it.
        if(![app_settings isKindOfClass:[NSDictionary class]]) {
            app_settings = nil;
        }
        // Sandboxed cfprefsd can omit another app's dictionary despite libSandy's file grant.
        NSDictionary* filePreferences = nil;
        if(!app_settings && bundleIdentifierObject) {
            filePreferences = [NSDictionary dictionaryWithContentsOfFile:@SHADOW_PREFS_PLIST];
            id fileSettings = filePreferences[bundleIdentifierObject];
            app_settings = [fileSettings isKindOfClass:[NSDictionary class]] ? fileSettings : nil;
        }

        // Default-on product semantics: a missing Global_Enabled (fresh install,
        // migrated prefs) means every app is protected. Only an explicit NO
        // turns the global fallback off.
        id globalRaw = [defaults objectForKey:SHDWGlobalEnabledID];
        if(!globalRaw) {
            if(!filePreferences) {
                filePreferences = [NSDictionary dictionaryWithContentsOfFile:@SHADOW_PREFS_PLIST];
            }
            globalRaw = filePreferences[SHDWGlobalEnabledID];
        }

        id excludedRaw = [defaults objectForKey:SHDWGlobalDisabledAppsID];
        if(!excludedRaw) {
            if(!filePreferences) {
                filePreferences = [NSDictionary dictionaryWithContentsOfFile:@SHADOW_PREFS_PLIST];
            }
            excludedRaw = filePreferences[SHDWGlobalDisabledAppsID];
        }

        // License gate: fail closed. The daemon verifies the signed license as
        // root and mirrors the verdict into this same prefs file, the only one
        // libSandy grants this sandbox. The expiry is re-checked here so a dead
        // or stopped daemon cannot extend a lapsed license.
        NSString* licenseState = @"missing";
        BOOL licensed = isVerificationApp;
        if(licensed) {
            licenseState = @"test-bypass";
        } else {
            id stateRaw = [defaults objectForKey:@"License_State"];
            id epochRaw = [defaults objectForKey:@"License_ExpiresEpoch"];
            if(![stateRaw isKindOfClass:[NSString class]] ||
               ![epochRaw respondsToSelector:@selector(doubleValue)]) {
                if(!filePreferences) {
                    filePreferences = [NSDictionary dictionaryWithContentsOfFile:@SHADOW_PREFS_PLIST];
                }
                if(![stateRaw isKindOfClass:[NSString class]]) {
                    stateRaw = filePreferences[@"License_State"];
                }
                if(![epochRaw respondsToSelector:@selector(doubleValue)]) {
                    epochRaw = filePreferences[@"License_ExpiresEpoch"];
                }
            }
            if([stateRaw isKindOfClass:[NSString class]]) {
                licenseState = stateRaw;
            }
            double expiry = [epochRaw respondsToSelector:@selector(doubleValue)]
                                ? [epochRaw doubleValue] : 0.0;
            licensed = [licenseState isEqualToString:@"active"]
                && expiry > [[NSDate date] timeIntervalSince1970];
        }
        shdw_lab_log("license=%s licensed=%d", licenseState.UTF8String, licensed ? 1 : 0);

        // An explicit per-app App_Enabled is user intent and beats the exclusion
        // list; without it, apps whose anti-tamper kills injected processes are
        // left alone so they at least start.
        BOOL excluded = isVerificationApp
            ? NO
            : SHDWApplicationExcluded(app_settings, excludedRaw, bundleIdentifierObject);

        BOOL shdw_lab_enabled = SHDWApplicationEnabled(app_settings,
            SHDWGlobalEnabledValue(globalRaw),
            [defaults boolForKey:SHDWSingleToggleMigrationID],
            isDetectorRunner);
        if(excluded) {
            shdw_lab_enabled = NO;
        }

        shdw_lab_log("bundle=%s settings=%d global=%s excluded=%d enabled=%d",
                     bundleIdentifier, app_settings ? 1 : 0,
                     globalRaw ? (([globalRaw boolValue]) ? "on" : "off") : "default-on",
                     excluded ? 1 : 0, shdw_lab_enabled ? 1 : 0);

        NSString* guardPath = (isDetectorRunner || isVerificationApp)
            ? nil : shdw_home_state_path("shdw_guard.plist");

        // Fail-safe: two consecutive launches that died inside the guard window
        // stand Shadow down for this app instead of looping the crash.
        BOOL guardBlocked = NO;
        if(shdw_lab_enabled) {
            guardBlocked = shdw_guard_enter(guardPath, bundleIdentifierObject,
                                            executablePath,
                                            app_settings[SHDWAppEnabledID] != nil);
        }

        shdw_selfcheck(bundleIdentifierObject, executablePath, app_settings, globalRaw,
                       excludedRaw, shdw_read_state(guardPath), shdw_lab_enabled, excluded,
                       guardBlocked, licenseState);

        if(!licensed) {
            shdw_lab_log("license gate: payload not loaded (state=%s)",
                         licenseState.UTF8String);
            return;
        }

        if(!shdw_lab_enabled || guardBlocked) {
            return;
        }

        // Load the payload (ShadowCore.dylib) from its fixed install path:
        // /usr/lib, prefixed by the package scheme (rootless/roothide stage
        // under /var/jb). The payload is NOT a DynamicLibraries tweak — it must
        // load only through this gated dlopen, never through the runtime's own
        // injection. On failure: log and return, never crash.
        NSString* payloadPath = [@THEOS_PACKAGE_INSTALL_PREFIX stringByAppendingString:@"/usr/lib/ShadowCore.dylib"];

        shdw_lab_log("dlopen %s", [payloadPath UTF8String]);
        if(!dlopen([payloadPath UTF8String], RTLD_NOW)) {
            const char* shdw_err = dlerror();
            shdw_lab_log("dlopen FAILED: %s", shdw_err ?: "?");
            shdw_guard_note_core(guardPath, NO, shdw_err);
            NSLog(@"[Shadow] payload load failed: %s", shdw_err ?: "?");
            NSString* shdw_errPath = [NSTemporaryDirectory() stringByAppendingPathComponent:@"shdw_payload.err"];
            [(shdw_err ? [NSString stringWithUTF8String:shdw_err] : @"?") writeToFile:shdw_errPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
        } else {
            shdw_guard_note_core(guardPath, YES, NULL);
            NSString* shdw_okPath = [NSTemporaryDirectory() stringByAppendingPathComponent:@"shdw_payload.ok"];
            [@"ok" writeToFile:shdw_okPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
            shdw_lab_log("dlopen OK");
        }
    }
}
