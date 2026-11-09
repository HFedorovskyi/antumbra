#ifndef shadow_plugin_h
#define shadow_plugin_h

#import <Foundation/Foundation.h>

// Canonical plugin registry — single source of truth for hook/policy
// lifecycle, built-in profile and planner. Pure Foundation; safe to link
// from any binary and from the host test harness.
// Hybrid seam: SHDWPlugin is the renamed SHDWInstallUnit (type alias kept
// for compat), SHDWPluginRegistry is the renamed SHDWInstallUnits.

#if defined(__GNUC__) && (__GNUC__ >= 4)
#define SHDW_EXPORT __attribute__((visibility("default")))
#else
#define SHDW_EXPORT
#endif

#pragma mark - Hook IDs (plist preference keys)

#define SHDWUniversalFilesystemID @"Universal_Filesystem"
#define SHDWUniversalURLSchemeID @"Universal_URLScheme"
#define SHDWUniversalEnvVarsID @"Universal_EnvVars"
#define SHDWUniversalFoundationID @"Universal_Foundation"
#define SHDWUniversalMachBootstrapID @"Universal_MachBootstrap"
#define SHDWUniversalIOKitID @"Universal_IOKit"
#define SHDWUniversalLowLevelCID @"Universal_LowLevelC"
#define SHDWUniversalAntiDebuggingID @"Universal_AntiDebugging"
#define SHDWUniversalCodeSigningID @"Universal_CodeSigning"
#define SHDWUniversalDynamicLibrariesExtraID @"Universal_DynamicLibrariesExtra"
#define SHDWUniversalSyscallID @"Universal_Syscall"
#define SHDWUniversalSandboxID @"Universal_Sandbox"
#define SHDWUniversalMemoryID @"Universal_Memory"
#define SHDWUniversalHideAppsID @"Universal_HideApps"
#define SHDWUniversalPseudoSandboxModeID @"Universal_PseudoSandboxMode"
#define SHDWUniversalPathRewriteID @"Universal_PathRewrite"
#define SHDWUniversalMemoryLevelHidingID @"Universal_MemoryLevelHiding"
#define SHDWUniversalHarnessBaselineID @"Universal_HarnessBaseline"

#define SHDWAdapterDeviceCheckID @"Adapter_DeviceCheck"
#define SHDWAdapterFreeRASPID @"Adapter_FreeRASP"
#define SHDWAdapterDeviceSecurityKitID @"Adapter_DeviceSecurityKit"
#define SHDWAdapterIOSSecuritySuiteID @"Adapter_IOSSecuritySuite"
#define SHDWAdapterMobileProtectID @"Adapter_MobileProtect"
#define SHDWAdapterPureLiveID @"Adapter_PureLive"
#define SHDWAdapterLicelID @"Adapter_Licel"
#define SHDWAdapterTransaktID @"Adapter_Transakt"
#define SHDWAdapterDTTJailbreakDetectionID @"Adapter_DTTJailbreakDetection"
#define SHDWAdapterSafeDeviceID @"Adapter_SafeDevice"
#define SHDWAdapterJailMonkeyID @"Adapter_JailMonkey"

#define SHDWAppEnabledID @"App_Enabled"
// Pane language, independent of the system locale: "en" or "ru". English is the
// default, so a fresh install and a reset both land on English.
#define SHDWUILanguageID @"UILanguage"
// Read-only migration keys. New settings write only App_Enabled.
#define SHDWGlobalEnabledID @"Global_Enabled"
// Optional array of bundle ids kept out of injection. Absent (the normal case)
// falls back to SHDWDefaultExcludedApps().
#define SHDWGlobalDisabledAppsID @"Global_DisabledApps"
#define SHDWAppDisabledID @"App_Disabled"
#define SHDWSingleToggleMigrationID @"SingleToggleMigrated"

// Aggressive detector neutralization. Live scalar, resolved like activation:
// a global default (root scalar) with an optional per-app override (same key
// inside the app dict; absent = follow global). When on, disable-style adapter
// paths (which force a detector's check result to "clean") activate in addition
// to the natural, stock-shaped bypasses. Off = natural bypasses only, so the
// process looks like a pristine stock device rather than one actively fighting
// a named detector. Only meaningful when the app is enabled.
#define SHDWDetectorAggressiveID @"Detector_Aggressive"

// Deep tier-2 hiding. Tier-2 units (installed-app enumeration hiding,
// NSBundle/NSFileManager message hooks, URL-scheme checks) normally install
// only after detector evidence. With this set the process arms them at
// construction, so custom detectors that never trip an adapter still see the
// hidden view. Resolved like activation: per-app override, else the global
// scalar. Deliberately does NOT enable disable-style neutralizers — verdicts
// stay stock-shaped.
#define SHDWDeepTier2ID @"Deep_Tier2"

// Debug-only bisection switch: a space-separated list of plugin IDs the planner
// must skip even though the fixed profile enables them. Absent in production
// profiles, so normal installs are unaffected.
#define SHDWDebugDisabledPluginsID @"Debug_DisabledPlugins"

// Debug-only fragments of the dyld lane: skip the dyld_all_image_infos
// memory-hiding patch, and skip the inline (SPI) hooks on libdyld.
#define SHDWDebugDyldNoInfosID @"Debug_Dyld_NoInfos"
#define SHDWDebugDyldNoSpiInlineID @"Debug_Dyld_NoSpiInline"
#define SHDWDebugDyldSkipRebindsID @"Debug_Dyld_SkipRebinds"

// Resolve the effective aggressive-neutralization state for an app: the per-app
// override if present, else the global default. Mirrors
// SHDWApplicationEnabled's global-fallback shape.
static inline BOOL SHDWDetectorAggressiveEnabled(NSDictionary *appSettings,
                                                 BOOL globalAggressive) {
  id appValue = appSettings[SHDWDetectorAggressiveID];
  return appValue ? [appValue boolValue] : globalAggressive;
}

static inline BOOL SHDWApplicationEnabled(NSDictionary *appSettings,
                                          BOOL legacyGlobalEnabled,
                                          BOOL singleToggleMigrated,
                                          BOOL forceEnabled) {
  if (forceEnabled) {
    return YES;
  }
  if ([appSettings[SHDWAppDisabledID] boolValue]) {
    return NO;
  }
  // Before migration, App_Enabled=NO meant "follow global" rather than off.
  if (!singleToggleMigrated && legacyGlobalEnabled) {
    return YES;
  }
  id appEnabled = appSettings[SHDWAppEnabledID];
  return appEnabled ? [appEnabled boolValue] : legacyGlobalEnabled;
}

// Product default: a missing Global_Enabled (fresh install, migrated prefs)
// means every app is protected. Only an explicit NO turns the fallback off.
static inline BOOL SHDWGlobalEnabledValue(id globalValue) {
  return globalValue ? [globalValue boolValue] : YES;
}

// Bundle ids that must never be injected: their anti-tamper kills an injected
// process before any hook can help, so injection only turns a detector's
// warning into an instant crash. An explicit per-app App_Enabled overrides it.
static inline NSArray *SHDWDefaultExcludedApps(void) {
  return @[ @"com.revolut.revolut" ];
}

static inline BOOL SHDWApplicationExcluded(NSDictionary *appSettings,
                                           id excludedApps,
                                           NSString *bundleIdentifier) {
  if (!bundleIdentifier) {
    return NO;
  }
  if (appSettings[SHDWAppEnabledID] != nil) {
    return NO;
  }
  NSArray *excluded = [excludedApps isKindOfClass:[NSArray class]]
                          ? excludedApps
                          : SHDWDefaultExcludedApps();
  return [excluded containsObject:bundleIdentifier];
}

#pragma mark - Lifecycle phases

typedef NS_ENUM(NSInteger, SHDWLifecyclePhase) {
  SHDWPhaseAlways = 0,
  SHDWPhaseTier1,
  SHDWPhaseTier2,
  SHDWPhaseUIKit,
  SHDWPhaseEscalation,
  SHDWPhaseSDKFallback,
};

typedef NS_ENUM(NSInteger, SHDWLifecycleEvent) {
  SHDWEventCtor = 0,
  SHDWEventUIKitLoaded,
  SHDWEventDetectorEscalation,
  SHDWEventSDKFallback,
};

#pragma mark - Native HookKit request capabilities

typedef NS_OPTIONS(NSUInteger, SHDWCapabilities) {
  SHDWCapMessage = 1 << 0,
  SHDWCapFunction = 1 << 1,
  SHDWCapInline = 1 << 2,
  SHDWCapPrivateSym = 1 << 3,
};

#pragma mark - Plugin (renamed InstallUnit)

typedef NS_ENUM(NSInteger, SHDWCapabilityKind) {
  SHDWCapabilityNone = 0,
  SHDWCapabilityMessage,
  SHDWCapabilityFunction,
  SHDWCapabilitySymlookup,
  SHDWCapabilityPrivateSym,
};

// One installable plugin = one installer call with one backend role.
// Renamed from SHDWInstallUnit; pluginID is canonical, unitID is compat alias
// via macro.
typedef struct {
  const char *pluginID;
  NSString *prefKey;
  SHDWLifecyclePhase phase;
  SHDWCapabilityKind capability;
  unsigned ctorInstall : 1;
  unsigned verify : 1;
} SHDWPlugin;
#ifndef unitID
#define unitID pluginID
#endif

// Backward-compat alias — single source, no duplication.
typedef SHDWPlugin SHDWInstallUnit;

#pragma mark - Registry (renamed InstallUnits)

SHDW_EXPORT const SHDWPlugin *SHDWPluginRegistry(NSUInteger *outCount);
// Compat: old name forwards to new impl
SHDW_EXPORT const SHDWInstallUnit *SHDWInstallUnits(NSUInteger *outCount);

#pragma mark - Built-in profile

SHDW_EXPORT NSDictionary<NSString *, id> *SHDWDefaultHookSettings(void);

#pragma mark - Capability metadata

SHDW_EXPORT NSString *SHDWHookGroupCapabilityKind(NSString *groupID);

#pragma mark - Planner (pure)

SHDW_EXPORT NSArray<NSString *> *
SHDWPluginPlan(NSDictionary<NSString *, id> *prefs, SHDWCapabilities caps,
               SHDWLifecycleEvent event);
// Compat
SHDW_EXPORT NSArray<NSString *> *
SHDWHookPlan(NSDictionary<NSString *, id> *prefs, SHDWCapabilities caps,
             SHDWLifecycleEvent event);

#endif // shadow_plugin_h
