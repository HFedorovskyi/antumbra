#import <Shadow/HookConfiguration.h>
#import <Shadow/SHDWPluginOrder.inc>

// Canonical metadata for the hook lifecycle/configuration registry — see
// SHDWPlugin.h. Pure Foundation; no behavior on its own.
// Hybrid seam: kSHDWPlugins is the renamed kSHDWInstallUnits (alias kept).

#pragma mark - Plugin registry (renamed InstallUnits)

// Canonical ordered plugin table. Every lifecycle pass walks this order.
// Hybrid: order verified against SHDWPluginOrder.inc at compile time.
static const SHDWPlugin kSHDWPlugins[] = {
    // Identity concealment — unconditional, installed for every enabled app.
    {"Universal_Dyld", NULL, SHDWPhaseAlways, SHDWCapabilityFunction, 1, 1},
    {"Universal_Filesystem_C", SHDWUniversalFilesystemID, SHDWPhaseTier1,
     SHDWCapabilityFunction, 1, 1},
    {"Universal_EnvVars_C", SHDWUniversalEnvVarsID, SHDWPhaseTier1,
     SHDWCapabilityFunction, 1, 1},
    {"Universal_EnvVars_ObjC", SHDWUniversalEnvVarsID, SHDWPhaseTier1,
     SHDWCapabilityMessage, 1, 0},
    {"Adapter_DeviceCheck", SHDWAdapterDeviceCheckID, SHDWPhaseSDKFallback,
     SHDWCapabilityMessage, 1, 0},
    {"Adapter_FreeRASP", SHDWAdapterFreeRASPID, SHDWPhaseAlways,
     SHDWCapabilityFunction, 1, 0},
    {"Universal_MachBootstrap", SHDWUniversalMachBootstrapID, SHDWPhaseTier1,
     SHDWCapabilityFunction, 1, 1},
    {"Universal_IOKit", SHDWUniversalIOKitID, SHDWPhaseTier1,
     SHDWCapabilityFunction, 1, 1},
    {"Universal_LowLevelC", SHDWUniversalLowLevelCID, SHDWPhaseTier1,
     SHDWCapabilityFunction, 1, 1},
    {"Universal_AntiDebugging", SHDWUniversalAntiDebuggingID, SHDWPhaseTier1,
     SHDWCapabilityFunction, 1, 1},
    // Code-signing self-validation concealment: rebind-lane C hooks on the
    // Security.framework validity surface (own-executable failures only).
    {"Universal_CodeSigning", SHDWUniversalCodeSigningID, SHDWPhaseTier1,
     SHDWCapabilityFunction, 1, 1},
    {"Universal_ObjC", NULL, SHDWPhaseAlways, SHDWCapabilityMessage, 1, 0},
    // method_getImplementation rides the rebind lane (subMain's inline
    // preflight refuses its tiny prologue; see shadowhook_objc_methodimpl).
    {"Universal_ObjC_MethodImplementation", NULL, SHDWPhaseAlways,
     SHDWCapabilityFunction, 1, 0},
    {"Universal_Syscall", SHDWUniversalSyscallID, SHDWPhaseTier1,
     SHDWCapabilityFunction, 1, 1},
    {"Universal_Memory", SHDWUniversalMemoryID, SHDWPhaseTier1,
     SHDWCapabilityFunction, 1, 1},
    {"Universal_Sandbox", SHDWUniversalSandboxID, SHDWPhaseTier1,
     SHDWCapabilityFunction, 1, 1},
    {"Universal_HideClasses", NULL, SHDWPhaseAlways, SHDWCapabilityMessage, 1,
     0},
    {"Universal_SymbolLookup", NULL, SHDWPhaseAlways, SHDWCapabilitySymlookup,
     1, 1},
    // dlopen_internal: ctor installs it pref-gated; detector escalation
    // installs it unconditionally (the coordinator gates on the backend).
    {"Universal_DynamicLibrariesExtra", SHDWUniversalDynamicLibrariesExtraID,
     SHDWPhaseEscalation, SHDWCapabilityPrivateSym, 1, 1},
    // Generic detector integrity: reveal pre-Shadow IMPs and protect only
    // import slots Shadow actually rebound. Installed on detector evidence.
    {"Universal_DetectorIntegrity", NULL, SHDWPhaseTier2,
     SHDWCapabilityFunction, 0, 0},
    // Message-lane units install together with the Tier-1 lanes for every
    // enabled app; their target classes are always present once Foundation is.
    // Units that need detector evidence keep their evidence-gated phase.
    {"Universal_Filesystem_ObjC", SHDWUniversalFilesystemID, SHDWPhaseTier1,
     SHDWCapabilityMessage, 1, 0},
    {"Universal_Foundation_ObjC", SHDWUniversalFoundationID, SHDWPhaseTier1,
     SHDWCapabilityMessage, 1, 0},
    // LaunchServices classes may not be loaded at ctor time; install on
    // detector evidence, when the framework that owns them is on the stack.
    {"Universal_HideApps", SHDWUniversalHideAppsID, SHDWPhaseTier2,
     SHDWCapabilityMessage, 0, 0},
    // UIKit-load groups (the classes only exist once UIKit is loaded).
    {"Universal_URLScheme", SHDWUniversalURLSchemeID, SHDWPhaseUIKit,
     SHDWCapabilityMessage, 0, 0},
    {"Universal_Foundation_UIKit", SHDWUniversalFoundationID, SHDWPhaseUIKit,
     SHDWCapabilityMessage, 0, 0},
    // LAContext + Security passcode-status neutralizer; self-gates on
    // aggressive
    // mode internally. UIKit phase (LocalAuthentication/Security load with the
    // app UI). Message+function mix, so declare the message-capable UIKit slot.
    {"Universal_PasscodeStatus", NULL, SHDWPhaseUIKit, SHDWCapabilityMessage, 0,
     0},
    {"Adapter_DeviceSecurityKit", SHDWAdapterDeviceSecurityKitID,
     SHDWPhaseSDKFallback, SHDWCapabilityMessage, 1, 0},
    {"Adapter_IOSSecuritySuite", SHDWAdapterIOSSecuritySuiteID,
     SHDWPhaseSDKFallback, SHDWCapabilityFunction, 1, 0},
    // Dynatrace MobileProtect: obfuscated Swift checks with no ObjC selector
    // table; the adapter anchors on LC_UUID rows. Termination trap only.
    {"Adapter_MobileProtect", SHDWAdapterMobileProtectID, SHDWPhaseSDKFallback,
     SHDWCapabilityFunction, 1, 0},
    // PureLive/FaceTec bank face SDK: seal-store and self-compare patches
    // keyed by image UUID. Disable-style, so aggressive mode only.
    {"Adapter_PureLive", SHDWAdapterPureLiveID, SHDWPhaseSDKFallback,
     SHDWCapabilityFunction, 1, 0},
    // Licel iOS Runtime: the SDK installs a delegate class it creates at
    // runtime; when its hand-off breaks the app never runs its own delegate.
    // Message lane on UIApplication.
    {"Adapter_Licel", SHDWAdapterLicelID, SHDWPhaseSDKFallback,
     SHDWCapabilityMessage, 1, 0},
    // TransaktSDK (Netcetera S-ID / S-pushTAN): cached __DATA verdicts behind
    // one-shot guards, read through five ObjC -isSecure methods. Disable-style,
    // but default-on like the Kaspi adapter: the SDK gates the launch.
    {"Adapter_Transakt", SHDWAdapterTransaktID, SHDWPhaseSDKFallback,
     SHDWCapabilityMessage, 1, 0},
    // Policy plugins — evaluated via RestrictionEngine / policy/*.m, not via
    // HookCoordinator install. Registered here so SHDWPluginRegistry is the
    // single source for hook+policy metadata. Never installed via HookPlan
    // (ctorInstall 0). Pref gating lives in policy code, not planner.
    {"Policy_Path", NULL, SHDWPhaseAlways, SHDWCapabilityNone, 0, 0},
    {"Policy_Environment", NULL, SHDWPhaseAlways, SHDWCapabilityNone, 0, 0},
    {"Policy_Process", NULL, SHDWPhaseAlways, SHDWCapabilityNone, 0, 0},
    {"Policy_PseudoSandbox", NULL, SHDWPhaseAlways, SHDWCapabilityNone, 0, 0},
};

// Hybrid verification: plugin count must match canonical order
_Static_assert(sizeof(kSHDWPlugins) / sizeof(kSHDWPlugins[0]) ==
                   SHDW_PLUGIN_COUNT,
               "plugin count != SHDW_PLUGIN_COUNT");

const SHDWPlugin *SHDWPluginRegistry(NSUInteger *outCount) {
  if (outCount) {
    *outCount = sizeof(kSHDWPlugins) / sizeof(kSHDWPlugins[0]);
  }
  return kSHDWPlugins;
}

const SHDWInstallUnit *SHDWInstallUnits(NSUInteger *outCount) {
  // Compat shim — same storage, new name
  if (outCount) {
    *outCount = sizeof(kSHDWPlugins) / sizeof(kSHDWPlugins[0]);
  }
  return (const SHDWInstallUnit *)kSHDWPlugins;
}

#pragma mark - Built-in profile

NSDictionary<NSString *, id> *SHDWDefaultHookSettings(void) {
  return @{
    SHDWUniversalFilesystemID : @(YES),
    SHDWUniversalURLSchemeID : @(YES),
    SHDWUniversalEnvVarsID : @(YES),
    SHDWUniversalFoundationID : @(YES),
    SHDWUniversalMachBootstrapID : @(YES),
    SHDWUniversalIOKitID : @(YES),
    SHDWUniversalLowLevelCID : @(YES),
    SHDWUniversalAntiDebuggingID : @(YES),
    SHDWUniversalCodeSigningID : @(YES),
    SHDWUniversalDynamicLibrariesExtraID : @(YES),
    SHDWUniversalSyscallID : @(YES),
    SHDWUniversalSandboxID : @(YES),
    SHDWUniversalMemoryID : @(YES),
    SHDWUniversalHideAppsID : @(YES),
    SHDWUniversalPseudoSandboxModeID : @(0),
    SHDWUniversalPathRewriteID : @(YES),
    SHDWUniversalMemoryLevelHidingID : @(YES),
    SHDWAdapterDeviceCheckID : @(YES),
    SHDWAdapterFreeRASPID : @(YES),
    SHDWAdapterDeviceSecurityKitID : @(YES),
    SHDWAdapterIOSSecuritySuiteID : @(YES),
    SHDWAdapterMobileProtectID : @(YES),
    SHDWAdapterPureLiveID : @(YES),
    SHDWAdapterLicelID : @(YES),
    SHDWAdapterTransaktID : @(YES),
    SHDWAdapterDTTJailbreakDetectionID : @(YES),
    SHDWAdapterSafeDeviceID : @(YES),
    SHDWAdapterJailMonkeyID : @(YES),
    // Off by default: the natural, stock-shaped bypasses run for every
    // enabled app; disable-style neutralizers only activate when the user
    // opts into aggressive mode (globally or per app).
    SHDWDetectorAggressiveID : @(NO)
  };
}

#pragma mark - Capability metadata

// Registry capability -> group kind: PrivateSym is the private-symbol (inline)
// lane; rows with no prefKey (None/Symlookup) never contribute a group.
static NSString *SHDWCapabilityKindName(SHDWCapabilityKind capability) {
  switch (capability) {
  case SHDWCapabilityFunction:
    return @"function";
  case SHDWCapabilityMessage:
    return @"message";
  case SHDWCapabilityPrivateSym:
    return @"inline";
  default:
    return @"none";
  }
}

NSString *SHDWHookGroupCapabilityKind(NSString *groupID) {
  static NSDictionary<NSString *, NSString *> *kinds = nil;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    NSMutableDictionary<NSString *, NSString *> *map =
        [NSMutableDictionary new];
    NSUInteger count = 0;
    const SHDWPlugin *plugins = SHDWPluginRegistry(&count);
    // FIRST registry row per prefKey wins — load-bearing for composite
    // groups: Universal_Filesystem is the C lane's "function", never the
    // later Universal_Filesystem_ObjC's "message".
    for (const SHDWPlugin *plugin = plugins; plugin < plugins + count;
         plugin++) {
      if (plugin->prefKey && !map[plugin->prefKey]) {
        map[plugin->prefKey] = SHDWCapabilityKindName(plugin->capability);
      }
    }
    // IDs the registry has no prefKey row for: detector-only adapters
    // (registered in the detector table, not the hook registry) and the
    // non-hook policy toggles.
    [map addEntriesFromDictionary:@{
      SHDWAdapterDTTJailbreakDetectionID : @"message",
      SHDWAdapterSafeDeviceID : @"message",
      SHDWAdapterJailMonkeyID : @"message",
      SHDWUniversalPseudoSandboxModeID : @"none",
      SHDWUniversalPathRewriteID : @"none",
      SHDWUniversalMemoryLevelHidingID : @"none",
    }];
    kinds = map;
  });
  return kinds[groupID];
}

#pragma mark - Planner

static BOOL SHDWPluginEnabled(const SHDWPlugin *plugin,
                              NSDictionary<NSString *, id> *prefs,
                              SHDWLifecycleEvent event) {
  // Debug bisection: skip any plugin the profile names explicitly. This is the
  // only way to switch off the preference-less Always rows, which the fixed
  // built-in profile installs for every enabled app.
  NSString *debugDisabled = prefs[SHDWDebugDisabledPluginsID];
  if ([debugDisabled isKindOfClass:[NSString class]] &&
      [[debugDisabled componentsSeparatedByString:@" "]
          containsObject:[NSString stringWithUTF8String:plugin->pluginID]]) {
    return NO;
  }
  // Harness frameworks load per detector. Both baseline and prearmed test
  // modes defer target-dependent adapters until that first pass has loaded
  // every target; production apps have no Harness profile key and
  // retain their early adapter behavior.
  if (plugin->phase == SHDWPhaseSDKFallback && event == SHDWEventCtor &&
      prefs[SHDWUniversalHarnessBaselineID] != nil) {
    return NO;
  }
  if (!plugin->prefKey) {
    return YES;
  }
  if (event == SHDWEventDetectorEscalation &&
      plugin->phase == SHDWPhaseEscalation) {
    return YES;
  }
  return [prefs[plugin->prefKey] boolValue];
}

static BOOL SHDWPluginCapable(const SHDWPlugin *plugin, SHDWCapabilities caps) {
  if (plugin->phase == SHDWPhaseEscalation) {
    return YES;
  }
  if (plugin->capability != SHDWCapabilityMessage) {
    return YES;
  }
  return (caps & SHDWCapMessage) != 0;
}

// Install order inside one event: dyld lane, message lanes, then the rest.
enum { SHDWInstallRankImage = 0, SHDWInstallRankMessage, SHDWInstallRankRest };

static NSInteger SHDWPluginInstallRank(const SHDWPlugin *plugin) {
  if (strcmp(plugin->unitID, "Universal_Dyld") == 0) {
    return SHDWInstallRankImage;
  }
  if (plugin->capability == SHDWCapabilityMessage ||
      strcmp(plugin->unitID, "Universal_ObjC_MethodImplementation") == 0) {
    return SHDWInstallRankMessage;
  }
  return SHDWInstallRankRest;
}

NSArray<NSString *> *SHDWPluginPlan(NSDictionary<NSString *, id> *prefs,
                                    SHDWCapabilities caps,
                                    SHDWLifecycleEvent event) {
  NSDictionary<NSString *, id> *effective = prefs ?: SHDWDefaultHookSettings();
  NSMutableArray<NSString *> *ranked[3] = {
      [NSMutableArray new], [NSMutableArray new], [NSMutableArray new]};
  NSUInteger count = 0;
  const SHDWPlugin *plugins = SHDWPluginRegistry(&count);
  for (NSUInteger i = 0; i < count; i++) {
    const SHDWPlugin *plugin = &plugins[i];
    BOOL include = NO;
    switch (event) {
    case SHDWEventCtor:
      include = plugin->ctorInstall != 0;
      break;
    case SHDWEventUIKitLoaded:
      include = plugin->phase == SHDWPhaseUIKit;
      break;
    case SHDWEventDetectorEscalation:
      include = plugin->phase == SHDWPhaseTier2 ||
                plugin->phase == SHDWPhaseEscalation;
      break;
    case SHDWEventSDKFallback:
      include = plugin->phase == SHDWPhaseSDKFallback;
      break;
    }
    if (!include)
      continue;
    if (!SHDWPluginEnabled(plugin, effective, event))
      continue;
    if (!SHDWPluginCapable(plugin, caps))
      continue;
    NSString *unitID = [NSString stringWithUTF8String:plugin->unitID];
    [ranked[SHDWPluginInstallRank(plugin)] addObject:unitID];
  }
  [ranked[SHDWInstallRankImage]
      addObjectsFromArray:ranked[SHDWInstallRankMessage]];
  [ranked[SHDWInstallRankImage]
      addObjectsFromArray:ranked[SHDWInstallRankRest]];
  return ranked[SHDWInstallRankImage];
}

// Compat shims — forward to new planner
NSArray<NSString *> *SHDWHookPlan(NSDictionary<NSString *, id> *prefs,
                                  SHDWCapabilities caps,
                                  SHDWLifecycleEvent event) {
  return SHDWPluginPlan(prefs, caps, event);
}
