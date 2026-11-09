#import "SettingsMigration.h"

#import <Shadow/SHDWPlugin.h>

NSDictionary<NSString *, id> *
SHDWMigratedHookSettings(NSDictionary<NSString *, id> *settings) {
  NSMutableDictionary<NSString *, id> *migrated =
      [settings mutableCopy] ?: [NSMutableDictionary new];

  // App_Disabled used to override App_Enabled. The single-toggle model
  // expresses the same state directly and never writes App_Disabled again.
  if ([settings[SHDWAppDisabledID] boolValue]) {
    migrated[SHDWAppEnabledID] = @NO;
  }
  [migrated removeObjectForKey:SHDWAppDisabledID];

  // Shadow runs its fixed full-capability profile whenever an app is enabled;
  // stored hook toggles (Universal_*, Adapter_*, the legacy Hook_* names,
  // etc.) no longer take effect. Live mode scalars are read back through
  // userDefaults. Prune the plist down to the live surface so obsolete keys
  // can never linger as
  // phantom switches that reduce capability. Kept scalars are the
  // activation/migration markers and
  // the per-app harness baseline; dict values are preserved untouched — at
  // the root they are per-app override dicts, and inside a per-app dict the
  // Test_DetectorOverrides map (both handled by a separate migration pass).
  static NSSet *liveScalarKeys = nil;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    liveScalarKeys = [NSSet setWithArray:@[
      SHDWGlobalEnabledID,
      SHDWGlobalDisabledAppsID,
      SHDWSingleToggleMigrationID,
      SHDWAppEnabledID,
      SHDWUniversalHarnessBaselineID,
      // A mode, not a hook toggle: pruned would silently disable it.
      SHDWUniversalPseudoSandboxModeID,
      // Live at both scopes: the global default (root scalar) and the
      // per-app override (same key inside an app dict).
      SHDWDetectorAggressiveID,
      SHDWDeepTier2ID,
      // The pane renders its labels from this choice, not from the system
      // locale. It lives in the same domain, so a migration pass running in
      // any injected app would otherwise prune the user's pick back to the
      // English default.
      SHDWUILanguageID,
      // Debug bisection list; kept so the prune cannot eat it before the
      // planner reads it.
      SHDWDebugDisabledPluginsID,
      SHDWDebugDyldNoInfosID,
      SHDWDebugDyldNoSpiInlineID,
      SHDWDebugDyldSkipRebindsID,
    ]];
  });

  for (NSString *key in [migrated allKeys]) {
    if ([migrated[key] isKindOfClass:[NSDictionary class]]) {
      continue;
    }
    // Debug_* is the bisection surface: it must survive so an A/B run can
    // be driven from the on-disk plist instead of being pruned on sight.
    // Universal_*/Adapter_*/Detector_* are live per-app planner inputs
    // (SHDWPlugin rows carry those keys) and pane-written choices — pruning
    // them silently changes the hook plan for that app.
    if (![liveScalarKeys containsObject:key] && ![key hasPrefix:@"Debug_"] &&
        ![key hasPrefix:@"Universal_"] && ![key hasPrefix:@"Adapter_"] &&
        ![key hasPrefix:@"Detector_"]) {
      [migrated removeObjectForKey:key];
    }
  }

  return [migrated copy];
}
