#import "SHDWPrefs.h"
#import "SHDWPaneLog.h"

#import <Preferences/PSSpecifier.h>
#import <Shadow/HookConfiguration.h>
#import <Shadow/JBPath.h>
#import <Shadow/Settings.h>
#import <UIKit/UIKit.h>

static NSBundle *SHDWLanguageBundle(NSString *language) {
  static NSMutableDictionary<NSString *, NSBundle *> *bundles;
  static dispatch_once_t once;
  dispatch_once(&once, ^{
    bundles = [NSMutableDictionary new];
  });
  NSBundle *strings = bundles[language];
  if (!strings) {
    NSBundle *pane =
        [NSBundle bundleForClass:NSClassFromString(@"SHDWRootListController")];
    NSString *path = [pane pathForResource:language ofType:@"lproj"];
    strings = path ? [NSBundle bundleWithPath:path] : nil;
    if (!strings) {
      // A missing table must not blank the pane: fall back to the bundle's
      // development region.
      strings = pane;
    }
    bundles[language] = strings;
  }
  return strings;
}

// PSListController resolves plist labels with the *system* language before the
// pane sees them, so on a Russian device the name arrives already translated.
// Map every shipped translation back to its key: the key is what the pane
// language is chosen from, and English must win on a fresh install.
static NSString *SHDWLabelKey(NSString *label, NSString *table) {
  if (!label.length) {
    return label;
  }
  static NSMutableDictionary<NSString *, NSDictionary *> *indexes;
  static dispatch_once_t once;
  dispatch_once(&once, ^{
    indexes = [NSMutableDictionary new];
  });
  NSString *indexID = table ?: @"";
  NSDictionary *index = indexes[indexID];
  if (!index) {
    NSMutableDictionary *reversed = [NSMutableDictionary new];
    for (NSString *language in
         @[ @"en", @"ru", @"ar", @"zh-Hans", @"zh-Hant" ]) {
      NSString *path =
          [SHDWLanguageBundle(language) pathForResource:table
                                                 ofType:@"strings"];
      NSDictionary *strings =
          path ? [NSDictionary dictionaryWithContentsOfFile:path] : nil;
      for (NSString *key in strings) {
        NSString *value = strings[key];
        if ([value isKindOfClass:[NSString class]] && !reversed[value]) {
          reversed[value] = key;
        }
      }
    }
    index = reversed;
    indexes[indexID] = index;
  }
  NSString *key = index[label];
  return key ?: label;
}

void SHDWLocalizeSpecifiers(NSArray *specifiers, NSBundle *bundle,
                            NSString *table) {
  (void)bundle; // the language comes from the pane pref, not the system locale
  SHDWPaneLog(@"localize enter count=%lu table=%@",
              (unsigned long)specifiers.count, table);
  // Specifier properties survive repeated localization, so keep the plist key
  // in a private property and translate from it every time. Without that a
  // language flip would look up the already-translated text as a key.
  static NSString *const labelKey = @"SHDWOriginalLabel";
  static NSString *const footerKey = @"SHDWOriginalFooter";
  for (PSSpecifier *specifier in specifiers) {
    NSString *label = [specifier propertyForKey:labelKey];
    if (!label.length) {
      label = SHDWLabelKey(specifier.name, table);
      if (label.length) {
        [specifier setProperty:label forKey:labelKey];
      }
    }
    if (label.length) {
      specifier.name = SHDWLocalizedString(label, table);
    }
    NSString *footer = [specifier propertyForKey:footerKey];
    if (!footer.length) {
      footer = SHDWLabelKey([specifier propertyForKey:@"footerText"], table);
      if (footer.length) {
        [specifier setProperty:footer forKey:footerKey];
      }
    }
    if (footer.length) {
      [specifier setProperty:SHDWLocalizedString(footer, table)
                      forKey:@"footerText"];
    }
  }
  SHDWPaneLog(@"localize done");
}

NSString *SHDWUILanguage(void) {
  NSString *language = [[[ShadowSettings sharedInstance] userDefaults]
      stringForKey:SHDWUILanguageID];
  return [language isEqualToString:@"ru"] ? @"ru" : @"en";
}

NSString *SHDWLocalizedString(NSString *key, NSString *table) {
  if (!key.length) {
    return key;
  }
  return [SHDWLanguageBundle(SHDWUILanguage()) localizedStringForKey:key
                                                               value:key
                                                               table:table];
}

NSString *SHDWInstalledVersion(void) {
  SHDWPaneLog(@"InstalledVersion enter");
  // The status file is large; share the local result across both panes.
  static NSString *packageVersion;
  if (!packageVersion) {
    for (NSString *statusPath in @[
#ifdef SHADOW_SETTINGS_EMBEDDED
           @"/var/lib/dpkg/status",
#else
           JBPath(@"/var/lib/dpkg/status"),
#endif
           [@THEOS_PACKAGE_INSTALL_PREFIX
               stringByAppendingString:@"/var/lib/dpkg/status"]
         ]) {
      if (![[NSFileManager defaultManager] fileExistsAtPath:statusPath])
        continue;
      NSString *status = [NSString stringWithContentsOfFile:statusPath
                                                   encoding:NSUTF8StringEncoding
                                                      error:nil];
      if (status) {
        NSRegularExpression *regex = [NSRegularExpression
            regularExpressionWithPattern:
                @"(?:^|\\n)Package: "
                @"(?:me\\.fedorovskyi\\.(?:antumbra|shadow)|me\\.jjolano\\."
                @"shadow)(?:\\.legacy)?\\n(?:[^\\n]+\\n)*?Version: ([^\\n]+)"
                                 options:0
                                   error:nil];
        NSTextCheckingResult *match =
            [regex firstMatchInString:status
                              options:0
                                range:NSMakeRange(0, status.length)];
        if (match) {
          packageVersion = [[status substringWithRange:[match rangeAtIndex:1]]
              stringByTrimmingCharactersInSet:
                  [NSCharacterSet whitespaceAndNewlineCharacterSet]];
          if (packageVersion.length)
            break;
          packageVersion = nil;
        }
      }
    }
  }
  return packageVersion;
}

BOOL SHDWAppEnabled(NSUserDefaults *prefs, NSString *appID) {
  NSDictionary *appPrefs = [prefs dictionaryForKey:appID];
  BOOL enabled = SHDWApplicationEnabled(
      appPrefs,
      SHDWGlobalEnabledValue([prefs objectForKey:SHDWGlobalEnabledID]),
      [prefs boolForKey:SHDWSingleToggleMigrationID], NO);
  if (enabled &&
      SHDWApplicationExcluded(
          appPrefs, [prefs objectForKey:SHDWGlobalDisabledAppsID], appID)) {
    enabled = NO;
  }
  return enabled;
}

void SHDWWriteAppEnabled(NSUserDefaults *prefs, NSString *appID, BOOL enabled) {
  NSMutableDictionary *appPrefs =
      [[prefs dictionaryForKey:appID] mutableCopy] ?: [NSMutableDictionary new];
  appPrefs[SHDWAppEnabledID] = @(enabled);
  [appPrefs removeObjectForKey:SHDWAppDisabledID];
  [prefs setBool:YES forKey:SHDWSingleToggleMigrationID];
  [prefs setObject:[appPrefs copy] forKey:appID];
}

BOOL SHDWAppFollowsGlobal(NSUserDefaults *prefs, NSString *appID) {
  return !SHDWAppIsCustomized([prefs dictionaryForKey:appID]);
}

BOOL SHDWAppIsCustomized(id appPrefs) {
  return [appPrefs isKindOfClass:[NSDictionary class]] &&
         ([appPrefs objectForKey:SHDWAppEnabledID] != nil ||
          [appPrefs objectForKey:SHDWAppDisabledID] != nil ||
          [appPrefs objectForKey:SHDWDetectorAggressiveID] != nil);
}

BOOL SHDWResetApp(NSUserDefaults *prefs, NSString *appID) {
  if (appID.length == 0)
    return NO;
  [prefs removeObjectForKey:appID];
  // Do not roll back asynchronous defaults writes with a potentially stale
  // snapshot.
  return [prefs synchronize];
}

UIImage *SHDWSettingsSymbol(NSString *name) {
  if (![UIImage respondsToSelector:@selector(systemImageNamed:)])
    return nil;
  return [[UIImage systemImageNamed:name]
      imageWithRenderingMode:UIImageRenderingModeAlwaysTemplate];
}

void SHDWClearAppOverrides(NSUserDefaults *prefs, NSString *appID) {
  NSMutableDictionary *appPrefs = [[prefs dictionaryForKey:appID] mutableCopy];
  if (!appPrefs) {
    return;
  }
  [appPrefs removeObjectForKey:SHDWAppEnabledID];
  [appPrefs removeObjectForKey:SHDWAppDisabledID];
  [appPrefs removeObjectForKey:SHDWDetectorAggressiveID];
  [prefs setBool:YES forKey:SHDWSingleToggleMigrationID];
  // Drop the app's dictionary entirely once it holds no overrides, so a
  // "follow global" app leaves no residue in the backing plist.
  if (appPrefs.count == 0) {
    [prefs removeObjectForKey:appID];
  } else {
    [prefs setObject:[appPrefs copy] forKey:appID];
  }
}

BOOL SHDWAppAggressive(NSUserDefaults *prefs, NSString *appID) {
  NSDictionary *appPrefs = [prefs dictionaryForKey:appID];
  return SHDWDetectorAggressiveEnabled(
      appPrefs, [prefs boolForKey:SHDWDetectorAggressiveID]);
}

void SHDWWriteAppAggressive(NSUserDefaults *prefs, NSString *appID,
                            BOOL aggressive) {
  NSMutableDictionary *appPrefs =
      [[prefs dictionaryForKey:appID] mutableCopy] ?: [NSMutableDictionary new];
  appPrefs[SHDWDetectorAggressiveID] = @(aggressive);
  [prefs setObject:[appPrefs copy] forKey:appID];
}

void SHDWToggleHaptic(void) {
  // Fresh instance per event: toggle flips are rare, allocation cost is
  // irrelevant next to the impact itself.
  UIImpactFeedbackGenerator *generator = [(UIImpactFeedbackGenerator *)
          [NSClassFromString(@"UIImpactFeedbackGenerator") alloc]
      initWithStyle:UIImpactFeedbackStyleLight];
  [generator impactOccurred];
}
