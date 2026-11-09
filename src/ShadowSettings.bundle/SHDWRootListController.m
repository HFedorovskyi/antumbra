#import "SHDWRootListController.h"
#import "SHDWPaneLog.h"
#import "SHDWPrefs.h"

#import <Shadow/SHDWPlugin.h>
#import <Shadow/Settings.h>

static void SHDWPaneExceptionHandler(NSException *e) {
  SHDWPaneLog(@"UNCAUGHT %@: %@\n%@", e.name, e.reason,
              [e.callStackSymbols componentsJoinedByString:@"\n"]);
}

@implementation SHDWRootListController {
  NSUserDefaults *prefs;
}

+ (void)load {
  SHDWPaneLog(@"bundle loaded, bundle=%@", [NSBundle bundleForClass:self]);
  NSSetUncaughtExceptionHandler(&SHDWPaneExceptionHandler);
}

- (NSArray *)specifiers {
  SHDWPaneLog(@"specifiers enter");
  if (!_specifiers) {
    SHDWPaneLog(@"specifiers loading plist");
    _specifiers = [self loadSpecifiersFromPlistName:@"Root" target:self];
    SHDWPaneLog(@"specifiers loaded count=%lu",
                (unsigned long)_specifiers.count);
    SHDWLocalizeSpecifiers(_specifiers, [NSBundle bundleForClass:[self class]],
                           @"Root");
    self.title = SHDWLocalizedString(@"PANEL_TITLE", @"Root");
    SHDWPaneLog(@"specifiers localized");
    for (NSString *identifier in @[ @"ApplicationsSummary", @"RootAbout" ]) {
      UIImage *icon = SHDWSettingsSymbol(
          [identifier isEqualToString:@"RootAbout"] ? @"info.circle"
                                                    : @"square.grid.2x2");
      SHDWPaneLog(@"specifiers symbol %@ -> %@", identifier, icon);
      if (icon)
        [[self specifierForID:identifier] setProperty:icon forKey:@"iconImage"];
    }
    SHDWPaneLog(@"specifiers done");
  }

  return _specifiers;
}

- (id)readPreferenceValue:(PSSpecifier *)specifier {
  NSString *key = [specifier identifier];

  // The two language switches are views over one string pref, so neither can
  // be read or written through the generic path.
  if ([key isEqualToString:@"Language_English"] ||
      [key isEqualToString:@"Language_Russian"]) {
    BOOL russian = [key isEqualToString:@"Language_Russian"];
    return @([SHDWUILanguage() isEqualToString:(russian ? @"ru" : @"en")]);
  }

  if ([key isEqualToString:@"ApplicationsSummary"]) {
    // Count apps not following the global settings: an app "follows
    // global" until it writes an explicit activation override (App_Enabled)
    // or a per-app aggressive override (Detector_Aggressive). Legacy
    // App_Disabled counts too, since it also overrides the global toggle.
    // The subtext is a bare number; with no overrides there is nothing to
    // display, so omit the label entirely.
    NSInteger customized = 0;
    for (id value in [prefs dictionaryRepresentation].allValues) {
      if (SHDWAppIsCustomized(value)) {
        customized++;
      }
    }

    if (customized == 0) {
      return nil;
    }

    return [NSNumberFormatter
        localizedStringFromNumber:@(customized)
                      numberStyle:NSNumberFormatterDecimalStyle];
  }

  return [prefs objectForKey:[specifier identifier]];
}

- (void)setPreferenceValue:(id)value forSpecifier:(PSSpecifier *)specifier {
  NSString *key = [specifier identifier];

  if ([key isEqualToString:@"Language_English"] ||
      [key isEqualToString:@"Language_Russian"]) {
    // A switch turned off means "not this one", not "no language": there is
    // always exactly one selected. Only the on-flip changes the pref, and the
    // paired switch is refreshed so both rows agree.
    if (![value boolValue]) {
      [self reloadSpecifier:specifier];
      return;
    }
    BOOL russian = [key isEqualToString:@"Language_Russian"];
    [prefs setObject:(russian ? @"ru" : @"en") forKey:SHDWUILanguageID];
    [prefs synchronize];
    SHDWToggleHaptic();
    [self applyLanguage];
    return;
  }

  SHDWToggleHaptic();
  [prefs setObject:value forKey:key];
  [prefs synchronize];
}

- (void)applyLanguage {
  SHDWLocalizeSpecifiers(_specifiers, [NSBundle bundleForClass:[self class]],
                         @"Root");
  self.title = SHDWLocalizedString(@"PANEL_TITLE", @"Root");
  for (NSString *specID in @[ @"Language_English", @"Language_Russian" ]) {
    PSSpecifier *row = [self specifierForID:specID];
    if (row) {
      [self reloadSpecifier:row];
    }
  }
  // Group headers and footers were rewritten in place; only the table needs
  // to lay them out again.
  [self.table reloadData];
}

- (void)viewWillAppear:(BOOL)animated {
  SHDWPaneLog(@"viewWillAppear enter");
  [super viewWillAppear:animated];
  SHDWPaneLog(@"viewWillAppear super done");

  // Re-read on return: the summary derives from switches changed on pushed
  // app pages, and the global switches can be wiped by Reset Settings in the
  // About pane. Without this, popping back shows stale switch/summary state
  // even though the stored values changed.
  for (NSString *specID in @[
         @"Global_Enabled", @"Universal_PseudoSandboxMode",
         @"Detector_Aggressive", @"ApplicationsSummary", @"Language_English",
         @"Language_Russian"
       ]) {
    PSSpecifier *specifier = [self specifierForID:specID];
    SHDWPaneLog(@"viewWillAppear reload %@ spec=%@", specID, specifier);
    if (specifier) {
      [self reloadSpecifier:specifier];
    }
  }
  SHDWPaneLog(@"viewWillAppear done");
}

- (void)viewDidAppear:(BOOL)animated {
  SHDWPaneLog(@"viewDidAppear");
  [super viewDidAppear:animated];
}

- (instancetype)init {
  SHDWPaneLog(@"init enter");
  if ((self = [super init])) {
    SHDWPaneLog(@"init super ok");
    prefs = [[ShadowSettings sharedInstance] userDefaults];
    SHDWPaneLog(@"init prefs=%@", prefs);
  }

  SHDWPaneLog(@"init done");
  return self;
}
@end
