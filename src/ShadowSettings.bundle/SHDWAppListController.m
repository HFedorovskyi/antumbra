#import "SHDWAppListController.h"
#import "SHDWBlacklist.h"
#import "SHDWPrefs.h"

#import <AltList/LSApplicationProxy+AltList.h>
#import <Shadow/Settings.h>

@implementation SHDWAppListController {
  NSUserDefaults *prefs;

  // Kept across reloads so the single Follow Global toggle can animate the
  // per-app rows in/out (native insert/delete) instead of a full table
  // reload; once removed, specifierForID: can no longer find them to put
  // them back. The Neutralization group header rides with its row, since an
  // empty group would otherwise linger under Follow Global.
  PSSpecifier *enabledSpecifier;
  PSSpecifier *aggressiveSpecifier;
  PSSpecifier *aggressiveGroupSpecifier;
  PSSpecifier *optOutSpecifier;
}

static PSSpecifier *SHDWSpecifierWithID(NSArray *specifiers,
                                        NSString *identifier) {
  for (PSSpecifier *specifier in specifiers) {
    if ([[specifier identifier] isEqualToString:identifier]) {
      return specifier;
    }
  }
  return nil;
}

- (NSArray *)specifiers {
  if (!_specifiers) {
    NSArray *loaded = [self loadSpecifiersFromPlistName:@"App" target:self];
    SHDWLocalizeSpecifiers(loaded, [NSBundle bundleForClass:[self class]],
                           @"App");
    self.title = SHDWLocalizedString(@"APP_SETTINGS", @"App");

    enabledSpecifier = SHDWSpecifierWithID(loaded, @"App_Enabled");
    aggressiveSpecifier = SHDWSpecifierWithID(loaded, @"Detector_Aggressive");
    aggressiveGroupSpecifier =
        SHDWSpecifierWithID(loaded, @"AppAggressiveGroup");
    optOutSpecifier = SHDWSpecifierWithID(loaded, @"App_OptOutInjection");

    LSApplicationProxy *proxy =
        [LSApplicationProxy applicationProxyForIdentifier:[self applicationID]];
    if (proxy.atl_fastDisplayName.length > 0) {
      self.title = proxy.atl_fastDisplayName;
    }

    // One Follow Global toggle governs the whole app: following global =
    // no per-app overrides, so both the activation and aggressive rows are
    // hidden — together with the now-empty Neutralization group header —
    // until the user opts out. Hiding happens on the array being built, not
    // through removeSpecifier:, which would drive a table update from inside
    // the getter while PSListController is already reloading.
    NSMutableArray *visible = [loaded mutableCopy];
    if ([self followGlobal]) {
      if (enabledSpecifier) {
        [visible removeObject:enabledSpecifier];
      }
      if (aggressiveSpecifier) {
        [visible removeObject:aggressiveSpecifier];
      }
      if (aggressiveGroupSpecifier) {
        [visible removeObject:aggressiveGroupSpecifier];
      }
    }
    _specifiers = visible;

    [self updateSettingsGroupFooter];
  }
  return _specifiers;
}

- (void)viewWillAppear:(BOOL)animated {
  [super viewWillAppear:animated];
  // The opt-out lives in Dopamine's config, which only the root daemon can
  // read; ask it on every appearance and reconcile the switch when it answers.
  NSString *appID = [self applicationID];
  __weak __typeof(self) weakSelf = self;
  PSSpecifier *specifier = optOutSpecifier;
  SHDWBlacklistRefresh(appID, ^(BOOL blacklisted, BOOL ok) {
    (void)blacklisted;
    __typeof(self) strongSelf = weakSelf;
    if (ok && strongSelf) {
      [strongSelf reloadSpecifier:specifier];
    }
  });
}

- (BOOL)followGlobal {
  return SHDWAppFollowsGlobal(prefs, [self applicationID]);
}

// Group footer explains the current state; the group is found by id (its
// display name is localized) and the footer is written already-localized.
- (void)updateSettingsGroupFooter {
  PSSpecifier *settingsGroup = [self specifierForID:@"AppSettingsGroup"];
  if (!settingsGroup) {
    return;
  }

  NSString *footer = [self followGlobal]
                         ? SHDWLocalizedString(@"APP_USES_GLOBAL", @"App")
                         : SHDWLocalizedString(@"APP_SETTINGS_DESC", @"App");
  [settingsGroup setProperty:footer forKey:@"footerText"];
  [self reloadSpecifier:settingsGroup];
}

- (id)readPreferenceValue:(PSSpecifier *)specifier {
  NSString *key = [specifier identifier];

  if ([key isEqualToString:@"App_FollowGlobal"]) {
    return @([self followGlobal]);
  }

  if ([key isEqualToString:@"App_Enabled"]) {
    return @(SHDWAppEnabled(prefs, [self applicationID]));
  }

  if ([key isEqualToString:@"Detector_Aggressive"]) {
    return @(SHDWAppAggressive(prefs, [self applicationID]));
  }

  if ([key isEqualToString:@"App_OptOutInjection"]) {
    BOOL known = NO;
    BOOL blacklisted = SHDWBlacklistCachedState([self applicationID], &known);
    return @(known && blacklisted);
  }

  return nil;
}

- (void)setPreferenceValue:(id)value forSpecifier:(PSSpecifier *)specifier {
  SHDWToggleHaptic();
  NSString *key = [specifier identifier];

  if ([key isEqualToString:@"App_FollowGlobal"]) {
    // A single Follow Global toggle governs the whole app. Following global
    // clears both per-app overrides and hides both explicit rows; opting
    // out seeds each from its current effective state and reveals both.
    // Rows animate in/out like Settings' own conditional rows instead of a
    // full table reload.
    if ([value boolValue]) {
      SHDWClearAppOverrides(prefs, [self applicationID]);
      // Rows are absent while the app already follows global settings; a
      // second removal would leave PSListController's row bookkeeping stale.
      if ([_specifiers containsObject:aggressiveSpecifier]) {
        [self removeSpecifier:aggressiveSpecifier animated:YES];
      }
      if ([_specifiers containsObject:enabledSpecifier]) {
        [self removeSpecifier:enabledSpecifier animated:YES];
      }
      if ([_specifiers containsObject:aggressiveGroupSpecifier]) {
        [self removeSpecifier:aggressiveGroupSpecifier animated:YES];
      }
    } else {
      SHDWWriteAppEnabled(prefs, [self applicationID],
                          SHDWAppEnabled(prefs, [self applicationID]));
      SHDWWriteAppAggressive(prefs, [self applicationID],
                             SHDWAppAggressive(prefs, [self applicationID]));
      // App_Enabled sits under the activation group (after the toggle);
      // Detector_Aggressive sits under its own group header.
      [self insertSpecifier:enabledSpecifier
             afterSpecifier:[self specifierForID:@"App_FollowGlobal"]
                   animated:YES];
      [self insertSpecifier:aggressiveGroupSpecifier
             afterSpecifier:enabledSpecifier
                   animated:YES];
      [self insertSpecifier:aggressiveSpecifier
             afterSpecifier:aggressiveGroupSpecifier
                   animated:YES];
      [self reloadSpecifier:enabledSpecifier];
      [self reloadSpecifier:aggressiveSpecifier];
    }
    [self updateSettingsGroupFooter];
    return;
  }

  if ([key isEqualToString:@"App_Enabled"]) {
    SHDWWriteAppEnabled(prefs, [self applicationID], [value boolValue]);
    return;
  }

  if ([key isEqualToString:@"Detector_Aggressive"]) {
    SHDWWriteAppAggressive(prefs, [self applicationID], [value boolValue]);
    return;
  }

  if ([key isEqualToString:@"App_OptOutInjection"]) {
    __weak __typeof(self) weakSelf = self;
    PSSpecifier *specifier = optOutSpecifier;
    SHDWBlacklistSetState([self applicationID], [value boolValue], ^(BOOL ok) {
      __typeof(self) strongSelf = weakSelf;
      if (strongSelf) {
        [strongSelf reloadSpecifier:specifier];
      }
    });
  }
}

- (void)resetAppSettings:(id)sender {
  NSString *title = SHDWLocalizedString(@"RESET_APP", @"App");
  UIAlertController *alert = [UIAlertController
      alertControllerWithTitle:title
                       message:SHDWLocalizedString(@"RESET_APP_CONFIRM", @"App")
                preferredStyle:UIAlertControllerStyleAlert];
  [alert addAction:[UIAlertAction actionWithTitle:SHDWLocalizedString(
                                                      @"RESET_CANCEL", @"App")
                                            style:UIAlertActionStyleCancel
                                          handler:nil]];
  [alert
      addAction:
          [UIAlertAction
              actionWithTitle:title
                        style:UIAlertActionStyleDestructive
                      handler:^(UIAlertAction *action) {
                        BOOL saved = SHDWResetApp(prefs, [self applicationID]);
                        [self reloadSpecifiers];
                        if (saved) {
                          SHDWToggleHaptic();
                        } else {
                          UIAlertController *failure = [UIAlertController
                              alertControllerWithTitle:SHDWLocalizedString(
                                                           @"RESET_APP_FAILED",
                                                           @"App")
                                               message:
                                                   SHDWLocalizedString(
                                                       @"RESET_APP_FAILED_DESC",
                                                       @"App")
                                        preferredStyle:
                                            UIAlertControllerStyleAlert];
                          [failure
                              addAction:
                                  [UIAlertAction
                                      actionWithTitle:SHDWLocalizedString(
                                                          @"RESET_OK", @"App")
                                                style:UIAlertActionStyleDefault
                                              handler:nil]];
                          [self
                              dismissViewControllerAnimated:YES
                                                 completion:^{
                                                   [self
                                                       presentViewController:
                                                           failure
                                                                    animated:YES
                                                                  completion:
                                                                      nil];
                                                 }];
                        }
                      }]];
  [self presentViewController:alert animated:YES completion:nil];
}

- (instancetype)init {
  if ((self = [super init])) {
    prefs = [[ShadowSettings sharedInstance] userDefaults];
  }
  return self;
}
@end
