#define SHADOW_RULESETS "/Library/Shadow/Rulesets"
#define SHADOW_DB_PLIST SHADOW_RULESETS "/dpkgInstalled.plist"
#define SHADOW_PREFS_PLIST                                                     \
  "/var/mobile/Library/Preferences/me.jjolano.shadow.plist"

#import <Foundation/Foundation.h>

// Darwin raises NSInvalidArgumentException from -[NSString
// fileSystemRepresentation] for @"". The spelling comes from the host app, so
// an empty (or nil) path must degrade to "" instead of aborting the process.
static inline const char *SHDWFSPath(NSString *path) {
  if (path == nil || path.length == 0) {
    return "";
  }
  return [path fileSystemRepresentation];
}

#ifndef DEBUG
#define NSLog(...) (void)0
#endif

#ifndef kCFCoreFoundationVersionNumber_iOS_14_1
#define kCFCoreFoundationVersionNumber_iOS_14_1 1751.108
#endif

#ifndef kCFCoreFoundationVersionNumber_iOS_11_0
#define kCFCoreFoundationVersionNumber_iOS_11_0 1443.00
#endif
