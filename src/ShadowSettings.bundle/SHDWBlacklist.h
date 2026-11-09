#import <Foundation/Foundation.h>

// Root-side opt-out channel. Settings runs sandboxed and cannot read Dopamine's
// /var/jb/basebin/config.plist, so state travels as request plists written into
// Settings' own data container. The shdwbl daemon authorizes them because the
// container owner matches com.apple.Preferences, applies the change as root and
// writes a .result next to the request.

// Synchronous cache lookup; *known is NO until the first refresh completes.
BOOL SHDWBlacklistCachedState(NSString *bundleID, BOOL *known);

// Asynchronous; completion runs on the main queue.
void SHDWBlacklistRefresh(NSString *bundleID,
                          void (^completion)(BOOL blacklisted, BOOL ok));
void SHDWBlacklistSetState(NSString *bundleID, BOOL blacklisted,
                           void (^completion)(BOOL ok));
