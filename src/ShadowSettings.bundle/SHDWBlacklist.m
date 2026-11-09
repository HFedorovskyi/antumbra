#import "SHDWBlacklist.h"

#include <unistd.h>

static NSMutableDictionary<NSString *, NSNumber *> *gCache;
static NSLock *gLock;
static dispatch_queue_t gQueue;

static void SHDWBlacklistInit(void) {
  static dispatch_once_t once;
  dispatch_once(&once, ^{
    gCache = [NSMutableDictionary dictionary];
    gLock = [NSLock new];
    gQueue = dispatch_queue_create("com.jjolano.shadow.blacklist.ui",
                                   DISPATCH_QUEUE_SERIAL);
  });
}

static NSString *SHDWBlacklistDir(void) {
  NSString *dir = [NSHomeDirectory()
      stringByAppendingPathComponent:
          @"Library/Application Support/Shadow/blacklist-requests"];
  [[NSFileManager defaultManager] createDirectoryAtPath:dir
                            withIntermediateDirectories:YES
                                             attributes:nil
                                                  error:NULL];
  return dir;
}

// The daemon only accepts a request once its scan tick picks it up, so give it
// time for two ticks plus the write; a missing daemon just times out.
static NSDictionary *SHDWBlacklistSend(NSString *bundleID, NSString *action,
                                       NSTimeInterval timeout) {
  NSString *base = [SHDWBlacklistDir()
      stringByAppendingPathComponent:[NSString
                                         stringWithFormat:@"ui-%d-%@.plist",
                                                          getpid(),
                                                          [[NSUUID UUID]
                                                              UUIDString]]];
  NSDictionary *request = @{@"bid" : bundleID, @"action" : action};
  if (![request writeToFile:base atomically:YES]) {
    return nil;
  }

  NSString *resultPath = [base stringByAppendingString:@".result"];
  NSDictionary *parsed = nil;
  NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:timeout];
  while ([deadline timeIntervalSinceNow] > 0) {
    NSString *text = [NSString stringWithContentsOfFile:resultPath
                                               encoding:NSUTF8StringEncoding
                                                  error:NULL];
    if (text) {
      NSMutableDictionary *fields = [NSMutableDictionary dictionary];
      for (NSString *token in [text componentsSeparatedByString:@" "]) {
        NSRange eq = [token rangeOfString:@"="];
        if (eq.location != NSNotFound && eq.location + 1 < token.length) {
          // The result line ends with a newline, so the last value carries it.
          NSString *value = [[token substringFromIndex:eq.location + 1]
              stringByTrimmingCharactersInSet:
                  [NSCharacterSet whitespaceAndNewlineCharacterSet]];
          fields[[token substringToIndex:eq.location]] = value;
        }
      }
      parsed = fields;
      break;
    }
    usleep(150 * 1000);
  }
  [[NSFileManager defaultManager] removeItemAtPath:base error:NULL];
  [[NSFileManager defaultManager] removeItemAtPath:resultPath error:NULL];
  return parsed;
}

static void SHDWBlacklistStore(NSString *bundleID, BOOL blacklisted) {
  SHDWBlacklistInit();
  [gLock lock];
  gCache[bundleID] = @(blacklisted);
  [gLock unlock];
}

BOOL SHDWBlacklistCachedState(NSString *bundleID, BOOL *known) {
  SHDWBlacklistInit();
  [gLock lock];
  NSNumber *value = gCache[bundleID];
  [gLock unlock];
  if (known) {
    *known = value != nil;
  }
  return [value boolValue];
}

static void SHDWBlacklistRun(NSString *bundleID, NSString *action,
                             BOOL optimistic, BOOL applyOptimistic,
                             void (^completion)(BOOL, BOOL)) {
  SHDWBlacklistInit();
  if (applyOptimistic) {
    SHDWBlacklistStore(bundleID, optimistic);
  }
  dispatch_async(gQueue, ^{
    NSDictionary *result = SHDWBlacklistSend(bundleID, action, 5.0);
    BOOL ok = result && [result[@"rc"] isEqualToString:@"0"];
    BOOL blacklisted = optimistic;
    if (result[@"blacklisted"]) {
      blacklisted = [result[@"blacklisted"] isEqualToString:@"1"];
    }
    if (ok) {
      SHDWBlacklistStore(bundleID, blacklisted);
    }
    if (completion) {
      dispatch_async(dispatch_get_main_queue(), ^{
        completion(blacklisted, ok);
      });
    }
  });
}

void SHDWBlacklistRefresh(NSString *bundleID, void (^completion)(BOOL, BOOL)) {
  SHDWBlacklistRun(bundleID, @"status", NO, NO, completion);
}

void SHDWBlacklistSetState(NSString *bundleID, BOOL blacklisted,
                           void (^completion)(BOOL)) {
  SHDWBlacklistRun(bundleID, blacklisted ? @"add" : @"remove", blacklisted, YES,
                   ^(BOOL state, BOOL ok) {
                     if (!ok) {
                       // Nothing was applied; drop the optimistic value so the
                       // switch falls back to "not opted out" until a refresh.
                       SHDWBlacklistInit();
                       [gLock lock];
                       [gCache removeObjectForKey:bundleID];
                       [gLock unlock];
                     }
                     if (completion) {
                       completion(ok);
                     }
                   });
}
