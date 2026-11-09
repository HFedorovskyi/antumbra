// shdwbl — root-side ProcessBlacklist applier and product shell for Antumbra.
//
// The tweak runs as mobile inside the app sandbox and cannot edit Dopamine's
// /var/jb/basebin/config.plist, so an opt-out is expressed as a request file
// in a mobile-writable directory. This daemon applies it as root and writes a
// .result next to the request. launchdhook re-reads config.plist when its
// mtime moves forward, so the rename below is what makes the change take
// effect on the next spawn.
//
// Requests are deleted after processing; the .result file stays for the
// writer to poll. A request names either an executable ("exe") or a bundle id
// ("bid", resolved against the installed app bundles).
//
// Trust: the root request directory is trusted. A request found inside an app
// container is honoured only for that container's own bundle or from the
// Settings app (the user-facing toggle).
//
// Gap 6: ProcessBlacklist matches the executable path exactly, and an app
// update replaces its /private/var/containers/Bundle/Application/<UUID>
// directory, so a path-keyed opt-out silently stops applying to the app it
// was written for. The daemon therefore remembers every opt-out it wrote by
// bundle id (blacklist-own.plist) and reconciles the paths whenever the
// installed bundle set changes: an updated app's entry is moved to the new
// path, a dead duplicate is pruned, and a stale entry whose app still exists
// under another UUID is repaired. Entries the daemon never wrote are left
// alone unless a live entry for the same .app already covers the app.
//
// License: the payload refuses to load unless the prefs carry
// License_State=active with an epoch in the future. Only root writes those
// keys; they come from a signed license file verified here (ECDSA P-256 over
// a canonical string). The stub re-checks the expiry itself, so a dead daemon
// cannot extend a lapsed license.
//
// Modes: -d (daemon), add <exe>, remove <exe>, addb <bid>, removeb <bid>,
//        status <bid>, list, own, reconcile, ping, doctor [--json],
//        debugged status|on|off, update <deb> [--apply], rollback [id],
//        snapshots, prep apply|status|revert <bid> | prep apply-all,
//        license status|verify <file>|install <file>|remove

#include <CommonCrypto/CommonDigest.h>
#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#import <Security/Security.h>
// libproc has no iOS SDK header; the symbols live in libSystem and are used by
// the jailbreak tooling on this device.
extern int proc_listallpids(void *buffer, int buffersize);
extern int proc_pidpath(int pid, void *buffer, uint32_t buffersize);
#define SHDW_PIDPATH_MAX 4096
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/wait.h>
#include <unistd.h>

static NSString *const kBuild = @"g5shell-11";
static NSString *const kConfig = @"/var/jb/basebin/config.plist";
static NSString *const kLaunchdLog =
    @"/var/log/com.apple.xpc.launchd/launchd.log";
static NSString *const kReqDir =
    @"/var/mobile/Library/Application Support/Shadow/blacklist-requests";
static NSString *const kOwnFile =
    @"/var/mobile/Library/Application Support/Shadow/blacklist-own.plist";
static NSString *const kStateRoot =
    @"/var/mobile/Library/Application Support/Shadow";
static NSString *const kManifest =
    @"/var/mobile/Library/Application Support/Shadow/payload.plist";
static NSString *const kPrefs =
    @"/var/mobile/Library/Preferences/me.jjolano.shadow.plist";
static NSString *const kPackageId = @"me.fedorovskyi.antumbra";
static NSString *const kChoicyPrefs =
    @"/var/mobile/Library/Preferences/com.opa334.choicyprefs.plist";
static NSString *const kJbStateDir = @"/var/jb/var/lib/shadow";
static NSString *const kLicenseFile = @"/var/jb/var/lib/shadow/license.plist";
static NSString *const kStealthState = @"/var/jb/var/lib/shadow/stealth.plist";
static NSString *const kLicenseState =
    @"/var/jb/var/lib/shadow/license.state.plist";
static NSString *const kDaemonLog = @"/var/jb/var/log/shdw-blacklistd.log";
static NSString *const kWatcherLog = @"/var/jb/var/log/shadow-watcher.log";
static NSString *const kAppBundleRoot =
    @"/private/var/containers/Bundle/Application";
static NSString *const kDataRoot =
    @"/private/var/mobile/Containers/Data/Application";
static NSString *const kSettingsBid = @"com.apple.Preferences";
static NSString *const kJailbreakLib = @"/var/jb/basebin/libjailbreak.dylib";
static const char *const kMarkDebuggedKey = "markAppsAsDebugged";
static NSString *const kRequestSuffix =
    @"/Library/Application Support/Shadow/blacklist-requests/";
static const uid_t kMobile = 501;

static NSString *const kPayloadCore = @"/var/jb/usr/lib/ShadowCore.dylib";
static NSString *const kPayloadStub =
    @"/var/jb/Library/MobileSubstrate/DynamicLibraries/Shadow.dylib";
static NSString *const kPayloadFilter =
    @"/var/jb/Library/MobileSubstrate/DynamicLibraries/Shadow.plist";
static NSString *const kPayloadFramework =
    @"/var/jb/Library/Frameworks/Shadow.framework/Shadow";
static NSString *const kPayloadSettings =
    @"/var/jb/Library/PreferenceBundles/ShadowSettings.bundle/ShadowSettings";
static NSString *const kPayloadShdw = @"/var/jb/usr/local/bin/shdw";
static NSString *const kPayloadShdwbl = @"/var/jb/usr/local/bin/shdwbl";

// Public half of the offline issuer key (X9.63 uncompressed point, base64).
// Rotating the key means shipping a new binary.
static NSString *const kLicensePubB64 =
    @"BA2II3wFdRXqwiGphVbB6x6UTOYwc9x6E5EFy0bDGzncEPtdvZcJEkCe/P7sEc4VgQljQTgasDnyr5bwC8+ZgTY=";
static NSString *const kLicensePrefix = @"shadow-license-v1";

#pragma mark - Small helpers

static NSString *shdwbl_md5(NSString *path) {
  NSData *data = [NSData dataWithContentsOfFile:path
                                        options:NSDataReadingMappedIfSafe
                                          error:NULL];
  if (!data) {
    return nil;
  }
  unsigned char digest[CC_MD5_DIGEST_LENGTH];
  CC_MD5(data.bytes, (CC_LONG)data.length, digest);
  NSMutableString *hex =
      [NSMutableString stringWithCapacity:CC_MD5_DIGEST_LENGTH * 2];
  for (int i = 0; i < CC_MD5_DIGEST_LENGTH; i++) {
    [hex appendFormat:@"%02x", digest[i]];
  }
  return hex;
}

static BOOL shdwbl_is_macho(NSString *path) {
  int fd = open(path.fileSystemRepresentation, O_RDONLY);
  if (fd < 0) {
    return NO;
  }
  uint32_t magic = 0;
  ssize_t n = read(fd, &magic, sizeof magic);
  close(fd);
  if (n != (ssize_t)sizeof magic) {
    return NO;
  }
  return magic == 0xfeedfacf || magic == 0xcffaedfe || magic == 0xcafebabe ||
         magic == 0xbebafeca || magic == 0xfeedface || magic == 0xcefaedfe;
}

// Drain a pipe without trusting the child to stay under a page.
static NSData *shdwbl_read_all(int fd) {
  NSMutableData *out = [NSMutableData data];
  char buf[4096];
  ssize_t n;
  while ((n = read(fd, buf, sizeof buf)) > 0) {
    [out appendBytes:buf length:(NSUInteger)n];
    if (out.length > 1024 * 1024) {
      break;
    }
  }
  return out;
}

// No popen: this install has no /bin/sh (rootless Dopamine keeps every tool
// under /var/jb), so popen always ended in a 127. posix_spawn with an argv
// vector and no shell is also the only form that cannot be quoting-injected.
// NULL envp gives the child an empty environment on Darwin, which dpkg rejects
// with "PATH is not set"; a fixed PATH also keeps the spawn independent of
// whatever environment launchd handed this daemon. Every tool this binary runs
// lives under /var/jb on a rootless install.
static char *shdwbl_child_env[] = {
    "PATH=/var/jb/usr/bin:/var/jb/bin:/usr/bin:/bin:/usr/sbin:/sbin",
    "HOME=/var/mobile",
    NULL,
};

static NSString *shdwbl_spawn(NSArray<NSString *> *args, BOOL mergeStderr,
                              int *status) {
  if (!args.count) {
    if (status)
      *status = -1;
    return @"";
  }
  int fds[2];
  if (pipe(fds) != 0) {
    if (status)
      *status = -1;
    return @"";
  }
  posix_spawn_file_actions_t actions;
  posix_spawn_file_actions_init(&actions);
  posix_spawn_file_actions_adddup2(&actions, fds[1], STDOUT_FILENO);
  if (mergeStderr) {
    posix_spawn_file_actions_adddup2(&actions, fds[1], STDERR_FILENO);
  }
  posix_spawn_file_actions_addclose(&actions, fds[0]);
  posix_spawn_file_actions_addclose(&actions, fds[1]);

  NSUInteger count = args.count;
  char **argv = calloc(count + 1, sizeof(char *));
  for (NSUInteger i = 0; i < count; i++) {
    argv[i] = strdup(args[i].fileSystemRepresentation);
  }
  pid_t pid = 0;
  int rc = posix_spawn(&pid, argv[0], &actions, NULL, argv, shdwbl_child_env);
  posix_spawn_file_actions_destroy(&actions);
  for (NSUInteger i = 0; i < count; i++) {
    free(argv[i]);
  }
  free(argv);
  close(fds[1]);

  NSString *out = nil;
  if (rc != 0) {
    close(fds[0]);
    if (status)
      *status = -1;
    return @"";
  }
  out = [[NSString alloc] initWithData:shdwbl_read_all(fds[0])
                              encoding:NSUTF8StringEncoding];
  close(fds[0]);
  int waitStatus = 0;
  while (waitpid(pid, &waitStatus, 0) < 0 && errno == EINTR) {
  }
  if (status) {
    *status = WIFEXITED(waitStatus) ? WEXITSTATUS(waitStatus) : -1;
  }
  return
      [out
          stringByTrimmingCharactersInSet:[NSCharacterSet
                                              whitespaceAndNewlineCharacterSet]]
          ?: @"";
}

static BOOL shdwbl_write_plist(NSString *path, NSDictionary *dict, uid_t uid,
                               gid_t gid, mode_t mode) {
  NSPropertyListFormat format = NSPropertyListXMLFormat_v1_0;
  NSData *existing = [NSData dataWithContentsOfFile:path];
  if (existing) {
    [NSPropertyListSerialization propertyListWithData:existing
                                              options:0
                                               format:&format
                                                error:NULL];
  }
  NSData *data = [NSPropertyListSerialization dataWithPropertyList:dict
                                                            format:format
                                                           options:0
                                                             error:NULL];
  if (!data) {
    return NO;
  }
  NSString *tmp = [path stringByAppendingFormat:@".tmp.%d", getpid()];
  if (![data writeToFile:tmp atomically:NO]) {
    return NO;
  }
  chown(tmp.fileSystemRepresentation, uid, gid);
  chmod(tmp.fileSystemRepresentation, mode);
  if (rename(tmp.fileSystemRepresentation, path.fileSystemRepresentation) !=
      0) {
    unlink(tmp.fileSystemRepresentation);
    return NO;
  }
  return YES;
}

static NSString *shdwbl_device_uuid(void) {
  static NSString *uuid;
  static BOOL resolved;
  if (!resolved) {
    resolved = YES;
    io_service_t service = IOServiceGetMatchingService(
        MACH_PORT_NULL, IOServiceMatching("IOPlatformExpertDevice"));
    if (service) {
      CFTypeRef value = IORegistryEntryCreateCFProperty(
          service, CFSTR("IOPlatformUUID"), kCFAllocatorDefault, 0);
      IOObjectRelease(service);
      if (value) {
        if (CFGetTypeID(value) == CFStringGetTypeID()) {
          char buf[128] = {0};
          if (CFStringGetCString(value, buf, sizeof buf,
                                 kCFStringEncodingUTF8)) {
            uuid = @(buf);
          }
        }
        CFRelease(value);
      }
    }
  }
  return uuid;
}

static NSString *shdwbl_utc_string(NSDate *date) {
  static NSDateFormatter *formatter;
  if (!formatter) {
    formatter = [NSDateFormatter new];
    formatter.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
    formatter.timeZone = [NSTimeZone timeZoneWithAbbreviation:@"UTC"];
    formatter.dateFormat = @"yyyy-MM-dd'T'HH:mm:ss'Z'";
  }
  return date ? [formatter stringFromDate:date] : nil;
}

static NSDate *shdwbl_utc_date(NSString *text) {
  static NSDateFormatter *formatter;
  if (!formatter) {
    formatter = [NSDateFormatter new];
    formatter.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
    formatter.timeZone = [NSTimeZone timeZoneWithAbbreviation:@"UTC"];
    formatter.dateFormat = @"yyyy-MM-dd'T'HH:mm:ss'Z'";
  }
  if (![text isKindOfClass:[NSString class]] || !text.length) {
    return nil;
  }
  return [formatter dateFromString:text];
}

static pid_t shdwbl_find_pid(NSString *executablePath) {
  int count = proc_listallpids(NULL, 0);
  if (count <= 0) {
    return -1;
  }
  pid_t *pids = calloc((size_t)count + 16, sizeof(pid_t));
  if (!pids) {
    return -1;
  }
  count =
      proc_listallpids(pids, (int)((size_t)count + 16) * (int)sizeof(pid_t));
  pid_t found = -1;
  char path[SHDW_PIDPATH_MAX];
  for (int i = 0; i < count; i++) {
    if (proc_pidpath(pids[i], path, sizeof path) <= 0) {
      continue;
    }
    if (strcmp(path, executablePath.fileSystemRepresentation) == 0) {
      found = pids[i];
      break;
    }
  }
  free(pids);
  return found;
}

#pragma mark - Paths and bundle ids

static BOOL shdwbl_valid_exe(NSString *exe) {
  if (![exe isKindOfClass:[NSString class]] || exe.length < 16) {
    return NO;
  }
  if (![exe hasPrefix:@"/"]) {
    return NO;
  }
  if ([exe containsString:@".."]) {
    return NO;
  }
  if (![exe containsString:@"/Bundle/Application/"]) {
    return NO;
  }
  if (![exe containsString:@".app/"]) {
    return NO;
  }
  return YES;
}

static BOOL shdwbl_valid_bid(NSString *bid) {
  if (![bid isKindOfClass:[NSString class]] || bid.length < 3 ||
      bid.length > 155) {
    return NO;
  }
  if ([bid containsString:@"/"] || [bid containsString:@".."]) {
    return NO;
  }
  return YES;
}

// launchdhook matches the executable path exactly; dyld reports the
// /private/var spelling for some spawns, so both forms go in.
static NSArray<NSString *> *shdwbl_variants(NSString *exe) {
  if ([exe hasPrefix:@"/private/var/containers/"]) {
    return @[ exe, [exe substringFromIndex:8] ];
  }
  if ([exe hasPrefix:@"/var/containers/"]) {
    return @[ exe, [@"/private" stringByAppendingString:exe] ];
  }
  return @[ exe ];
}

static NSString *shdwbl_app_path(NSString *exe) {
  NSRange r = [exe rangeOfString:@".app/"];
  if (r.location == NSNotFound) {
    return nil;
  }
  return [exe substringToIndex:r.location + 4];
}

static NSString *shdwbl_app_name(NSString *exe) {
  return [shdwbl_app_path(exe) lastPathComponent];
}

static NSString *shdwbl_app_bid(NSString *exe) {
  NSString *app = shdwbl_app_path(exe);
  if (!app) {
    return nil;
  }
  NSDictionary *info =
      [NSDictionary dictionaryWithContentsOfFile:
                        [app stringByAppendingPathComponent:@"Info.plist"]];
  return [info[@"CFBundleIdentifier"] isKindOfClass:[NSString class]]
             ? info[@"CFBundleIdentifier"]
             : nil;
}

static NSString *shdwbl_exe_for_bid(NSString *bid) {
  NSFileManager *fm = [NSFileManager defaultManager];
  for (NSString *uuid in [fm contentsOfDirectoryAtPath:kAppBundleRoot
                                                 error:NULL]) {
    NSString *dir = [kAppBundleRoot stringByAppendingPathComponent:uuid];
    for (NSString *name in [fm contentsOfDirectoryAtPath:dir error:NULL]) {
      if (![name hasSuffix:@".app"]) {
        continue;
      }
      NSString *app = [dir stringByAppendingPathComponent:name];
      NSDictionary *info =
          [NSDictionary dictionaryWithContentsOfFile:
                            [app stringByAppendingPathComponent:@"Info.plist"]];
      if (![info[@"CFBundleIdentifier"] isEqual:bid]) {
        continue;
      }
      NSString *exe = info[@"CFBundleExecutable"];
      if (![exe isKindOfClass:[NSString class]] || !exe.length) {
        return nil;
      }
      return [app stringByAppendingPathComponent:exe];
    }
  }
  return nil;
}

// One pass over the bundle root instead of one per bundle id: the reconcile
// runs on every install/update, so the directory scan must stay cheap.
static NSDictionary<NSString *, NSString *> *shdwbl_app_map(void) {
  NSMutableDictionary *map = [NSMutableDictionary dictionary];
  NSFileManager *fm = [NSFileManager defaultManager];
  for (NSString *uuid in [fm contentsOfDirectoryAtPath:kAppBundleRoot
                                                 error:NULL]) {
    NSString *dir = [kAppBundleRoot stringByAppendingPathComponent:uuid];
    for (NSString *name in [fm contentsOfDirectoryAtPath:dir error:NULL]) {
      if (![name hasSuffix:@".app"]) {
        continue;
      }
      NSString *app = [dir stringByAppendingPathComponent:name];
      NSDictionary *info =
          [NSDictionary dictionaryWithContentsOfFile:
                            [app stringByAppendingPathComponent:@"Info.plist"]];
      NSString *bid = info[@"CFBundleIdentifier"];
      NSString *exe = info[@"CFBundleExecutable"];
      if (![bid isKindOfClass:[NSString class]] || !bid.length ||
          ![exe isKindOfClass:[NSString class]] || !exe.length) {
        continue;
      }
      map[bid] = [app stringByAppendingPathComponent:exe];
    }
  }
  return map;
}

static NSDictionary *shdwbl_load_config(void) {
  NSData *raw = [NSData dataWithContentsOfFile:kConfig];
  if (!raw) {
    return nil;
  }
  id parsed = [NSPropertyListSerialization
      propertyListWithData:raw
                   options:NSPropertyListMutableContainersAndLeaves
                    format:NULL
                     error:NULL];
  return [parsed isKindOfClass:[NSDictionary class]] ? parsed : nil;
}

static BOOL shdwbl_is_blacklisted(NSString *exe) {
  NSDictionary *cfg = shdwbl_load_config();
  NSArray *list = cfg[@"ProcessBlacklist"];
  if (![list isKindOfClass:[NSArray class]]) {
    return NO;
  }
  for (NSString *v in shdwbl_variants(exe)) {
    if ([list containsObject:v]) {
      return YES;
    }
  }
  return NO;
}

// The guard files its opt-out request on the launch *after* the short run and
// names that run's pid. A clean exit(0) or a force-quit (SIGKILL) says nothing
// about injection: only a crash signal or a non-zero exit justifies handing the
// app to the systemhook blacklist, because that list is what silently keeps the
// stub out of a fixed app later.
static BOOL shdwbl_launchd_exit_is_crash(NSString *bid, NSInteger pid) {
  if (pid <= 0 || !bid.length) {
    return NO;
  }
  NSData *raw = [NSData dataWithContentsOfFile:kLaunchdLog
                                       options:NSDataReadingMappedIfSafe
                                         error:NULL];
  if (!raw) {
    return NO;
  }
  NSString *log = [[NSString alloc] initWithData:raw
                                        encoding:NSUTF8StringEncoding];
  if (!log) {
    return NO;
  }
  NSString *jobNeedle = [bid stringByAppendingString:@"["];
  NSString *pidNeedle = [NSString stringWithFormat:@" [%ld])", (long)pid];
  __block NSString *line = nil;
  [log enumerateLinesUsingBlock:^(NSString *entry, BOOL *stop) {
    if ([entry rangeOfString:jobNeedle].location != NSNotFound &&
        [entry rangeOfString:pidNeedle].location != NSNotFound &&
        [entry rangeOfString:@"exited due to"].location != NSNotFound) {
      line = entry; // pid reuse: the last match is the run the guard saw
    }
  }];
  NSRange r = [line rangeOfString:@"exited due to "];
  if (r.location == NSNotFound) {
    return NO;
  }
  NSString *reason = [line substringFromIndex:NSMaxRange(r)];
  for (NSString *sig in @[
         @"SIGSEGV", @"SIGABRT", @"SIGBUS", @"SIGILL", @"SIGTRAP", @"SIGFPE",
         @"SIGSYS"
       ]) {
    if ([reason hasPrefix:sig]) {
      return YES;
    }
  }
  if ([reason hasPrefix:@"exit("]) {
    NSRange close = [reason rangeOfString:@")"];
    if (close.location != NSNotFound) {
      NSString *code =
          [reason substringWithRange:NSMakeRange(5, close.location - 5)];
      return ![code isEqualToString:@"0"];
    }
  }
  return NO;
}

static BOOL shdwbl_save(NSDictionary *cfg) {
  NSData *data = [NSPropertyListSerialization
      dataWithPropertyList:cfg
                    format:NSPropertyListXMLFormat_v1_0
                   options:0
                     error:NULL];
  if (!data) {
    return NO;
  }
  NSString *tmp = [kConfig stringByAppendingFormat:@".tmp.%d", getpid()];
  if (![data writeToFile:tmp atomically:NO]) {
    return NO;
  }
  chown(tmp.fileSystemRepresentation, 0, 0);
  chmod(tmp.fileSystemRepresentation, 0644);
  if (rename(tmp.fileSystemRepresentation, kConfig.fileSystemRepresentation) !=
      0) {
    unlink(tmp.fileSystemRepresentation);
    return NO;
  }
  return YES;
}

// blacklist-own.plist: { bids = { <bid> = { exe = <path>, owned = [<variants>]
// } } }
static NSMutableDictionary *shdwbl_load_own(void) {
  NSData *raw = [NSData dataWithContentsOfFile:kOwnFile];
  id parsed = nil;
  if (raw) {
    parsed = [NSPropertyListSerialization
        propertyListWithData:raw
                     options:NSPropertyListMutableContainersAndLeaves
                      format:NULL
                       error:NULL];
  }
  NSMutableDictionary *own = [parsed isKindOfClass:[NSMutableDictionary class]]
                                 ? parsed
                                 : [NSMutableDictionary dictionary];
  if (![own[@"bids"] isKindOfClass:[NSMutableDictionary class]]) {
    own[@"bids"] = [NSMutableDictionary dictionary];
  }
  return own;
}

static BOOL shdwbl_save_own(NSDictionary *own) {
  NSData *data = [NSPropertyListSerialization
      dataWithPropertyList:own
                    format:NSPropertyListXMLFormat_v1_0
                   options:0
                     error:NULL];
  if (!data) {
    return NO;
  }
  NSString *tmp = [kOwnFile stringByAppendingFormat:@".tmp.%d", getpid()];
  if (![data writeToFile:tmp atomically:NO]) {
    return NO;
  }
  chown(tmp.fileSystemRepresentation, 0, 0);
  chmod(tmp.fileSystemRepresentation, 0644);
  if (rename(tmp.fileSystemRepresentation, kOwnFile.fileSystemRepresentation) !=
      0) {
    unlink(tmp.fileSystemRepresentation);
    return NO;
  }
  return YES;
}

static void shdwbl_own_record(NSString *bid, NSString *exe, BOOL add) {
  if (!shdwbl_valid_bid(bid)) {
    return;
  }
  NSMutableDictionary *own = shdwbl_load_own();
  NSMutableDictionary *bids = own[@"bids"];
  if (add) {
    bids[bid] = [@{@"exe" : exe, @"owned" : shdwbl_variants(exe)} mutableCopy];
  } else if (bids[bid]) {
    [bids removeObjectForKey:bid];
  } else {
    return;
  }
  shdwbl_save_own(own);
}

static int shdwbl_apply(NSString *exe, BOOL add, NSString *bid) {
  if (!shdwbl_valid_exe(exe)) {
    fprintf(stderr, "reject exe=%s\n", exe.UTF8String ?: "(null)");
    return 2;
  }

  NSFileManager *fm = [NSFileManager defaultManager];
  NSString *bak = [kConfig stringByAppendingString:@".shdwbak"];
  if (![fm fileExistsAtPath:bak] && [fm fileExistsAtPath:kConfig]) {
    [fm copyItemAtPath:kConfig toPath:bak error:NULL];
  }

  NSDictionary *cfg = shdwbl_load_config();
  NSMutableDictionary *mutable =
      cfg ? [cfg mutableCopy] : [NSMutableDictionary dictionary];
  NSArray *list = mutable[@"ProcessBlacklist"];
  NSMutableArray *bl = [list isKindOfClass:[NSArray class]]
                           ? [list mutableCopy]
                           : [NSMutableArray array];

  BOOL changed = NO;
  for (NSString *v in shdwbl_variants(exe)) {
    if (add) {
      if (![bl containsObject:v]) {
        [bl addObject:v];
        changed = YES;
      }
    } else {
      if ([bl containsObject:v]) {
        [bl removeObject:v];
        changed = YES;
      }
    }
  }
  if (!changed) {
    // Rewriting config.plist on every launch would only churn launchdhook's
    // mtime check, so an already-satisfied request is a no-op. Ownership is
    // still recorded so a later update can be followed.
    shdwbl_own_record(bid ?: shdwbl_app_bid(exe), exe, add);
    return 0;
  }
  mutable[@"ProcessBlacklist"] = bl;
  if (!shdwbl_save(mutable)) {
    return 3;
  }
  shdwbl_own_record(bid ?: shdwbl_app_bid(exe), exe, add);
  fprintf(stderr, "%s %s entries=%lu\n", add ? "add" : "remove", exe.UTF8String,
          (unsigned long)bl.count);
  return 0;
}

// Keep the list aligned with what is installed. Three moves, in order:
//   1. adopt live entries we did not write (they become bid-tracked too),
//   2. prune a dead path when a live entry for the same .app already covers it,
//   3. repair a dead path whose .app still exists under exactly one installed
//      bundle, and move every owned entry to its current executable.
// Anything ambiguous is left untouched and logged.
static NSInteger shdwbl_reconcile(void) {
  NSDictionary *cfg = shdwbl_load_config();
  if (!cfg) {
    return 0;
  }
  NSArray *list = cfg[@"ProcessBlacklist"];
  NSMutableArray *bl = [list isKindOfClass:[NSArray class]]
                           ? [list mutableCopy]
                           : [NSMutableArray array];
  NSMutableDictionary *own = shdwbl_load_own();
  NSMutableDictionary *bids = own[@"bids"];
  NSDictionary *appmap = shdwbl_app_map();
  NSFileManager *fm = [NSFileManager defaultManager];
  BOOL cfgChanged = NO;
  BOOL ownChanged = NO;

  // 1. Adopt live entries by their bundle id.
  for (NSString *v in [bl copy]) {
    if (![fm fileExistsAtPath:v]) {
      continue;
    }
    NSString *bid = shdwbl_app_bid(v);
    if (!bid) {
      continue;
    }
    NSMutableDictionary *rec = bids[bid];
    if (!rec) {
      rec = [NSMutableDictionary dictionary];
      bids[bid] = rec;
      ownChanged = YES;
    }
    NSArray *variants = shdwbl_variants(v);
    NSArray *owned =
        [rec[@"owned"] isKindOfClass:[NSArray class]] ? rec[@"owned"] : @[];
    NSMutableArray *merged = [owned mutableCopy];
    for (NSString *x in variants) {
      if (![merged containsObject:x]) {
        [merged addObject:x];
      }
    }
    if (![merged isEqualToArray:owned]) {
      rec[@"owned"] = merged;
      ownChanged = YES;
    }
    if (![rec[@"exe"] isEqual:v]) {
      rec[@"exe"] = v;
      ownChanged = YES;
    }
  }

  // 2. Dead duplicate next to a live entry for the same app.
  NSMutableSet *liveNames = [NSMutableSet set];
  for (NSString *v in bl) {
    if ([fm fileExistsAtPath:v]) {
      NSString *name = shdwbl_app_name(v);
      if (name) {
        [liveNames addObject:name];
      }
    }
  }
  for (NSString *v in [bl copy]) {
    if ([fm fileExistsAtPath:v]) {
      continue;
    }
    NSString *name = shdwbl_app_name(v);
    if (name && [liveNames containsObject:name]) {
      [bl removeObject:v];
      cfgChanged = YES;
      fprintf(stderr, "reconcile prune %s\n", v.UTF8String);
    }
  }

  // 3. Stale entry, app still installed under another bundle directory.
  for (NSString *v in [bl copy]) {
    if ([fm fileExistsAtPath:v]) {
      continue;
    }
    NSString *name = shdwbl_app_name(v);
    if (!name) {
      continue;
    }
    NSString *matchBid = nil;
    NSString *matchExe = nil;
    NSInteger matches = 0;
    for (NSString *bid in appmap) {
      NSString *exe = appmap[bid];
      if ([shdwbl_app_name(exe) isEqualToString:name]) {
        matchBid = bid;
        matchExe = exe;
        matches++;
      }
    }
    if (matches != 1) {
      // Reconcile repeats on a timer; log an unresolvable entry once per
      // daemon lifetime instead of every pass.
      static NSMutableSet *logged;
      if (!logged) {
        logged = [NSMutableSet set];
      }
      if (![logged containsObject:v]) {
        [logged addObject:v];
        fprintf(stderr, "reconcile leave %s (installed matches=%ld)\n",
                v.UTF8String, (long)matches);
      }
      continue;
    }
    [bl removeObject:v];
    for (NSString *x in shdwbl_variants(matchExe)) {
      if (![bl containsObject:x]) {
        [bl addObject:x];
      }
    }
    bids[matchBid] = [@{@"exe" : matchExe, @"owned" : shdwbl_variants(matchExe)}
        mutableCopy];
    cfgChanged = YES;
    ownChanged = YES;
    fprintf(stderr, "reconcile repair %s -> %s bid=%s\n", v.UTF8String,
            matchExe.UTF8String, matchBid.UTF8String);
  }

  // 4. Follow every owned bundle id to its current executable.
  for (NSString *bid in [bids copy]) {
    NSMutableDictionary *rec = bids[bid];
    NSArray *owned =
        [rec[@"owned"] isKindOfClass:[NSArray class]] ? rec[@"owned"] : @[];
    NSString *exe = appmap[bid];
    if (exe) {
      NSArray *variants = shdwbl_variants(exe);
      for (NSString *v in owned) {
        if (![variants containsObject:v] && [bl containsObject:v]) {
          [bl removeObject:v];
          cfgChanged = YES;
          fprintf(stderr, "reconcile move-out %s bid=%s\n", v.UTF8String,
                  bid.UTF8String);
        }
      }
      for (NSString *v in variants) {
        if (![bl containsObject:v]) {
          [bl addObject:v];
          cfgChanged = YES;
          fprintf(stderr, "reconcile move-in %s bid=%s\n", v.UTF8String,
                  bid.UTF8String);
        }
      }
      if (![rec[@"owned"] isEqualToArray:variants]) {
        rec[@"owned"] = variants;
        ownChanged = YES;
      }
      if (![rec[@"exe"] isEqual:exe]) {
        rec[@"exe"] = exe;
        ownChanged = YES;
      }
    } else {
      // Not installed right now: drop paths that no longer exist, keep the
      // bundle id so a reinstall is followed too.
      NSMutableArray *kept = [NSMutableArray array];
      for (NSString *v in owned) {
        if ([fm fileExistsAtPath:v]) {
          [kept addObject:v];
        } else if ([bl containsObject:v]) {
          [bl removeObject:v];
          cfgChanged = YES;
          fprintf(stderr, "reconcile drop %s bid=%s (not installed)\n",
                  v.UTF8String, bid.UTF8String);
        }
      }
      if (![kept isEqualToArray:owned]) {
        rec[@"owned"] = kept;
        ownChanged = YES;
      }
    }
  }

  if (cfgChanged) {
    NSMutableDictionary *mutable = [cfg mutableCopy];
    mutable[@"ProcessBlacklist"] = bl;
    if (!shdwbl_save(mutable)) {
      fprintf(stderr, "reconcile save failed\n");
      return 0;
    }
    fprintf(stderr, "reconcile applied entries=%lu\n", (unsigned long)bl.count);
  }
  if (ownChanged) {
    shdwbl_save_own(own);
  }
  return (NSInteger)bl.count;
}

#pragma mark - License

typedef NS_ENUM(NSInteger, SHDWLicenseState) {
  SHDWLicenseMissing = 0,
  SHDWLicenseActive,
  SHDWLicenseExpired,
  SHDWLicenseInvalid,
  SHDWLicenseForeign,
};

// Canonical bytes must match tools/shdwlic.py exactly.
static NSString *shdwbl_license_canonical(NSDictionary *doc) {
  id format = doc[@"Format"];
  id holder = doc[@"Holder"];
  id issued = doc[@"Issued"];
  id expires = doc[@"Expires"];
  id devices = doc[@"Devices"];
  id features = doc[@"Features"];
  return [NSString
      stringWithFormat:@"%@\n%ld\n%@\n%@\n%@\n%@\n%@\n", kLicensePrefix,
                       [format isKindOfClass:[NSNumber class]]
                           ? (long)[format integerValue]
                           : 0L,
                       [holder isKindOfClass:[NSString class]] ? holder : @"",
                       [issued isKindOfClass:[NSString class]] ? issued : @"",
                       [expires isKindOfClass:[NSString class]] ? expires : @"",
                       [devices isKindOfClass:[NSArray class]]
                           ? [devices componentsJoinedByString:@","]
                           : @"",
                       [features isKindOfClass:[NSArray class]]
                           ? [features componentsJoinedByString:@","]
                           : @""];
}

static NSData *shdwbl_b64_decode(NSString *text) {
  return [[NSData alloc]
      initWithBase64EncodedString:text
                          options:NSDataBase64DecodingIgnoreUnknownCharacters];
}

static BOOL shdwbl_ecdsa_verify(NSData *message, NSData *signature) {
  NSData *pub = shdwbl_b64_decode(kLicensePubB64);
  if (!pub || !message.length || !signature.length) {
    return NO;
  }
  NSDictionary *attrs = @{
    (__bridge id)kSecAttrKeyType : (__bridge id)kSecAttrKeyTypeECSECPrimeRandom,
    (__bridge id)kSecAttrKeyClass : (__bridge id)kSecAttrKeyClassPublic,
    (__bridge id)kSecAttrKeySizeInBits : @256,
  };
  CFErrorRef error = NULL;
  SecKeyRef key = SecKeyCreateWithData((__bridge CFDataRef)pub,
                                       (__bridge CFDictionaryRef)attrs, &error);
  if (!key) {
    if (error) {
      CFRelease(error);
    }
    return NO;
  }
  BOOL ok = SecKeyVerifySignature(
      key, kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
      (__bridge CFDataRef)message, (__bridge CFDataRef)signature, &error);
  if (!ok && error) {
    CFRelease(error);
  }
  CFRelease(key);
  return ok;
}

static NSString *shdwbl_license_state_name(SHDWLicenseState state) {
  switch (state) {
  case SHDWLicenseActive:
    return @"active";
  case SHDWLicenseExpired:
    return @"expired";
  case SHDWLicenseInvalid:
    return @"invalid";
  case SHDWLicenseForeign:
    return @"foreign";
  default:
    return @"missing";
  }
}

static SHDWLicenseState
shdwbl_license_eval_doc(NSDictionary *doc, NSString **reason, NSDate **expiry) {
  if (reason) {
    *reason = @"";
  }
  if (expiry) {
    *expiry = nil;
  }
  if (![doc isKindOfClass:[NSDictionary class]]) {
    if (reason)
      *reason = @"license is not a dictionary";
    return SHDWLicenseInvalid;
  }
  id format = doc[@"Format"];
  if (![format isKindOfClass:[NSNumber class]] || [format integerValue] != 1) {
    if (reason)
      *reason = @"unsupported Format";
    return SHDWLicenseInvalid;
  }
  for (NSString *key in @[ @"Holder", @"Issued", @"Expires" ]) {
    id value = doc[key];
    if (![value isKindOfClass:[NSString class]] ||
        ![(NSString *)value length]) {
      if (reason)
        *reason = [NSString stringWithFormat:@"missing %@", key];
      return SHDWLicenseInvalid;
    }
  }
  if (![doc[@"Devices"] isKindOfClass:[NSArray class]]) {
    if (reason)
      *reason = @"missing Devices";
    return SHDWLicenseInvalid;
  }
  NSData *signature = doc[@"Sig"];
  if (![signature isKindOfClass:[NSData class]]) {
    if (reason)
      *reason = @"missing Sig";
    return SHDWLicenseInvalid;
  }
  NSData *message =
      [shdwbl_license_canonical(doc) dataUsingEncoding:NSUTF8StringEncoding];
  if (!shdwbl_ecdsa_verify(message, signature)) {
    if (reason)
      *reason = @"signature rejected";
    return SHDWLicenseInvalid;
  }
  NSDate *issued = shdwbl_utc_date(doc[@"Issued"]);
  NSDate *expires = shdwbl_utc_date(doc[@"Expires"]);
  if (!issued || !expires) {
    if (reason)
      *reason = @"unparsable Issued/Expires";
    return SHDWLicenseInvalid;
  }
  if (expiry) {
    *expiry = expires;
  }
  if ([issued timeIntervalSinceNow] > 86400) {
    if (reason)
      *reason = @"issued in the future";
    return SHDWLicenseInvalid;
  }
  NSString *device = shdwbl_device_uuid();
  BOOL bound = NO;
  for (id entry in doc[@"Devices"]) {
    if ([entry isKindOfClass:[NSString class]] &&
        ([entry isEqualToString:@"*"] ||
         (device && [entry isEqualToString:device]))) {
      bound = YES;
      break;
    }
  }
  if (!bound) {
    if (reason) {
      *reason = [NSString stringWithFormat:@"not bound to this device (%@)",
                                           device ?: @"unknown"];
    }
    return SHDWLicenseForeign;
  }
  if ([expires timeIntervalSinceNow] <= 0) {
    if (reason) {
      *reason = [NSString stringWithFormat:@"expired %@", doc[@"Expires"]];
    }
    return SHDWLicenseExpired;
  }
  if (reason) {
    *reason = @"";
  }
  return SHDWLicenseActive;
}

static NSDictionary *shdwbl_license_values(SHDWLicenseState state,
                                           NSDictionary *doc,
                                           NSString *reason) {
  NSDate *expiry = shdwbl_utc_date(doc[@"Expires"]);
  return @{
    @"License_State" : shdwbl_license_state_name(state),
    @"License_Reason" : reason ?: @"",
    @"License_Holder" : [doc[@"Holder"] isKindOfClass:[NSString class]]
        ? doc[@"Holder"]
        : @"",
    @"License_Expires" : [doc[@"Expires"] isKindOfClass:[NSString class]]
        ? doc[@"Expires"]
        : @"",
    @"License_ExpiresEpoch" : @(expiry ? [expiry timeIntervalSince1970] : 0),
    @"License_Device" : shdwbl_device_uuid() ?: @"",
  };
}

// Mirrors the verdict into the prefs file the stub reads. Only writes when a
// value actually moved: cfprefsd may rewrite the file at any time, so the
// daemon re-asserts on every pass instead of trying to win a race.
static void shdwbl_prefs_merge(NSDictionary *values) {
  NSDictionary *current = [NSDictionary dictionaryWithContentsOfFile:kPrefs];
  NSMutableDictionary *prefs =
      current ? [current mutableCopy] : [NSMutableDictionary dictionary];
  BOOL changed = NO;
  for (NSString *key in values) {
    if (![prefs[key] isEqual:values[key]]) {
      prefs[key] = values[key];
      changed = YES;
    }
  }
  if (changed) {
    shdwbl_write_plist(kPrefs, prefs, 0, 0, 0644);
  }
}

static SHDWLicenseState shdwbl_license_sync(void) {
  NSDictionary *doc = [NSDictionary dictionaryWithContentsOfFile:kLicenseFile];
  NSString *reason = nil;
  NSDate *expiry = nil;
  SHDWLicenseState state =
      doc ? shdwbl_license_eval_doc(doc, &reason, &expiry) : SHDWLicenseMissing;
  if (state == SHDWLicenseMissing) {
    reason = @"no license installed";
  }

  NSMutableDictionary *record =
      [shdwbl_license_values(state, doc, reason) mutableCopy];
  record[@"Checked"] = shdwbl_utc_string([NSDate date]);
  record[@"CheckedEpoch"] = @([[NSDate date] timeIntervalSince1970]);
  record[@"Device"] = shdwbl_device_uuid() ?: @"unknown";
  record[@"Build"] = kBuild;
  [[NSFileManager defaultManager] createDirectoryAtPath:kJbStateDir
                            withIntermediateDirectories:YES
                                             attributes:nil
                                                  error:NULL];
  chown(kJbStateDir.fileSystemRepresentation, 0, 0);
  chmod(kJbStateDir.fileSystemRepresentation, 0755);
  shdwbl_write_plist(kLicenseState, record, 0, 0, 0600);
  shdwbl_prefs_merge(shdwbl_license_values(state, doc, reason));
  return state;
}

static int shdwbl_license_install(NSString *path) {
  NSDictionary *doc = [NSDictionary dictionaryWithContentsOfFile:path];
  if (![doc isKindOfClass:[NSDictionary class]]) {
    fprintf(stderr, "not a plist dictionary: %s\n", path.UTF8String);
    return 2;
  }
  NSString *reason = nil;
  NSDate *expiry = nil;
  SHDWLicenseState state = shdwbl_license_eval_doc(doc, &reason, &expiry);
  if (state != SHDWLicenseActive) {
    fprintf(stderr, "rejected (%s): %s\n",
            shdwbl_license_state_name(state).UTF8String, reason.UTF8String);
    shdwbl_license_sync();
    return 4;
  }
  [[NSFileManager defaultManager] createDirectoryAtPath:kJbStateDir
                            withIntermediateDirectories:YES
                                             attributes:nil
                                                  error:NULL];
  chown(kJbStateDir.fileSystemRepresentation, 0, 0);
  chmod(kJbStateDir.fileSystemRepresentation, 0755);
  if (!shdwbl_write_plist(kLicenseFile, doc, 0, 0, 0600)) {
    fprintf(stderr, "cannot write %s\n", kLicenseFile.UTF8String);
    return 3;
  }
  shdwbl_license_sync();
  printf("rc=0 state=active holder=%s expires=%s device=%s\n",
         [doc[@"Holder"] UTF8String] ?: "-",
         [doc[@"Expires"] UTF8String] ?: "-",
         shdwbl_device_uuid().UTF8String ?: "-");
  return 0;
}

static int shdwbl_license_status(BOOL json) {
  NSDictionary *doc = [NSDictionary dictionaryWithContentsOfFile:kLicenseFile];
  NSString *reason = nil;
  NSDate *expiry = nil;
  SHDWLicenseState state =
      doc ? shdwbl_license_eval_doc(doc, &reason, &expiry) : SHDWLicenseMissing;
  if (state == SHDWLicenseMissing) {
    reason = @"no license installed";
  }
  double days = expiry ? [expiry timeIntervalSinceNow] / 86400.0 : 0;
  if (json) {
    NSDictionary *out = @{
      @"state" : shdwbl_license_state_name(state),
      @"reason" : reason ?: @"",
      @"holder" : [doc[@"Holder"] isKindOfClass:[NSString class]]
          ? doc[@"Holder"]
          : @"",
      @"expires" : [doc[@"Expires"] isKindOfClass:[NSString class]]
          ? doc[@"Expires"]
          : @"",
      @"days_left" : @(days),
      @"device" : shdwbl_device_uuid() ?: @"",
    };
    NSData *data = [NSJSONSerialization dataWithJSONObject:out
                                                   options:0
                                                     error:NULL];
    fwrite(data.bytes, 1, data.length, stdout);
    printf("\n");
  } else {
    printf(
        "rc=%d state=%s holder=%s expires=%s days_left=%.1f device=%s reason=%s\n",
        state == SHDWLicenseActive ? 0 : 4,
        shdwbl_license_state_name(state).UTF8String,
        [doc[@"Holder"] isKindOfClass:[NSString class]]
            ? [doc[@"Holder"] UTF8String]
            : "-",
        expiry ? shdwbl_utc_string(expiry).UTF8String : "-", days,
        shdwbl_device_uuid().UTF8String ?: "-", reason.UTF8String ?: "");
  }
  return state == SHDWLicenseActive ? 0 : 4;
}

#pragma mark - Daemon ping

static NSString *shdwbl_ping_line(NSTimeInterval timeout) {
  NSFileManager *fm = [NSFileManager defaultManager];
  [fm createDirectoryAtPath:kReqDir
      withIntermediateDirectories:YES
                       attributes:nil
                            error:NULL];
  NSString *name =
      [NSString stringWithFormat:@"ping-%d-%.0f.plist", getpid(),
                                 [[NSDate date] timeIntervalSince1970]];
  NSString *path = [kReqDir stringByAppendingPathComponent:name];
  [@{@"action" : @"ping"} writeToFile:path atomically:YES];
  NSString *resultPath = [path stringByAppendingString:@".result"];
  NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:timeout];
  while ([[NSDate date] compare:deadline] == NSOrderedAscending) {
    NSString *result = [NSString stringWithContentsOfFile:resultPath
                                                 encoding:NSUTF8StringEncoding
                                                    error:NULL];
    if (result.length) {
      [fm removeItemAtPath:resultPath error:NULL];
      return [result stringByTrimmingCharactersInSet:
                         [NSCharacterSet whitespaceAndNewlineCharacterSet]];
    }
    usleep(200000);
  }
  [fm removeItemAtPath:path error:NULL];
  return nil;
}

static int shdwbl_ping_cli(void) {
  NSString *line = shdwbl_ping_line(8);
  if (!line) {
    fprintf(stderr, "rc=5 no answer from blacklistd\n");
    return 5;
  }
  printf("%s\n", line.UTF8String);
  return [line containsString:[NSString stringWithFormat:@"build=%@", kBuild]]
             ? 0
             : 6;
}

#pragma mark - Doctor

#define SHDW_OK 0
#define SHDW_WARN 1
#define SHDW_ERR 2

static void shdwbl_check_prep(NSMutableArray *checks);

static void shdwbl_check(NSMutableArray *checks, NSString *name,
                         NSInteger level, NSString *detail) {
  [checks addObject:@{
    @"name" : name,
    @"level" : @(level),
    @"detail" : detail ?: @""
  }];
}

static NSString *shdwbl_file_state(NSString *path) {
  NSDictionary *attrs =
      [[NSFileManager defaultManager] attributesOfItemAtPath:path error:NULL];
  if (!attrs) {
    return @"missing";
  }
  return [NSString
      stringWithFormat:@"uid=%d mode=0%o size=%lld",
                       (int)[attrs[NSFileOwnerAccountID] unsignedIntValue],
                       (unsigned)[attrs[NSFilePosixPermissions]
                           unsignedShortValue],
                       (long long)[attrs[NSFileSize] longLongValue]];
}

static void shdwbl_check_config(NSMutableArray *checks) {
  NSDictionary *cfg = shdwbl_load_config();
  if (!cfg) {
    shdwbl_check(checks, @"config", SHDW_ERR,
                 @"config.plist missing or not a dict");
    return;
  }
  id list = cfg[@"ProcessBlacklist"];
  if (![list isKindOfClass:[NSArray class]]) {
    shdwbl_check(checks, @"config", SHDW_WARN, @"no ProcessBlacklist array");
    return;
  }
  NSMutableSet *seen = [NSMutableSet set];
  NSMutableSet *dups = [NSMutableSet set];
  NSMutableArray *dead = [NSMutableArray array];
  NSMutableArray *unpaired = [NSMutableArray array];
  NSMutableArray *bad = [NSMutableArray array];
  for (id entry in list) {
    if (![entry isKindOfClass:[NSString class]]) {
      [bad addObject:[entry description]];
      continue;
    }
    if ([seen containsObject:entry]) {
      [dups addObject:entry];
    }
    [seen addObject:entry];
    if (![[NSFileManager defaultManager] fileExistsAtPath:entry]) {
      [dead addObject:entry];
      continue;
    }
    for (NSString *variant in shdwbl_variants(entry)) {
      if (![list containsObject:variant]) {
        [unpaired addObject:entry];
        break;
      }
    }
  }
  NSMutableArray *notes = [NSMutableArray array];
  [notes
      addObject:[NSString
                    stringWithFormat:@"%lu entries",
                                     (unsigned long)[(NSArray *)list count]]];
  if (dups.count) {
    [notes
        addObject:[NSString
                      stringWithFormat:@"%lu duplicate(s): %@",
                                       (unsigned long)dups.count,
                                       [[dups.allObjects
                                           subarrayWithRange:NSMakeRange(
                                                                 0,
                                                                 MIN(dups.count,
                                                                     2))]
                                           componentsJoinedByString:@" "]]];
  }
  if (bad.count) {
    [notes addObject:[NSString stringWithFormat:@"%lu non-string entry(ies)",
                                                (unsigned long)bad.count]];
  }
  if (dead.count) {
    [notes
        addObject:[NSString
                      stringWithFormat:@"%lu dead path(s): %@",
                                       (unsigned long)dead.count,
                                       [[dead
                                           subarrayWithRange:NSMakeRange(
                                                                 0,
                                                                 MIN(dead.count,
                                                                     2))]
                                           componentsJoinedByString:@" "]]];
  }
  if (unpaired.count) {
    [notes addObject:[NSString stringWithFormat:
                                   @"%lu entry(ies) without the /private twin",
                                   (unsigned long)unpaired.count]];
  }
  NSInteger level = (bad.count || dead.count) ? SHDW_WARN : SHDW_OK;
  shdwbl_check(checks, @"config", level,
               [notes componentsJoinedByString:@", "]);
}

static void shdwbl_check_ownership(NSMutableArray *checks) {
  NSMutableDictionary *own = shdwbl_load_own();
  NSDictionary *bids = own[@"bids"];
  NSDictionary *appmap = shdwbl_app_map();
  NSDictionary *cfg = shdwbl_load_config();
  NSArray *list = [cfg[@"ProcessBlacklist"] isKindOfClass:[NSArray class]]
                      ? cfg[@"ProcessBlacklist"]
                      : @[];
  NSMutableArray *notes = [NSMutableArray array];
  NSInteger level = SHDW_OK;
  NSInteger stale = 0;
  NSInteger missing = 0;
  for (NSString *bid in bids) {
    NSDictionary *rec = bids[bid];
    NSString *installed = appmap[bid];
    if (!installed) {
      [notes addObject:[NSString stringWithFormat:@"%@ not installed", bid]];
      continue;
    }
    if (![rec[@"exe"] isEqual:installed]) {
      stale++;
      [notes addObject:[NSString stringWithFormat:@"%@ path stale", bid]];
    }
    NSArray *owned =
        [rec[@"owned"] isKindOfClass:[NSArray class]] ? rec[@"owned"] : @[];
    for (NSString *variant in owned) {
      if (![list containsObject:variant]) {
        missing++;
      }
    }
  }
  if (stale) {
    level = SHDW_WARN;
  }
  if (missing) {
    level = SHDW_WARN;
    [notes
        addObject:[NSString
                      stringWithFormat:@"%ld owned path(s) absent from config",
                                       (long)missing]];
  }
  [notes insertObject:[NSString stringWithFormat:@"%lu tracked bid(s)",
                                                 (unsigned long)bids.count]
              atIndex:0];
  shdwbl_check(checks, @"ownership", level,
               [notes componentsJoinedByString:@", "]);
}

static NSString *shdwbl_dpkg_version(void);

static void shdwbl_check_payload(NSMutableArray *checks) {
  NSArray *paths = @[
    kPayloadCore, kPayloadStub, kPayloadFilter, kPayloadFramework,
    kPayloadSettings, kPayloadShdw, kPayloadShdwbl
  ];
  NSDictionary *manifest =
      [NSDictionary dictionaryWithContentsOfFile:kManifest];
  NSDictionary *expected =
      [manifest[@"Files"] isKindOfClass:[NSDictionary class]]
          ? manifest[@"Files"]
          : nil;
  NSString *manifestVersion =
      [manifest[@"Version"] isKindOfClass:[NSString class]]
          ? manifest[@"Version"]
          : nil;
  NSString *installedVersion = shdwbl_dpkg_version();
  // A dpkg/Sileo install swaps the payload without touching the manifest, so
  // a version difference means "updated outside shdwbl", not corruption.
  BOOL replacedByDpkg = manifestVersion.length && installedVersion.length &&
                        ![manifestVersion isEqual:installedVersion];
  NSMutableArray *notes = [NSMutableArray array];
  NSInteger level = SHDW_OK;
  for (NSString *path in paths) {
    NSString *name = [path lastPathComponent];
    if (![[NSFileManager defaultManager] fileExistsAtPath:path]) {
      [notes addObject:[NSString stringWithFormat:@"%@ missing", name]];
      level = SHDW_ERR;
      continue;
    }
    BOOL isBinary = ![path hasSuffix:@".plist"];
    if (isBinary && !shdwbl_is_macho(path)) {
      [notes addObject:[NSString stringWithFormat:@"%@ not Mach-O", name]];
      level = SHDW_ERR;
    }
    NSString *md5 = shdwbl_md5(path);
    NSString *want = expected[path];
    if ([want isKindOfClass:[NSString class]] && ![want isEqual:md5]) {
      [notes addObject:[NSString stringWithFormat:@"%@ md5 %@ != payload %@",
                                                  name, md5 ?: @"?", want]];
      if (replacedByDpkg) {
        if (level == SHDW_OK) {
          level = SHDW_WARN;
        }
      } else {
        level = SHDW_ERR;
      }
    }
  }
  if (!manifest) {
    [notes addObject:@"no payload manifest (update never run here)"];
    if (level == SHDW_OK) {
      level = SHDW_WARN;
    }
  } else if (manifestVersion) {
    [notes
        addObject:replacedByDpkg
                      ? [NSString
                            stringWithFormat:@"manifest version %@, dpkg %@",
                                             manifestVersion, installedVersion]
                      : [NSString stringWithFormat:@"manifest version %@",
                                                   manifestVersion]];
  }
  shdwbl_check(checks, @"payload", level,
               [notes componentsJoinedByString:@", "]);
}

static NSString *shdwbl_dpkg_version(void) {
  int status = 0;
  NSString *version = shdwbl_spawn(
      @[ @"/var/jb/usr/bin/dpkg-query", @"-W", @"-f=${Version}", kPackageId ],
      NO, &status);
  return status == 0 && version.length ? version : nil;
}

static void shdwbl_check_version(NSMutableArray *checks) {
  NSString *version = shdwbl_dpkg_version();
  if (!version.length) {
    shdwbl_check(checks, @"dpkg", SHDW_WARN,
                 @"package not in the dpkg database");
    return;
  }
  NSDictionary *manifest =
      [NSDictionary dictionaryWithContentsOfFile:kManifest];
  NSString *manifestVersion =
      [manifest[@"Version"] isKindOfClass:[NSString class]]
          ? manifest[@"Version"]
          : nil;
  NSString *detail =
      [NSString stringWithFormat:@"dpkg %@, build %@", version, kBuild];
  NSInteger level = SHDW_OK;
  if (manifestVersion && ![manifestVersion isEqual:version]) {
    level = SHDW_WARN;
    detail = [detail stringByAppendingFormat:@", payload %@ (db not updated)",
                                             manifestVersion];
  }
  shdwbl_check(checks, @"dpkg", level, detail);
}

static void shdwbl_check_daemon(NSMutableArray *checks) {
  NSString *line = shdwbl_ping_line(5);
  if (!line) {
    shdwbl_check(checks, @"daemon", SHDW_ERR,
                 @"blacklistd did not answer a ping");
    return;
  }
  BOOL sameBuild =
      [line containsString:[NSString stringWithFormat:@"build=%@", kBuild]];
  shdwbl_check(
      checks, @"daemon", sameBuild ? SHDW_OK : SHDW_WARN,
      sameBuild
          ? line
          : [NSString stringWithFormat:@"%@ (running an older binary)", line]);
}

static void shdwbl_check_watcher(NSMutableArray *checks) {
  pid_t pid = shdwbl_find_pid(kPayloadShdw);
  if (pid > 0) {
    shdwbl_check(checks, @"watcher", SHDW_OK,
                 [NSString stringWithFormat:@"shdw pid %d", pid]);
  } else {
    shdwbl_check(checks, @"watcher", SHDW_WARN,
                 @"shdw watcher not running (ruleset regeneration only)");
  }
}

static void shdwbl_check_prefs(NSMutableArray *checks) {
  NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:kPrefs];
  if (!prefs) {
    shdwbl_check(checks, @"prefs", SHDW_ERR,
                 @"prefs plist missing or unreadable");
    return;
  }
  NSString *state = shdwbl_file_state(kPrefs);
  NSDictionary *cfg = shdwbl_load_config();
  NSArray *list = [cfg[@"ProcessBlacklist"] isKindOfClass:[NSArray class]]
                      ? cfg[@"ProcessBlacklist"]
                      : @[];
  id global = prefs[@"Global_Enabled"];
  id disabled = prefs[@"Global_DisabledApps"];
  NSMutableArray *notes = [NSMutableArray array];
  [notes addObject:[NSString
                       stringWithFormat:@"global=%@",
                                        global ? ([global boolValue] ? @"on"
                                                                     : @"off")
                                               : @"default-on"]];
  NSInteger level = SHDW_OK;
  if (![state hasPrefix:@"uid=0 "]) {
    level = SHDW_WARN;
  }
  if ([disabled isKindOfClass:[NSArray class]]) {
    [notes
        addObject:[NSString stringWithFormat:@"prefs-excluded=%lu",
                                             (unsigned long)[disabled count]]];
    NSMutableArray *unlisted = [NSMutableArray array];
    for (id bid in disabled) {
      if (![bid isKindOfClass:[NSString class]]) {
        continue;
      }
      NSString *exe = shdwbl_exe_for_bid(bid);
      BOOL covered = NO;
      for (NSString *variant in exe ? shdwbl_variants(exe) : @[]) {
        if ([list containsObject:variant]) {
          covered = YES;
          break;
        }
      }
      if (!covered) {
        [unlisted addObject:bid];
      }
    }
    if (unlisted.count) {
      [notes
          addObject:[NSString
                        stringWithFormat:
                            @"%lu excluded app(s) not in "
                            @"ProcessBlacklist (systemhook still inserted): %@",
                            (unsigned long)unlisted.count,
                            [[unlisted
                                subarrayWithRange:NSMakeRange(
                                                      0,
                                                      MIN(unlisted.count, 3))]
                                componentsJoinedByString:@" "]]];
      level = SHDW_WARN;
    }
  }
  [notes addObject:state];
  shdwbl_check(checks, @"prefs", level, [notes componentsJoinedByString:@", "]);
}

// An explicit per-app App_Enabled is user intent, but systemhook reads the path
// list before the stub runs: an app that is both forced on and blacklisted is
// silently left uninjected. That is the state a crash guard leaves behind after
// the crash it reacted to has been fixed.
static void shdwbl_check_intent(NSMutableArray *checks) {
  NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:kPrefs];
  NSDictionary *cfg = shdwbl_load_config();
  NSArray *list = [cfg[@"ProcessBlacklist"] isKindOfClass:[NSArray class]]
                      ? cfg[@"ProcessBlacklist"]
                      : @[];
  NSMutableArray *conflicts = [NSMutableArray array];
  for (NSString *bid in prefs) {
    id settings = prefs[bid];
    if (![settings isKindOfClass:[NSDictionary class]]) {
      continue;
    }
    id enabled = settings[@"App_Enabled"];
    if (![enabled respondsToSelector:@selector(boolValue)] ||
        ![enabled boolValue]) {
      continue;
    }
    NSString *exe = shdwbl_exe_for_bid(bid);
    for (NSString *variant in exe ? shdwbl_variants(exe) : @[]) {
      if ([list containsObject:variant]) {
        [conflicts addObject:bid];
        break;
      }
    }
  }
  if (conflicts.count) {
    shdwbl_check(
        checks, @"intent", SHDW_WARN,
        [NSString
            stringWithFormat:@"%lu forced-on app(s) blacklisted: %@",
                             (unsigned long)conflicts.count,
                             [[conflicts
                                 subarrayWithRange:NSMakeRange(
                                                       0,
                                                       MIN(conflicts.count, 3))]
                                 componentsJoinedByString:@" "]]);
  } else {
    shdwbl_check(checks, @"intent", SHDW_OK, @"forced-on apps not blacklisted");
  }
}

static void shdwbl_check_license(NSMutableArray *checks) {
  NSDictionary *doc = [NSDictionary dictionaryWithContentsOfFile:kLicenseFile];
  NSString *reason = nil;
  NSDate *expiry = nil;
  SHDWLicenseState state =
      doc ? shdwbl_license_eval_doc(doc, &reason, &expiry) : SHDWLicenseMissing;
  NSInteger level = state == SHDWLicenseActive ? SHDW_OK : SHDW_ERR;
  NSMutableArray *notes = [NSMutableArray array];
  if (doc[@"Holder"] || doc[@"Expires"]) {
    [notes
        addObject:[NSString stringWithFormat:@"%@ / %@", doc[@"Holder"] ?: @"?",
                                             doc[@"Expires"] ?: @"?"]];
  }
  if (state == SHDWLicenseActive) {
    [notes addObject:[NSString stringWithFormat:@"%.1f day(s) left",
                                                [expiry timeIntervalSinceNow] /
                                                    86400.0]];
  } else {
    [notes addObject:reason ?: @"not active"];
  }
  NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:kPrefs];
  NSString *mirrored = [prefs[@"License_State"] isKindOfClass:[NSString class]]
                           ? prefs[@"License_State"]
                           : @"absent";
  if (![mirrored isEqual:shdwbl_license_state_name(state)]) {
    [notes addObject:[NSString stringWithFormat:@"prefs say %@", mirrored]];
    if (level == SHDW_OK) {
      level = SHDW_WARN;
    }
  }
  shdwbl_check(
      checks, @"license", level,
      [NSString stringWithFormat:@"%@: %@", shdwbl_license_state_name(state),
                                 [notes componentsJoinedByString:@", "]]);
}

static void shdwbl_check_guard(NSMutableArray *checks) {
  NSFileManager *fm = [NSFileManager defaultManager];
  NSArray *uuids = [fm contentsOfDirectoryAtPath:kDataRoot error:NULL];
  NSMutableArray *blocked = [NSMutableArray array];
  NSMutableArray *struck = [NSMutableArray array];
  for (NSString *uuid in uuids) {
    NSString *guard = [[kDataRoot stringByAppendingPathComponent:uuid]
        stringByAppendingPathComponent:
            @"Library/Application Support/Shadow/shdw_guard.plist"];
    NSDictionary *state = [NSDictionary dictionaryWithContentsOfFile:guard];
    if (![state isKindOfClass:[NSDictionary class]]) {
      continue;
    }
    NSString *bid = [state[@"bundle"] isKindOfClass:[NSString class]]
                        ? state[@"bundle"]
                        : uuid;
    if ([state[@"disabled"] boolValue]) {
      [blocked addObject:bid];
    } else if ([state[@"strikes"] integerValue] > 0) {
      [struck addObject:bid];
    }
  }
  NSMutableArray *notes = [NSMutableArray array];
  [notes addObject:[NSString stringWithFormat:@"%lu blocked",
                                              (unsigned long)blocked.count]];
  if (blocked.count) {
    [notes addObject:[[blocked subarrayWithRange:NSMakeRange(
                                                     0, MIN(blocked.count, 3))]
                         componentsJoinedByString:@" "]];
  }
  if (struck.count) {
    [notes
        addObject:[NSString
                      stringWithFormat:
                          @"%lu with strikes: %@", (unsigned long)struck.count,
                          [[struck
                              subarrayWithRange:NSMakeRange(
                                                    0, MIN(struck.count, 3))]
                              componentsJoinedByString:@" "]]];
  }
  shdwbl_check(checks, @"guard",
               blocked.count || struck.count ? SHDW_WARN : SHDW_OK,
               [notes componentsJoinedByString:@", "]);
}

// Dopamine marks every process it injects with CS_DEBUGGED (and drops CS_HARD /
// CS_KILL) when its "markAppsAsDebugged" setting is on. Detector SDKs read that
// bit through csops and treat the app as debugged; Chase's zShield fails its
// first verdict on it. The setting is the only lever: the kernel does not let
// us clear the bit on a live process
// (jbclient_platform_set_process_debugged(pid, 0) reports success and leaves
// the flag in place).
static void *shdwbl_jbclient(void) {
  static void *handle = NULL;
  if (!handle) {
    handle = dlopen(kJailbreakLib.fileSystemRepresentation, RTLD_NOW);
    if (handle) {
      int (*init)(void) =
          (int (*)(void))dlsym(handle, "jbclient_initialize_primitives");
      if (init) {
        init();
      }
    }
  }
  return handle;
}

// -1 = not available (no libjailbreak / not Dopamine), otherwise the bool
// value.
static int shdwbl_debugged_get(void) {
  void *handle = shdwbl_jbclient();
  if (!handle) {
    return -1;
  }
  int (*getb)(const char *, int) =
      (int (*)(const char *, int))dlsym(handle, "jbclient_jbsettings_get_bool");
  if (!getb) {
    return -1;
  }
  int value = getb(kMarkDebuggedKey, 2);
  return value == 2 ? -1 : value;
}

static BOOL shdwbl_debugged_set(BOOL value) {
  void *handle = shdwbl_jbclient();
  if (!handle) {
    return NO;
  }
  int (*setb)(const char *, int) = (int (*)(const char *, int))dlsym(
      handle, "jbclient_platform_jbsettings_set_bool");
  if (!setb) {
    return NO;
  }
  return setb(kMarkDebuggedKey, value ? 1 : 0) == 0;
}

// Desired value of Dopamine's `markAppsAsDebugged`, persisted in stealth.plist.
// Default (no state file) is NO: injected apps must not carry CS_DEBUGGED.
static BOOL shdwbl_debugged_wanted(void) {
  NSDictionary *state =
      [NSDictionary dictionaryWithContentsOfFile:kStealthState];
  if (!state) {
    return NO;
  }
  id value = state[@"MarkAppsAsDebugged"];
  return value ? [value boolValue] : NO;
}

static void shdwbl_debugged_remember(BOOL on) {
  NSString *dir = [kStealthState stringByDeletingLastPathComponent];
  [[NSFileManager defaultManager] createDirectoryAtPath:dir
                            withIntermediateDirectories:YES
                                             attributes:nil
                                                  error:NULL];
  NSMutableDictionary *state =
      [[NSDictionary dictionaryWithContentsOfFile:kStealthState] mutableCopy];
  if (!state) {
    state = [NSMutableDictionary dictionary];
  }
  state[@"MarkAppsAsDebugged"] = @(on);
  if (![state writeToFile:kStealthState atomically:YES]) {
    fprintf(stderr, "debugged: cannot write %s\n", kStealthState.UTF8String);
  }
}

// jbsettings live in shared memory only, so a reboot restores Dopamine's
// default (marking on). Re-apply the desired value whenever it drifts.
static void shdwbl_debugged_enforce(void) {
  int current = shdwbl_debugged_get();
  if (current < 0) {
    return;
  }
  BOOL want = shdwbl_debugged_wanted();
  if (current == (want ? 1 : 0)) {
    return;
  }
  BOOL ok = shdwbl_debugged_set(want);
  fprintf(stderr, "debugged enforce %d -> %d rc=%d\n", current, want ? 1 : 0,
          ok ? 0 : 1);
}

static void shdwbl_check_debugged(NSMutableArray *checks) {
  int value = shdwbl_debugged_get();
  if (value == 0) {
    shdwbl_check(checks, @"debugged", SHDW_OK,
                 @"apps spawn without CS_DEBUGGED");
  } else if (value == 1) {
    shdwbl_check(checks, @"debugged", SHDW_WARN,
                 @"markAppsAsDebugged=1 (injected apps carry CS_DEBUGGED)");
  } else {
    shdwbl_check(checks, @"debugged", SHDW_OK, @"setting not available");
  }
}

static void shdwbl_check_environment(NSMutableArray *checks) {
  NSMutableArray *notes = [NSMutableArray array];
  NSInteger level = SHDW_OK;

  struct statvfs vfs;
  if (statvfs("/var/jb", &vfs) == 0) {
    unsigned long long freeBytes =
        (unsigned long long)vfs.f_bavail * (unsigned long long)vfs.f_frsize;
    [notes addObject:[NSString stringWithFormat:@"free=%llu MB",
                                                freeBytes / (1024 * 1024)]];
    if (freeBytes < 300ULL * 1024 * 1024) {
      level = SHDW_WARN;
    }
  }

  for (NSString *log in @[ kDaemonLog, kWatcherLog ]) {
    NSDictionary *attrs =
        [[NSFileManager defaultManager] attributesOfItemAtPath:log error:NULL];
    unsigned long long size = [attrs[NSFileSize] unsignedLongLongValue];
    if (size > 5ULL * 1024 * 1024) {
      level = SHDW_WARN;
      [notes addObject:[NSString stringWithFormat:@"%@ is %llu MB",
                                                  [log lastPathComponent],
                                                  size / (1024 * 1024)]];
    }
  }

  NSDictionary *choicy =
      [NSDictionary dictionaryWithContentsOfFile:kChoicyPrefs];
  if (choicy) {
    NSData *serialized = [NSPropertyListSerialization
        dataWithPropertyList:choicy
                      format:NSPropertyListXMLFormat_v1_0
                     options:0
                       error:NULL];
    NSString *text = [[NSString alloc] initWithData:serialized
                                           encoding:NSUTF8StringEncoding];
    if ([text containsString:@"me.jjolano.shadow"]) {
      level = SHDW_WARN;
      [notes addObject:@"Choicy mentions this tweak (check per-app injection)"];
    }
  }

  NSArray *pending =
      [[NSFileManager defaultManager] contentsOfDirectoryAtPath:kReqDir
                                                          error:NULL];
  NSInteger stale = 0;
  for (NSString *name in pending) {
    if (![name hasSuffix:@".plist"]) {
      continue;
    }
    NSString *path = [kReqDir stringByAppendingPathComponent:name];
    NSDictionary *attrs =
        [[NSFileManager defaultManager] attributesOfItemAtPath:path error:NULL];
    NSDate *modified = attrs[NSFileModificationDate];
    if (modified && [[NSDate date] timeIntervalSinceDate:modified] > 120) {
      stale++;
    }
  }
  if (stale) {
    level = SHDW_WARN;
    [notes addObject:[NSString stringWithFormat:@"%ld stale request(s)",
                                                (long)stale]];
  }
  if (!notes.count) {
    [notes addObject:@"ok"];
  }
  shdwbl_check(checks, @"environment", level,
               [notes componentsJoinedByString:@", "]);
}

// forHealth skips the checks that describe the product policy or the user's
// data (license, prefs, guard, environment): an update must not be rolled back
// because a license is absent or an app crashed earlier.
static NSInteger shdwbl_doctor(NSMutableArray *checks, BOOL forHealth) {
  shdwbl_check(checks, @"root", geteuid() == 0 ? SHDW_OK : SHDW_ERR,
               [NSString stringWithFormat:@"uid %d", geteuid()]);
  shdwbl_check_config(checks);
  shdwbl_check_ownership(checks);
  shdwbl_check_payload(checks);
  shdwbl_check_version(checks);
  shdwbl_check_daemon(checks);
  shdwbl_check_watcher(checks);
  if (!forHealth) {
    shdwbl_check_prefs(checks);
    shdwbl_check_intent(checks);
    shdwbl_check_license(checks);
    shdwbl_check_guard(checks);
    shdwbl_check_debugged(checks);
    shdwbl_check_prep(checks);
    shdwbl_check_environment(checks);
  }
  NSInteger level = SHDW_OK;
  for (NSDictionary *check in checks) {
    level = MAX(level, [check[@"level"] integerValue]);
  }
  return level;
}

static int shdwbl_doctor_cli(BOOL json) {
  NSMutableArray *checks = [NSMutableArray array];
  NSInteger level = shdwbl_doctor(checks, NO);
  NSInteger warnings = 0;
  NSInteger errors = 0;
  for (NSDictionary *check in checks) {
    if ([check[@"level"] integerValue] == SHDW_ERR) {
      errors++;
    } else if ([check[@"level"] integerValue] == SHDW_WARN) {
      warnings++;
    }
  }
  if (json) {
    NSDictionary *out = @{
      @"build" : kBuild,
      @"device" : shdwbl_device_uuid() ?: @"",
      @"errors" : @(errors),
      @"warnings" : @(warnings),
      @"checks" : checks,
    };
    NSData *data =
        [NSJSONSerialization dataWithJSONObject:out
                                        options:NSJSONWritingPrettyPrinted
                                          error:NULL];
    fwrite(data.bytes, 1, data.length, stdout);
    printf("\n");
  } else {
    for (NSDictionary *check in checks) {
      NSInteger checkLevel = [check[@"level"] integerValue];
      const char *tag = checkLevel == SHDW_ERR    ? "ERR "
                        : checkLevel == SHDW_WARN ? "warn"
                                                  : "ok  ";
      printf("[%s] %-12s %s\n", tag, [check[@"name"] UTF8String],
             [check[@"detail"] UTF8String]);
    }
    printf("doctor: %lu checks, %ld error(s), %ld warning(s)\n",
           (unsigned long)checks.count, (long)errors, (long)warnings);
  }
  return level;
}

#pragma mark - Updater

// Update = validate the deb -> stage it -> snapshot the installed payload and
// the state files -> journal -> dpkg -i -> restart the daemon -> health check.
// Any failure after the journal is written rolls the payload back from the
// snapshot bytes, so a broken package cannot leave the device without a working
// Shadow. The state copies in the snapshot are for manual recovery; automatic
// rollback only touches payload files and the manifest, because config/prefs/
// license may have changed for unrelated reasons since the snapshot.
static NSString *const kSnapshotsDir = @"/var/jb/var/lib/shadow/snapshots";
static NSString *const kDebStoreDir = @"/var/jb/var/lib/shadow/debs";
static NSString *const kJournalFile = @"/var/jb/var/lib/shadow/update.plist";
static NSString *const kPayloadVersionFile =
    @"/var/jb/var/lib/shadow/payload.version";
static NSString *const kUpdateLock = @"/var/jb/var/lib/shadow/update.lock";
static NSString *const kDaemonJob = @"me.fedorovskyi.antumbra.blacklistd";
static const NSUInteger kSnapshotKeep = 5;
static const NSUInteger kDebStoreKeep = 3;

static NSArray<NSString *> *shdwbl_payload_paths(void) {
  return @[
    kPayloadCore, kPayloadStub, kPayloadFilter, kPayloadFramework,
    kPayloadSettings, kPayloadShdw, kPayloadShdwbl
  ];
}

static int shdwbl_update_lock_acquire(void);

static NSDictionary *shdwbl_journal(void) {
  return [NSDictionary dictionaryWithContentsOfFile:kJournalFile];
}

static BOOL shdwbl_journal_write(NSMutableDictionary *journal) {
  journal[@"Updated"] = shdwbl_utc_string([NSDate date]);
  return shdwbl_write_plist(kJournalFile, journal, 0, 0, 0644);
}

static NSString *shdwbl_deb_field(NSString *deb, NSString *field) {
  int status = 0;
  NSString *out = shdwbl_spawn(
      @[ @"/var/jb/usr/bin/dpkg-deb", @"-f", deb, field ], NO, &status);
  return status == 0 && out.length ? out : nil;
}

static BOOL shdwbl_copy_path(NSString *src, NSString *dst) {
  NSFileManager *fm = [NSFileManager defaultManager];
  if (![fm fileExistsAtPath:src]) {
    return NO;
  }
  [fm createDirectoryAtPath:[dst stringByDeletingLastPathComponent]
      withIntermediateDirectories:YES
                       attributes:nil
                            error:NULL];
  [fm removeItemAtPath:dst error:NULL];
  if (![fm copyItemAtPath:src toPath:dst error:NULL]) {
    return NO;
  }
  chown(dst.fileSystemRepresentation, 0, 0);
  return YES;
}

static void shdwbl_remove_tree(NSString *path) {
  [[NSFileManager defaultManager] removeItemAtPath:path error:NULL];
}

static NSString *shdwbl_installed_version(void) {
  NSDictionary *manifest =
      [NSDictionary dictionaryWithContentsOfFile:kManifest];
  if ([manifest[@"Version"] isKindOfClass:[NSString class]]) {
    return manifest[@"Version"];
  }
  int status = 0;
  NSString *version = shdwbl_spawn(
      @[ @"/var/jb/usr/bin/dpkg-query", @"-W", @"-f=${Version}", kPackageId ],
      NO, &status);
  return status == 0 && version.length ? version : nil;
}

static void shdwbl_payload_manifest_write(NSString *version, NSString *debPath,
                                          NSString *debMD5,
                                          NSDictionary *files) {
  NSDictionary *manifest = @{
    @"Version" : version ?: @"",
    @"Build" : kBuild,
    @"Created" : shdwbl_utc_string([NSDate date]),
    @"Deb" : debPath.lastPathComponent ?: @"",
    @"DebMD5" : debMD5 ?: @"",
    @"Files" : files ?: @{},
  };
  shdwbl_write_plist(kManifest, manifest, 0, 0, 0644);
  [(version ?: @"") writeToFile:kPayloadVersionFile
                     atomically:YES
                       encoding:NSUTF8StringEncoding
                          error:NULL];
  chown(kPayloadVersionFile.fileSystemRepresentation, 0, 0);
  chmod(kPayloadVersionFile.fileSystemRepresentation, 0644);
}

static NSString *shdwbl_snapshot_create(NSString *fromVersion,
                                        NSString *toVersion, NSString *debPath,
                                        NSString *debMD5,
                                        NSDictionary *newFiles) {
  NSFileManager *fm = [NSFileManager defaultManager];
  [fm createDirectoryAtPath:kSnapshotsDir
      withIntermediateDirectories:YES
                       attributes:nil
                            error:NULL];
  NSString *ident =
      [NSString stringWithFormat:@"%lld-%@", (long long)time(NULL),
                                 toVersion.length ? toVersion : @"unknown"];
  NSString *base = [kSnapshotsDir stringByAppendingPathComponent:ident];
  NSString *payloadDir = [base stringByAppendingPathComponent:@"payload"];
  NSString *stateDir = [base stringByAppendingPathComponent:@"state"];
  [fm createDirectoryAtPath:payloadDir
      withIntermediateDirectories:YES
                       attributes:nil
                            error:NULL];

  NSMutableDictionary *files = [NSMutableDictionary dictionary];
  for (NSString *path in shdwbl_payload_paths()) {
    NSString *md5 = shdwbl_md5(path);
    if (!md5) {
      continue;
    }
    files[path] = md5;
    shdwbl_copy_path(path, [payloadDir stringByAppendingString:path]);
  }
  for (NSString *path in @[
         kConfig, kPrefs, kOwnFile, kManifest, kLicenseFile, kLicenseState,
         kPayloadVersionFile
       ]) {
    shdwbl_copy_path(path, [stateDir stringByAppendingString:path]);
  }

  NSDictionary *meta = @{
    @"Id" : ident,
    @"Created" : shdwbl_utc_string([NSDate date]),
    @"FromVersion" : fromVersion ?: @"",
    @"ToVersion" : toVersion ?: @"",
    @"Build" : kBuild,
    @"Deb" : debPath.lastPathComponent ?: @"",
    @"DebMD5" : debMD5 ?: @"",
    @"Files" : files,
    @"NewFiles" : newFiles ?: @{},
  };
  shdwbl_write_plist([base stringByAppendingPathComponent:@"meta.plist"], meta,
                     0, 0, 0644);

  if (debPath && debMD5) {
    [fm createDirectoryAtPath:kDebStoreDir
        withIntermediateDirectories:YES
                         attributes:nil
                              error:NULL];
    NSString *kept = [kDebStoreDir
        stringByAppendingPathComponent:[debMD5
                                           stringByAppendingString:@".deb"]];
    shdwbl_copy_path(debPath, kept);
    chmod(kept.fileSystemRepresentation, 0644);
  }
  return ident;
}

// Snapshot ids begin with a timestamp, but the deb store is keyed by md5, so
// name order says nothing about age: pruning by name dropped the deb that had
// just been installed. Order by mtime instead.
static NSComparisonResult shdwbl_store_age_compare(id a, id b, void *ctx) {
  (void)ctx;
  struct stat sa = {0}, sb = {0};
  stat([a fileSystemRepresentation], &sa);
  stat([b fileSystemRepresentation], &sb);
  if (sa.st_mtimespec.tv_sec != sb.st_mtimespec.tv_sec) {
    return sa.st_mtimespec.tv_sec < sb.st_mtimespec.tv_sec
               ? NSOrderedAscending
               : NSOrderedDescending;
  }
  if (sa.st_mtimespec.tv_nsec != sb.st_mtimespec.tv_nsec) {
    return sa.st_mtimespec.tv_nsec < sb.st_mtimespec.tv_nsec
               ? NSOrderedAscending
               : NSOrderedDescending;
  }
  return [a compare:b];
}

static void shdwbl_prune_store(NSString *dir, NSUInteger keep) {
  NSFileManager *fm = [NSFileManager defaultManager];
  NSMutableArray<NSString *> *paths = [NSMutableArray array];
  for (NSString *name in [fm contentsOfDirectoryAtPath:dir error:NULL]) {
    [paths addObject:[dir stringByAppendingPathComponent:name]];
  }
  [paths sortUsingFunction:shdwbl_store_age_compare context:NULL];
  if (paths.count <= keep) {
    return;
  }
  for (NSUInteger i = 0; i + keep < paths.count; i++) {
    shdwbl_remove_tree(paths[i]);
  }
}

// The daemon serves requests on a 2 s tick and a freshly started one spends a
// few seconds in its post-install reconcile before the first scan, so every
// ping has to outlive that tick instead of racing it.
static NSString *shdwbl_last_ping;

static BOOL shdwbl_wait_daemon(NSTimeInterval seconds, NSString *build) {
  NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:seconds];
  while ([[NSDate date] compare:deadline] == NSOrderedAscending) {
    NSString *line = shdwbl_ping_line(4.0);
    if (line) {
      shdwbl_last_ping = line;
      if (!build || [line containsString:[NSString stringWithFormat:@"build=%@",
                                                                    build]]) {
        return YES;
      }
    }
    usleep(250000);
  }
  return NO;
}

// A surviving old process answers pings with its own build, which used to pass
// the check and skip the kickstart. Ask for the build we just installed and
// force launchd to replace anything that does not report it.
static BOOL shdwbl_restart_daemon(NSString *build) {
  if (shdwbl_wait_daemon(8.0, build)) {
    return YES;
  }
  int status = -1;
  shdwbl_spawn(
      @[
        @"/var/jb/usr/bin/launchctl", @"kickstart", @"-k",
        [@"system/" stringByAppendingString:kDaemonJob]
      ],
      YES, &status);
  if (status != 0) {
    shdwbl_spawn(
        @[
          @"/var/jb/usr/bin/launchctl", @"kickstart", @"-k",
          [@"user/501/" stringByAppendingString:kDaemonJob]
        ],
        YES, &status);
  }
  return shdwbl_wait_daemon(20.0, build);
}

static int shdwbl_rollback_to(NSString *ident, NSString *reason, BOOL restart) {
  if (!ident.length) {
    fprintf(stderr, "rollback: no snapshot id\n");
    return 2;
  }
  NSString *base = [kSnapshotsDir stringByAppendingPathComponent:ident];
  NSString *payloadDir = [base stringByAppendingPathComponent:@"payload"];
  NSString *stateDir = [base stringByAppendingPathComponent:@"state"];
  NSDictionary *meta =
      [NSDictionary dictionaryWithContentsOfFile:
                        [base stringByAppendingPathComponent:@"meta.plist"]];
  NSDictionary *files = [meta[@"Files"] isKindOfClass:[NSDictionary class]]
                            ? meta[@"Files"]
                            : nil;
  if (!files) {
    fprintf(stderr, "rollback: snapshot %s is missing or has no file list\n",
            ident.UTF8String);
    return 2;
  }

  int failures = 0;
  for (NSString *path in files) {
    NSString *src = [payloadDir stringByAppendingString:path];
    if (![[NSFileManager defaultManager] fileExistsAtPath:src]) {
      failures++;
      fprintf(stderr, "rollback: %s missing from snapshot\n", path.UTF8String);
      continue;
    }
    if (!shdwbl_copy_path(src, path)) {
      failures++;
      continue;
    }
    if (![files[path] isEqual:(shdwbl_md5(path) ?: @"")]) {
      failures++;
      fprintf(stderr, "rollback: %s md5 mismatch after restore\n",
              path.UTF8String);
    }
  }

  NSString *stateManifest = [stateDir stringByAppendingString:kManifest];
  if ([[NSFileManager defaultManager] fileExistsAtPath:stateManifest]) {
    shdwbl_copy_path(stateManifest, kManifest);
  } else {
    [[NSFileManager defaultManager] removeItemAtPath:kManifest error:NULL];
  }
  NSString *stateVersion =
      [stateDir stringByAppendingString:kPayloadVersionFile];
  if ([[NSFileManager defaultManager] fileExistsAtPath:stateVersion]) {
    shdwbl_copy_path(stateVersion, kPayloadVersionFile);
  }

  NSMutableDictionary *journal =
      [shdwbl_journal() mutableCopy] ?: [NSMutableDictionary dictionary];
  journal[@"Stage"] = failures ? @"rollback-failed" : @"rolled-back";
  journal[@"Snapshot"] = ident;
  journal[@"Reason"] = reason ?: @"";
  journal[@"RolledBack"] = shdwbl_utc_string([NSDate date]);
  shdwbl_journal_write(journal);

  if (restart) {
    if (!shdwbl_restart_daemon(nil)) {
      fprintf(stderr, "rollback: daemon did not come back after restore\n");
    }
  }
  fprintf(stderr, "rollback %s %s failures=%d\n", failures ? "FAILED" : "done",
          ident.UTF8String, failures);
  return failures ? 4 : 0;
}

static int shdwbl_update_apply(NSString *debPath, BOOL apply) {
  NSFileManager *fm = [NSFileManager defaultManager];
  if (geteuid() != 0) {
    fprintf(stderr, "reject: update needs root\n");
    return 2;
  }
  if (![fm fileExistsAtPath:debPath]) {
    fprintf(stderr, "reject: no such file %s\n", debPath.UTF8String);
    return 2;
  }
  NSString *debMD5 = shdwbl_md5(debPath);
  NSString *package = shdwbl_deb_field(debPath, @"Package");
  NSString *version = shdwbl_deb_field(debPath, @"Version");
  NSString *architecture = shdwbl_deb_field(debPath, @"Architecture");
  if (!debMD5 || !version) {
    fprintf(stderr, "reject: not a readable .deb\n");
    return 2;
  }
  if (package && ![package isEqualToString:kPackageId]) {
    fprintf(stderr, "reject: package %s, expected %s\n", package.UTF8String,
            kPackageId.UTF8String);
    return 2;
  }
  if (architecture && ![architecture hasPrefix:@"iphoneos-arm64"]) {
    fprintf(
        stderr,
        "reject: architecture %s, this install is rootless iphoneos-arm64\n",
        architecture.UTF8String);
    return 2;
  }

  NSString *staging =
      [kJbStateDir stringByAppendingFormat:@"/staging-%d", getpid()];
  shdwbl_remove_tree(staging);
  [fm createDirectoryAtPath:staging
      withIntermediateDirectories:YES
                       attributes:nil
                            error:NULL];
  int status = 0;
  NSString *out = shdwbl_spawn(
      @[ @"/var/jb/usr/bin/dpkg-deb", @"-x", debPath, staging ], YES, &status);
  if (status != 0) {
    fprintf(stderr, "reject: dpkg-deb -x rc=%d %s\n", status, out.UTF8String);
    shdwbl_remove_tree(staging);
    return 3;
  }

  NSMutableDictionary *files = [NSMutableDictionary dictionary];
  NSMutableArray *problems = [NSMutableArray array];
  for (NSString *path in shdwbl_payload_paths()) {
    NSString *staged = [staging stringByAppendingString:path];
    if (![fm fileExistsAtPath:staged]) {
      [problems addObject:[NSString stringWithFormat:@"%@ missing", path]];
      continue;
    }
    if (![path hasSuffix:@".plist"] && !shdwbl_is_macho(staged)) {
      [problems addObject:[NSString stringWithFormat:@"%@ not Mach-O", path]];
      continue;
    }
    files[path] = shdwbl_md5(staged);
  }
  if (problems.count) {
    fprintf(stderr, "reject: payload incomplete: %s\n",
            [[problems componentsJoinedByString:@"; "] UTF8String]);
    shdwbl_remove_tree(staging);
    return 3;
  }

  NSString *fromVersion = shdwbl_installed_version();
  printf("package=%s version=%s arch=%s md5=%s\n", kPackageId.UTF8String,
         version.UTF8String, architecture.UTF8String ?: "-", debMD5.UTF8String);
  for (NSString *path in
       [files.allKeys sortedArrayUsingSelector:@selector(compare:)]) {
    printf("  %s  %s\n", [files[path] UTF8String], path.UTF8String);
  }
  if (!apply) {
    printf("staged only; add --apply to install\n");
    shdwbl_remove_tree(staging);
    return 0;
  }

  // Held until this process exits; a second updater or a daemon that starts
  // during dpkg must see it and leave recovery alone.
  int lock = shdwbl_update_lock_acquire();
  if (lock < 0) {
    fprintf(stderr, "reject: another update is already in flight\n");
    shdwbl_remove_tree(staging);
    return 7;
  }

  NSString *snapshot =
      shdwbl_snapshot_create(fromVersion, version, debPath, debMD5, files);
  NSMutableDictionary *journal = [@{
    @"Stage" : @"installing",
    @"Snapshot" : snapshot,
    @"FromVersion" : fromVersion ?: @"",
    @"ToVersion" : version,
    @"Deb" : debPath.lastPathComponent ?: @"",
    @"DebMD5" : debMD5,
    @"Updater" : @(getpid()),
    @"Started" : shdwbl_utc_string([NSDate date]),
  } mutableCopy];
  if (!shdwbl_journal_write(journal)) {
    fprintf(stderr, "reject: cannot write the update journal\n");
    shdwbl_remove_tree(staging);
    return 3;
  }
  printf("snapshot=%s from=%s to=%s\n", snapshot.UTF8String,
         (fromVersion ?: @"unknown").UTF8String, version.UTF8String);

  out =
      shdwbl_spawn(@[ @"/var/jb/usr/bin/dpkg", @"-i", debPath ], YES, &status);
  if (status != 0) {
    fprintf(stderr, "dpkg -i rc=%d: %s\n", status, out.UTF8String);
    shdwbl_rollback_to(snapshot, @"dpkg-failed", YES);
    shdwbl_remove_tree(staging);
    return 4;
  }
  // dpkg normally replaces every payload file; a file it did not replace
  // would only surface later as a confusing doctor mismatch, so fail here.
  NSInteger notReplaced = 0;
  for (NSString *path in files) {
    NSString *installed = shdwbl_md5(path);
    if (![installed isEqual:files[path]]) {
      notReplaced++;
      fprintf(stderr, "verify %s installed=%s expected=%s\n", path.UTF8String,
              installed.UTF8String ?: "missing", [files[path] UTF8String]);
    }
  }
  if (notReplaced) {
    fprintf(stderr, "verify failed: %ld payload file(s) not replaced\n",
            (long)notReplaced);
    shdwbl_rollback_to(snapshot, @"verify-failed", YES);
    shdwbl_remove_tree(staging);
    return 5;
  }
  shdwbl_payload_manifest_write(version, debPath, debMD5, files);

  // The updater keeps running the pre-update binary, so its own kBuild is the
  // old tag. Ask the payload that was just installed what it answers, and
  // require the daemon to answer with that build; the wait covers a fresh
  // daemon's first reconcile pass and the kickstart covers a daemon that is
  // still the old process.
  int buildStatus = -1;
  NSString *expectedBuild =
      shdwbl_spawn(@[ kPayloadShdwbl, @"build" ], NO, &buildStatus);
  if (buildStatus != 0) {
    expectedBuild = nil;
  }
  shdwbl_last_ping = nil;
  if (!shdwbl_restart_daemon(expectedBuild)) {
    fprintf(stderr,
            "new daemon did not answer with build=%s (%s), rolling back\n",
            expectedBuild.length ? expectedBuild.UTF8String : "any",
            shdwbl_last_ping.UTF8String ?: "no answer");
    shdwbl_rollback_to(snapshot, @"daemon-unhealthy", YES);
    shdwbl_remove_tree(staging);
    return 5;
  }
  NSMutableArray *checks = [NSMutableArray array];
  NSInteger level = shdwbl_doctor(checks, YES);
  if (level >= SHDW_ERR) {
    for (NSDictionary *check in checks) {
      if ([check[@"level"] integerValue] == SHDW_ERR) {
        fprintf(stderr, "health: %s %s\n", [check[@"name"] UTF8String],
                [check[@"detail"] UTF8String]);
      }
    }
    shdwbl_rollback_to(snapshot, @"doctor-error", YES);
    shdwbl_remove_tree(staging);
    return 6;
  }

  journal[@"Stage"] = @"applied";
  journal[@"Applied"] = shdwbl_utc_string([NSDate date]);
  shdwbl_journal_write(journal);
  shdwbl_prune_store(kSnapshotsDir, kSnapshotKeep);
  shdwbl_prune_store(kDebStoreDir, kDebStoreKeep);
  shdwbl_remove_tree(staging);
  printf("rc=0 applied version=%s snapshot=%s\n", version.UTF8String,
         snapshot.UTF8String);
  return 0;
}

// dpkg replaces the updater's own executable while the update is in flight, so
// proc_pidpath stops resolving for exactly the process whose liveness decides
// whether recovery may run. An flock the updater holds for its whole lifetime
// survives that rename (the kernel releases it only when the process dies).
static int shdwbl_update_lock_acquire(void) {
  int fd = open(kUpdateLock.fileSystemRepresentation, O_CREAT | O_RDWR, 0600);
  if (fd < 0) {
    return -1;
  }
  if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
    close(fd);
    return -1;
  }
  return fd;
}

// An update interrupted between the journal and the health check leaves the
// payload in an unknown state. The daemon runs this before serving requests.
// The package's postinst restarts this daemon from inside `dpkg -i`, so a
// journal whose updater still holds the lock is a running install, not a crash.
static void shdwbl_update_recover(void) {
  NSDictionary *journal = shdwbl_journal();
  if (![journal[@"Stage"] isEqual:@"installing"]) {
    return;
  }
  int lock = shdwbl_update_lock_acquire();
  if (lock < 0) {
    return;
  }
  fprintf(stderr, "update: interrupted install of %s, rolling back to %s\n",
          [journal[@"ToVersion"] UTF8String] ?: "-",
          [journal[@"Snapshot"] UTF8String] ?: "-");
  shdwbl_rollback_to(journal[@"Snapshot"], @"interrupted", NO);
  close(lock);
}

static int shdwbl_snapshots_cli(void) {
  NSFileManager *fm = [NSFileManager defaultManager];
  NSArray *names = [[fm contentsOfDirectoryAtPath:kSnapshotsDir error:NULL]
      sortedArrayUsingSelector:@selector(compare:)];
  for (NSString *name in names) {
    NSString *base = [kSnapshotsDir stringByAppendingPathComponent:name];
    NSDictionary *meta =
        [NSDictionary dictionaryWithContentsOfFile:
                          [base stringByAppendingPathComponent:@"meta.plist"]];
    printf("%s from=%s to=%s created=%s files=%lu\n", name.UTF8String,
           [meta[@"FromVersion"] UTF8String] ?: "-",
           [meta[@"ToVersion"] UTF8String] ?: "-",
           [meta[@"Created"] UTF8String] ?: "-",
           (unsigned long)[meta[@"Files"] count]);
  }
  NSDictionary *journal = shdwbl_journal();
  if (journal) {
    printf("journal stage=%s to=%s reason=%s\n",
           [journal[@"Stage"] UTF8String] ?: "-",
           [journal[@"ToVersion"] UTF8String] ?: "-",
           [journal[@"Reason"] UTF8String] ?: "-");
  }
  return 0;
}

#pragma mark - Request scan

static void shdwbl_mkreqdir(void) {
  NSFileManager *fm = [NSFileManager defaultManager];
  [fm createDirectoryAtPath:kReqDir
      withIntermediateDirectories:YES
                       attributes:nil
                            error:NULL];
  chown(kReqDir.fileSystemRepresentation, kMobile, kMobile);
  chmod(kReqDir.fileSystemRepresentation, 0775);
}

// A sandboxed app can only write inside its own data container, so the stub
// drops its request there. The container's owner bundle id must match the
// request target; the Settings app is the user-facing exception.
static NSString *shdwbl_container_bid(NSString *requestPath) {
  NSRange r = [requestPath rangeOfString:kRequestSuffix];
  if (r.location == NSNotFound) {
    return nil; // trusted root-written directory
  }
  NSString *container = [requestPath substringToIndex:r.location];
  NSString *meta =
      [container stringByAppendingPathComponent:
                     @".com.apple.mobile_container_manager.metadata.plist"];
  NSDictionary *m = [NSDictionary dictionaryWithContentsOfFile:meta];
  return [m[@"MCMMetadataIdentifier"] isKindOfClass:[NSString class]]
             ? m[@"MCMMetadataIdentifier"]
             : nil;
}

static BOOL shdwbl_request_allowed(NSString *owner, NSString *bid,
                                   NSString *exe) {
  if (!owner) {
    return YES;
  }
  if ([owner isEqualToString:kSettingsBid]) {
    return YES;
  }
  if (bid && [owner isEqualToString:bid]) {
    return YES;
  }
  NSString *target = exe ? shdwbl_app_bid(exe) : nil;
  return target && [owner isEqualToString:target];
}

static void shdwbl_scan_dir(NSString *dir) {
  NSFileManager *fm = [NSFileManager defaultManager];
  NSArray *names = [fm contentsOfDirectoryAtPath:dir error:NULL];
  for (NSString *name in names) {
    if (![name hasSuffix:@".plist"]) {
      continue;
    }
    NSString *path = [dir stringByAppendingPathComponent:name];
    NSDictionary *req = [NSDictionary dictionaryWithContentsOfFile:path];
    if (![req isKindOfClass:[NSDictionary class]]) {
      continue; // still being written; try again next tick
    }
    NSString *action = [req[@"action"] isKindOfClass:[NSString class]]
                           ? req[@"action"]
                           : @"add";

    if ([action isEqualToString:@"ping"]) {
      NSDictionary *cfg = shdwbl_load_config();
      NSUInteger entries =
          [cfg[@"ProcessBlacklist"] isKindOfClass:[NSArray class]]
              ? [cfg[@"ProcessBlacklist"] count]
              : 0;
      NSString *result = [NSString
          stringWithFormat:@"rc=0 action=ping build=%@ pid=%d entries=%lu\n",
                           kBuild, getpid(), (unsigned long)entries];
      NSString *resultPath = [path stringByAppendingString:@".result"];
      [result writeToFile:resultPath
               atomically:YES
                 encoding:NSUTF8StringEncoding
                    error:NULL];
      [fm removeItemAtPath:path error:NULL];
      continue;
    }

    NSString *bid =
        [req[@"bid"] isKindOfClass:[NSString class]] ? req[@"bid"] : nil;
    NSString *exe =
        [req[@"exe"] isKindOfClass:[NSString class]] ? req[@"exe"] : nil;
    NSString *owner = shdwbl_container_bid(path);
    int rc = 2;
    BOOL resolved = NO;

    if (bid) {
      if (shdwbl_valid_bid(bid)) {
        exe = shdwbl_exe_for_bid(bid);
        if (!exe) {
          rc = 5; // not installed under a bundle container
        } else {
          resolved = YES;
        }
      }
    } else if (exe) {
      if (!bid) {
        bid = shdwbl_app_bid(exe);
      }
      resolved = YES;
    }

    if (resolved) {
      id reqPid = [req[@"pid"] respondsToSelector:@selector(integerValue)]
                      ? req[@"pid"]
                      : nil;
      if (!shdwbl_request_allowed(owner, bid, exe)) {
        rc = 4; // request targets another app
      } else if ([action isEqualToString:@"status"]) {
        rc = 0;
      } else if (![action isEqualToString:@"remove"] && reqPid &&
                 !shdwbl_launchd_exit_is_crash(bid, [reqPid integerValue])) {
        rc = 6; // previous run quit or was killed, not a crash
      } else {
        rc = shdwbl_apply(exe, ![action isEqualToString:@"remove"], bid);
      }
    }

    BOOL listed = exe && shdwbl_is_blacklisted(exe);
    NSString *result = [NSString
        stringWithFormat:@"rc=%d action=%@ bid=%@ exe=%@ blacklisted=%d%@\n",
                         rc, action, bid ?: @"-", exe ?: @"-", listed ? 1 : 0,
                         rc == 6 ? @" skipped=noncrash" : @""];
    NSString *resultPath = [path stringByAppendingString:@".result"];
    [result writeToFile:resultPath
             atomically:YES
               encoding:NSUTF8StringEncoding
                  error:NULL];
    chown(resultPath.fileSystemRepresentation, kMobile, kMobile);
    [fm removeItemAtPath:path error:NULL];
    fprintf(stderr, "request %s rc=%d\n", path.UTF8String, rc);
  }
}

static void shdwbl_scan(void) {
  shdwbl_mkreqdir();
  shdwbl_scan_dir(kReqDir);

  NSFileManager *fm = [NSFileManager defaultManager];
  NSError *err = nil;
  NSArray *uuids = [fm contentsOfDirectoryAtPath:kDataRoot error:&err];
  static NSInteger lastCount = -1;
  if (!uuids) {
    fprintf(stderr, "scan root error: %s\n", err.description.UTF8String ?: "?");
    return;
  }
  if ((NSInteger)uuids.count != lastCount) {
    fprintf(stderr, "scan root dirs=%lu\n", (unsigned long)uuids.count);
    lastCount = (NSInteger)uuids.count;
  }
  for (NSString *uuid in uuids) {
    NSString *dir = [kDataRoot stringByAppendingPathComponent:uuid];
    dir = [dir stringByAppendingPathComponent:
                   @"Library/Application Support/Shadow/blacklist-requests"];
    BOOL isDir = NO;
    if ([fm fileExistsAtPath:dir isDirectory:&isDir] && isDir) {
      shdwbl_scan_dir(dir);
    }
  }
}

// An install or update replaces the bundle directory, which moves the root's
// mtime. Poll it every tick (a single stat) and reconcile on change, with a
// slow periodic pass as a fallback for anything that does not touch it.
static BOOL shdwbl_bundle_root_changed(void) {
  static time_t lastMtime = 0;
  static ino_t lastIno = 0;
  struct stat st;
  if (stat(kAppBundleRoot.fileSystemRepresentation, &st) != 0) {
    return NO;
  }
  if (st.st_mtimespec.tv_sec != lastMtime || st.st_ino != lastIno) {
    lastMtime = st.st_mtimespec.tv_sec;
    lastIno = st.st_ino;
    return YES;
  }
  return NO;
}

static int shdwbl_cli_bid(NSString *verb, NSString *bid) {
  if (!shdwbl_valid_bid(bid)) {
    fprintf(stderr, "reject bid=%s\n", bid.UTF8String ?: "(null)");
    return 2;
  }
  NSString *exe = shdwbl_exe_for_bid(bid);
  if (!exe) {
    fprintf(stderr, "not installed: %s\n", bid.UTF8String);
    return 5;
  }
  if ([verb isEqualToString:@"status"]) {
    printf("rc=0 action=status bid=%s exe=%s blacklisted=%d\n", bid.UTF8String,
           exe.UTF8String, shdwbl_is_blacklisted(exe) ? 1 : 0);
    return 0;
  }
  return shdwbl_apply(exe, [verb isEqualToString:@"addb"], bid);
}

#pragma mark - shdw-prep static lane

// A detector runtime shipped inside an app bundle (Licel's ios_runtime class)
// can be neutralized offline: its __mod_init_func size is cleared, the file is
// re-signed ad-hoc and that cdhash is put into the jailbreak trustcache, so the
// app runs its own code without any injection. The offline half is
// work/prep_lib.py plus work/cdhash.py; this side installs the resulting
// payload, re-applies it after an app update and can revert it.
//
// The payload is pinned to the app's main binary; when an update changes that
// binary the pin stops matching and nothing is touched, so the bundle never
// ends up with a runtime from a different version.

static NSString *const kPrepRoot = @"/var/jb/usr/share/shdw-prep";
static NSString *const kPrepBackupRoot = @"/var/jb/var/lib/shadow/prep-backup";
static NSString *const kPrepState = @"/var/jb/var/lib/shadow/prep.plist";
static NSString *const kJbctlPath = @"/var/jb/usr/bin/jbctl";
static const uid_t kInstalld = 33;

static NSString *shdwbl_prep_dir(NSString *bid) {
  return [kPrepRoot stringByAppendingPathComponent:bid];
}

static NSDictionary *shdwbl_prep_manifest(NSString *bid) {
  if (!shdwbl_valid_bid(bid)) {
    return nil;
  }
  NSDictionary *m =
      [NSDictionary dictionaryWithContentsOfFile:
                        [shdwbl_prep_dir(bid)
                            stringByAppendingPathComponent:@"manifest.plist"]];
  if (![m isKindOfClass:[NSDictionary class]] || ![m[@"Bid"] isEqual:bid]) {
    return nil;
  }
  if (![m[@"ExeRel"] isKindOfClass:[NSString class]] ||
      ![m[@"ExeMd5"] isKindOfClass:[NSString class]] ||
      ![m[@"Files"] isKindOfClass:[NSArray class]]) {
    return nil;
  }
  return m;
}

static BOOL shdwbl_prep_rel_ok(NSString *rel) {
  return [rel isKindOfClass:[NSString class]] && rel.length > 0 &&
         ![rel hasPrefix:@"/"] && ![rel containsString:@".."];
}

static BOOL shdwbl_prep_tc_has(NSString *cdhash) {
  int status = -1;
  NSString *out =
      shdwbl_spawn(@[ kJbctlPath, @"trustcache", @"info" ], YES, &status);
  if (status != 0 || ![cdhash isKindOfClass:[NSString class]]) {
    return NO;
  }
  return [out rangeOfString:cdhash options:NSCaseInsensitiveSearch].location !=
         NSNotFound;
}

// jbctl answers 0 for any 40-hex string, so its exit code says nothing about
// whether the entry is live; confirm against the table instead. jbctl also
// appends unconditionally - the boot pass runs this for every patched file on
// every daemon start, so without the pre-check the table grows by one row per
// file per start (Durak: 100 identical rows after a day of restarts).
static BOOL shdwbl_prep_tc_add(NSString *cdhash) {
  if (![cdhash isKindOfClass:[NSString class]] || cdhash.length != 40) {
    return NO;
  }
  if (shdwbl_prep_tc_has(cdhash)) {
    return YES;
  }
  int status = -1;
  shdwbl_spawn(@[ kJbctlPath, @"trustcache", @"add", cdhash ], YES, &status);
  return status == 0 && shdwbl_prep_tc_has(cdhash);
}

// copy + fsync + chown/chmod, then X.new -> mv -f: a half-written file must
// never sit under the bundle path the app is about to exec.
static BOOL shdwbl_prep_copy(NSString *src, NSString *dst, mode_t mode,
                             uid_t uid, gid_t gid) {
  NSString *parent = [dst stringByDeletingLastPathComponent];
  [[NSFileManager defaultManager] createDirectoryAtPath:parent
                            withIntermediateDirectories:YES
                                             attributes:nil
                                                  error:NULL];
  int in = open(src.fileSystemRepresentation, O_RDONLY);
  if (in < 0) {
    return NO;
  }
  NSString *tmp = [dst stringByAppendingString:@".new"];
  unlink(tmp.fileSystemRepresentation);
  int out =
      open(tmp.fileSystemRepresentation, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (out < 0) {
    close(in);
    return NO;
  }
  BOOL ok = YES;
  char buf[1 << 16];
  ssize_t n;
  while ((n = read(in, buf, sizeof buf)) > 0) {
    ssize_t off = 0;
    while (off < n) {
      ssize_t w = write(out, buf + off, (size_t)(n - off));
      if (w <= 0) {
        ok = NO;
        break;
      }
      off += w;
    }
    if (!ok) {
      break;
    }
  }
  if (n < 0) {
    ok = NO;
  }
  if (ok && fsync(out) != 0) {
    ok = NO;
  }
  close(in);
  close(out);
  if (!ok) {
    unlink(tmp.fileSystemRepresentation);
    return NO;
  }
  chown(tmp.fileSystemRepresentation, uid, gid);
  chmod(tmp.fileSystemRepresentation, mode);
  if (rename(tmp.fileSystemRepresentation, dst.fileSystemRepresentation) != 0) {
    unlink(tmp.fileSystemRepresentation);
    return NO;
  }
  return YES;
}

static NSString *shdwbl_prep_backup_path(NSString *bid, NSString *rel) {
  return [[kPrepBackupRoot stringByAppendingPathComponent:bid]
      stringByAppendingPathComponent:rel];
}

static NSMutableDictionary *shdwbl_prep_state(void) {
  NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:kPrepState];
  return [d isKindOfClass:[NSDictionary class]]
             ? [d mutableCopy]
             : [NSMutableDictionary dictionary];
}

static void shdwbl_prep_state_set(NSString *bid, NSDictionary *entry) {
  NSMutableDictionary *state = shdwbl_prep_state();
  state[bid] = entry;
  shdwbl_write_plist(kPrepState, state, 0, 0, 0644);
}

// Results: 0 applied, 1 already applied, 2 no payload, 3 pin mismatch,
// 4 file is neither the known original nor the patched copy, 5 app missing,
// 6 io/signature problem.
static int shdwbl_prep_one(NSString *bid, BOOL quiet) {
  NSDictionary *m = shdwbl_prep_manifest(bid);
  if (!m) {
    return 2;
  }
  NSString *exe = shdwbl_exe_for_bid(bid);
  NSString *app = exe ? shdwbl_app_path(exe) : nil;
  if (!app) {
    if (!quiet) {
      fprintf(stderr, "prep %s: app not installed\n", bid.UTF8String);
    }
    return 5;
  }
  NSString *exePath = [app stringByAppendingPathComponent:m[@"ExeRel"]];
  if (![shdwbl_md5(exePath) isEqual:m[@"ExeMd5"]]) {
    if (!quiet) {
      fprintf(stderr, "prep %s: pin mismatch (app updated), payload skipped\n",
              bid.UTF8String);
    }
    return 3;
  }

  int result = 1;
  NSMutableArray *records = [NSMutableArray array];
  for (NSDictionary *f in m[@"Files"]) {
    NSString *rel = f[@"Rel"];
    if (!shdwbl_prep_rel_ok(rel) ||
        ![f[@"OrigMd5"] isKindOfClass:[NSString class]] ||
        ![f[@"PatchedMd5"] isKindOfClass:[NSString class]] ||
        ![f[@"Cdhash"] isKindOfClass:[NSString class]]) {
      result = 6;
      break;
    }
    NSString *dst = [app stringByAppendingPathComponent:rel];
    NSString *cur = shdwbl_md5(dst);
    if ([cur isEqual:f[@"PatchedMd5"]]) {
      // Trustcache entries do not survive a reboot; the file does.
      if (!shdwbl_prep_tc_add(f[@"Cdhash"])) {
        result = 6;
        break;
      }
      [records addObject:@{@"Rel" : rel, @"State" : @"patched"}];
      continue;
    }
    if (![cur isEqual:f[@"OrigMd5"]]) {
      result = 4;
      break;
    }
    NSString *src =
        [[shdwbl_prep_dir(bid) stringByAppendingPathComponent:@"files"]
            stringByAppendingPathComponent:rel];
    if (![shdwbl_md5(src) isEqual:f[@"PatchedMd5"]]) {
      if (!quiet) {
        fprintf(stderr, "prep %s: payload file %s is corrupt\n", bid.UTF8String,
                rel.UTF8String);
      }
      result = 6;
      break;
    }
    NSString *backup = shdwbl_prep_backup_path(bid, rel);
    if (![[NSFileManager defaultManager] fileExistsAtPath:backup] &&
        !shdwbl_prep_copy(dst, backup, 0644, 0, 0)) {
      result = 6;
      break;
    }
    if (!shdwbl_prep_copy(src, dst,
                          (mode_t)([f[@"Mode"] unsignedIntValue] ?: 0755),
                          kInstalld, kInstalld) ||
        !shdwbl_prep_tc_add(f[@"Cdhash"])) {
      result = 6;
      break;
    }
    [records addObject:@{@"Rel" : rel, @"State" : @"applied"}];
    result = 0;
  }

  NSMutableDictionary *entry = [shdwbl_prep_state()[bid] mutableCopy]
                                   ?: [NSMutableDictionary dictionary];
  entry[@"Checked"] = shdwbl_utc_string([NSDate date]);
  entry[@"Version"] = m[@"Version"] ?: @"";
  entry[@"Result"] = @(result);
  if (records.count) {
    entry[@"Files"] = records;
  }
  shdwbl_prep_state_set(bid, entry);
  if (!quiet && result == 0) {
    printf("rc=0 applied bid=%s files=%lu\n", bid.UTF8String,
           (unsigned long)records.count);
  }
  return result;
}

static int shdwbl_prep_all(BOOL quiet) {
  NSArray *bids =
      [[NSFileManager defaultManager] contentsOfDirectoryAtPath:kPrepRoot
                                                          error:NULL];
  int applied = 0, noop = 0, skipped = 0, failed = 0;
  for (NSString *bid in bids) {
    if (!shdwbl_prep_manifest(bid)) {
      continue;
    }
    int rc = shdwbl_prep_one(bid, YES);
    switch (rc) {
    case 0:
      applied++;
      break;
    case 1:
      noop++;
      break;
    case 2:
      break;
    case 3:
      skipped++;
      break;
    default:
      failed++;
      break;
    }
  }
  if (quiet) {
    if (applied || failed) {
      fprintf(stderr, "prep applied=%d noop=%d skipped=%d failed=%d\n", applied,
              noop, skipped, failed);
    }
  } else {
    printf("rc=0 applied=%d noop=%d skipped=%d failed=%d\n", applied, noop,
           skipped, failed);
  }
  return 0;
}

static int shdwbl_prep_status(NSString *bid) {
  NSDictionary *m = shdwbl_prep_manifest(bid);
  NSString *exe = shdwbl_exe_for_bid(bid);
  NSString *app = exe ? shdwbl_app_path(exe) : nil;
  if (!m) {
    printf("rc=%d bid=%s payload=no%s\n", app ? 0 : 5, bid.UTF8String,
           app ? "" : " installed=no");
    return app ? 0 : 5;
  }
  NSString *pin =
      app ? shdwbl_md5([app stringByAppendingPathComponent:m[@"ExeRel"]]) : nil;
  NSString *pinState = !pin                         ? @"noapp"
                       : [pin isEqual:m[@"ExeMd5"]] ? @"match"
                                                    : @"mismatch";
  printf("rc=0 bid=%s payload=yes version=%s pin=%s files=%lu\n",
         bid.UTF8String, [m[@"Version"] description].UTF8String ?: "",
         pinState.UTF8String, (unsigned long)[m[@"Files"] count]);
  for (NSDictionary *f in m[@"Files"]) {
    NSString *rel = f[@"Rel"];
    NSString *cur =
        app ? shdwbl_md5([app stringByAppendingPathComponent:rel]) : nil;
    NSString *state = !cur                             ? @"unknown"
                      : [cur isEqual:f[@"PatchedMd5"]] ? @"patched"
                      : [cur isEqual:f[@"OrigMd5"]]    ? @"original"
                                                       : @"foreign";
    printf("file %s state=%s md5=%s cdhash=%s tc=%s\n", rel.UTF8String,
           state.UTF8String, cur ? cur.UTF8String : "-",
           [f[@"Cdhash"] description].UTF8String ?: "",
           shdwbl_prep_tc_has(f[@"Cdhash"]) ? "yes" : "no");
  }
  return 0;
}

static int shdwbl_prep_revert(NSString *bid) {
  NSDictionary *m = shdwbl_prep_manifest(bid);
  if (!m) {
    fprintf(stderr, "prep %s: no payload\n", bid.UTF8String);
    return 2;
  }
  NSString *exe = shdwbl_exe_for_bid(bid);
  NSString *app = exe ? shdwbl_app_path(exe) : nil;
  if (!app) {
    fprintf(stderr, "prep %s: app not installed\n", bid.UTF8String);
    return 5;
  }
  int rc = 0;
  NSMutableArray *records = [NSMutableArray array];
  for (NSDictionary *f in m[@"Files"]) {
    NSString *rel = f[@"Rel"];
    if (!shdwbl_prep_rel_ok(rel)) {
      rc = 6;
      continue;
    }
    NSString *dst = [app stringByAppendingPathComponent:rel];
    NSString *backup = shdwbl_prep_backup_path(bid, rel);
    if (![[NSFileManager defaultManager] fileExistsAtPath:backup]) {
      if ([shdwbl_md5(dst) isEqual:f[@"OrigMd5"]]) {
        [records addObject:@{@"Rel" : rel, @"State" : @"original"}];
        continue;
      }
      rc = 3;
      continue;
    }
    if (![shdwbl_md5(backup) isEqual:f[@"OrigMd5"]] ||
        !shdwbl_prep_copy(backup, dst, 0755, kInstalld, kInstalld)) {
      rc = 6;
      continue;
    }
    [records addObject:@{@"Rel" : rel, @"State" : @"reverted"}];
  }
  NSMutableDictionary *entry = [shdwbl_prep_state()[bid] mutableCopy]
                                   ?: [NSMutableDictionary dictionary];
  entry[@"Checked"] = shdwbl_utc_string([NSDate date]);
  entry[@"Result"] = @(rc ? rc : 0);
  if (records.count) {
    entry[@"Files"] = records;
  }
  shdwbl_prep_state_set(bid, entry);
  printf("rc=%d reverted bid=%s files=%lu\n", rc, bid.UTF8String,
         (unsigned long)records.count);
  return rc;
}

static void shdwbl_check_prep(NSMutableArray *checks) {
  NSArray *bids =
      [[NSFileManager defaultManager] contentsOfDirectoryAtPath:kPrepRoot
                                                          error:NULL];
  NSMutableArray *notes = [NSMutableArray array];
  NSInteger level = SHDW_OK;
  NSInteger payloads = 0;
  for (NSString *bid in bids) {
    NSDictionary *m = shdwbl_prep_manifest(bid);
    if (!m) {
      continue;
    }
    payloads++;
    NSString *exe = shdwbl_exe_for_bid(bid);
    NSString *app = exe ? shdwbl_app_path(exe) : nil;
    if (!app) {
      level = MAX(level, SHDW_WARN);
      [notes addObject:[NSString stringWithFormat:@"%@: not installed", bid]];
      continue;
    }
    if (![shdwbl_md5([app stringByAppendingPathComponent:m[@"ExeRel"]])
            isEqual:m[@"ExeMd5"]]) {
      level = MAX(level, SHDW_WARN);
      [notes addObject:[NSString stringWithFormat:@"%@: pin mismatch", bid]];
      continue;
    }
    NSInteger patched = 0;
    for (NSDictionary *f in m[@"Files"]) {
      if ([shdwbl_md5([app stringByAppendingPathComponent:f[@"Rel"]])
              isEqual:f[@"PatchedMd5"]]) {
        patched++;
      }
    }
    if (patched == (NSInteger)[m[@"Files"] count]) {
      [notes addObject:[NSString stringWithFormat:@"%@: applied", bid]];
    } else {
      level = MAX(level, SHDW_WARN);
      [notes addObject:[NSString stringWithFormat:@"%@: %ld/%lu applied", bid,
                                                  (long)patched,
                                                  (unsigned long)[m[@"Files"]
                                                      count]]];
    }
  }
  if (!payloads) {
    [notes addObject:@"no payloads"];
  }
  shdwbl_check(checks, @"prep", level, [notes componentsJoinedByString:@", "]);
}

int main(int argc, char **argv) {
  @autoreleasepool {
    if (argc >= 2 && strcmp(argv[1], "-d") == 0) {
      shdwbl_mkreqdir();
      fprintf(stderr, "shdwbl up dir=%s build=%s\n", kReqDir.UTF8String,
              kBuild.UTF8String);
      shdwbl_update_recover();
      // Answer whatever is already queued before the post-install pass,
      // which can hold the loop for seconds right after dpkg.
      shdwbl_scan();
      shdwbl_reconcile();
      shdwbl_debugged_enforce();
      shdwbl_prep_all(YES);
      SHDWLicenseState license = shdwbl_license_sync();
      fprintf(stderr, "license state=%s\n",
              shdwbl_license_state_name(license).UTF8String);
      time_t lastPass = time(NULL);
      for (;;) {
        @autoreleasepool {
          shdwbl_scan();
          BOOL bundlesChanged = shdwbl_bundle_root_changed();
          if (bundlesChanged || time(NULL) - lastPass >= 60) {
            shdwbl_reconcile();
            shdwbl_debugged_enforce();
            if (bundlesChanged) {
              shdwbl_prep_all(YES);
            }
            shdwbl_license_sync();
            lastPass = time(NULL);
          }
        }
        sleep(2);
      }
    }
    if (argc >= 3 && strcmp(argv[1], "add") == 0) {
      return shdwbl_apply([NSString stringWithUTF8String:argv[2]], YES, nil);
    }
    if (argc >= 3 && strcmp(argv[1], "remove") == 0) {
      return shdwbl_apply([NSString stringWithUTF8String:argv[2]], NO, nil);
    }
    if (argc >= 3 &&
        (strcmp(argv[1], "addb") == 0 || strcmp(argv[1], "removeb") == 0 ||
         strcmp(argv[1], "status") == 0)) {
      return shdwbl_cli_bid([NSString stringWithUTF8String:argv[1]],
                            [NSString stringWithUTF8String:argv[2]]);
    }
    if (argc >= 2 && strcmp(argv[1], "list") == 0) {
      NSDictionary *cfg = shdwbl_load_config();
      for (NSString *v in cfg[@"ProcessBlacklist"]) {
        printf("%s\n", v.UTF8String);
      }
      return 0;
    }
    if (argc >= 2 && strcmp(argv[1], "own") == 0) {
      NSData *data = [NSPropertyListSerialization
          dataWithPropertyList:shdwbl_load_own()
                        format:NSPropertyListXMLFormat_v1_0
                       options:0
                         error:NULL];
      if (data) {
        fwrite(data.bytes, 1, data.length, stdout);
      }
      return 0;
    }
    if (argc >= 2 && strcmp(argv[1], "reconcile") == 0) {
      NSInteger entries = shdwbl_reconcile();
      printf("rc=0 entries=%ld\n", (long)entries);
      return 0;
    }
    if (argc >= 2 && strcmp(argv[1], "ping") == 0) {
      return shdwbl_ping_cli();
    }
    if (argc >= 2 && strcmp(argv[1], "debugged") == 0) {
      NSString *verb =
          argc >= 3 ? [NSString stringWithUTF8String:argv[2]] : @"status";
      if ([verb isEqualToString:@"status"]) {
        int value = shdwbl_debugged_get();
        printf("rc=0 markAppsAsDebugged=%d stealth=%s wanted=%d\n", value,
               value == 0   ? "ok"
               : value == 1 ? "debugged"
                            : "unknown",
               shdwbl_debugged_wanted() ? 1 : 0);
        return 0;
      }
      BOOL on = [verb isEqualToString:@"on"];
      if (!on && ![verb isEqualToString:@"off"]) {
        fprintf(stderr, "usage: shdwbl debugged [status|on|off]\n");
        return 2;
      }
      BOOL ok = shdwbl_debugged_set(on);
      if (ok) {
        shdwbl_debugged_remember(on);
      }
      printf("rc=%d markAppsAsDebugged=%d\n", ok ? 0 : 1,
             shdwbl_debugged_get());
      return ok ? 0 : 1;
    }
    // Lets the updater learn the build tag of a payload it is about to
    // install without running it as a daemon.
    if (argc >= 2 && strcmp(argv[1], "build") == 0) {
      printf("%s\n", kBuild.UTF8String);
      return 0;
    }
    if (argc >= 2 && strcmp(argv[1], "doctor") == 0) {
      BOOL json = argc >= 3 && strcmp(argv[2], "--json") == 0;
      return shdwbl_doctor_cli(json);
    }
    if (argc >= 3 && strcmp(argv[1], "update") == 0) {
      BOOL apply = argc >= 4 && strcmp(argv[3], "--apply") == 0;
      return shdwbl_update_apply([NSString stringWithUTF8String:argv[2]],
                                 apply);
    }
    if (argc >= 2 && strcmp(argv[1], "rollback") == 0) {
      NSString *ident =
          argc >= 3 ? [NSString stringWithUTF8String:argv[2]] : nil;
      if (!ident.length) {
        ident = shdwbl_journal()[@"Snapshot"];
      }
      return shdwbl_rollback_to(ident, @"manual", YES);
    }
    if (argc >= 3 && strcmp(argv[1], "prep") == 0) {
      NSString *verb = [NSString stringWithUTF8String:argv[2]];
      if ([verb isEqualToString:@"apply-all"]) {
        return shdwbl_prep_all(NO);
      }
      NSString *bid = argc >= 4 ? [NSString stringWithUTF8String:argv[3]] : nil;
      if (!bid || !shdwbl_valid_bid(bid)) {
        fprintf(stderr, "usage: shdwbl prep apply|status|revert <bid> | "
                        "prep apply-all\n");
        return 2;
      }
      if ([verb isEqualToString:@"status"]) {
        return shdwbl_prep_status(bid);
      }
      if ([verb isEqualToString:@"revert"]) {
        return shdwbl_prep_revert(bid);
      }
      if ([verb isEqualToString:@"apply"]) {
        int rc = shdwbl_prep_one(bid, NO);
        if (rc == 1) {
          printf("rc=0 already-applied bid=%s\n", bid.UTF8String);
          rc = 0;
        }
        return rc;
      }
    }
    if (argc >= 2 && strcmp(argv[1], "snapshots") == 0) {
      return shdwbl_snapshots_cli();
    }
    if (argc >= 3 && strcmp(argv[1], "license") == 0) {
      NSString *verb = [NSString stringWithUTF8String:argv[2]];
      if ([verb isEqualToString:@"status"]) {
        BOOL json = argc >= 4 && strcmp(argv[3], "--json") == 0;
        return shdwbl_license_status(json);
      }
      if ([verb isEqualToString:@"install"] && argc >= 4) {
        return shdwbl_license_install([NSString stringWithUTF8String:argv[3]]);
      }
      if ([verb isEqualToString:@"verify"] && argc >= 4) {
        NSDictionary *doc = [NSDictionary
            dictionaryWithContentsOfFile:[NSString
                                             stringWithUTF8String:argv[3]]];
        NSString *reason = nil;
        NSDate *expiry = nil;
        SHDWLicenseState state = shdwbl_license_eval_doc(doc, &reason, &expiry);
        printf("rc=%d state=%s expires=%s reason=%s\n",
               state == SHDWLicenseActive ? 0 : 4,
               shdwbl_license_state_name(state).UTF8String,
               expiry ? shdwbl_utc_string(expiry).UTF8String : "-",
               reason.UTF8String ?: "");
        return state == SHDWLicenseActive ? 0 : 4;
      }
      if ([verb isEqualToString:@"remove"]) {
        [[NSFileManager defaultManager] removeItemAtPath:kLicenseFile
                                                   error:NULL];
        shdwbl_license_sync();
        printf("rc=0 state=missing\n");
        return 0;
      }
    }
    fprintf(stderr, "usage: shdwbl -d | add <exe> | remove <exe> | "
                    "addb <bid> | removeb <bid> | status <bid> | list | "
                    "own | reconcile | ping | build | doctor [--json] | "
                    "debugged [status|on|off] | "
                    "update <deb> [--apply] | rollback [id] | snapshots | "
                    "prep apply|status|revert <bid> | prep apply-all | "
                    "license status [--json] | license verify <file> | "
                    "license install <file> | license remove\n");
    return 1;
  }
}
