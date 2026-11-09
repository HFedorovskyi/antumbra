// Web security-status cookie neutralizer.
//
// Kaspi publishes a compact security vector into its web view as the `xs`
// cookie. The entrance server reads it on POST /api/v1/entrance/step and
// answers CheckSecurityFailed when the vector carries the risk bit
// ("...|GS:R=1"); the identical request with "GS:R=0" is accepted, and the
// rest of the vector is zero. Only that one bit is rewritten, every other
// byte of the cookie (and every other cookie) passes through untouched.
// Pref: Detector_XsCookie.
#import "UniversalHooks.h"

@interface WKHTTPCookieStore : NSObject
- (void)setCookie:(NSHTTPCookie *)cookie completionHandler:(void (^)(void))completionHandler;
@end

static NSHTTPCookie* shdw_xs_cookie_cleaned(NSHTTPCookie* cookie) {
    if(!shdw_detector_xscookie || cookie == nil) {
        return cookie;
    }
    if(![[cookie name] isEqualToString:@"xs"]) {
        return cookie;
    }

    NSString* value = [cookie value];
    if(![value containsString:@"GS:R=1"]) {
        return cookie;
    }

    NSString* cleaned = [value stringByReplacingOccurrencesOfString:@"GS:R=1"
                                                         withString:@"GS:R=0"];
    NSMutableDictionary* properties = [[cookie properties] mutableCopy];
    if(properties == nil) {
        return cookie;
    }
    properties[NSHTTPCookieValue] = cleaned;
    NSHTTPCookie* result = [NSHTTPCookie cookieWithProperties:properties];
    if(result == nil) {
        return cookie;
    }

    if(shdw_diag_enabled) {
        shdw_diag_log("XSCOOK %s -> %s", [value UTF8String] ?: "", [cleaned UTF8String] ?: "");
    }
    return result;
}

%group shadowhook_WKHTTPCookieStoreXs
%hook WKHTTPCookieStore

- (void)setCookie:(NSHTTPCookie *)cookie
    completionHandler:(void (^)(void))completionHandler __attribute__((annotate("hookkit:allow_inherited"))) {
    %orig(shdw_xs_cookie_cleaned(cookie), completionHandler);
}
%end
%end

void shdw_universal_webcookiesafe(SHDWHookSession* hooks) {
    (void)hooks;
    if(!shdw_detector_xscookie) {
        return;
    }
    %init(shadowhook_WKHTTPCookieStoreXs);
}
