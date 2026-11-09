// Screen-capture gate neutralizer.
//
// Banking apps close the session and refuse the login flow when the screen is
// reported as being captured (UIScreen.isCaptured / mirroredScreen), because
// the login form would land in the recording. On a handheld nothing is being
// mirrored, and the capture flag has no bearing on the security posture of the
// device. When the per-app pref Detector_ScreenCap is set, report the stock
// "not captured" answer and keep the rest of UIScreen untouched.
#import "UniversalHooks.h"

%group shadowhook_UIScreen
%hook UIScreen

- (BOOL)isCaptured __attribute__((annotate("hookkit:allow_inherited"))) {
    if(!shdw_detector_screencap) {
        return %orig;
    }

    BOOL captured = %orig;
    if(shdw_diag_enabled) {
        shdw_diag_log("SCAP isCaptured orig=%d ext=%d", (int)captured, (int)isCallerExternal());
    }
    return NO;
}

- (UIScreen *)mirroredScreen __attribute__((annotate("hookkit:allow_inherited"))) {
    if(!shdw_detector_screencap) {
        return %orig;
    }

    UIScreen *mirror = %orig;
    if(shdw_diag_enabled && mirror != nil) {
        shdw_diag_log("SCAP mirroredScreen non-nil -> nil");
    }
    return nil;
}
%end
%end

// Observation only: the class-level screen list is what an app compares against
// when it wants "an external display is attached". Never altered, only logged.
%group shadowhook_UIScreenList
%hook UIScreen

+ (NSArray *)screens __attribute__((annotate("hookkit:allow_inherited"))) {
    NSArray *list = %orig;
    if(shdw_detector_screencap && shdw_diag_enabled && [list count] != 1) {
        shdw_diag_log("SCAP screens n=%lu", (unsigned long)[list count]);
    }
    return list;
}
%end
%end

void shdw_universal_screencapture(SHDWHookSession* hooks) {
    (void)hooks;
    %init(shadowhook_UIScreen);

    Class screenClass = objc_getClass("UIScreen");
    if(screenClass && class_getClassMethod(screenClass, @selector(screens))) {
        %init(shadowhook_UIScreenList);
    }
}
