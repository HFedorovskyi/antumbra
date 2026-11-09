// Diagnostic banner probe: names the screen and the code path behind a blocking
// alert. Observation only (pref Debug_BannerProbe); nothing is altered — every
// method falls through to the original implementation.
#import "UniversalHooks.h"

@interface UIView (ShdwRecursiveDescription)
- (NSString *)recursiveDescription;
@end

// WebKit is not linked by ShadowCore: declare only the signatures that are
// hooked, so the classes resolve at runtime through objc_getClass.
@class WKWebViewConfiguration;

@interface WKWebView : NSObject
- (instancetype)initWithFrame:(CGRect)frame configuration:(WKWebViewConfiguration *)configuration;
- (void)loadRequest:(NSURLRequest *)request;
- (void)loadHTMLString:(NSString *)string baseURL:(NSURL *)baseURL;
- (void)loadFileURL:(NSURL *)URL allowingReadAccessToURL:(NSURL *)readAccessURL;
- (void)evaluateJavaScript:(NSString *)javaScriptString
         completionHandler:(void (^)(id result, NSError *error))completionHandler;
@end

@interface WKUserContentController : NSObject
- (void)addScriptMessageHandler:(id)scriptMessageHandler name:(NSString *)name;
- (void)addUserScript:(id)userScript;
@end

@interface WKUserScript : NSObject
- (instancetype)initWithSource:(NSString *)source
                 injectionTime:(NSInteger)injectionTime
             forMainFrameOnly:(BOOL)forMainFrameOnly;
@end

@interface WKWebViewConfiguration : NSObject
- (WKUserContentController *)userContentController;
@end

@interface WKScriptMessage : NSObject
- (NSString *)name;
- (id)body;
@end

static void shdw_banner_dump_window(void);

static BOOL shdw_banner_text_is_interesting(NSString *text) {
    if(![text isKindOfClass:[NSString class]] || [text length] == 0) {
        return NO;
    }

    static NSString *const keys[] = {
        @"требовани", @"соответств", @"безопасн", @"войти",
        @"недоступ", @"заблок", @"ограничен", @"доступ",
    };

    for(size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        if([text rangeOfString:keys[i] options:NSCaseInsensitiveSearch].location != NSNotFound) {
            return YES;
        }
    }
    return NO;
}

static void shdw_banner_log_text(const char *prefix, NSString *text, size_t cap) {
    const char *utf8 = [text UTF8String];
    size_t len = utf8 ? strlen(utf8) : 0;
    if(len > cap) {
        len = cap;
    }
    for(size_t off = 0; off < len; off += 800) {
        size_t chunk = len - off < 800 ? len - off : 800;
        shdw_diag_log("%s %.*s", prefix, (int)chunk, utf8 + off);
    }
}

// Web-side oracle: the auth/registration form is a WKWebView, so nothing the
// banner says exists in the UIKit hierarchy. The script walks the DOM, keeps
// only leaf nodes whose text matches the detector vocabulary of this screen,
// and reports each with its class chain.
// Installed at document start into every web view: records the requests the
// page itself makes, so the API call that flips it into the safety screen is
// visible from the app process.
static NSString *shdw_banner_net_js(void) {
    return @"(function(){"
           @"if(window.__shdwNetInstalled)return;window.__shdwNetInstalled=true;window.__shdwNet=[];"
           @"function push(s){try{window.__shdwNet.push(s);if(window.__shdwNet.length>80)window.__shdwNet.shift();}catch(e){}}"
           @"try{var of=window.fetch;if(of){window.fetch=function(){"
           @"var a=arguments;var url=(a[0]&&a[0].url)||String(a[0]);"
           @"try{var hh='';if(a[1]&&a[1].headers){var hs=a[1].headers;"
           @"if(hs.entries){var e=[];hs.forEach(function(v,k){e.push(k+': '+v);});hh=e.join(' | ');}"
           @"else hh=JSON.stringify(hs);}"
           @"push('FETCHH '+url+' ['+String(hh).substring(0,600)+']');}catch(e){}"
           @"return of.apply(this,a).then(function(r){try{"
           @"if(r&&r.clone){r.clone().text().then(function(t){push('FETCH '+url+' -> '+r.status+' '+String(t).substring(0,1500));});}"
           @"else push('FETCH '+url+' -> '+r.status);}catch(e){}return r;});};}}catch(e){push('FETCH_ERR '+e);}"
           @"try{var oo=XMLHttpRequest.prototype.open,os=XMLHttpRequest.prototype.send,"
           @"osh=XMLHttpRequest.prototype.setRequestHeader;"
           @"XMLHttpRequest.prototype.open=function(m,u){try{this.__shdw={m:m,u:String(u),h:[]};}catch(e){}return oo.apply(this,arguments);};"
           @"XMLHttpRequest.prototype.setRequestHeader=function(k,v){try{this.__shdw.h.push(k+': '+v);}catch(e){}return osh.apply(this,arguments);};"
           @"XMLHttpRequest.prototype.send=function(b){var x=this;"
           @"try{var hs='';try{hs=String(x.__shdw&&x.__shdw.h?x.__shdw.h.join(' | '):'');}catch(e){}"
           @"push('XHRH '+x.__shdw.m+' '+x.__shdw.u+' ['+hs+']');"
           @"if(b)push('XHRBODY '+x.__shdw.m+' '+x.__shdw.u+' :: '+String(b).substring(0,800));"
           @"this.addEventListener('load',function(){var req='';"
           @"try{req=String(x.__shdw&&x.__shdw.m)+' '+String(x.__shdw&&x.__shdw.u);}catch(e){}"
           @"push('XHR '+req+' -> '+x.status+' '+String(x.responseText||'').substring(0,1500));});}catch(e){}"
           @"return os.apply(this,arguments);};}catch(e){push('XHR_ERR '+e);}"
           @"try{var dd=Object.getOwnPropertyDescriptor(Document.prototype,'cookie');"
           @"if(dd&&dd.set){Object.defineProperty(document,'cookie',{configurable:true,get:function(){return dd.get.call(document);},"
           @"set:function(v){try{push('COOKIESET '+String(v).substring(0,600));}catch(e){}return dd.set.call(document,v);}});}}catch(e){push('CKDEF_ERR '+e);}"
           @"try{push('UA '+navigator.userAgent+' LOC '+location.href);}catch(e){}"
           @"})()";
}

static NSString *shdw_banner_js_payload(void) {
    return @"(function(){try{"
           @"var kw=['требовани','соответств','безопасн','ограничен','заблок','недоступ','запис','экрана','снимок','войти'];"
           @"var out=[];var all=document.querySelectorAll('*');"
           @"for(var i=0;i<all.length;i++){var n=all[i];"
           @"if(n.children&&n.children.length>0)continue;"
           @"var t=(n.textContent||'').replace(/\\s+/g,' ').trim();"
           @"if(!t||t.length>400)continue;"
           @"var lt=t.toLowerCase();var hit=false;"
           @"for(var k=0;k<kw.length;k++){if(lt.indexOf(kw[k])>=0){hit=true;break;}}"
           @"if(!hit)continue;"
           @"var p=[];var q=n;for(var d=0;q&&d<8;d++){"
           @"p.push(q.tagName+(q.id?('#'+q.id):'')+(q.className&&q.className.toString?('.'+q.className.toString().replace(/\\s+/g,'.').substring(0,60)):''));"
           @"q=q.parentElement;}"
           @"out.push(p.join(' < ')+' :: '+t);"
           @"if(out.length>=40)break;}"
           @"var s='HREF '+(location?location.href:'')+'\\n';"
           @"if(out.length){s+=out.join('\\n');"
           @"s+='\\nBODY\\n'+(document.body?document.body.innerText:'').substring(0,3000);}"
           @"try{var net=(window.__shdwNet&&window.__shdwNet.length)?window.__shdwNet.splice(0,25):[];"
           @"if(net.length){s+='\\nNET\\n'+net.join('\\n');}}catch(e){}"
           @"try{s+='\\nCOOKIE '+String(document.cookie||'').substring(0,700);}catch(e){}"
           @"return s;"
           @"}catch(e){return 'JSERR '+e;}})()";
}

static NSMutableDictionary *shdw_banner_web_last;

static void shdw_banner_dump_web_view(UIView *view, int *found) {
    if(!view) {
        return;
    }

    Class webViewClass = NSClassFromString(@"WKWebView");
    if(webViewClass && [view isKindOfClass:webViewClass]) {
        (*found)++;
        NSString *key = [NSString stringWithFormat:@"%p", view];
        WKWebView *web = (WKWebView *)view;
        shdw_diag_log("WEB view %d %s frame=%.0fx%.0f",
                      *found, object_getClassName(view),
                      (double)view.frame.size.width, (double)view.frame.size.height);
        [web evaluateJavaScript:shdw_banner_js_payload()
              completionHandler:^(id result, NSError *error) {
            if(error) {
                shdw_diag_log("WEB err %s", [[error description] UTF8String] ?: "");
                return;
            }
            if(![result isKindOfClass:[NSString class]]) {
                return;
            }
            NSString *text = (NSString *)result;
            if(!shdw_banner_web_last) {
                shdw_banner_web_last = [NSMutableDictionary new];
            }
            if([shdw_banner_web_last[key] isEqualToString:text]) {
                return;
            }
            shdw_banner_web_last[key] = text;
            shdw_banner_log_text("WEB", text, 7000);
        }];
    }

    for(UIView *sub in view.subviews) {
        shdw_banner_dump_web_view(sub, found);
    }
}

%group shadowhook_bannerprobe_vc
%hook UIViewController

- (void)presentViewController:(UIViewController *)viewControllerToPresent
                     animated:(BOOL)flag
                   completion:(void (^)(void))completion
    __attribute__((annotate("hookkit:allow_inherited"))) {
    if(shdw_debug_bannerprobe && viewControllerToPresent) {
        const char *cls = object_getClassName(viewControllerToPresent);
        shdw_diag_log("BAN present %s", cls ? cls : "(null)");

        if([viewControllerToPresent isKindOfClass:[UIAlertController class]]) {
            UIAlertController *alert = (UIAlertController *)viewControllerToPresent;
            shdw_diag_log("BAN alert title=%s msg=%s",
                          [alert.title UTF8String] ?: "",
                          [alert.message UTF8String] ?: "");
        }
    }

    %orig;

    if(shdw_debug_bannerprobe) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            shdw_banner_dump_window();
        });
    }
}
%end
%end

%group shadowhook_bannerprobe_label
%hook UILabel

- (void)setText:(NSString *)text __attribute__((annotate("hookkit:allow_inherited"))) {
    if(shdw_debug_bannerprobe && shdw_banner_text_is_interesting(text)) {
        shdw_diag_log("BAN label %s", [text UTF8String]);
        shdw_diag_backtrace("banlbl");
    }

    %orig;
}

- (void)setAttributedText:(NSAttributedString *)text __attribute__((annotate("hookkit:allow_inherited"))) {
    if(shdw_debug_bannerprobe && [text isKindOfClass:[NSAttributedString class]] &&
       shdw_banner_text_is_interesting([text string])) {
        shdw_diag_log("BAN alabel %s", [[text string] UTF8String]);
        shdw_diag_backtrace("banlbl");
    }

    %orig;
}
%end
%end

%group shadowhook_bannerprobe_nav
%hook UINavigationController

- (void)pushViewController:(UIViewController *)viewController animated:(BOOL)animated
    __attribute__((annotate("hookkit:allow_inherited"))) {
    if(shdw_debug_bannerprobe && viewController) {
        const char *cls = object_getClassName(viewController);
        shdw_diag_log("BAN push %s", cls ? cls : "(null)");
    }

    %orig;
}
%end
%end

%group shadowhook_bannerprobe_web
%hook WKWebView

- (void)loadRequest:(NSURLRequest *)request __attribute__((annotate("hookkit:allow_inherited"))) {
    if(shdw_debug_bannerprobe) {
        NSString *url = [[request URL] absoluteString];
        shdw_diag_log("WEB load %s", [url UTF8String] ?: "(null)");
    }

    %orig;
}

- (void)evaluateJavaScript:(NSString *)javaScriptString
         completionHandler:(void (^)(id result, NSError *error))completionHandler
    __attribute__((annotate("hookkit:allow_inherited"))) {
    if(shdw_debug_bannerprobe && [javaScriptString length]) {
        shdw_banner_log_text("WEB appjs", javaScriptString, 1200);
        if([javaScriptString rangeOfString:@"xs="].location != NSNotFound) {
            shdw_diag_log("WEB xsjs len=%lu", (unsigned long)[javaScriptString length]);
            shdw_diag_backtrace("xsjs");
        }
    }

    %orig;
}

- (instancetype)initWithFrame:(CGRect)frame configuration:(WKWebViewConfiguration *)configuration
    __attribute__((annotate("hookkit:allow_inherited"))) {
    if(shdw_debug_bannerprobe && configuration) {
        @try {
            WKUserContentController *controller = [configuration userContentController];
            Class scriptClass = NSClassFromString(@"WKUserScript");
            if(controller && scriptClass) {
                WKUserScript *script = [[scriptClass alloc] initWithSource:shdw_banner_net_js()
                                                                  injectionTime:0
                                                              forMainFrameOnly:NO];
                if(script) {
                    [controller addUserScript:script];
                    shdw_diag_log("WEB net script installed");
                }
            }
        } @catch(NSException *exception) {
            shdw_diag_log("WEB net script failed %s", [[exception reason] UTF8String] ?: "");
        }
    }

    return %orig;
}
%end
%end

@interface WKHTTPCookieStore : NSObject
- (void)setCookie:(NSHTTPCookie *)cookie completionHandler:(void (^)(void))completionHandler;
@end

static void shdw_banner_log_cookie(NSHTTPCookie *cookie, const char *source) {
    if(!cookie) {
        return;
    }
    NSString *name = [cookie name];
    NSString *value = [cookie value];
    shdw_diag_log("COOK %s %s=%s", source, [name UTF8String] ?: "", [value UTF8String] ?: "");
    if([name isEqualToString:@"xs"]) {
        shdw_diag_log("COOKPROPS xs %s", [[[cookie properties] description] UTF8String] ?: "");
        shdw_diag_backtrace("xsck");
    }
}

%group shadowhook_bannerprobe_cookies
%hook NSHTTPCookieStorage

- (void)setCookie:(NSHTTPCookie *)cookie __attribute__((annotate("hookkit:allow_inherited"))) {
    if(shdw_debug_bannerprobe) {
        shdw_banner_log_cookie(cookie, "storage");
    }
    %orig;
}

- (void)setCookies:(NSArray *)cookies forURL:(NSURL *)URL
    mainDocumentURL:(NSURL *)mainDocumentURL __attribute__((annotate("hookkit:allow_inherited"))) {
    if(shdw_debug_bannerprobe) {
        for(NSHTTPCookie *cookie in cookies) {
            shdw_banner_log_cookie(cookie, "storage-many");
        }
    }
    %orig;
}
%end
%end

%group shadowhook_bannerprobe_wkcookies
%hook WKHTTPCookieStore

- (void)setCookie:(NSHTTPCookie *)cookie
    completionHandler:(void (^)(void))completionHandler __attribute__((annotate("hookkit:allow_inherited"))) {
    if(shdw_debug_bannerprobe) {
        shdw_banner_log_cookie(cookie, "wkstore");
    }
    %orig;
}
%end
%end

%group shadowhook_bannerprobe_cookieheader
%hook NSHTTPCookie

+ (NSArray *)cookiesWithResponseHeaderFields:(NSDictionary *)headerFields forURL:(NSURL *)URL
    __attribute__((annotate("hookkit:allow_inherited"))) {
    NSArray *result = %orig;
    if(shdw_debug_bannerprobe) {
        for(NSHTTPCookie *cookie in result) {
            if([[cookie name] isEqualToString:@"xs"]) {
                shdw_diag_log("CSET xs=%s url=%s",
                              [[cookie value] UTF8String] ?: "",
                              [[URL absoluteString] UTF8String] ?: "");
                shdw_diag_backtrace("xshdr");
            } else if([[cookie name] isEqualToString:@"pk"] || [[cookie name] isEqualToString:@"pkTag"]) {
                shdw_diag_log("CSET %s len=%lu url=%s",
                              [[cookie name] UTF8String] ?: "",
                              (unsigned long)[[cookie value] length],
                              [[URL absoluteString] UTF8String] ?: "");
                shdw_diag_backtrace("xshdr");
            }
        }
    }
    return result;
}

+ (NSDictionary *)requestHeaderFieldsWithCookies:(NSArray *)cookies
    __attribute__((annotate("hookkit:allow_inherited"))) {
    if(shdw_debug_bannerprobe) {
        for(NSHTTPCookie *cookie in cookies) {
            if([[cookie name] isEqualToString:@"xs"]) {
                shdw_diag_log("CREQ xs=%s", [[cookie value] UTF8String] ?: "");
                shdw_diag_backtrace("xsreq");
            }
        }
    }
    return %orig;
}
%end
%end

%group shadowhook_bannerprobe_bodytrace
%hook NSURLRequest

- (NSData *)HTTPBody __attribute__((annotate("hookkit:allow_inherited"))) {
    NSData *body = %orig;
    if(shdw_debug_bannerprobe && [body length] > 32 && [body length] < 65536) {
        @try {
            NSString *text = [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
            if(text && ([text rangeOfString:@"gsStatus"].location != NSNotFound ||
                       [text rangeOfString:@"rhStatus"].location != NSNotFound ||
                       [text rangeOfString:@"isRooted"].location != NSNotFound)) {
                shdw_diag_log("NREQ %s", [[[self URL] absoluteString] UTF8String] ?: "");
                shdw_banner_log_text("NREQBODY", text, 2400);
                shdw_diag_backtrace("nreq");
            }
        } @catch(NSException *exception) {
        }
    }
    return body;
}
%end
%end

static BOOL shdw_banner_props_are_xs(NSDictionary *properties) {
    id name = [properties objectForKey:NSHTTPCookieName];
    return [name isKindOfClass:[NSString class]] && [(NSString *)name isEqualToString:@"xs"];
}

static void shdw_banner_log_cookie_create(NSDictionary *properties, const char *source) {
    id value = [properties objectForKey:NSHTTPCookieValue];
    shdw_diag_log("%s xs=%s", source,
                  [value isKindOfClass:[NSString class]] ? [(NSString *)value UTF8String] : "");
    shdw_diag_backtrace("xsmk");
}

%group shadowhook_bannerprobe_cookiecreate_class
%hook NSHTTPCookie

+ (id)cookieWithProperties:(NSDictionary *)properties __attribute__((annotate("hookkit:allow_inherited"))) {
    if(shdw_debug_bannerprobe && shdw_banner_props_are_xs(properties)) {
        shdw_banner_log_cookie_create(properties, "COOKCREATE");
    }
    return %orig;
}
%end
%end

%group shadowhook_bannerprobe_cookiecreate_init
%hook NSHTTPCookie

- (id)initWithProperties:(NSDictionary *)properties __attribute__((annotate("hookkit:allow_inherited"))) {
    if(shdw_debug_bannerprobe && shdw_banner_props_are_xs(properties)) {
        shdw_banner_log_cookie_create(properties, "COOKINIT");
    }
    return %orig;
}
%end
%end

%group shadowhook_bannerprobe_message
%hook WKScriptMessage

- (NSString *)name __attribute__((annotate("hookkit:allow_inherited"))) {
    NSString *messageName = %orig;
    if(shdw_debug_bannerprobe && messageName) {
        static void *lastMessage = NULL;
        if((__bridge void *)self != lastMessage) {
            lastMessage = (__bridge void *)self;
            id payload = nil;
            @try {
                payload = [self body];
            } @catch(NSException *exception) {
                payload = nil;
            }
            NSString *description = [payload isKindOfClass:[NSString class]]
                ? (NSString *)payload
                : [payload description];
            shdw_diag_log("WEB msg %s", [messageName UTF8String]);
            if([description length]) {
                shdw_banner_log_text("WEB msgbody", description, 900);
            }
        }
    }
    return messageName;
}
%end
%end

%group shadowhook_bannerprobe_webbridge
%hook WKUserContentController

- (void)addScriptMessageHandler:(id)scriptMessageHandler name:(NSString *)name
    __attribute__((annotate("hookkit:allow_inherited"))) {
    if(shdw_debug_bannerprobe && [name length]) {
        shdw_diag_log("WEB bridge %s", [name UTF8String]);
    }

    %orig;
}
%end
%end

// Periodic on-screen text dump: the only UI oracle available while the screen
// mirror channel is down. Walks every window and logs each label, button title,
// text view and accessibility label, plus the presented view-controller chain.
static void shdw_banner_dump_view(UIView *view, int depth) {
    if(!view || depth > 64) {
        return;
    }

    if([view isKindOfClass:[UILabel class]]) {
        NSString *text = ((UILabel *)view).text;
        if([text length]) {
            shdw_diag_log("VIS L%d label: %s", depth, [text UTF8String]);
        }
    } else if([view isKindOfClass:[UITextView class]]) {
        NSString *text = ((UITextView *)view).text;
        if([text length]) {
            shdw_diag_log("VIS L%d textview: %s", depth, [text UTF8String]);
        }
    } else if([view isKindOfClass:[UITextField class]]) {
        NSString *text = ((UITextField *)view).text;
        if([text length]) {
            shdw_diag_log("VIS L%d field: %s", depth, [text UTF8String]);
        }
    } else if([view isKindOfClass:[UIButton class]]) {
        NSString *text = [(UIButton *)view titleForState:UIControlStateNormal];
        if([text length]) {
            shdw_diag_log("VIS L%d button: %s", depth, [text UTF8String]);
        }
    } else if([view respondsToSelector:@selector(text)]) {
        id text = [view performSelector:@selector(text)];
        if([text isKindOfClass:[NSString class]] && [text length]) {
            shdw_diag_log("VIS L%d rawtext %s: %s", depth, object_getClassName(view), [text UTF8String]);
        }
    }

    // SwiftUI and custom-drawn text does not go through UILabel; its text is
    // only reachable as an accessibility string.
    NSString *acc = [view accessibilityLabel];
    if([acc length]) {
        shdw_diag_log("VIS L%d acc: %s", depth, [acc UTF8String]);
    }

    for(UIView *sub in view.subviews) {
        shdw_banner_dump_view(sub, depth + 1);
    }
}

// UIKit's private recursiveDescription carries class names, frames and the text
// of every subview, including hierarchies that never touch UILabel.
static void shdw_banner_dump_desc(UIView *view) {
    if(![view respondsToSelector:@selector(recursiveDescription)]) {
        shdw_diag_log("VIS DESC unavailable");
        return;
    }

    const char *utf8 = [[view recursiveDescription] UTF8String];
    size_t len = utf8 ? strlen(utf8) : 0;
    shdw_diag_log("VIS DESC begin len=%zu", len);

    for(size_t off = 0; off < len; off += 900) {
        size_t chunk = len - off < 900 ? len - off : 900;
        shdw_diag_log("VIS DESC %.*s", (int)chunk, utf8 + off);
    }
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
static void shdw_banner_dump_window(void) {
    UIApplication *app = [UIApplication sharedApplication];
    if(!app) {
        return;
    }

    NSArray<UIWindow *> *windows = app.windows;
    shdw_diag_log("VIS === dump windows=%lu", (unsigned long)windows.count);

    NSUInteger index = 0;
    for(UIWindow *window in windows) {
        if(!window) {
            continue;
        }

        shdw_diag_log("VIS W%lu %s level=%.1f hidden=%d key=%d",
                      (unsigned long)index++,
                      object_getClassName(window),
                      (double)window.windowLevel,
                      (int)window.isHidden,
                      (int)window.isKeyWindow);

        int guard = 0;
        for(UIViewController *vc = window.rootViewController; vc && guard < 12; vc = vc.presentedViewController, guard++) {
            shdw_diag_log("VIS VC %s", object_getClassName(vc));
        }

        shdw_banner_dump_view(window, 0);

        int webCount = 0;
        shdw_banner_dump_web_view(window, &webCount);

        if(window.rootViewController.presentedViewController) {
            shdw_banner_dump_desc(window);
        }
    }
}
#pragma clang diagnostic pop

static void shdw_banner_dump_schedule(int remaining) {
    if(remaining <= 0) {
        return;
    }

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        shdw_banner_dump_window();
        shdw_banner_dump_schedule(remaining - 1);
    });
}

void shdw_universal_bannerprobe(SHDWHookSession* hooks) {
    (void)hooks;
    if(!shdw_debug_bannerprobe) {
        return;
    }

    %init(shadowhook_bannerprobe_vc);
    %init(shadowhook_bannerprobe_label);
    %init(shadowhook_bannerprobe_nav);
    %init(shadowhook_bannerprobe_web);
    %init(shadowhook_bannerprobe_cookies);
    %init(shadowhook_bannerprobe_wkcookies);
    %init(shadowhook_bannerprobe_cookieheader);
    %init(shadowhook_bannerprobe_bodytrace);
    %init(shadowhook_bannerprobe_message);
    %init(shadowhook_bannerprobe_webbridge);

    Class cookieClass = objc_getClass("NSHTTPCookie");
    if(cookieClass && class_getClassMethod(cookieClass, @selector(cookieWithProperties:))) {
        %init(shadowhook_bannerprobe_cookiecreate_class);
    }
    if(cookieClass && class_getInstanceMethod(cookieClass, @selector(initWithProperties:))) {
        %init(shadowhook_bannerprobe_cookiecreate_init);
    }

    shdw_banner_dump_schedule(200);
}
