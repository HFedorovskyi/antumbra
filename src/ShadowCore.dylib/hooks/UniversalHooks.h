#ifndef shdw_universal_hooks_h
#define shdw_universal_hooks_h

#import "../HookAdapterBridge.h"
#import "hooks.h"

void shdw_universal_dyld(SHDWHookSession *hooks);
void shdw_universal_filesystem_c(SHDWHookSession *hooks);
void shdw_universal_envvars_c(SHDWHookSession *hooks);
void shdw_universal_envpolicy(SHDWHookSession *hooks);
void shdw_universal_nsprocessinfo(SHDWHookSession *hooks);
void shdw_universal_passcode_status(SHDWHookSession *hooks);
void shdw_universal_mach_bootstrap(SHDWHookSession *hooks);
void shdw_universal_iokit(SHDWHookSession *hooks);
// Adopt the IOKit address a detector just resolved via dlsym: store it as the
// original and return the Shadow wrapper to hand back for this lookup. The
// framework is often dlopen'd with a local handle (invisible to
// dlsym(RTLD_DEFAULT)) and HookKit refuses entry patching these targets.
void *shdw_iokit_adopt_dlsym(const char *c_symbol, void *address);
void shdw_universal_low_level_c(SHDWHookSession *hooks);
void shdw_universal_antidebugging(SHDWHookSession *hooks);
void shdw_universal_codesigning(SHDWHookSession *hooks);
void shdw_universal_objc(SHDWHookSession *hooks);
void shdw_universal_objc_methodimpl(SHDWHookSession *hooks);
void shdw_universal_objc_methodimpl_detector(SHDWHookSession *hooks);
void shdw_universal_syscall(SHDWHookSession *hooks);
void shdw_universal_memory(SHDWHookSession *hooks);
void shdw_universal_sandbox(SHDWHookSession *hooks);
// Rewrite suspicious LC_LOAD_DYLIB names in the main executable's load commands
// (e.g. a link-time @rpath/Shadow.framework/Shadow) so a raw memory walk of the
// Mach-O header reads nothing suspicious. Injected Shadow adds no load command.
void shdw_hide_main_image_loadcmd_names(void);
void shdw_image_provenance_normalize(void);
void shdw_universal_hide_classes(SHDWHookSession *hooks);
void shdw_universal_symlookup(SHDWHookSession *hooks);
void shdw_universal_symaddrlookup(SHDWHookSession *hooks);
void shdw_universal_dynamic_libraries_extra(SHDWHookSession *hooks);
void shdw_universal_import_slot_protection(SHDWHookSession *hooks);
void shdw_universal_filesystem_objc(SHDWHookSession *hooks);
void shdw_universal_foundation_objc(SHDWHookSession *hooks);
void shdw_universal_hide_apps(SHDWHookSession *hooks);
void shdw_universal_url_scheme(SHDWHookSession *hooks);
void shdw_universal_foundation_uikit(SHDWHookSession *hooks);
void shdw_universal_screencapture(SHDWHookSession *hooks);
void shdw_universal_webcookiesafe(SHDWHookSession *hooks);
void shdw_universal_bannerprobe(SHDWHookSession *hooks);
void shdw_universal_nsarray(SHDWHookSession *hooks);
void shdw_universal_nsdictionary(SHDWHookSession *hooks);
void shdw_universal_nsdata(SHDWHookSession *hooks);
void shdw_universal_nsbundle(SHDWHookSession *hooks);
void shdw_universal_nsfilehandle(SHDWHookSession *hooks);
void shdw_universal_nsfileversion(SHDWHookSession *hooks);
void shdw_universal_nsfilewrapper(SHDWHookSession *hooks);
void shdw_universal_nsstring(SHDWHookSession *hooks);
void shdw_universal_nsurl(SHDWHookSession *hooks);
void shdw_universal_nsthread(SHDWHookSession *hooks);
void shdw_universal_nstask(SHDWHookSession *hooks);
void shdw_universal_user_defaults(SHDWHookSession *hooks);

void shdw_universal_rebind_image(SHDWHookSession *hooks,
                                 const void *imageHeader);
void shdw_universal_antidebugging_rebind_image(SHDWHookSession *hooks,
                                               const void *imageHeader);
// Image-scoped ObjC-introspection rebinds for late-loaded detector frameworks.
void shdw_universal_objc_rebind_image(SHDWHookSession *hooks,
                                      const void *imageHeader);
void shdw_universal_objc_methodimpl_rebind_image(SHDWHookSession *hooks,
                                                 const void *imageHeader);
void shdw_universal_feature_filesystem_metadata(SHDWHookSession *hooks);
void shdw_universal_feature_symbolic_links(SHDWHookSession *hooks);
void shdw_universal_feature_launchservices_url_filtering(
    SHDWHookSession *hooks);
void *shdw_universal_file_exists_original(void);
void *shdw_universal_file_exists_replacement(void);
void *shdw_universal_readable_file_original(void);

// Task exception ports owned by the jailbreak's exception-based hooking engine
// (ElleKit's EKLaunchExceptionHandler). Shadow pre-initialises that handler, so
// it records the ports the handler adds and the sandbox lane hides exactly
// those from external probes — leaving the app's own handlers untouched.
extern mach_port_t shdw_ek_exc_ports[EXC_TYPES_COUNT];
extern int shdw_ek_exc_port_count;

#endif
