#ifndef shadow_diag_h
#define shadow_diag_h

#include <stddef.h>
#include <stdint.h>

void shdw_diag_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void shdw_diag_describe(char *out, size_t size, void *addr);
void shdw_diag_backtrace(const char *tag);
void shdw_diag_install(void);

// Master switch for the diagnostic lane: when 0 the log writer does nothing
// and the exit/signal instrumentation is never installed (pref: Debug_Diag).
extern int shdw_diag_enabled;

// Bisection: keep diagnostics but leave the process signal dispositions alone
// (pref: Debug_DiagNoSignal).
extern int shdw_diag_no_signals;

// Logging only: keep the trace lane armed without installing the exit or
// signal instrumentation the verdict phase would trip over (pref: Debug_Trace).
extern int shdw_diag_trace_only;

// Trace-only sub-mode: install the passthrough exit/terminate hooks so a
// silent self-exit is identified, without blocking or signal handlers
// (pref: Debug_ExitTrace).
extern int shdw_diag_exit_trace;

// Bisection: log every raw-svc site hit from external callers (pref:
// Debug_SvcTrace).
extern int shdw_diag_svc_trace;

// Diagnostic lane for the libsystem_kernel _exit stub, which no rebind
// can reach (pref: Debug_ExitProbe).
extern int shdw_diag_exit_probe;

// Diagnostic lane: turn the libsystem_kernel termination stubs into BRK
// traps so a call leaves a crash report naming its caller (pref:
// Debug_ExitBrk).
extern int shdw_diag_exit_brk;
void shdw_diag_install_exit_brk(void);

// Diagnostic lane: acknowledge CS_OPS_MARKKILL for this process without
// handing it to the kernel (pref: Debug_NoSelfMarkKill).
extern int shdw_diag_no_self_markkill;

// Heartbeat sampler for external kills (pref: Debug_Heartbeat).
extern int shdw_diag_heartbeat;

// Signal-disposition sampler: names the live owner of SIGSEGV/SIGTRAP after
// startup, so a detector replacing the diagnostic handler is visible
// (pref: Debug_SigWatch).
extern int shdw_diag_sigwatch;
void shdw_diag_install_exit_probe(void);
void *shdw_diag_raw_dlsym(const char *symbol);

// Raw-syscall unit lane switch: 0 = every lane, 1 = svc patching only,
// 2 = syscall/libc hooks only. Diagnostic bisection knob (Debug_SyscallLane).
extern int shdw_diag_syscall_lane;

// Diagnostic lane for the memory hooks: 1 logs every region returned to an
// external caller plus every restricted/point policy decision
// (pref: Debug_MemTrace). Budgeted; off in production.
extern int shdw_diag_mem_trace;

// Diagnostic lane: leave headerless executable regions visible to external
// region walkers (pref: Debug_MemOpaquePass).
extern int shdw_diag_mem_opaque_pass;

// Diagnostic lane: one-shot OS fingerprint dump at ctor (pref: Debug_EnvDump).
extern int shdw_diag_envdump_flag;
void shdw_diag_envdump_run(void);

// Diagnostic lane: log external filesystem probes whose path names a
// jailbreak artifact, plus dyld image enumeration (pref: Debug_PathTrace).
extern int shdw_diag_path_trace;

// Same lane without the artifact filter: log every hook-visible filesystem
// probe up to a fixed budget, whatever the path (pref: Debug_FsAll).
extern int shdw_diag_fs_all;

// Diagnostic lane: dump the ObjC surface (methods/ivars) of runtime classes
// whose names name the integrity stacks (pref: Debug_ObjcDump).
extern int shdw_diag_objc_dump;
void shdw_diag_fs_probe(const char *api, const char *path);
void shdw_diag_dyld_image(const char *api, int idx, const char *path);
void shdw_diag_dyld_count(unsigned seen, unsigned truth);

// Diagnostic lane: one line per queried OS surface (sysctl/sysctlbyname,
// exception ports, dyld image lookups) with the external caller and the
// value the process was handed (pref: Debug_ApiTrace).
extern int shdw_diag_api_trace;
void shdw_diag_apitrace(void *caller, const char *fmt, ...);
// Diagnostic lane: same as apitrace, but only when the caller address lies in
// an image whose path contains this token (pref: Debug_TraceImage).
extern char shdw_diag_trace_image[96];
void shdw_diag_trace_image_entry(void *caller, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

// Diagnostic lane: hand external callers the unfiltered dyld image table
// (pref: Debug_DyldTruth). Bisects whether a detector is tripped by the
// image-table filtering itself rather than by a real artifact.
extern int shdw_diag_dyld_truth;

// Diagnostic lane: external dlsym returns the stock address, not Shadow's
// replacement (pref: Debug_DlsymRaw). Bisects whether a detector's verdict
// comes from inspecting the resolved pointer itself.
extern int shdw_diag_dlsym_raw;

// Diagnostic lane (pref: Debug_OzTable): point the OZLivenessSDK captured
// cells for readlink (idx 80) and task_get_special_port (idx 13) at the
// system originals after the SDK resolves them. See dyld.x.
extern int shdw_diag_oz_table;

// Diagnostic lane (pref: Debug_OzTag): tag the six OZLivenessSDK `mov w30,#0xc`
// virtual-register initialisers so a poisoned (fp,lr) frame names its source.
extern int shdw_diag_oz_tag;

// Diagnostic lane (pref: Debug_OzRecord): at the 0xc fault dump the VM record
// the dispatcher selected (pool + (const - key) * 0x5a0), annotated.
extern int shdw_diag_oz_record;

// Diagnostic lane (pref: Debug_OzVerdictThread): park the libdispatch worker
// that receives OZ's 0xc verdict on a scratch stack and exit only that thread.
extern int shdw_diag_oz_verdict_thread;

// Diagnostic lane: republish ShadowCore in the enumerated dyld snapshot
// under a fixed framework path (pref: Debug_ExposeSelf).
extern int shdw_diag_expose_self;

// Diagnostic lane: log every entry of the filtered image snapshot once
// (pref: Debug_DyldDumpAll).
extern int shdw_diag_dyld_dump_all;

// Diagnostic lane: record one detector's interpreter-state transitions into a
// ring buffer for the fault dump (pref: Debug_StateProbe, spec
// "<image path suffix>|<siteRVA>|<resumeRVA>"). Off in production.
void shdw_diag_state_probe(const char *spec);

// Diagnostic lane: snapshot every GPR plus the top of the stack at each
// branch that leads into a detector's verdict funnel, then continue to the
// branch's original target (pref: Debug_FunnelProbe, spec
// "<image path suffix>;<siteRVA>:<resumeRVA>;..."). The ring is dumped on the
// first signal the process takes, so the last sample is the decision that
// killed it. Off in production.
void shdw_diag_funnel_probe(const char *spec);
void shdw_funnel_dump(const char *tag);

// Diagnostic lane: turn every inline `svc #0x80` in one detector image into a
// trapped, logged and replayed syscall (pref: Debug_InSvc, image path
// suffix). Off in production.
void shdw_diag_insvc_probe(const char *imageSuffix, uint64_t rangeStart,
                           uint64_t rangeEnd, int entryMode);

// Diagnostic lane: log one entry of the filtered dyld image snapshot the
// detector is handed (name, header, slide), for fault-time comparison.
void shdw_diag_dyld_snapshot_dump(const char *tag, uint32_t idx);

#endif
