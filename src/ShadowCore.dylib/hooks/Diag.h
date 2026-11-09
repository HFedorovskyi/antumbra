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

// Default-off: rewrite svc sites inside app-bundle images. Detector SDKs that
// hash their own __TEXT treat the rewrite as tampering and fail closed
// (pref: Debug_SvcAppImages).
extern int shdw_diag_svc_app_images;

// Diagnostic lane for the libsystem_kernel _exit stub, which no rebind
// can reach (pref: Debug_ExitProbe).
extern int shdw_diag_exit_probe;

// Diagnostic lane: turn the libsystem_kernel termination stubs into BRK
// traps so a call leaves a crash report naming its caller (pref:
// Debug_ExitBrk).
extern int shdw_diag_exit_brk;
void shdw_diag_install_exit_brk(void);

// Sparkasse/Promon SHIELD: one-shot hardware breakpoints on the framework's
// exit thunk (+0x430d9c) and its +load entry (+0x3c1be8) (pref: Debug_SpkBrk).
extern int shdw_diag_spkbrk;
// Sparkasse: clear the config singleton's verdict byte from a poller thread
// (pref: Debug_SpkFix). No debug registers involved.
extern int shdw_diag_spkfix;
// Sparkasse: log the framework's syscalls through its own dispatch stub.
extern int shdw_diag_spkstub;
// Sparkasse: return from the terminate-or-continue gate without either branch.
extern int shdw_diag_spkskip;
// Watch-only decoder probe (+0x406e50 call, +0x4038a4 entry). Pref:
// Debug_SpkDec.
extern int shdw_diag_spkdec;
// Watch-only message dump around the tag decoder. Pref: Debug_SpkMsg.
extern int shdw_diag_spkmsg;
// Verdict byte 0 only, no gate skip. Pref: Debug_SpkZero.
extern int shdw_diag_spkzero;
// Gate target resolution (four exec breakpoints). Pref: Debug_SpkGate.
extern int shdw_diag_spkgate;
// One-shot dump of the decrypted terminate chain. Pref: Debug_SpkMem.
extern int shdw_diag_spkmem;
// Exec breakpoint on the dispatch cell's svc target: names every syscall the
// image issues. Pref: Debug_SpkSvc.
extern int shdw_diag_spksvc;
extern int shdw_diag_spkforge;
extern int shdw_diag_spkevt;
extern int shdw_diag_spkrearm;
extern int shdw_diag_spksample;
extern int shdw_diag_spkhash;
extern int shdw_diag_spkcache;
extern int shdw_diag_spkexit;
extern int shdw_diag_spkbt;
extern int shdw_diag_spkscene;

// Diagnostic lane: acknowledge CS_OPS_MARKKILL for this process without
// handing it to the kernel (pref: Debug_NoSelfMarkKill).
extern int shdw_diag_no_self_markkill;

// Heartbeat sampler for external kills (pref: Debug_Heartbeat).
extern int shdw_diag_heartbeat;

// Signal-disposition sampler: names the live owner of SIGSEGV/SIGTRAP after
// startup, so a detector replacing the diagnostic handler is visible
// (pref: Debug_SigWatch).
extern int shdw_diag_sigwatch;

// Re-arm the diagnostic SIGTRAP handler in front of a later owner so a poison
// BRK swallowed by that owner still leaves a record (pref: Debug_SigRearm).
extern int shdw_diag_sigrearm;

// Slot-transition watcher: timestamp the rewrite of a detector's own once-slots
// and capture the writing thread's PC (pref: Debug_SlotWatch).
extern int shdw_diag_slotwatch;

// Per-thread PC ring sampler: on the fault dump, the faulting thread's last
// samples show which detector block was executing (pref: Debug_PcSample).
// Extra path fragment denied inside the SHIELD syscall lane (pref:
// Debug_DenySubstr).
extern char shdw_insvc_deny_substr[192];

extern int shdw_diag_pcsample;
extern int shdw_diag_pc_dump;
extern int shdw_diag_prm_dump;
extern int shdw_cell_shim_on;
extern int shdw_diag_no_waitrel;
void shdw_diag_pcsample_dump(const char *tag, uint32_t tid);
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

// Diagnostic lane (pref: Debug_MemShare): one-shot ctor snapshot of the
// share_mode/page accounting of every dyld image's __TEXT, walked region by
// region so page-granular COW splits from inline hooks are visible.
extern int shdw_diag_mem_share;
void shdw_mem_share_dump(void);

// Diagnostic lane (pref: Debug_MemShareTrace): the same submap fields for
// every region an external caller queries, i.e. what a detector is handed.
extern int shdw_diag_mem_share_trace;

// Sub-lane (pref: Debug_MemShareRaw): log the raw reply words instead of the
// decoded fields, to pin the layout of a short submap reply.
extern int shdw_diag_mem_share_raw;

// Normalization lane (pref: Debug_MemSplit): rewrite the short-submap reply
// for a COW/writable code page carved out of the dyld shared cache to the
// fields of its nearest clean cache fragment, so an external region walk sees
// a homogeneous mapping instead of inline-hook pages.
extern int shdw_diag_mem_split;

// Normalization lane (pref: Debug_MemTextMax): clear VM_PROT_WRITE from the
// max_protection of executable regions handed to external callers. A
// debug-signed launch maps bundled framework __TEXT run-writable (5/7) where
// a stock launch maps it r-x (5/5), which a region walker can read as
// tamper evidence.
extern int shdw_diag_mem_textmax;

// Flavor-9 reply logger (pref: Debug_MemExtInfo only). Flavor 9 is
// VM_REGION_BASIC_INFO_64 (count 9), not extended info, so there is no
// pages_dirtied/share_mode field to rewrite: Debug_MemExtDirt is dead and must
// stay off (w3 is the `shared` flag, w5 the offset low half).
extern int shdw_diag_mem_extinfo;
extern int shdw_diag_mem_extdirt;

// VM-frame dump at the 0xc fault (pref: Debug_VmFrame). After the epilogue the
// poisoned pair sits at sp_fault-0x10, so S = sp_fault-0x50 and the interpreter
// context is S-0xa00 -- which the kernel sigframe has already overwritten by
// the time SIGSEGV runs. The lane therefore cannot recover the hash state and
// is superseded by Debug_ExcCatch.
extern int shdw_diag_vmframe;

// JSON verdict scan at the 0x-c fault (pref: Debug_JsonScan). The faulting
// thread carries x24 = 0x6e6f73616572227b, the little-endian bytes `{"reason`,
// i.e. the VM is holding a JSON report literal. The handler walks the task's
// writable regions and dumps the first `{"reason` buffers so the detection
// reason string is recovered instead of inferred.
extern int shdw_diag_jsonscan;

// Mach exception ports: the OZ verdict BRK (OZ+0x3af93c) never reaches the
// SIGTRAP handler, so someone owns EXC_BREAKPOINT. Debug_ExcPorts logs the
// task/thread port owners over startup; Debug_ExcCatch takes the port, logs
// the VM context at the trap and resumes at pc+4 (pref: Debug_ExcPorts /
// Debug_ExcCatch).
extern int shdw_diag_excports;
extern int shdw_diag_exccatch;
extern int shdw_diag_excwatch;
extern int shdw_diag_svcforge;

// Production installer for the syscall-forge lane: starts the exception watch
// and the hardware-breakpoint sweep without the Debug_Diag instrumentation
// (no hooks, no logging, no signal work). Idempotent.
void shdw_diag_install_oz_forge(void);

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
// Same filter, emitted after the call with what the caller was handed
// (return value, errno, or the decoded result buffer).
void shdw_diag_trace_image_result(void *caller, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

// Diagnostic lane: hand external callers the unfiltered dyld image table
// (pref: Debug_DyldTruth). Bisects whether a detector is tripped by the
// image-table filtering itself rather than by a real artifact.
extern int shdw_diag_dyld_truth;

// Diagnostic lane: external dlsym returns the stock address, not Shadow's
// replacement (pref: Debug_DlsymRaw). Bisects whether a detector's verdict
// comes from inspecting the resolved pointer itself.
extern int shdw_diag_dlsym_raw;

// Diagnostic lane (pref: Debug_OzTable): after an OZLivenessSDK dlsym call,
// rewrite the SDK's captured result cells for readlink (idx 80) and
// task_get_special_port (idx 13) to their system originals, so the captured
// pointer table names real images. Never touches the enumeration cells.
extern int shdw_diag_oz_table;

// Diagnostic lane (pref: Debug_OzTag): rewrite OZ's six `mov w30,#0xc`
// virtual-register initialisers with distinct tags. If the (fp,lr) frame is
// poisoned from one of them, the fault lr names the site that supplied 0xc.
extern int shdw_diag_oz_tag;

// Diagnostic lane (pref: Debug_OzRecord): dump the VM record behind the 0xc
// fault (pool + (const - key) * 0x5a0) so the fail step's handler is named.
extern int shdw_diag_oz_record;

// Diagnostic lane (pref: Debug_OzVerdictThread): park the worker thread that
// takes OZ's 0xc verdict instead of letting the process die with it.
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

// Diagnostic lane: snapshot the record dispatcher's check-function pointer and
// its verdict around the call (pref: Debug_OzCall, image path suffix). Off in
// production.
void shdw_diag_oz_call_probe(const char *imageSuffix);

// Diagnostic lane: turn every inline `svc #0x80` in one detector image into a
// trapped, logged and replayed syscall (pref: Debug_InSvc, image path
// suffix). Off in production.
void shdw_diag_insvc_probe(const char *imageSuffix, uint64_t rangeStart,
                           uint64_t rangeEnd, int entryMode);

// Diagnostic lane: log one entry of the filtered dyld image snapshot the
// detector is handed (name, header, slide), for fault-time comparison.
void shdw_diag_dyld_snapshot_dump(const char *tag, uint32_t idx);

#endif
