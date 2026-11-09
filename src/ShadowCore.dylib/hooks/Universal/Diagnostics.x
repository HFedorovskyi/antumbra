#import "UniversalHooks.h"

#import "../../HookCoordinator.h"

// Temporary diagnostic lane: durable on-disk trace of detector trips, hook
// install steps and every way a process can end. Plain libc only so it works
// before Foundation is usable; the recursion guard keeps a hook that logs
// from re-entering this writer.

#include <dlfcn.h>
#include <errno.h>
#include <execinfo.h>
#include <fcntl.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach/exc.h>
#include <mach/mach.h>
#include <mach/arm/thread_status.h>
#include <mach/vm_map.h>
#include <mach/vm_region.h>
#include <libkern/OSCacheControl.h>

// mach_vm.h is "unsupported" in the iPhoneOS SDK; the prototype is the same
// one mem.x declares for its hook.
extern kern_return_t mach_vm_region(vm_map_read_t target_task, mach_vm_address_t* address, mach_vm_size_t* size, vm_region_flavor_t flavor, vm_region_info_t info, mach_msg_type_number_t* infoCnt, mach_port_t* object_name);
#include <objc/runtime.h>
#include <objc/message.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/ucontext.h>
#include <time.h>
#include <unistd.h>

#if __has_feature(ptrauth_calls)
#include <ptrauth.h>
#endif

int shdw_diag_enabled = 0;
int shdw_diag_no_signals = 0;
int shdw_diag_trace_only = 0;
int shdw_diag_exit_trace = 0;
static int shdw_diag_fd = -1;
static _Thread_local int shdw_diag_busy = 0;
static char shdw_diag_path[PATH_MAX] = {0};

static void shdw_diag_open(void) {
    char dir[PATH_MAX];
    const char *home = getenv("HOME");

    if (home && home[0]) {
        snprintf(dir, sizeof dir, "%s/Library/Caches", home);
        mkdir(dir, 0755);
    } else {
        snprintf(dir, sizeof dir, "/tmp");
    }

    snprintf(shdw_diag_path, sizeof shdw_diag_path, "%s/shdwdiag.log", dir);
    shdw_diag_fd = open(shdw_diag_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
}

void shdw_spk_munged_dump(const char *tag, uint64_t lr_off);

void shdw_diag_log(const char *fmt, ...) {
    if (!shdw_diag_enabled || shdw_diag_busy) {
        return;
    }

    shdw_diag_busy = 1;

    struct timespec ts = {0};
    clock_gettime(CLOCK_REALTIME, &ts);

    char line[2048];
    int n = snprintf(line, sizeof line, "%ld.%03ld pid=%d ",
                     (long)ts.tv_sec, (long)(ts.tv_nsec / 1000000), getpid());

    va_list ap;
    va_start(ap, fmt);
    n += vsnprintf(line + n, sizeof line - (size_t)n, fmt, ap);
    va_end(ap);

    if (n < 0) {
        n = 0;
    }
    if (n > (int)sizeof line - 2) {
        n = (int)sizeof line - 2;
    }
    line[n++] = '\n';

    if (shdw_diag_fd < 0) {
        shdw_diag_open();
    }
    if (shdw_diag_fd >= 0) {
        ssize_t ignored = write(shdw_diag_fd, line, (size_t)n);
        // Apps that close every descriptor they do not own (closefrom) after
        // our ctor silently kill this log. Reopen rather than lose the rest
        // of the run.
        if (ignored != (ssize_t)n && errno == EBADF) {
            shdw_diag_fd = -1;
            shdw_diag_open();
            if (shdw_diag_fd >= 0) {
                ignored = write(shdw_diag_fd, line, (size_t)n);
            }
        }
        (void)ignored;
    }

    shdw_diag_busy = 0;
}

void shdw_diag_describe(char *out, size_t size, void *addr) {
    Dl_info info;

    if (addr && dladdr(addr, &info) && info.dli_fname) {
        unsigned long off = (unsigned long)((uintptr_t)addr -
                                            (uintptr_t)info.dli_fbase);
        if (info.dli_sname) {
            snprintf(out, size, "%s+0x%lx (%s)", info.dli_fname, off,
                     info.dli_sname);
        } else {
            snprintf(out, size, "%s+0x%lx", info.dli_fname, off);
        }
        return;
    }

    snprintf(out, size, "%p", addr);
}

// Same as shdw_diag_describe with the image path reduced to its basename, so
// long roothide preboot paths do not eat the whole buffer.
static void shdw_diag_describe_short(char *out, size_t size, void *addr) {
    Dl_info info;

    if (addr && dladdr(addr, &info) && info.dli_fname) {
        const char *base = strrchr(info.dli_fname, '/');
        unsigned long off = (unsigned long)((uintptr_t)addr -
                                            (uintptr_t)info.dli_fbase);
        base = base ? base + 1 : info.dli_fname;
        if (info.dli_sname) {
            snprintf(out, size, "%s+0x%lx(%s)", base, off, info.dli_sname);
        } else {
            snprintf(out, size, "%s+0x%lx", base, off);
        }
        return;
    }

    snprintf(out, size, "%p", addr);
}

int shdw_diag_svc_app_images = 0;
int shdw_diag_api_trace = 0;
int shdw_diag_dyld_truth = 0;
int shdw_diag_expose_self = 0;
int shdw_diag_dlsym_raw = 0;
int shdw_diag_oz_table = 0;
int shdw_diag_oz_tag = 0;
int shdw_diag_oz_record = 0;
int shdw_diag_oz_verdict_thread = 0;
int shdw_diag_dyld_dump_all = 0;
int shdw_diag_vmframe = 0;
int shdw_diag_jsonscan = 0;

// Verdict-thread parking. OZ's jailbreak verdict is delivered as a deliberate
// jump to a null virtual pc (pc==lr<0x10000) on a libdispatch worker; the fault
// carries the verdict record pool in x0. Handing that SIGSEGV to the original
// disposition kills the process even though only the verdict thread is doomed,
// so with this lane on the thread is moved to a scratch stack and exited.
static uint8_t shdw_verdict_stack[0x10000] __attribute__((aligned(16)));
static void shdw_verdict_exit_stub(void) {
    pthread_exit(NULL);
}
static int shdw_diag_api_lines = 0;

// One line per queried surface, tagged with the external caller: the point is
// the sequence a detector runs and the value each call handed back, not the
// call itself.
void shdw_diag_apitrace(void *caller, const char *fmt, ...) {
    if (!shdw_diag_api_trace || !shdw_diag_enabled) {
        return;
    }
    if (__atomic_add_fetch(&shdw_diag_api_lines, 1, __ATOMIC_RELAXED) > 30000) {
        return;
    }

    char who[160];
    char msg[768];
    va_list ap;

    shdw_diag_describe_short(who, sizeof who, caller);
    va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);
    shdw_diag_log("APITRACE caller=%s %s", who, msg);
}

char shdw_diag_trace_image[96];

static _Thread_local int shdw_diag_trace_busy = 0;

void shdw_diag_trace_image_entry(void *caller, const char *fmt, ...) {
    if (!shdw_diag_api_trace || !shdw_diag_trace_image[0] || !caller ||
        shdw_diag_trace_busy) {
        return;
    }
    shdw_diag_trace_busy = 1;
    Dl_info info;
    if (dladdr(caller, &info) && info.dli_fname &&
        strstr(info.dli_fname, shdw_diag_trace_image) != NULL) {
        char msg[640];
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(msg, sizeof msg, fmt, ap);
        va_end(ap);
        shdw_diag_log("IMGTRACE caller=%p+0x%lx %s", (void *)info.dli_fbase,
                      (unsigned long)((uintptr_t)caller - (uintptr_t)info.dli_fbase),
                      msg);
    }
    shdw_diag_trace_busy = 0;
}

void shdw_diag_trace_image_result(void *caller, const char *fmt, ...) {
    if (!shdw_diag_api_trace || !shdw_diag_trace_image[0] || !caller ||
        shdw_diag_trace_busy) {
        return;
    }
    shdw_diag_trace_busy = 1;
    Dl_info info;
    if (dladdr(caller, &info) && info.dli_fname &&
        strstr(info.dli_fname, shdw_diag_trace_image) != NULL) {
        char msg[640];
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(msg, sizeof msg, fmt, ap);
        va_end(ap);
        shdw_diag_log("IMGRET caller=%p+0x%lx %s", (void *)info.dli_fbase,
                      (unsigned long)((uintptr_t)caller - (uintptr_t)info.dli_fbase),
                      msg);
    }
    shdw_diag_trace_busy = 0;
}

// Raw stack scan. Detector cold paths stomp their own frame record before
// trapping (HceSdk writes 0x18 over [x29] and [x29+8] right before an
// objc_msgSend(0xc6, 0x18)), so the frame-pointer walk stops after one frame.
// The frames above sp are still intact: report the words there that resolve
// into non-system images.
// Dump every integer register plus sp/fp/lr. Cold paths that destroy their
// own frame record leave the small immediates they crashed on visible only
// in the argument registers.
static void shdw_diag_dump_regs(const char *tag, ucontext_t *uc, uintptr_t pcv,
                                uintptr_t lrv) {
    if(!uc) {
        return;
    }

    const uint64_t* x = uc->uc_mcontext->__ss.__x;

    for (int i = 0; i < 29; i++) {
        shdw_diag_log("  %s reg x%02d=%p", tag, i, (void*)(uintptr_t)x[i]);
    }

    shdw_diag_log("  %s reg pc=%p sp=%p fp=%p lr=%p", tag, (void*)pcv,
                  (void*)arm_thread_state64_get_sp(uc->uc_mcontext->__ss),
                  (void*)arm_thread_state64_get_fp(uc->uc_mcontext->__ss),
                  (void*)lrv);
}

// Faulting objects are untrusted: mach_vm_read refuses an unmapped address
// instead of taking a second fault inside the handler.
static void shdw_diag_peek_words(const char *tag, uintptr_t base, size_t off,
                                 size_t bytes) {
    if(!base || !bytes || bytes > 64 || bytes % 8) {
        return;
    }

    uint64_t words[8] = {0};
    vm_size_t out = 0;
    kern_return_t kr = vm_read_overwrite(
        mach_task_self(), (vm_address_t)(base + off), (vm_size_t)bytes,
        (vm_address_t)words, &out);
    if(kr != KERN_SUCCESS || out != bytes) {
        shdw_diag_log("  %s base=%p off=0x%lx unreadable(%d)", tag, (void*)base,
                      (unsigned long)off, (int)kr);
        return;
    }

    char line[160];
    size_t pos = 0;
    for(size_t i = 0; i < bytes / 8 && pos < sizeof line - 24; i++) {
        pos += (size_t)snprintf(line + pos, sizeof line - pos, " %llx",
                                (unsigned long long)words[i]);
    }
    shdw_diag_log("  %s base=%p off=0x%lx:%s", tag, (void*)base,
                  (unsigned long)off, line);
}

static void shdw_diag_dump_block(const char *tag, uintptr_t addr, size_t bytes) {
    for (size_t off = 0; off < bytes; off += 0x40) {
        shdw_diag_peek_words(tag, addr, off, 0x40);
    }
}

// ASCII rendering of a live buffer (the JSON verdict is text, hex wastes the
// line budget). Non-printables become '.', backslash is hidden so the log line
// stays one line.
static void shdw_diag_dump_ascii(const char *tag, uintptr_t addr, size_t bytes) {
    static uint8_t buf[512];
    char line[200];
    vm_size_t got = 0;
    size_t pos = 0;

    if(bytes > sizeof buf) {
        bytes = sizeof buf;
    }
    if(!addr || !bytes) {
        return;
    }
    if(vm_read_overwrite(mach_task_self(), (vm_address_t)addr, (vm_size_t)bytes,
                         (vm_address_t)buf, &got) != KERN_SUCCESS || !got) {
        shdw_diag_log("  %s %p unreadable", tag, (void*)addr);
        return;
    }
    for(size_t i = 0; i < got; i++) {
        unsigned char c = buf[i];

        line[pos++] = (c >= 0x20 && c < 0x7f && c != '\\') ? (char)c : '.';
        if(pos == sizeof line - 1) {
            line[pos] = 0;
            shdw_diag_log("  %s %p: %s", tag, (void*)(addr + i + 1 - pos), line);
            pos = 0;
        }
    }
    if(pos) {
        line[pos] = 0;
        shdw_diag_log("  %s %p: %s", tag, (void*)(addr + got - pos), line);
    }
}

// Walks the frame-pointer chain of the trapping thread. The VM runs on the
// detector's own stack, so a poisoned (fp,lr) return pair shows up here as a
// link whose saved lr is a non-code value. vm_read_overwrite keeps a racing fp
// from faulting inside the exception handler.
static void shdw_diag_fp_walk(const char *tag, uintptr_t fp, uintptr_t sp) {
    uint64_t f[32];
    uint64_t l[32];
    int n = 0;
    uintptr_t cur = fp;

    while(n < 32 && cur >= sp && (cur & 7) == 0) {
        uint64_t w[2] = {0, 0};
        vm_size_t out = 0;

        if(vm_read_overwrite(mach_task_self(), (vm_address_t)cur, 16,
                             (vm_address_t)w, &out) != KERN_SUCCESS ||
           out != 16) {
            break;
        }
        f[n] = (uint64_t)cur;
        l[n] = w[1];
        n++;
        if(w[0] <= cur || (w[0] & 7) || w[0] - sp > (1ull << 24)) {
            break;
        }
        cur = (uintptr_t)w[0];
    }
    for(int i = 0; i < n; i += 4) {
        char line[256];
        size_t pos = 0;

        for(int j = i; j < n && j < i + 4; j++) {
            pos += (size_t)snprintf(line + pos, sizeof line - pos,
                                    " f%d=%#llx l%d=%#llx", j,
                                    (unsigned long long)f[j], j,
                                    (unsigned long long)l[j]);
        }
        shdw_diag_log("  %s n=%d%s", tag, n, line);
    }
}

// The fatal jump carries x24 = `{"reason` in a register, i.e. the VM holds a
// JSON report literal when it decides. Walk the task's writable regions and
// dump every buffer that starts with that literal: the report body names the
// check that failed, which the external calls never do. Allocation-free so it
// can run inside the SIGSEGV handler; 64 KB window and 600 MB cap keep it
// bounded.
#define SHDW_JSON_WINDOW (64u * 1024u)
#define SHDW_JSON_CAP (600ull << 20)
static void shdw_diag_json_scan(void) {
    static uint8_t win[SHDW_JSON_WINDOW];
    static const char pat[8] = { '{', '"', 'r', 'e', 'a', 's', 'o', 'n' };
    mach_vm_address_t addr = 0;
    unsigned long long scanned = 0;
    int hits = 0;
    int guard = 0;

    while(hits < 3 && scanned < SHDW_JSON_CAP && guard++ < 20000) {
        mach_vm_size_t size = 0;
        vm_region_basic_info_data_64_t bi;
        mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t obj = MACH_PORT_NULL;
        kern_return_t kr = mach_vm_region(mach_task_self(), &addr, &size,
                                          VM_REGION_BASIC_INFO_64,
                                          (vm_region_info_t)&bi, &cnt, &obj);

        if(obj != MACH_PORT_NULL) {
            mach_port_deallocate(mach_task_self(), obj);
        }
        if(kr != KERN_SUCCESS || size == 0) {
            break;
        }
        if((bi.protection & (VM_PROT_READ | VM_PROT_WRITE)) ==
               (VM_PROT_READ | VM_PROT_WRITE) && size >= 16) {
            mach_vm_size_t seg = size < SHDW_JSON_CAP ? size : SHDW_JSON_CAP;

            for(mach_vm_size_t off = 0; off + 8 <= seg && hits < 3;
                off += SHDW_JSON_WINDOW) {
                vm_size_t want = (vm_size_t)((seg - off) < SHDW_JSON_WINDOW
                                                 ? (seg - off)
                                                 : SHDW_JSON_WINDOW);
                vm_size_t got = 0;

                if(vm_read_overwrite(mach_task_self(),
                                     (vm_address_t)(addr + off), want,
                                     (vm_address_t)win, &got) != KERN_SUCCESS ||
                   got < 8) {
                    continue;
                }
                scanned += got;
                for(vm_size_t i = 0; i + 8 <= got; i++) {
                    if(memcmp(win + i, pat, 8) == 0) {
                        uintptr_t hit = (uintptr_t)(addr + off + i);

                        shdw_diag_log("JSONSCAN hit=%d addr=%p region=%p+0x%llx "
                                      "off=0x%llx", hits, (void*)hit,
                                      (void*)(uintptr_t)addr,
                                      (unsigned long long)size,
                                      (unsigned long long)(off + i));
                        shdw_diag_dump_ascii("json", hit, 384);
                        hits++;
                        i += 384;
                    }
                    if(scanned >= SHDW_JSON_CAP) {
                        break;
                    }
                }
            }
        }
        if((mach_vm_address_t)(addr + size) <= addr) {
            break;
        }
        addr += size;
    }
    shdw_diag_log("JSONSCAN done hits=%d bytes=%llu", hits, scanned);
}

// A saved link register always points just past a BL. Requiring that byte
// pattern rejects the stale pointers a plain word scan picks up.
static BOOL shdw_diag_is_return_address(uintptr_t word) {
    Dl_info dl;

    if(word < 0x1000 || !dladdr((void*)word, &dl) || !dl.dli_fname) {
        return NO;
    }

    if(strncmp(dl.dli_fname, "/usr/lib/", 9) == 0 ||
       strncmp(dl.dli_fname, "/System/", 8) == 0) {
        return NO;
    }

    uint32_t insn = *(const uint32_t*)(word - 4);
    return (insn >> 26) == 0x25;
}

__attribute__((unused)) static void shdw_diag_stack_scan(const char *tag, ucontext_t *uc) {
    if(!uc) {
        return;
    }

    uintptr_t sp = (uintptr_t)arm_thread_state64_get_sp(uc->uc_mcontext->__ss);

    if(!sp) {
        return;
    }

    vm_address_t region = sp;
    vm_size_t region_size = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object_name = MACH_PORT_NULL;

    if(vm_region_64(mach_task_self(), &region, &region_size,
                    VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info,
                    &info_count, &object_name) != KERN_SUCCESS) {
        return;
    }

    if(object_name != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), object_name);
    }

    if(region > sp || region_size < sizeof(uintptr_t)) {
        return;
    }

    size_t avail = (size_t)(region + region_size - sp);
    size_t bytes = avail < (size_t)(64 * 1024) ? avail : (size_t)(64 * 1024);
    size_t words = bytes / sizeof(uintptr_t);
    const uintptr_t* stack = (const uintptr_t*)sp;
    int logged = 0;

    for(size_t i = 0; i < words && logged < 48; i++) {
        uintptr_t word = stack[i];

        if(!shdw_diag_is_return_address(word)) {
            continue;
        }

        char desc[512];
        shdw_diag_describe(desc, sizeof desc, (void*)word);
        shdw_diag_log("  %s stack[%zu] sp+0x%zx %s", tag, i,
                      i * sizeof(uintptr_t), desc);
        logged++;
    }
}

// dladdr takes the dyld lock, and a fault raised inside dyld/ObjC setup holds
// that very lock, so symbolizing every stack word in the handler deadlocks the
// process. The ranges are snapshotted once at install instead: the handler then
// resolves words with plain comparisons and no loader call.
typedef struct {
    uintptr_t base;
    uintptr_t end;
    const char *name;
} shdw_diag_img_range_t;

#define SHDW_DIAG_IMG_MAX 1600

static shdw_diag_img_range_t shdw_diag_imgs[SHDW_DIAG_IMG_MAX];
static int shdw_diag_img_count = 0;

static void shdw_diag_snapshot_images(void) {
    uint32_t count = _dyld_image_count();
    int n = 0;

    for(uint32_t i = 0; i < count && n < SHDW_DIAG_IMG_MAX; i++) {
        const struct mach_header *header = _dyld_get_image_header(i);
        const char *name = _dyld_get_image_name(i);

        if(!header || !name) {
            continue;
        }

        const struct mach_header_64 *h64 = (const struct mach_header_64 *)header;
        const uint8_t *lc = (const uint8_t *)(h64 + 1);
        uintptr_t lo = ~(uintptr_t)0;
        uintptr_t hi = 0;

        for(uint32_t c = 0; c < h64->ncmds; c++) {
            const struct load_command *cmd = (const struct load_command *)lc;

            if(cmd->cmdsize < sizeof(struct load_command)) {
                break;
            }
            if(cmd->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg =
                    (const struct segment_command_64 *)cmd;

                // __PAGEZERO has vmaddr 0 and would swallow the whole address
                // space; every real segment starts above it.
                if(seg->vmaddr != 0 && seg->vmsize != 0) {
                    if(seg->vmaddr < lo) {
                        lo = seg->vmaddr;
                    }
                    if(seg->vmaddr + seg->vmsize > hi) {
                        hi = seg->vmaddr + seg->vmsize;
                    }
                }
            }
            lc += cmd->cmdsize;
        }

        uintptr_t end = (uintptr_t)header + 0x4000;
        if(lo != ~(uintptr_t)0 && hi > lo) {
            end = (uintptr_t)header + (hi - lo);
        }

        shdw_diag_imgs[n].base = (uintptr_t)header;
        shdw_diag_imgs[n].end = end;
        shdw_diag_imgs[n].name = name;
        n++;
    }

    shdw_diag_img_count = n;
}

static const char *shdw_diag_image_for_word(uintptr_t word, uintptr_t *offset) {
    for(int i = 0; i < shdw_diag_img_count; i++) {
        if(word >= shdw_diag_imgs[i].base && word < shdw_diag_imgs[i].end) {
            *offset = word - shdw_diag_imgs[i].base;
            return shdw_diag_imgs[i].name;
        }
    }
    return NULL;
}

static uint64_t shdw_diag_peek(uintptr_t address, size_t size);
static void shdw_diag_dump_block(const char *tag, uintptr_t addr, size_t bytes);

static void shdw_diag_dump_stack_raw(const char *tag, ucontext_t *uc) {
    if(!uc) {
        return;
    }

    uintptr_t sp = (uintptr_t)arm_thread_state64_get_sp(uc->uc_mcontext->__ss);
    uintptr_t fp = (uintptr_t)arm_thread_state64_get_fp(uc->uc_mcontext->__ss);

    if(sp < 0x10000) {
        return;
    }

    // The OZ VM swaps sp into its own context buffer, so the poisoned saved
    // frame sits below the fault sp (the epilogue already ran add sp, sp, #N
    // before the ret). Walk down before walking up.
    for(int i = 96; i >= 1; i--) {
        uintptr_t addr = sp - (uintptr_t)i * 8;
        uint64_t word = shdw_diag_peek(addr, 8);
        uintptr_t off = 0;
        const char *name = word >= 0x10000 ? shdw_diag_image_for_word((uintptr_t)word, &off) : NULL;

        if(name) {
            const char *base = strrchr(name, '/');
            shdw_diag_log("  %s stk sp-0x%x = 0x%016llx %s+0x%lx", tag, i * 8,
                          (unsigned long long)word, base ? base + 1 : name,
                          (unsigned long)off);
        } else {
            shdw_diag_log("  %s stk sp-0x%x = 0x%016llx", tag, i * 8,
                          (unsigned long long)word);
        }
    }

    const uintptr_t* stack = (const uintptr_t*)sp;

    for(int i = 0; i < 160; i++) {
        uintptr_t word = stack[i];
        uintptr_t off = 0;
        const char *name = word >= 0x10000 ? shdw_diag_image_for_word(word, &off) : NULL;

        if(name) {
            const char *base = strrchr(name, '/');
            shdw_diag_log("  %s stk sp+0x%x = 0x%016llx %s+0x%lx", tag, i * 8,
                          (unsigned long long)word, base ? base + 1 : name,
                          (unsigned long)off);
        } else {
            shdw_diag_log("  %s stk sp+0x%x = 0x%016llx", tag, i * 8,
                          (unsigned long long)word);
        }
    }

    for(int i = 0; i < 24; i++) {
        if(fp < sp || fp >= sp + 0x40000 || (fp & 7)) {
            break;
        }

        uintptr_t next = ((const uintptr_t*)fp)[0];
        uintptr_t lr = ((const uintptr_t*)fp)[1];

        shdw_diag_log("  %s fpc[%d] @0x%016llx lr=0x%016llx next=0x%016llx",
                      tag, i, (unsigned long long)fp, (unsigned long long)lr,
                      (unsigned long long)next);

        if(next <= fp) {
            break;
        }

        fp = next;
    }
}

// The protected entry paths funnel through a state machine: the context
// keeps the current state at +0x5c and the jump table dispatches on it.
// When one of its cold blocks traps, the surviving context pointer is in
// x19, so its slots name the failed check and the buffer it read.
static BOOL shdw_diag_can_read(uintptr_t addr) {
    vm_address_t region = (vm_address_t)addr;
    vm_size_t region_size = 0;
    vm_region_basic_info_data_64_t vinfo;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object = MACH_PORT_NULL;

    if(vm_region_64(mach_task_self(), &region, &region_size,
                    VM_REGION_BASIC_INFO_64, (vm_region_info_t)&vinfo,
                    &count, &object) != KERN_SUCCESS) {
        return NO;
    }

    if(object != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), object);
    }

    if(!(vinfo.protection & VM_PROT_READ) || addr < region) {
        return NO;
    }

    return region_size - (addr - region) >= sizeof(uintptr_t);
}


typedef int (*shdw_proc_regionfilename_fn)(int pid, uint64_t address,
                                           void *buffer, uint32_t buffersize);

static void shdw_diag_region(const char *tag, const char *what, uintptr_t addr) {
    if(addr < 0x10000) {
        shdw_diag_log("  %s region %s addr=%p invalid", tag, what, (void*)addr);
        return;
    }

    vm_address_t region = (vm_address_t)addr;
    vm_size_t region_size = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object = MACH_PORT_NULL;
    kern_return_t kr = vm_region_64(mach_task_self(), &region, &region_size,
                                    VM_REGION_BASIC_INFO_64,
                                    (vm_region_info_t)&info, &count, &object);

    char path[PATH_MAX];
    path[0] = 0;

    static shdw_proc_regionfilename_fn rrf = NULL;
    static BOOL tried = NO;

    if(!tried) {
        tried = YES;
        rrf = (shdw_proc_regionfilename_fn)dlsym(RTLD_DEFAULT,
                                                 "proc_regionfilename");
    }

    if(rrf && rrf(getpid(), (uint64_t)addr, path, sizeof path) <= 0) {
        path[0] = 0;
    }

    if(object != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), object);
    }

    if(kr != KERN_SUCCESS) {
        shdw_diag_log("  %s region %s addr=%p kr=%d file=%s", tag, what,
                      (void*)addr, (int)kr, path);
        return;
    }

    shdw_diag_log("  %s region %s addr=%p base=%p size=%#llx prot=%d/%d "
                  "off=%#llx shared=%d file=%s",
                  tag, what, (void*)addr, (void*)region,
                  (unsigned long long)region_size,
                  (int)info.protection, (int)info.max_protection,
                  (unsigned long long)info.offset, (int)info.shared,
                  path);
}

static void shdw_diag_walk(const char *tag, uintptr_t from, uintptr_t len) {
    if(from < 0x10000 || !len) {
        return;
    }

    vm_address_t addr = (vm_address_t)from;
    vm_address_t end = (vm_address_t)(from + len);

    shdw_diag_log("  %s walk %p..%p", tag, (void*)from, (void*)end);

    while(addr < end) {
        vm_size_t size = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t object = MACH_PORT_NULL;
        vm_address_t region = addr;

        if(vm_region_64(mach_task_self(), &region, &size,
                        VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info,
                        &count, &object) != KERN_SUCCESS) {
            shdw_diag_log("  %s walk %p stop", tag, (void*)addr);
            return;
        }

        char path[PATH_MAX];
        path[0] = 0;

        static shdw_proc_regionfilename_fn rrf2 = NULL;
        static BOOL tried2 = NO;

        if(!tried2) {
            tried2 = YES;
            rrf2 = (shdw_proc_regionfilename_fn)dlsym(RTLD_DEFAULT,
                                                      "proc_regionfilename");
        }

        if(rrf2 && rrf2(getpid(), (uint64_t)region, path, sizeof path) <= 0) {
            path[0] = 0;
        }

        if(object != MACH_PORT_NULL) {
            mach_port_deallocate(mach_task_self(), object);
        }

        char head[48];
        head[0] = 0;

        if((info.protection & VM_PROT_READ) && region + 16 <= end) {
            const unsigned *w = (const unsigned*)region;
            snprintf(head, sizeof head, " %08x %08x %08x %08x",
                     w[0], w[1], w[2], w[3]);
        }

        shdw_diag_log("  %s walk %p size=%#llx prot=%d/%d off=%#llx %s%s",
                      tag, (void*)region, (unsigned long long)size,
                      (int)info.protection, (int)info.max_protection,
                      (unsigned long long)info.offset, path, head);

        if(size == 0) {
            return;
        }

        addr = region + size;
    }
}

static void shdw_diag_hex(const char *tag, const char *what, uintptr_t addr,
                          unsigned len) {
    if(addr < 0x10000) {
        return;
    }

    shdw_diag_log("  %s hex %s @%p len=%u", tag, what, (void*)addr, len);

    for(unsigned off = 0; off < len; off += 16) {
        uintptr_t at = addr + off;

        if(!shdw_diag_can_read(at + 12)) {
            shdw_diag_log("  %s hex   %p unreadable", tag, (void*)at);
            return;
        }

        shdw_diag_log("  %s hex   %p %08x %08x %08x %08x", tag, (void*)at,
                      *(unsigned*)at, *(unsigned*)(at + 4),
                      *(unsigned*)(at + 8), *(unsigned*)(at + 12));
    }
}

static void shdw_diag_vm_ctx(const char *tag, ucontext_t *uc) {
    if(!uc) {
        return;
    }

    uintptr_t ctx = (uintptr_t)uc->uc_mcontext->__ss.__x[19];
    char desc[512];

    shdw_diag_describe(desc, sizeof desc, (void*)ctx);
    shdw_diag_log("  %s vmctx x19=%s", tag, desc);

    if(ctx < 0x10000 || !shdw_diag_can_read(ctx + 0x2d48)) {
        return;
    }

    struct { unsigned off; const char *name; } slots[] = {
        {0x005c, "state"}, {0x0e84, "flag"}, {0x0f00, "v0f00"},
        {0x0f08, "v0f08"}, {0x0f14, "acc"},  {0x0f18, "dst"},
        {0x1f10, "p1f10"}, {0x2540, "p2540"}, {0x2550, "p2550"},
        {0x26a0, "flavor"}, {0x26a8, "infoCnt"}, {0x26b0, "walkStart"},
        {0x2568, "p2568"}, {0x2574, "sum"},  {0x2688, "p2688"},
        {0x2880, "buf"},   {0x29e8, "p29e8"}, {0x2bb8, "p2bb8"},
        {0x2d48, "cnt"},   {0x040c, "p040c"}, {0x0440, "p0440"},
        {0x0448, "p0448"}, {0x2548, "p2548"}, {0x2558, "p2558"},
        {0x2690, "cellA"}, {0x2698, "cellB"}, {0x26a0, "cellC"},
        {0x26a8, "cellD"}, {0x26b0, "cellE"}, {0x25f0, "p25f0"},
        {0x25f8, "p25f8"}, {0x2558, "p2558"},
        {0x1f20, "p1f20"}, {0x1f28, "p1f28"}, {0x1f30, "p1f30"},
        {0x1f38, "p1f38"}, {0x1f40, "p1f40"}, {0x1f48, "p1f48"},
        {0x1f68, "p1f68"}, {0x1f70, "p1f70"}, {0x1f78, "p1f78"},
        {0x1f90, "p1f90"}, {0x1f98, "p1f98"}, {0x2740, "p2740"},
        {0x2748, "p2748"}, {0x2750, "p2750"}, {0x2758, "p2758"},
        {0x2760, "p2760"}, {0x2768, "p2768"}, {0x2770, "p2770"},
        {0x2778, "p2778"},
    };

    for(size_t i = 0; i < sizeof slots / sizeof slots[0]; i++) {
        uintptr_t at = ctx + slots[i].off;

        if(!shdw_diag_can_read(at)) {
            shdw_diag_log("  %s vm %s unreadable", tag, slots[i].name);
            continue;
        }

        uint64_t value = *(uint64_t*)at;
        shdw_diag_log("  %s vm %s=%p", tag, slots[i].name,
                      (void*)(uintptr_t)value);
    }

    shdw_diag_log("  %s vm window 0x2400", tag);

    for(unsigned off = 0x2400; off < 0x2700; off += 16) {
        uintptr_t at = ctx + off;

        if(!shdw_diag_can_read(at + 12)) {
            shdw_diag_log("  %s vm   [%04x] unreadable", tag, off);
            continue;
        }

        shdw_diag_log("  %s vm   [%04x] %08x %08x %08x %08x", tag, off,
                      *(unsigned*)(at), *(unsigned*)(at + 4),
                      *(unsigned*)(at + 8), *(unsigned*)(at + 12));
    }

    static const unsigned ptr_offs[] = {0x0030, 0x1f10, 0x24f0, 0x2520,
                                        0x2538, 0x2550, 0x2688, 0x2880,
                                        0x2bb8, 0x29e8, 0x1f90, 0x2740,
                                        0x2768};

    for(size_t i = 0; i < sizeof ptr_offs / sizeof ptr_offs[0]; i++) {
        uintptr_t at = ctx + ptr_offs[i];

        if(!shdw_diag_can_read(at)) {
            continue;
        }

        uintptr_t p = (uintptr_t)*(uint64_t*)at;

        if(!p || !shdw_diag_can_read(p + 24)) {
            continue;
        }

        shdw_diag_describe(desc, sizeof desc, (void*)p);
        shdw_diag_log("  %s vm [%x] -> %s", tag, ptr_offs[i], desc);
        shdw_diag_log("  %s vm   %016llx %016llx %016llx %016llx", tag,
                      (unsigned long long)*(uint64_t*)p,
                      (unsigned long long)*(uint64_t*)(p + 8),
                      (unsigned long long)*(uint64_t*)(p + 16),
                      (unsigned long long)*(uint64_t*)(p + 24));
    }

    uintptr_t vbase = 0, vhdr = 0, vncmds = 0;

    if(shdw_diag_can_read(ctx + 0x0f08)) {
        vbase = (uintptr_t)*(uint64_t*)(ctx + 0x0f08);
    }
    if(shdw_diag_can_read(ctx + 0x2550)) {
        vhdr = (uintptr_t)*(uint64_t*)(ctx + 0x2550);
    }
    if(shdw_diag_can_read(ctx + 0x2538)) {
        vncmds = (uintptr_t)*(uint64_t*)(ctx + 0x2538);
    }

    shdw_diag_region(tag, "v0f08", vbase);
    shdw_diag_region(tag, "p2550", vhdr);
    shdw_diag_region(tag, "p2538", vncmds);
    shdw_diag_describe(desc, sizeof desc, (void*)vbase);
    shdw_diag_log("  %s desc v0f08=%s", tag, desc);
    shdw_diag_describe(desc, sizeof desc, (void*)vhdr);
    shdw_diag_log("  %s desc p2550=%s", tag, desc);
    shdw_diag_hex(tag, "base", vbase, 0x60);
    shdw_diag_hex(tag, "hdr", vhdr, 0x40);
    if(vhdr > 0x40) {
        shdw_diag_hex(tag, "hdr-40", vhdr - 0x40, 0x40);
    }

    uintptr_t cell = 0;

    if(shdw_diag_can_read(ctx + 0x2698)) {
        cell = (uintptr_t)*(uint64_t*)(ctx + 0x2698);
    }

    struct { unsigned off; const char *name; } cells[] = {
        {0x2690, "cellA"}, {0x2698, "cellB"}, {0x26a0, "cellC"},
        {0x25f0, "p25f0"}, {0x25f8, "p25f8"},
    };

    for(size_t i = 0; i < sizeof cells / sizeof cells[0]; i++) {
        uintptr_t at = ctx + cells[i].off;

        if(!shdw_diag_can_read(at)) {
            continue;
        }

        uintptr_t p = (uintptr_t)*(uint64_t*)at;

        shdw_diag_describe(desc, sizeof desc, (void*)p);
        shdw_diag_log("  %s vm %s self=%p desc=%s", tag, cells[i].name,
                      (void*)p, desc);

        if(p && shdw_diag_can_read(p)) {
            uintptr_t v = (uintptr_t)*(uint64_t*)p;
            shdw_diag_describe(desc, sizeof desc, (void*)v);
            shdw_diag_log("  %s vm %s raw=%p desc=%s", tag, cells[i].name,
                          (void*)v, desc);
            shdw_diag_region(tag, cells[i].name, v);
        }
    }

    uint32_t imgcount = _dyld_image_count();
    uint32_t imgidx = 0;

    if(shdw_diag_can_read(ctx + 0x0448)) {
        imgidx = (uint32_t)*(uint64_t*)(ctx + 0x0448);
    }

    const void *dh = (imgidx < imgcount) ? _dyld_get_image_header(imgidx)
                                         : NULL;
    const char *dn = (imgidx < imgcount) ? _dyld_get_image_name(imgidx)
                                         : NULL;
    shdw_diag_log("  %s dyld probe count=%u idx=%u hdr=%p name=%s", tag,
                  (unsigned)imgcount, (unsigned)imgidx, dh,
                  dn ? dn : "(null)");

    shdw_diag_region(tag, "cell", cell);

    if(cell && shdw_diag_can_read(cell)) {
        uintptr_t cellhdr = (uintptr_t)*(uint64_t*)cell;
        shdw_diag_log("  %s cell %p -> %p", tag, (void*)cell,
                      (void*)cellhdr);
        shdw_diag_region(tag, "cellhdr", cellhdr);
        shdw_diag_hex(tag, "cellhdr", cellhdr, 0x30);
    }

    uintptr_t anchor = vbase ? vbase : vhdr;

    if(anchor > 0x30000) {
        shdw_diag_walk(tag, (anchor & ~(uintptr_t)0xfff) - 0x10000, 0x80000);
    }
}

// The image list a detector walks comes from dyld. Log what dyld reports to
// this process, so a count/name/header disagreement is visible next to the
// context that tripped on it.
__attribute__((unused)) static void shdw_diag_dump_images(const char *tag) {
    uint32_t count = _dyld_image_count();

    shdw_diag_log("  %s images count=%u", tag, (unsigned)count);

    for(uint32_t i = 0; i < count; i++) {
        const struct mach_header_64* header =
            (const struct mach_header_64*)_dyld_get_image_header(i);
        const char* name = _dyld_get_image_name(i);

        if(!header) {
            shdw_diag_log("  %s image[%u] header=null name=%s", tag, (unsigned)i,
                          name ? name : "(null)");
            continue;
        }

        shdw_diag_log("  %s image[%u] base=%p magic=%08x type=%u ncmds=%u %s",
                      tag, (unsigned)i, (void*)header,
                      (unsigned)header->magic, (unsigned)header->filetype,
                      (unsigned)header->ncmds, name ? name : "(null)");
    }
}

void shdw_diag_backtrace(const char *tag) {
    void *frames[40];
    int count = backtrace(frames, 40);

    for (int i = 0; i < count; i++) {
        char frame[512];
        shdw_diag_describe(frame, sizeof frame, frames[i]);
        shdw_diag_log("  %s bt[%d] %s", tag, i, frame);
    }
}

static void (*shdw_diag_exit)(int);
static void (*shdw_diag__exit)(int);
static void (*shdw_diag_abort)(void);
static void (*shdw_diag_raise)(int);
static int (*shdw_diag_pthread_kill)(pthread_t, int);
static void (*shdw_diag_assert_rtn)(const char *, const char *, int,
                                    const char *);
static void (*shdw_diag_os_crash)(const char *);
static void (*shdw_diag_pthread_exit)(void *);
static volatile int shdw_diag_trap_count;

static void replaced_diag_exit(int status) {
    char caller[512];
    shdw_diag_describe(caller, sizeof caller, __builtin_return_address(0));
    shdw_diag_log("EXIT exit(%d) from %s traps=%d", status, caller,
                  shdw_diag_trap_count);
    shdw_diag_backtrace("exit");

    if (shdw_diag_exit) {
        shdw_diag_exit(status);
    }

    for (;;) {
        pause();
    }
}

static void replaced_diag__exit(int status) {
    char caller[512];
    shdw_diag_describe(caller, sizeof caller, __builtin_return_address(0));
    shdw_diag_log("EXIT _exit(%d) from %s", status, caller);
    shdw_diag_backtrace("_exit");

    if (shdw_diag__exit) {
        shdw_diag__exit(status);
    }

    for (;;) {
        pause();
    }
}

static void replaced_diag_abort(void) {
    char caller[512];
    shdw_diag_describe(caller, sizeof caller, __builtin_return_address(0));
    shdw_diag_log("EXIT abort() from %s", caller);
    shdw_diag_backtrace("abort");

    if (shdw_diag_abort) {
        shdw_diag_abort();
    }
}

static void replaced_diag_raise(int sig) {
    shdw_diag_log("SIGNAL raise(%d)", sig);

    if (shdw_diag_raise) {
        shdw_diag_raise(sig);
    }
}

static int replaced_diag_pthread_kill(pthread_t thread, int sig) {
    if (pthread_equal(thread, pthread_self())) {
        shdw_diag_log("SIGNAL pthread_kill(self, %d)", sig);
    }

    return shdw_diag_pthread_kill ? shdw_diag_pthread_kill(thread, sig) : -1;
}

static void replaced_diag_assert_rtn(const char *function, const char *file,
                                     int line, const char *expr) {
    shdw_diag_log("ASSERT %s:%d %s (%s)", file ?: "?", line, expr ?: "?",
                  function ?: "?");
    shdw_diag_backtrace("assert");

    if (shdw_diag_assert_rtn) {
        shdw_diag_assert_rtn(function, file, line, expr);
    }
}

static void replaced_diag_os_crash(const char *message) {
    shdw_diag_log("CRASH os_crash(%s)", message ?: "?");
    shdw_diag_backtrace("os_crash");

    if (shdw_diag_os_crash) {
        shdw_diag_os_crash(message);
    }
}

static void replaced_diag_pthread_exit(void *value) {
    if (pthread_main_np()) {
        char caller[512];
        shdw_diag_describe(caller, sizeof caller, __builtin_return_address(0));
        shdw_diag_log("EXIT pthread_exit(main) from %s", caller);
        shdw_diag_backtrace("pthread_exit");
    }

    if (shdw_diag_pthread_exit) {
        shdw_diag_pthread_exit(value);
    }
}

static kern_return_t (*shdw_diag_task_terminate)(task_t);
static kern_return_t replaced_diag_task_terminate(task_t target) {
    char caller[512];
    shdw_diag_describe(caller, sizeof caller, __builtin_return_address(0));
    shdw_diag_log("MACH task_terminate self=%d from %s",
                  target == mach_task_self(), caller);

    if (shdw_diag_task_terminate) {
        return shdw_diag_task_terminate(target);
    }

    return KERN_FAILURE;
}

static kern_return_t (*shdw_diag_thread_terminate)(thread_t);
static kern_return_t replaced_diag_thread_terminate(thread_t target) {
    char caller[512];
    shdw_diag_describe(caller, sizeof caller, __builtin_return_address(0));
    shdw_diag_log("MACH thread_terminate self=%d from %s",
                  pthread_mach_thread_np(pthread_self()) == target, caller);

    if (shdw_diag_thread_terminate) {
        return shdw_diag_thread_terminate(target);
    }

    return KERN_FAILURE;
}

static int (*shdw_diag_kill)(pid_t, int);
static int replaced_diag_kill(pid_t pid, int sig) {
    char caller[512];
    shdw_diag_describe(caller, sizeof caller, __builtin_return_address(0));
    shdw_diag_log("KILL pid=%d sig=%d from %s", (int)pid, sig, caller);

    return shdw_diag_kill ? shdw_diag_kill(pid, sig) : -1;
}

static int (*shdw_diag_killpg)(pid_t, int);
static int replaced_diag_killpg(pid_t pgrp, int sig) {
    char caller[512];
    shdw_diag_describe(caller, sizeof caller, __builtin_return_address(0));
    shdw_diag_log("KILLPG pgrp=%d sig=%d from %s", (int)pgrp, sig, caller);

    return shdw_diag_killpg ? shdw_diag_killpg(pgrp, sig) : -1;
}

static void (*shdw_diag_proc_exit)(int);
static void replaced_diag_proc_exit(int status) {
    char caller[512];
    shdw_diag_describe(caller, sizeof caller, __builtin_return_address(0));
    shdw_diag_log("EXIT proc_exit(%d) from %s", status, caller);
    shdw_diag_backtrace("proc_exit");

    if (shdw_diag_proc_exit) {
        shdw_diag_proc_exit(status);
    }

    for (;;) {
        pause();
    }
}

static void (*shdw_diag_abort_with_payload)(void *, size_t, const char *, void *,
                                            size_t);
static void replaced_diag_abort_with_payload(void *payload, size_t payload_size,
                                             const char *ns, void *reason,
                                             size_t reason_size) {
    shdw_diag_log("EXIT abort_with_payload size=%zu ns=%s", payload_size,
                  ns ?: "?");
    shdw_diag_backtrace("abort_with_payload");

    if (shdw_diag_abort_with_payload) {
        shdw_diag_abort_with_payload(payload, payload_size, ns, reason,
                                     reason_size);
    }
}

// Toolkit surface the resolver reaches for: passthrough wrappers that only
// feed the caller-filtered image trace (pref: Debug_ApiTrace + Debug_TraceImage).
static pid_t (*shdw_diag_getpid_orig)(void);
static pid_t shdw_diag_self_pid;
static pid_t replaced_diag_getpid(void) {
    shdw_diag_trace_image_entry(__builtin_return_address(0), "getpid");
    return shdw_diag_getpid_orig ? shdw_diag_getpid_orig() : shdw_diag_self_pid;
}

static int (*shdw_diag_nsgetpath)(char *, uint32_t *);
static int replaced_diag_nsgetpath(char *buf, uint32_t *size) {
    shdw_diag_trace_image_entry(__builtin_return_address(0),
                                "_NSGetExecutablePath buf=%p size=%p", buf, size);
    return shdw_diag_nsgetpath ? shdw_diag_nsgetpath(buf, size) : -1;
}

static int (*shdw_diag_unmount)(const char *, int);
static int replaced_diag_unmount(const char *path, int flags) {
    void *caller = __builtin_return_address(0);
    int savedErrno = errno;
    shdw_diag_trace_image_entry(caller, "unmount path=%s flags=%d",
                                path ? path : "(null)", flags);
    errno = savedErrno;
    int result = shdw_diag_unmount ? shdw_diag_unmount(path, flags) : -1;
    int resultErrno = errno;
    shdw_diag_trace_image_result(caller, "unmount path=%s flags=%d ret=%d errno=%d",
                                 path ? path : "(null)", flags, result, resultErrno);
    errno = resultErrno;
    return result;
}

static kern_return_t (*shdw_diag_task_get_state)(task_t,
                                                 thread_state_flavor_t,
                                                 thread_state_t,
                                                 mach_msg_type_number_t *);
static kern_return_t replaced_diag_task_get_state(task_t target,
                                                  thread_state_flavor_t flavor,
                                                  thread_state_t state,
                                                  mach_msg_type_number_t *count) {
    shdw_diag_trace_image_entry(__builtin_return_address(0),
                                "task_get_state flavor=%d", (int)flavor);
    return shdw_diag_task_get_state
               ? shdw_diag_task_get_state(target, flavor, state, count)
               : KERN_FAILURE;
}

static struct sigaction shdw_diag_prev_sa[NSIG];

// Ring positions shared with the fault handler: the PC dump starts from the
// position recorded at handler entry, so the handler's own logging samples
// never masquerade as detector activity.
volatile uint32_t shdw_pc_mark;
volatile uint32_t shdw_pc_pos;
volatile uint64_t shdw_pc_mark_ns;
static volatile sig_atomic_t shdw_diag_sig_logged[NSIG];

static int shdw_diag_read_words(uintptr_t address, uint64_t *words, size_t size) {
    vm_size_t readSize = 0;
    kern_return_t kr = vm_read_overwrite(mach_task_self(),
                                         (vm_address_t)address,
                                         (vm_size_t)size,
                                         (vm_address_t)words,
                                         &readSize);
    return kr == KERN_SUCCESS && readSize == size;
}

static uint64_t shdw_diag_peek(uintptr_t address, size_t size) {
    uint64_t v = 0;
    shdw_diag_read_words(address, &v, size);
    return v;
}

// Frame-pointer walk of a live thread. Used on the main thread while it sits
// inside ShadowCore code and never returns to the app.
static void shdw_diag_walk_thread(mach_port_t th, const char *tag) {
    arm_thread_state64_t st;
    mach_msg_type_number_t sc = ARM_THREAD_STATE64_COUNT;
    char d[120];

    if (thread_get_state(th, ARM_THREAD_STATE64, (thread_state_t)&st, &sc) !=
        KERN_SUCCESS) {
        return;
    }

    uintptr_t pc = arm_thread_state64_get_pc(st);
    uintptr_t lr = arm_thread_state64_get_lr(st);
    uintptr_t fp = arm_thread_state64_get_fp(st);
    shdw_diag_describe_short(d, sizeof d, (void *)pc);
    shdw_diag_log("  %s pc=%s", tag, d);
    shdw_diag_describe_short(d, sizeof d, (void *)lr);
    shdw_diag_log("  %s lr=%s", tag, d);

    for (int i = 0; i < 12 && fp; i++) {
        uint64_t frame[2] = {0};
        if (!shdw_diag_read_words(fp, frame, sizeof frame)) {
            break;
        }
        shdw_diag_describe_short(d, sizeof d, (void *)frame[1]);
        shdw_diag_log("  %s bt[%d] %p %s", tag, i, (void *)frame[1], d);
        if (frame[0] <= fp) {
            break;
        }
        fp = (uintptr_t)frame[0];
    }
}

static void shdw_diag_dump_words(const char *tag, uintptr_t address,
                                 size_t count) {
    uint64_t words[16] = {0};
    if (count > sizeof words / sizeof words[0]) {
        count = sizeof words / sizeof words[0];
    }
    size_t size = count * sizeof words[0];
    if (!shdw_diag_read_words(address, words, size)) {
        shdw_diag_log("OZSTATE %s address=%p unreadable", tag, (void *)address);
        return;
    }
    for (size_t i = 0; i < count; i++) {
        shdw_diag_log("OZSTATE %s[%zu] address=%p value=0x%016llx", tag, i,
                      (void *)(address + i * sizeof words[0]),
                      (unsigned long long)words[i]);
    }
}

typedef struct {
    const char* name;
    size_t resultIndex;
    uintptr_t slotOffset;
} shdw_diag_oz_symbol_t;

static const shdw_diag_oz_symbol_t shdw_diag_oz_symbols[] = {
    { "thread_get_state", 1, 0 },
    { "_dyld_get_image_vmaddr_slide", 4, 0 },
    { "__error", 5, 0x101edf8 },
    { "vm_region_recurse_64", 6, 0 },
    { "lround", 8, 0 },
    { "task_get_special_port", 13, 0 },
    { "getenv", 25, 0x101f080 },
    { "vm_map", 28, 0 },
    { "objc_terminate", 43, 0 },
    { "class_getInstanceMethod", 50, 0x101eef8 },
    { "difftime", 51, 0 },
    { "mach_port_insert_right", 53, 0 },
    { "__atomic_store", 57, 0 },
    { "mach_port_destroy", 69, 0 },
    { "method_setImplementation", 71, 0 },
    { "MTLCreateSystemDefaultDevice", 73, 0 },
    { "readlink", 80, 0 },
    { "pthread_mutex_unlock", 83, 0x101f268 },
    { "mach_port_allocate", 86, 0 },
    { "vm_protect", 92, 0 },
    { "close", 103, 0x101ef10 },
    { "_dyld_image_count", 111, 0x101ee58 },
    { "__atomic_load", 112, 0 },
    { "vm_region_64", 113, 0 },
    { "dladdr", 114, 0 },
    { "mach_msg", 115, 0 },
    { "time", 118, 0x101f6a8 },
    { "mach_thread_self", 119, 0 },
    { "vm_deallocate", 134, 0x101f6f8 },
    { "dispatch_once", 142, 0 },
    { "free", 143, 0x101f028 },
    { "calloc", 147, 0x101eef0 },
    { "malloc", 149, 0x101f108 },
    { "syscall", 154, 0 },
    { "madvise", 161, 0x101f100 },
    { "objc_msgSend", 169, 0x101f198 },
    { "pthread_once", 174, 0x101f270 },
    { "_dyld_get_image_header", 176, 0 },
    { "pthread_mutex_trylock", 177, 0 },
    { "mach_port_extract_right", 178, 0 },
};

static void shdw_diag_dump_oz_state(ucontext_t *uc, uintptr_t pcv) {
    shdw_diag_log("OZSTATE enter uc=%p pc=%p", uc, (void *)pcv);

    Dl_info image = {0};
    int imageFound = uc ? dladdr((void *)pcv, &image) : 0;
    shdw_diag_log("OZSTATE dladdr=%d name=%s base=%p", imageFound,
                  image.dli_fname ?: "<null>", image.dli_fbase);

    if (!imageFound || !image.dli_fname ||
        !strstr(image.dli_fname, "/OZLivenessSDK.framework/OZLivenessSDK")) {
        return;
    }

    uintptr_t base = (uintptr_t)image.dli_fbase;
    const uint64_t *x = uc->uc_mcontext->__ss.__x;
    shdw_diag_log("OZSTATE image=%s base=%p pcOffset=0x%lx", image.dli_fname,
                  image.dli_fbase, (unsigned long)(pcv - base));
    for (int i = 0; i < 29; i++) {
        shdw_diag_log("OZREG x%02d=0x%016llx", i,
                      (unsigned long long)x[i]);
    }
    shdw_diag_log("OZREG x28=0x%016llx fp=0x%016llx lr=0x%016llx sp=0x%016llx",
                  (unsigned long long)x[28],
                  (unsigned long long)arm_thread_state64_get_fp(uc->uc_mcontext->__ss),
                  (unsigned long long)arm_thread_state64_get_lr(uc->uc_mcontext->__ss),
                  (unsigned long long)arm_thread_state64_get_sp(uc->uc_mcontext->__ss));
    shdw_diag_log("OZREG expectedX25=%p actualDelta=%lld expectedNameBase=%p",
                  (void *)(base + 0x1067000),
                  (long long)(x[25] - (base + 0x1067000)),
                  (void *)(base + 0x1067330));

    shdw_diag_dump_words("control", base + 0x105c450, 4);
    shdw_diag_dump_words("hashState", base + 0x1068620, 16);
    shdw_diag_dump_words("dlsymSlot", base + 0x101ef90, 1);
    shdw_diag_dump_words("initState", base + 0x1067588, 1);

    uint64_t slot = 0;
    if (shdw_diag_read_words(base + 0x101ef90, &slot, sizeof slot)) {
        char target[512];
        shdw_diag_describe(target, sizeof target, (void *)(uintptr_t)slot);
        shdw_diag_log("OZSTATE dlsymTarget=%s", target);
    }

    for (size_t i = 0; i < sizeof shdw_diag_oz_symbols / sizeof shdw_diag_oz_symbols[0]; i++) {
        const shdw_diag_oz_symbol_t* entry = &shdw_diag_oz_symbols[i];
        uint64_t result = 0;
        uint64_t slot = 0;
        BOOL haveResult = shdw_diag_read_words(base + 0x105b910 + entry->resultIndex * 8,
                                               &result, sizeof result);
        BOOL haveSlot = entry->slotOffset &&
            shdw_diag_read_words(base + entry->slotOffset, &slot, sizeof slot);
        void* raw = shdw_diag_raw_dlsym(entry->name);
        char resultTarget[512];
        char slotTarget[512];
        char rawTarget[512];
        shdw_diag_describe(resultTarget, sizeof resultTarget,
                           haveResult ? (void*)(uintptr_t)result : NULL);
        shdw_diag_describe(slotTarget, sizeof slotTarget,
                           haveSlot ? (void*)(uintptr_t)slot : NULL);
        shdw_diag_describe(rawTarget, sizeof rawTarget, raw);
        shdw_diag_log("OZCOMPARE[%zu] lookupIndex=%zu sym=%s result=%p slot=%p raw=%p "
                      "resultRaw=%d slotRaw=%d resultSlot=%d resultDesc=%s "
                      "slotDesc=%s rawDesc=%s",
                      i, entry->resultIndex, entry->name,
                      haveResult ? (void*)(uintptr_t)result : NULL,
                      haveSlot ? (void*)(uintptr_t)slot : NULL,
                      raw,
                      haveResult && result == (uint64_t)(uintptr_t)raw,
                      haveSlot && slot == (uint64_t)(uintptr_t)raw,
                      haveResult && haveSlot && result == slot,
                      haveResult ? resultTarget : "unreadable",
                      entry->slotOffset ? (haveSlot ? slotTarget : "unreadable") : "no-import",
                      rawTarget);
    }
}


// Resuming an instruction writes a raw address, while the opaque arm64e thread
// state stores the PC signed with the process-independent code key. Mirror the
// inverse of arm_thread_state64_get_pc so the kernel restores exactly what a
// normal signal return would.
static void shdw_diag_set_pc(arm_thread_state64_t *ts, uintptr_t pc) {
#if __has_feature(ptrauth_calls) && defined(__LP64__)
    void *disc = ptrauth_string_discriminator("pc");
    uint32_t userBits = ts->__opaque_flags & 0xff000000u;

    if (!(ts->__opaque_flags & 0x4u) && userBits) {
        disc = ptrauth_blend_discriminator((void *)(uintptr_t)userBits, disc);
    }
    ts->__opaque_pc = ptrauth_sign_unauthenticated(
        (void *)pc, ptrauth_key_process_independent_code, disc);
#else
    ts->__pc = (uint64_t)pc;
#endif
}

static void shdw_diag_dump_state_ring(void);
static void shdw_diag_dump_hw_ring(void);
static void shdw_diag_dump_state_compare(uintptr_t ctx);

// Inline-syscall lane (Debug_InSvc). Every `svc #0x80` in the detector's
// __text becomes `udf #0` (SIGILL, not SIGTRAP: Dynatrace owns SIGTRAP), so
// the signal handler receives the exact
// syscall number (x16) and arguments the detector issues without passing
// through any libc entry Shadow can hook. The handler performs the real
// syscall on the interrupted register set, reports carry in CPSR.C and
// resumes after the trap, so detector behaviour is unchanged.
int shdw_insvc_on;
static volatile uint32_t shdw_insvc_events;
static volatile uint32_t shdw_insvc_logged;
static uint16_t shdw_insvc_seen[1024];

static long shdw_insvc_raw(long n, long a0, long a1, long a2, long a3,
                           long a4, long a5, long a6, long a7,
                           long *r1, int *carry) {
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;
    register long x6 __asm__("x6") = a6;
    register long x7 __asm__("x7") = a7;
    register long x16 __asm__("x16") = n;
    int c = 0;

    __asm__ __volatile__("svc #0x80\n\tcset %w[c], cs"
                         : "+r"(x0), "+r"(x1), [c] "=r"(c)
                         : "r"(x2), "r"(x3), "r"(x4), "r"(x5),
                           "r"(x6), "r"(x7), "r"(x16)
                         : "memory", "cc");
    *r1 = x1;
    *carry = c;
    return x0;
}


static int shdw_insvc_cstr(uintptr_t addr, char *out, size_t cap) {
    if(cap < 2 || addr < 0x1000) {
        return 0;
    }

    char buf[256];
    size_t want = cap - 1 < sizeof buf ? cap - 1 : sizeof buf - 1;
    vm_size_t got = 0;

    if(vm_read_overwrite(mach_task_self(), (vm_address_t)addr, (vm_size_t)want,
                         (vm_address_t)buf, &got) != KERN_SUCCESS || !got) {
        return 0;
    }
    buf[got < want ? got : want] = 0;

    size_t n = 0;
    while(n < want && buf[n]) {
        out[n] = buf[n];
        n++;
    }
    out[n] = 0;
    return n > 0;
}

char shdw_insvc_deny_substr[192];

static int shdw_insvc_path_denied(const char *p) {
    static const char *const deny[] = {
        "/var/jb", "TweakInject", "/procursus/", "dopamine", "libsubstrate",
        "ellekit", "libhooker", "/usr/lib/libjailbreak", "/basebin",
        "systemhook", "substitute", "/.procursus_strapped", "jbctl",
    };

    for(size_t i = 0; i < sizeof deny / sizeof deny[0]; i++) {
        if(strstr(p, deny[i])) {
            return 1;
        }
    }
    if(shdw_insvc_deny_substr[0] &&
       strstr(p, shdw_insvc_deny_substr)) {
        return 1;
    }
    return 0;
}

#define SHDW_FD_MAX 256

static char shdw_fd_path[SHDW_FD_MAX][192];

static void shdw_insvc_fd_track(long n, int a0, uintptr_t a1, uintptr_t a2,
                                long r0, uintptr_t lr) {
    if(n == 5 && r0 >= 0 && r0 < SHDW_FD_MAX) {
        char path[192];

        if(shdw_insvc_cstr((uintptr_t)a0, path, sizeof path)) {
            snprintf(shdw_fd_path[r0], sizeof shdw_fd_path[r0], "%s", path);
            shdw_diag_log("INSVCOPEN fd=%ld path=%s lr=%#lx", r0, path,
                          (unsigned long)lr);
        }
        return;
    }

    if((n == 3 || n == 153 || n == 6) && a0 >= 0 && a0 < SHDW_FD_MAX) {
        const char *p = shdw_fd_path[a0];
        shdw_diag_log("INSVCFD n=%ld fd=%d path=%s ret=%ld a1=%p a2=%p lr=%#lx",
                      n, a0, p[0] ? p : "<unknown>", r0, (void *)a1,
                      (void *)a2, (unsigned long)lr);
        if(n == 6) {
            shdw_fd_path[a0][0] = 0;
        }
    }
}

static __thread int shdw_insvc_reentry;

typedef struct { long n; uintptr_t lr; uintptr_t a0; } shdw_svrec;
static shdw_svrec shdw_svring[32];
static volatile uint32_t shdw_svpos;

static void shdw_svc_ring_dump(const char *tag) {
    uint32_t pos = __atomic_load_n(&shdw_svpos, __ATOMIC_RELAXED);
    char line[512];
    int w = 0;

    w += snprintf(line + w, sizeof line - (size_t)w, "%s last:", tag);
    for(uint32_t k = 0; k < 32; k++) {
        shdw_svrec *r = &shdw_svring[(pos + 63 - k) % 32];
        w += snprintf(line + w, sizeof line - (size_t)w, " %ld@%lx", r->n,
                      (unsigned long)r->lr);
        if(k % 8 == 7 || w > (int)sizeof line - 96) {
            shdw_diag_log("%s", line);
            w = 0;
            w += snprintf(line + w, sizeof line - (size_t)w, "%s cont:", tag);
        }
    }
}

static int shdw_insvc_emulate(ucontext_t *uc, uintptr_t pcv, unsigned long off) {
    uint64_t *x = uc->uc_mcontext->__ss.__x;
    long n = (long)x[16];
    long r1 = 0;
    int cf = 0;
    long r0 = 0;
    uintptr_t lrv = arm_thread_state64_get_lr(uc->uc_mcontext->__ss);

    if(shdw_insvc_reentry) {
        long rr1 = 0;
        int rcf = 0;

        x[0] = (uint64_t)shdw_insvc_raw(n, (long)x[0], (long)x[1], (long)x[2],
                                        (long)x[3], (long)x[4], (long)x[5],
                                        (long)x[6], (long)x[7], &rr1, &rcf);
        x[1] = (uint64_t)rr1;
        {
            uint32_t *cpsr = &uc->uc_mcontext->__ss.__cpsr;
            *cpsr = (*cpsr & ~0x20000000u) | (rcf ? 0x20000000u : 0u);
        }
        shdw_diag_set_pc(&uc->uc_mcontext->__ss, pcv + 4);
        return 1;
    }

    shdw_insvc_reentry = 1;

    {
        uint32_t rp = __atomic_add_fetch(&shdw_svpos, 1, __ATOMIC_RELAXED);
        shdw_svrec *r = &shdw_svring[rp % 32];
        r->n = n;
        r->lr = lrv;
        r->a0 = (uintptr_t)x[0];
    }

    if(n == 1) {
        static int exitTraps;

        if(exitTraps < 4) {
            char lrs[192];
            char sps[64];
            exitTraps++;
            shdw_diag_describe_short(lrs, sizeof lrs, (void *)lrv);
            shdw_diag_describe_short(sps, sizeof sps,
                                     (void *)(uintptr_t)arm_thread_state64_get_sp(uc->uc_mcontext->__ss));
            shdw_diag_log("EXITTRAP status=%ld lr=%s sp=%s x8=%#llx off=%#lx",
                          (long)x[0], lrs, sps, (unsigned long long)x[8], off);
            shdw_svc_ring_dump("EXITRING");
        }
        x[0] = 0;
        {
            uint32_t *cpsr = &uc->uc_mcontext->__ss.__cpsr;
            *cpsr &= ~0x20000000u;
        }
        shdw_insvc_reentry = 0;
        shdw_diag_set_pc(&uc->uc_mcontext->__ss, pcv + 4);
        return 1;
    }

    r0 = shdw_insvc_raw(n, (long)x[0], (long)x[1], (long)x[2], (long)x[3],
                        (long)x[4], (long)x[5], (long)x[6], (long)x[7],
                        &r1, &cf);

    if(n < 0 || (unsigned long)n >= 0x80000000ul) {
        static long mtCount;

        long c = __atomic_add_fetch(&mtCount, 1, __ATOMIC_RELAXED);

        if(c <= 8 || (c % 2000) == 0) {
            shdw_diag_log("MTRAP n=%#lx a0=%#llx a1=%#llx a2=%#llx a3=%#llx"
                          " ret=%ld cf=%d lr=%#lx cnt=%ld",
                          (unsigned long)n, (unsigned long long)x[0],
                          (unsigned long long)x[1], (unsigned long long)x[2],
                          (unsigned long long)x[3], r0, cf,
                          (unsigned long)lrv, c);
        }
    }

    // The SHIELD dispatcher is how the framework reaches the kernel for file
    // work; libc and syscall() hooks never see these. Log the path and answer
    // the hidden roots the way the rest of Shadow does.
    {
        int pidx = -1;

        switch(n) {
            case 5: case 18: case 33: case 58: case 157: case 188: case 190:
            case 216: case 277: case 279: case 280: case 284: case 338:
            case 340: case 341: case 342:
                pidx = 0;
                break;
            case 463: case 466: case 469: case 473:
                pidx = 1;
                break;
            default:
                break;
        }

        if(pidx >= 0) {
            char path[256];

            if(shdw_insvc_cstr((uintptr_t)x[pidx], path, sizeof path)) {
                int deny = shdw_insvc_path_denied(path);

                shdw_diag_log("INSVCPATH n=%ld a%d=%p path=%s deny=%d lr=%#lx",
                              n, pidx, (void *)x[pidx], path, deny,
                              (unsigned long)lrv);
                if(deny) {
                    x[0] = (uint64_t)(long)-2;   // ENOENT, same as the libc lane
                    {
                        uint32_t *cpsr = &uc->uc_mcontext->__ss.__cpsr;
                        *cpsr &= ~0x20000000u;
                    }
                    shdw_insvc_reentry = 0;
                    shdw_diag_set_pc(&uc->uc_mcontext->__ss, pcv + 4);
                    return 1;
                }
            } else {
                shdw_diag_log("INSVCPATH n=%ld a%d=%p unreadable lr=%#lx",
                              n, pidx, (void *)x[pidx], (unsigned long)lrv);
            }
        }
    }

    __atomic_add_fetch(&shdw_insvc_events, 1, __ATOMIC_RELAXED);
    if (n >= 0 && n < 1024 &&
        __atomic_fetch_add(&shdw_insvc_seen[n], 1, __ATOMIC_RELAXED) == 0) {
        shdw_diag_log("INSVCNEW n=%ld a0=%p a1=%p a2=%p ret=%ld cf=%d lr=%#lx"
                      " off=%#lx x19=%p",
                      n, (void *)x[0], (void *)x[1], (void *)x[2], r0, cf,
                      (unsigned long)lrv, off, (void *)x[19]);
    }
    if (__atomic_add_fetch(&shdw_insvc_logged, 1, __ATOMIC_RELAXED) <= 0) {
        shdw_diag_log("INSVC n=%ld a0=%p a1=%p a2=%p a3=%p ret=%ld cf=%d"
                      " lr=%#lx off=%#lx x19=%p x8=%#llx",
                      n, (void *)x[0], (void *)x[1], (void *)x[2], (void *)x[3],
                      r0, cf, (unsigned long)lrv, off, (void *)x[19],
                      (unsigned long long)x[8]);
    }
    shdw_insvc_fd_track(n, (int)x[0], (uintptr_t)x[1], (uintptr_t)x[2], r0, lrv);

    x[0] = (uint64_t)r0;
    x[1] = (uint64_t)r1;
    {
        uint32_t *cpsr = &uc->uc_mcontext->__ss.__cpsr;
        *cpsr = (*cpsr & ~0x20000000u) | (cf ? 0x20000000u : 0u);
    }
    shdw_insvc_reentry = 0;
    shdw_diag_set_pc(&uc->uc_mcontext->__ss, pcv + 4);
    return 1;
}

// Armed-stub table lives in ExitProbe.x: a BRK patched over a function's
// first word traps at that exact address.
extern const char* shdw_diag_brk_lookup(uintptr_t pc);

// TEMP DIAG: a termination reached through a cached or already-bound pointer
// never enters any rebind hook, but it still executes the function body. The
// armed BRK sits on the first word, so the trap names the function and lr
// holds the return address the caller expects. Log the call with its
// arguments, return 0 in x0 (success), and resume at lr.
static int shdw_diag_stub_skip(ucontext_t *uc) {
    uint64_t *x = uc->uc_mcontext->__ss.__x;
    uintptr_t pcv = arm_thread_state64_get_pc(uc->uc_mcontext->__ss);
    uintptr_t lrv = arm_thread_state64_get_lr(uc->uc_mcontext->__ss);
    const char *name = shdw_diag_brk_lookup(pcv);

    if (!name) {
        return 0;
    }

    shdw_diag_log("STUBHIT %s pc=%p lr=%p tid=%p x0=%p x1=%p x2=%p x3=%p x4=%p x5=%p x8=%p",
                  name, (void *)pcv, (void *)lrv, (void *)pthread_self(),
                  (void *)x[0], (void *)x[1], (void *)x[2], (void *)x[3],
                  (void *)x[4], (void *)x[5], (void *)x[8]);
    {
        char lrs[512];
        shdw_diag_describe(lrs, sizeof lrs, (void *)lrv);
        shdw_diag_log("STUBCTX %s lr=%s", name, lrs);
    }

    static int dumped;
    if (!dumped) {
        dumped = 1;
        shdw_diag_dump_stack_raw("stub", uc);
    }

    x[0] = 0;
    shdw_diag_set_pc(&uc->uc_mcontext->__ss, lrv);
    return 1;
}

// TEMP DIAG: the OZ verdict block at OZLivenessSDK+0x3af92c stores 4/0xc into
// its own frame and traps, and Dynatrace normally consumes that trap. Catching
// it names the VM context that failed the check (state 83, reachable only from
// state 82, which the byte-hash compare at 0x3af12c selects when
// [ctx+0x86c] != 0x3a9390fd) together with the buffer that was hashed.
static int shdw_diag_oz_poison(ucontext_t *uc, int sig) {
    uint64_t *x = uc->uc_mcontext->__ss.__x;
    uintptr_t pcv = arm_thread_state64_get_pc(uc->uc_mcontext->__ss);
    uintptr_t lrv = arm_thread_state64_get_lr(uc->uc_mcontext->__ss);
    Dl_info info = {0};
    uintptr_t ctx;
    uintptr_t base;
    int oz = dladdr((void *)pcv, &info) && info.dli_fname && info.dli_fbase &&
             strstr(info.dli_fname, "OZLivenessSDK") != NULL;

    {
        static int trapLogged;
        if (trapLogged < 40) {
            char pcs[160];
            char lrs[160];
            trapLogged++;
            shdw_diag_describe_short(pcs, sizeof pcs, (void *)pcv);
            shdw_diag_describe_short(lrs, sizeof lrs, (void *)lrv);
            shdw_diag_log("TRAPEV pc=%s lr=%s oz=%d off=%#lx sig=%d", pcs, lrs, oz,
                          oz ? (unsigned long)(pcv - (uintptr_t)info.dli_fbase)
                             : 0UL, sig);
        }
    }

    // The block's own brk is consumed by Dynatrace's SIGTRAP handler before it
    // reaches us, so the tag lane also plants a store to 0xdead one instruction
    // earlier: that faults with SIGSEGV (which Dynatrace chains) while x19 and
    // x29 still hold the VM context, before any frame word is poisoned.
    unsigned long off = (unsigned long)(pcv - (uintptr_t)info.dli_fbase);
    if (sig == SIGILL && __atomic_load_n(&shdw_insvc_on, __ATOMIC_ACQUIRE) &&
        *(const uint32_t *)pcv == 0x00000000u) {
        return shdw_insvc_emulate(uc, pcv, off);
    }
    if (!oz) {
        return 0;
    }
    // Lab: every OZ tamper block ends its frame poisoning with `brk #1`, and the
    // next instruction is the function's own epilogue (e.g. 0x5fd474 -> 0x5fd478).
    // Skipping the trap therefore returns normally instead of killing the app.
    if (sig == SIGTRAP && *(const uint32_t *)pcv == 0xd4200020u) {
        static int brkSkips;
        if (brkSkips < 40) {
            brkSkips++;
            shdw_diag_log("OZBRK skip off=%#lx lr=%#lx x19=%p fp=%p sp=%p", off,
                          (unsigned long)lrv, (void *)x[19],
                          (void *)arm_thread_state64_get_fp(uc->uc_mcontext->__ss),
                          (void *)arm_thread_state64_get_sp(uc->uc_mcontext->__ss));
        }
        shdw_diag_set_pc(&uc->uc_mcontext->__ss, pcv + 4);
        return 1;
    }
    if (sig == SIGTRAP && off != 0x3af93c) {
        return 0;
    }
    if (sig == SIGSEGV && off != 0x3af930) {
        return 0;
    }

    ctx = (uintptr_t)x[19];
    base = (uintptr_t)shdw_diag_peek(ctx + 0x570, 8);
    shdw_diag_log("OZPOISON pc=%p ctx=%p sp=%p fp=%p x22=%p x23=%p",
                  (void *)pcv, (void *)ctx,
                  (void *)arm_thread_state64_get_sp(uc->uc_mcontext->__ss),
                  (void *)arm_thread_state64_get_fp(uc->uc_mcontext->__ss),
                  (void *)x[22], (void *)x[23]);
    shdw_diag_log("OZPOISON ctx state=%#llx hash=%#llx len=%#llx p=%#llx"
                  " base=%#llx next=%#llx limit=%#llx",
                  (unsigned long long)shdw_diag_peek(ctx + 0x59c, 4),
                  (unsigned long long)shdw_diag_peek(ctx + 0x86c, 4),
                  (unsigned long long)shdw_diag_peek(ctx + 0x69c, 4),
                  (unsigned long long)shdw_diag_peek(ctx + 0x6a0, 8),
                  (unsigned long long)base,
                  (unsigned long long)shdw_diag_peek(ctx + 0x860, 8),
                  (unsigned long long)shdw_diag_peek(ctx + 0x870, 8));
    shdw_diag_peek_words("ozhash", base, 0, 64);
    shdw_diag_peek_words("ozhash", base, 0x40, 64);
    shdw_diag_peek_words("ozctx", ctx, 0x550, 64);
    shdw_diag_dump_stack_raw("ozpoison", uc);

    if (sig != SIGTRAP) {
        return 0;
    }
    shdw_diag_set_pc(&uc->uc_mcontext->__ss, pcv + 4);
    return 1;
}

// In-VM record dump (Debug_OzRecord). The dispatcher builds one record per
// virtual step as pool + (constant - key) * stride; at the 0xc fault x0 holds
// the pool while x22/x23 still hold the constant and the stride, so the step
// that delivered the verdict can be named without tracing every dispatch.
struct shdw_oz_cand {
    uint32_t c;
    uint32_t k;
};

static void shdw_diag_dump_oz_record(uintptr_t pool, uint64_t c22, uint64_t s23,
                                     int faultNo) {
    Dl_info pi = {0};
    if (!pool || !dladdr((void *)pool, &pi) || !pi.dli_fname || !pi.dli_fbase ||
        !strstr(pi.dli_fname, "OZLivenessSDK")) {
        return;
    }

    uintptr_t base = (uintptr_t)pi.dli_fbase;
    uint32_t k0 = (uint32_t)shdw_diag_peek(base + 0x1068590, 4);
    uint32_t k1 = (uint32_t)shdw_diag_peek(base + 0x1068540, 4);
    uint32_t k2 = (uint32_t)shdw_diag_peek(base + 0x1068568, 4);
    uint64_t tbl = shdw_diag_peek(base + 0x1067588, 8);
    char tbls[192];
    shdw_diag_describe_short(tbls, sizeof tbls, (void *)(uintptr_t)tbl);
    shdw_diag_log("OZREC n=%d base=%p pool=%p poff=0x%lx k590=%#x k540=%#x"
                  " k568=%#x tbl=%s x22=%#llx x23=%#llx",
                  faultNo, (void *)base, (void *)pool,
                  (unsigned long)(pool - base), k0, k1, k2, tbls,
                  (unsigned long long)c22, (unsigned long long)s23);

    struct shdw_oz_cand cand[4] = {
        {0x5e54e160u, k0},
        {0xd70ff229u, k1},
        {0xd70ff24du, k1},
        {0xd7c2866eu, k2},
    };
    uint64_t stride = s23 == 0x5a0 ? s23 : 0x5a0;

    for (unsigned i = 0; i < 4; i++) {
        uint32_t idx = cand[i].c - cand[i].k;
        uintptr_t rec = pool + (uintptr_t)((uint64_t)idx * stride);
        shdw_diag_log("OZREC cand=%u c=%#x k=%#x idx=%#x rec=%p", i,
                      cand[i].c, cand[i].k, idx, (void *)rec);
        shdw_diag_peek_words("rec", rec, 0, 0x40);

        if (i != 0) {
            continue;
        }
        // Annotate the whole record: a qword that resolves to a loaded image
        // or to OZ itself names the handler this step was dispatched with.
        for (size_t off = 0x40; off < 0x5a0; off += 8) {
            uint64_t v = shdw_diag_peek(rec + off, 8);
            if (v < 0x1000) {
                continue;
            }
            Dl_info di = {0};
            if (!dladdr((void *)(uintptr_t)v, &di) || !di.dli_fbase ||
                !di.dli_fname) {
                continue;
            }
            char d[192];
            shdw_diag_describe_short(d, sizeof d, (void *)(uintptr_t)v);
            shdw_diag_log("OZREC ptr off=%#lx %s", (unsigned long)off, d);
        }
    }
}

static int shdw_diag_trap_skip(int sig, ucontext_t *uc) {
    if (!shdw_diag_enabled || !uc) {
        return 0;
    }
    if (sig == SIGILL && __atomic_load_n(&shdw_insvc_on, __ATOMIC_ACQUIRE)) {
        uintptr_t ipc = arm_thread_state64_get_pc(uc->uc_mcontext->__ss);

        if (ipc && *(const uint32_t *)ipc == 0x00000000u) {
            Dl_info di = {0};
            unsigned long ioff = 0;

            if (dladdr((void *)ipc, &di) && di.dli_fbase) {
                ioff = (unsigned long)(ipc - (uintptr_t)di.dli_fbase);
            }
            return shdw_insvc_emulate(uc, ipc, ioff);
        }
    }
    if ((sig == SIGTRAP || sig == SIGSEGV) && shdw_diag_oz_poison(uc, sig)) {
        return 1;
    }
    if (sig == SIGTRAP && shdw_diag_stub_skip(uc)) {
        return 1;
    }
    if (sig != SIGSEGV) {
        return 0;
    }

    uint64_t *x = uc->uc_mcontext->__ss.__x;
    uintptr_t pcv = arm_thread_state64_get_pc(uc->uc_mcontext->__ss);
    uintptr_t lrv = arm_thread_state64_get_lr(uc->uc_mcontext->__ss);
    Dl_info called = {0};
    Dl_info caller = {0};
    static int faultLogged;
    int faultNo = __atomic_add_fetch(&shdw_diag_trap_count, 1, __ATOMIC_RELAXED);

    if (faultLogged < 120) {
        char pcs[256];
        char lrs[256];
        char x0s[256];
        char x1s[256];
        char x19s[256];
        char x20s[256];
        faultLogged++;
        shdw_diag_describe_short(pcs, sizeof pcs, (void *)pcv);
        shdw_diag_describe_short(lrs, sizeof lrs, (void *)lrv);
        shdw_diag_describe_short(x0s, sizeof x0s, (void *)x[0]);
        shdw_diag_describe_short(x1s, sizeof x1s, (void *)x[1]);
        shdw_diag_describe_short(x19s, sizeof x19s, (void *)x[19]);
        shdw_diag_describe_short(x20s, sizeof x20s, (void *)x[20]);
        shdw_diag_log("FAULT n=%d sig=%d pc=%s lr=%s x0=%p x1=%p x8=%p x9=%p",
                      faultNo, sig, pcs, lrs, (void *)x[0], (void *)x[1],
                      (void *)x[8], (void *)x[9]);
        shdw_diag_log("FAULTX n=%d x0=%s x1=%s", faultNo, x0s, x1s);
        shdw_diag_log("FAULT2 n=%d x19=%p x20=%p x21=%p x22=%p x23=%p x24=%p x28=%p",
                      faultNo, (void *)x[19], (void *)x[20], (void *)x[21],
                      (void *)x[22], (void *)x[23], (void *)x[24], (void *)x[28]);
        shdw_diag_log("FAULTX2 n=%d x19=%s x20=%s", faultNo, x19s, x20s);
        shdw_diag_log("OZCTX n=%d x19=%p state=%#llx hash=%#llx len=%#llx"
                      " p=%#llx base=%#llx next=%#llx limit=%#llx",
                      faultNo, (void *)x[19],
                      (unsigned long long)shdw_diag_peek((uintptr_t)x[19] + 0x59c, 4),
                      (unsigned long long)shdw_diag_peek((uintptr_t)x[19] + 0x86c, 4),
                      (unsigned long long)shdw_diag_peek((uintptr_t)x[19] + 0x69c, 4),
                      (unsigned long long)shdw_diag_peek((uintptr_t)x[19] + 0x6a0, 8),
                      (unsigned long long)shdw_diag_peek((uintptr_t)x[19] + 0x570, 8),
                      (unsigned long long)shdw_diag_peek((uintptr_t)x[19] + 0x860, 8),
                      (unsigned long long)shdw_diag_peek((uintptr_t)x[19] + 0x870, 8));
        // Interpreter-style obfuscation keeps its state in the heap object
        // held by x19; sample its live words while the frame is still valid.
        shdw_diag_peek_words("ctx", (uintptr_t)x[19], 0x60, 32);
        shdw_diag_peek_words("ctx", (uintptr_t)x[19], 0x1d0, 64);
        shdw_diag_peek_words("ctx", (uintptr_t)x[19], 0x210, 64);
        shdw_diag_peek_words("ctx", (uintptr_t)x[19], 0x250, 64);
        shdw_diag_peek_words("ctx", (uintptr_t)x[19], 0x290, 64);
        shdw_diag_peek_words("ctx", (uintptr_t)x[19], 0x300, 32);
        shdw_diag_peek_words("ctx", (uintptr_t)x[19], 0xb78, 32);
        shdw_diag_peek_words("ctx", (uintptr_t)x[19], 0x1f40, 48);
        shdw_diag_peek_words("ctx", (uintptr_t)x[19], 0x2640, 32);
        shdw_diag_dump_state_compare((uintptr_t)x[19]);
        shdw_diag_dump_state_ring();
        shdw_diag_dump_hw_ring();
    }

    // The VM epilogue ran before ret: for the OZ interpreter that means
    // sp == frameStart + 0xa50 and the poison pair sits at frame+0x40.
    if (shdw_diag_vmframe && pcv < 0x10000 && pcv == lrv) {
        uintptr_t sp = (uintptr_t)arm_thread_state64_get_sp(uc->uc_mcontext->__ss);
        uintptr_t pf = 0;
        for (uintptr_t a = sp; a > sp - 0x4000; a -= 8) {
            if (shdw_diag_peek(a, 8) == 4 && shdw_diag_peek(a + 8, 8) == 0xc) {
                pf = a - 0x40;
                break;
            }
        }
        shdw_diag_log("VMFRAME n=%d sp=%p frame=%p", faultNo, (void *)sp,
                      (void *)pf);
        if (pf) {
            uintptr_t p = (uintptr_t)shdw_diag_peek(pf + 0x570, 8);
            uintptr_t poff = 0;
            const char *pimg = p >= 0x10000 ? shdw_diag_image_for_word(p, &poff) : NULL;
            const char *pbase = pimg ? strrchr(pimg, '/') : NULL;
            shdw_diag_log("VMFRAME fields id=%#llx hash=%#llx seed=%#llx cnt=%#llx "
                          "next=%#llx p=%p image=%s+0x%lx",
                          (unsigned long long)shdw_diag_peek(pf + 0x59c, 4),
                          (unsigned long long)shdw_diag_peek(pf + 0x86c, 4),
                          (unsigned long long)shdw_diag_peek(pf + 0x69c, 4),
                          (unsigned long long)shdw_diag_peek(pf + 0x6a0, 8),
                          (unsigned long long)shdw_diag_peek(pf + 0x860, 8),
                          (void *)p, pbase ? pbase + 1 : (pimg ? pimg : "?"),
                          (unsigned long)poff);
            shdw_diag_peek_words("vmframe", pf, 0, 0x50);
            shdw_diag_peek_words("vmhash", p - 32, 0, 64);
        }
    }

    if (faultNo == 1 || pcv < 0x10000) {
        shdw_diag_dump_stack_raw(faultNo == 1 ? "stk" : "stkpoison", uc);
    }

    // x24 of the fatal jump holds the JSON report literal; recover the buffer
    // once so a second fault cannot re-walk the whole task.
    if (shdw_diag_jsonscan && pcv < 0x10000) {
        static int done;

        if (!done) {
            done = 1;
            shdw_diag_json_scan();
        }
    }

    if (shdw_diag_oz_record && pcv < 0x10000) {
        shdw_diag_dump_oz_record((uintptr_t)x[0], x[22], x[23], faultNo);
    }

    // Verdict-thread parking (Debug_OzVerdictThread): the 0xc jump is OZ's own
    // fail delivery on a libdispatch worker. Hand the block back to libdispatch
    // as if it had returned: the nearest libdispatch return address above the
    // faulting sp belongs to the block's caller, so resuming there with the
    // caller's frame leaves the worker pool intact. Exiting the thread instead
    // (fallback) keeps the process up but stalls launch until the watchdog.
    if (shdw_diag_oz_verdict_thread && pcv < 0x10000 && pcv == lrv) {
        Dl_info pool = {0};
        if (dladdr((void *)x[0], &pool) && pool.dli_fname &&
            strstr(pool.dli_fname, "OZLivenessSDK")) {
            uintptr_t sp = arm_thread_state64_get_sp(uc->uc_mcontext->__ss);
            for (unsigned off = 0; off < 0x200; off += 8) {
                uint64_t v = *(const uint64_t *)(sp + off);
                if (v < 0x100000000ull) {
                    continue;
                }
                Dl_info di = {0};
                if (!dladdr((void *)(uintptr_t)v, &di) || !di.dli_fname ||
                    !strstr(di.dli_fname, "libdispatch")) {
                    continue;
                }
                shdw_diag_log("OZKILL block-return n=%d pc=%p off=0x%x ret=%p"
                              " sp=%p new_sp=%p", faultNo, (void *)pcv, off,
                              (void *)(uintptr_t)v, (void *)sp, (void *)(sp + off + 8));
                shdw_diag_set_pc(&uc->uc_mcontext->__ss, (uintptr_t)v);
                arm_thread_state64_set_sp(uc->uc_mcontext->__ss, sp + off + 8);
                return 1;
            }
            shdw_diag_log("OZKILL thread-exit n=%d pc=%p lr=%p x0=%p sp=%p",
                          faultNo, (void *)pcv, (void *)lrv, (void *)x[0],
                          (void *)sp);
            shdw_diag_set_pc(&uc->uc_mcontext->__ss,
                             (uintptr_t)shdw_verdict_exit_stub);
            arm_thread_state64_set_sp(uc->uc_mcontext->__ss,
                (uintptr_t)(shdw_verdict_stack + sizeof shdw_verdict_stack));
            arm_thread_state64_set_lr_fptr(uc->uc_mcontext->__ss, (void *)0);
            return 1;
        }
    }

    if (x[0] > 0x10000 || x[1] > 0x10000) {
        return 0;
    }
    if (!dladdr((void *)pcv, &called) || !called.dli_sname ||
        strcmp(called.dli_sname, "objc_msgSend") != 0) {
        return 0;
    }
    if (!lrv || !dladdr((void *)lrv, &caller) || !caller.dli_fname) {
        return 0;
    }
    if (!strncmp(caller.dli_fname, "/usr/lib/", 9) ||
        !strncmp(caller.dli_fname, "/System/", 8)) {
        return 0;
    }

    uintptr_t site = lrv - (uintptr_t)caller.dli_fbase;
    static int logged;
    int hit = faultNo;

    // A self-check that faults at the same return address over and over is not
    // recovering -- it is spinning, and every resume burns a fault until the
    // host runtime decides the process is hopeless. Track the last few sites by
    // return address and hand the fault back to the original disposition once a
    // single site repeats past the limit, so the SDK dies its own natural death
    // instead of being walked in circles.
    static struct {
        uintptr_t lr;
        unsigned hits;
    } loops[8];
    static unsigned loopsNext;
    unsigned loopHits = 0;

    for (unsigned i = 0; i < 8; i++) {
        if (loops[i].lr == lrv) {
            loopHits = __atomic_add_fetch(&loops[i].hits, 1, __ATOMIC_RELAXED);
            break;
        }
    }
    if (!loopHits) {
        unsigned slot = __atomic_fetch_add(&loopsNext, 1, __ATOMIC_RELAXED) % 8;
        loops[slot].lr = lrv;
        loops[slot].hits = 1;
        loopHits = 1;
    }
    if (loopHits > 12) {
        static int loopLogged;
        if (loopLogged < 3) {
            loopLogged++;
            shdw_diag_log("TRAPLOOP n=%d site=%s+0x%lx hits=%u -- pass to original handler",
                          hit, caller.dli_fname, (unsigned long)site, loopHits);
        }
        return 0;
    }

    if (logged < 6) {
        logged++;
        shdw_diag_log("TRAPSKIP n=%d tid=%p site=%s+0x%lx recv=%p sel=%p x8=%#llx x9=%#llx",
                      hit, (void *)pthread_self(), caller.dli_fname,
                      (unsigned long)site, (void *)x[0], (void *)x[1],
                      (unsigned long long)x[8], (unsigned long long)x[9]);
        shdw_diag_log("TRAPHIT n=%d pc=%p lr=%p sp=%p fp=%p x19=%p x22=%p x24=%p x27=%p x28=%p",
                      hit, (void *)pcv, (void *)lrv,
                      (void *)arm_thread_state64_get_sp(uc->uc_mcontext->__ss),
                      (void *)arm_thread_state64_get_fp(uc->uc_mcontext->__ss),
                      (void *)x[19], (void *)x[22], (void *)x[24],
                      (void *)x[27], (void *)x[28]);
        if (hit == 1) {
            char pcs[512];
            char lrs[512];
            shdw_diag_describe(pcs, sizeof pcs, (void *)pcv);
            shdw_diag_describe(lrs, sizeof lrs, (void *)lrv);
            shdw_diag_log("TRAPCTX fault=%p pc=%s lr=%s", (void *)x[0], pcs, lrs);
            shdw_diag_dump_regs("trap", uc, pcv, lrv);
            if (!strncmp(caller.dli_fname, "/private/var/containers/Bundle/Application", 42)) {
                char x20s[512];
                char x22s[512];
                uint64_t slot860 = 0, slot868 = 0, slot910 = 0;
                uint64_t keyA = 0, keyB = 0, keyW = 0;
                uintptr_t obase = (uintptr_t)caller.dli_fbase;
                shdw_diag_describe(x20s, sizeof x20s, (void *)x[20]);
                shdw_diag_describe(x22s, sizeof x22s, (void *)x[22]);
                shdw_diag_read_words(obase + 0x105b860, &slot860, sizeof slot860);
                shdw_diag_read_words(obase + 0x105b868, &slot868, sizeof slot868);
                shdw_diag_read_words(obase + 0x105b910, &slot910, sizeof slot910);
                keyA = shdw_diag_peek(obase + 0x10930c8, 4);
                keyB = shdw_diag_peek(obase + 0x1092b70, 4);
                keyW = shdw_diag_peek(obase + 0x1097688, 4);
                shdw_diag_log("TRAPSLOT obase=%p slot860=%p(expectOZ=%p) slot868=%p(expectOZ=%p) "
                              "slot910=%p keyA=%#llx keyB=%#llx keyW=%#llx x20=%s x22=%s",
                              (void *)obase, (void *)(uintptr_t)slot860,
                              (void *)(obase + 0x51d28),
                              (void *)(uintptr_t)slot868,
                              (void *)(obase + 0x51c80),
                              (void *)(uintptr_t)slot910,
                              (unsigned long long)keyA, (unsigned long long)keyB,
                              (unsigned long long)keyW, x20s, x22s);
            }
        }
    }

    shdw_diag_set_pc(&uc->uc_mcontext->__ss, lrv);
    return 1;
}

// TEMP DIAG: chain to whatever was installed before this one instead of
// re-raising out of the handler. Re-raising generates a fresh signal at the
// handler's own frame, so a runtime that recovers from its fault (the Go
// runtime's guard-page SIGSEGV, the app's own signal chains) sees a fault in
// foreign code and aborts. Passing the original siginfo/ucontext through keeps
// the previous disposition doing exactly what it did before.
static void shdw_diag_signal_handler(int sig, siginfo_t *info, void *context) {
    if (shdw_diag_trap_skip(sig, (ucontext_t *)context)) {
        return;
    }
    if (!shdw_diag_sig_logged[sig]) {
        shdw_diag_sig_logged[sig] = 1;
        shdw_pc_mark = __atomic_load_n(&shdw_pc_pos, __ATOMIC_RELAXED);
        {
            struct timespec ts;
            clock_gettime(CLOCK_MONOTONIC, &ts);
            shdw_pc_mark_ns = (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
        }
        char pc[512];
        char lr[512];
        ucontext_t *uc = (ucontext_t *)context;
        // The field names differ between the opaque (ptrauth) and plain
        // thread-state layouts; the SDK accessors cover both.
        uintptr_t pcv = uc ? arm_thread_state64_get_pc(uc->uc_mcontext->__ss) : 0;
        uintptr_t lrv = uc ? arm_thread_state64_get_lr(uc->uc_mcontext->__ss) : 0;
        shdw_diag_describe(pc, sizeof pc, (void *)pcv);
        shdw_diag_describe(lr, sizeof lr, (void *)lrv);
        shdw_diag_log("SIGNAL caught sig=%d fault=%p pc=%s lr=%s", sig,
                      info ? info->si_addr : NULL, pc, lr);
        shdw_diag_dump_oz_state(uc, pcv);
        shdw_diag_dump_regs("sig", uc, pcv, lrv);
        shdw_diag_vm_ctx("sig", uc);
        shdw_funnel_dump("sig");
        if (uc) {
            uintptr_t s19 = (uintptr_t)uc->uc_mcontext->__ss.__x[19];
            if (s19) {
                shdw_diag_log("OZSTATE x19=%p [+59c]=%#llx [+664]=%#llx [+668]=%#llx"
                              " [+670]=%#llx [+810]=%#llx [+81c]=%#llx [+820]=%#llx",
                              (void *)s19,
                              (unsigned long long)shdw_diag_peek(s19 + 0x59c, 4),
                              (unsigned long long)shdw_diag_peek(s19 + 0x664, 4),
                              (unsigned long long)shdw_diag_peek(s19 + 0x668, 8),
                              (unsigned long long)shdw_diag_peek(s19 + 0x670, 8),
                              (unsigned long long)shdw_diag_peek(s19 + 0x810, 8),
                              (unsigned long long)shdw_diag_peek(s19 + 0x81c, 4),
                              (unsigned long long)shdw_diag_peek(s19 + 0x820, 8));
            }
        }
        shdw_diag_pcsample_dump("sig", (uint32_t)pthread_mach_thread_np(pthread_self()));
    }

    struct sigaction *prev = &shdw_diag_prev_sa[sig];

    if (prev->sa_flags & SA_SIGINFO) {
        if (prev->sa_sigaction) {
            prev->sa_sigaction(sig, info, context);
        }
        return;
    }

    if (prev->sa_handler == SIG_DFL || prev->sa_handler == SIG_IGN) {
        sigaction(sig, prev, NULL);
        raise(sig);
        return;
    }

    if (prev->sa_handler) {
        prev->sa_handler(sig);
    }
}

static void shdw_diag_install_signals(void) {
    static const int sigs[] = {SIGABRT, SIGSEGV, SIGBUS, SIGILL,
                               SIGFPE,  SIGSYS, SIGTRAP, SIGTERM};

    for (size_t i = 0; i < sizeof sigs / sizeof sigs[0]; i++) {
        struct sigaction sa;
        memset(&sa, 0, sizeof sa);
        sa.sa_sigaction = shdw_diag_signal_handler;
        sa.sa_flags = SA_SIGINFO;
        sigemptyset(&sa.sa_mask);
        sigaction(sigs[i], &sa, &shdw_diag_prev_sa[sigs[i]]);
    }
}

// A detector that installs its own SIGTRAP/SIGSEGV handler after this ctor
// silently takes the trap lane away from the diagnostic handler. This lane
// samples the live dispositions over the startup window and names the owner
// of each one, so a missing SIGTRAP record is not mistaken for "no trap"
// (pref: Debug_SigWatch).
int shdw_diag_sigwatch = 0;


// Change-driven variant: a 20 ms sweep logs every ownership transition, so a
// handler installed between the coarse marks (a detector arming its own
// SIGSEGV disposition, Dynatrace re-installing) is still named with its time.
static void shdw_diag_sigwatch_poll(unsigned ms, void **last) {
    static const int sigs[] = {SIGSEGV, SIGTRAP, SIGSYS, SIGABRT, SIGBUS};
    static const char *const names[] = {"SEGV", "TRAP", "SYS", "ABRT", "BUS"};

    for (size_t i = 0; i < sizeof sigs / sizeof sigs[0]; i++) {
        struct sigaction cur;
        memset(&cur, 0, sizeof cur);
        if(sigaction(sigs[i], NULL, &cur) != 0) {
            continue;
        }
        void *h = (cur.sa_flags & SA_SIGINFO) ? (void *)cur.sa_sigaction
                                              : (void *)cur.sa_handler;
        if(last[i] == h) {
            continue;
        }
        last[i] = h;
        char d[160];
        shdw_diag_describe_short(d, sizeof d, h);
        shdw_diag_log("SIGWATCH t=%ums sig=%s ours=%d flags=%#x handler=%s",
                      ms, names[i], h == (void *)shdw_diag_signal_handler,
                      (unsigned)cur.sa_flags, d);
    }
}

static void* shdw_diag_sigwatch_thread(void* arg) {
    (void)arg;
    static void *last[5];
    static int seeded;

    for(unsigned ms = 0; ms <= 2500; ms += 20) {
        struct timespec iv = {0, 20 * 1000 * 1000};
        if(ms) {
            nanosleep(&iv, NULL);
        }
        if(!seeded) {
            memset(last, 0xff, sizeof last);
            seeded = 1;
        }
        shdw_diag_sigwatch_poll(ms, last);
    }

    return NULL;
}

static void shdw_diag_install_sigwatch(void) {
    pthread_t th;
    pthread_attr_t attr;

    if (pthread_attr_init(&attr) != 0) {
        return;
    }
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&th, &attr, shdw_diag_sigwatch_thread, NULL);
    pthread_attr_destroy(&attr);
}

// Two OZ once-slots (0x105b860/0x105b868) hold file-time code pointers at load
// and are rewritten by OZ's own obfuscated VM. Both integrity gadgets compare
// the slot against its load-time value and poison when they differ, so the
// moment of the rewrite decides the verdict. This lane polls both slots and
// logs every transition with the three VM key globals (pref: Debug_SlotWatch).
int shdw_diag_slotwatch = 0;

static uintptr_t shdw_diag_slot_oz_base(void) {
    static uintptr_t cached;

    if (cached) {
        return cached;
    }

    uint32_t count = _dyld_image_count();

    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);

        if (name && strstr(name, "OZLivenessSDK")) {
            cached = (uintptr_t)_dyld_get_image_header(i);
            return cached;
        }
    }

    return 0;
}

static void shdw_diag_slotwatch_report(int n, uintptr_t base, uint64_t s860,
                                       uint64_t s868) {
    uint64_t keyA = shdw_diag_peek(base + 0x10930c8, 4);
    uint64_t keyB = shdw_diag_peek(base + 0x1092b70, 4);
    uint64_t keyW = shdw_diag_peek(base + 0x1097688, 4);

    shdw_diag_log("SLOTWATCH n=%d base=%p slot860=%p slot868=%p "
                  "keyA=%#llx keyB=%#llx keyW=%#llx",
                  n, (void *)base, (void *)(uintptr_t)s860,
                  (void *)(uintptr_t)s868, (unsigned long long)keyA,
                  (unsigned long long)keyB, (unsigned long long)keyW);

    thread_act_array_t list = NULL;
    mach_msg_type_number_t count = 0;

    if (task_threads(mach_task_self(), &list, &count) == KERN_SUCCESS && list) {
        for (mach_msg_type_number_t i = 0; i < count; i++) {
            arm_thread_state64_t st;
            mach_msg_type_number_t sc = ARM_THREAD_STATE64_COUNT;

            if (thread_get_state(list[i], ARM_THREAD_STATE64,
                                 (thread_state_t)&st, &sc) == KERN_SUCCESS) {
                char d[160];
                shdw_diag_describe_short(d, sizeof d,
                                         (void *)arm_thread_state64_get_pc(st));
                shdw_diag_log("SLOTWATCH th=%u pc=%s", (unsigned)i, d);
            }
            mach_port_deallocate(mach_task_self(), list[i]);
        }
        vm_deallocate(mach_task_self(), (vm_address_t)list,
                      count * sizeof(thread_t));
    }
}

static void* shdw_diag_slotwatch_thread(void* arg) {
    (void)arg;
    uint64_t last860 = 0;
    uint64_t last868 = 0;
    int logged = 0;
    const struct timespec iv = {0, 200 * 1000};

    for (;;) {
        uintptr_t base = shdw_diag_slot_oz_base();

        if (base) {
            uint64_t s860 = 0;
            uint64_t s868 = 0;

            if (shdw_diag_read_words(base + 0x105b860, &s860, sizeof s860) &&
                shdw_diag_read_words(base + 0x105b868, &s868, sizeof s868)) {
                if (s860 != last860 || s868 != last868) {
                    if (logged < 12) {
                        shdw_diag_slotwatch_report(logged, base, s860, s868);
                    }
                    logged++;
                    last860 = s860;
                    last868 = s868;
                }
            }
        }

        nanosleep(&iv, NULL);
    }

    return NULL;
}

static void shdw_diag_install_slotwatch(void) {
    pthread_t th;
    pthread_attr_t attr;

    if (pthread_attr_init(&attr) != 0) {
        return;
    }
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&th, &attr, shdw_diag_slotwatch_thread, NULL);
    pthread_attr_destroy(&attr);
}

// Dynatrace takes the SIGTRAP lane a few hundred ms into startup and consumes
// the trap instead of chaining it, so the poison BRK that produces the 0xc
// death is invisible. This lane re-installs the diagnostic handler in front of
// whoever owns SIGTRAP at that moment and keeps our previous disposition
// pointing at that owner, so the trap is recorded and then handed back
// unchanged (pref: Debug_SigRearm).
int shdw_diag_sigrearm = 0;

static void shdw_diag_sigrearm_pass_one(int sig, unsigned ms) {
    struct sigaction cur;
    memset(&cur, 0, sizeof cur);

    if (sigaction(sig, NULL, &cur) != 0) {
        return;
    }

    void *h = (cur.sa_flags & SA_SIGINFO) ? (void *)cur.sa_sigaction
                                          : (void *)cur.sa_handler;
    if (h == (void *)shdw_diag_signal_handler) {
        return;
    }

    struct sigaction sa;
    struct sigaction prev;
    memset(&sa, 0, sizeof sa);
    memset(&prev, 0, sizeof prev);
    sa.sa_sigaction = shdw_diag_signal_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);

    if (sigaction(sig, &sa, &prev) == 0) {
        static int rearmLogged;
        shdw_diag_prev_sa[sig] = prev;
        if (rearmLogged < 60) {
            char d[160];
            rearmLogged++;
            shdw_diag_describe_short(d, sizeof d, h);
            shdw_diag_log("REARM sig=%d t=%ums prev=%s", sig, ms, d);
        }
    }
}

static void shdw_diag_sigrearm_pass(unsigned ms) {
    shdw_diag_sigrearm_pass_one(SIGTRAP, ms);
    shdw_diag_sigrearm_pass_one(SIGILL, ms);
}

static void* shdw_diag_sigrearm_thread(void* arg) {
    (void)arg;
    // Tight sweep: Dynatrace reinstalls its handler at arbitrary moments and
    // the verdict trap fires ~1.5 s in, so a coarse schedule can miss it.
    for (unsigned ms = 0; ms <= 4000; ms += 2) {
        struct timespec iv = {0, 2 * 1000 * 1000};
        nanosleep(&iv, NULL);
        shdw_diag_sigrearm_pass(ms);
    }

    return NULL;
}

static void shdw_diag_install_sigrearm(void) {
    pthread_t th;
    pthread_attr_t attr;

    if (pthread_attr_init(&attr) != 0) {
        return;
    }
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&th, &attr, shdw_diag_sigrearm_thread, NULL);
    pthread_attr_destroy(&attr);
}

// OZ's verdict block ends in `brk #1` at OZ+0x3af93c, yet that trap never
// reaches the SIGTRAP handler: the process keeps running and only dies later
// at the poisoned return address. A Mach exception port is therefore consuming
// the trap. Debug_ExcPorts logs who owns the ports; Debug_ExcCatch takes
// EXC_BREAKPOINT for the process, records the VM state at the trap (the
// interpreter context in x19 is still intact there) and resumes at pc+4, which
// is what the previous owner did.
int shdw_diag_excports = 0;
int shdw_diag_exccatch = 0;
int shdw_diag_excwatch = 0;
// 0 = observe only; 1 = forge ENOENT (the stock-device answer) for the
// detector's __mac_syscall("Sandbox", 2, {.. "file-test-existence" ..}) calls;
// 2 = forge 0; 3 = production lane: site 0 only, the breakpoint stays armed
// after a forge (pc moves to the return address, so it cannot retrigger) and
// no observation work is done per hit. The thunk is skipped entirely: pc goes
// straight to the return address with the result word written, so the kernel
// never answers.
#define SHDW_FORGE_PROD 3
int shdw_diag_svcforge = 0;
// Sparkasse/Promon SHIELD: the framework's only exit carrier is the thunk at
// +0x430d9c. It builds SYS_exit (x16) and the status word (x0=1) from
// xor-masked constants, then dispatches through the guard cell at +0x9caab8.
// No libc exit is ever called, which is why the ExitProbe lane stayed silent.
// One hardware breakpoint there, one-shot, names the failing path (lr) and the
// register state without touching __text or the cell. +0x3c1be8 is the +load
// entry that runs first, kept as the timing reference. (pref: Debug_SpkBrk)
#define SHDW_SPK_EXIT 0x430d9c
// The predicate reads a byte at singleton+0x330. Its writers: the constructor
// stores 1 (+0x4032a0), a config decoder stores the result of the archive field
// (+0x403e0c), and the reset path stores 0 (+0x4546bc).
#define SHDW_SPK_CTOR 0x4032a0
#define SHDW_SPK_PRED_CALL 0x8ed0c
#define SHDW_SPK_PRED_RET 0x8ed10
#define SHDW_SPK_SETTER 0x403e0c
#define SHDW_SPK_CLEAR 0x4546bc
#define SHDW_SPK_POSTCALL 0x8ed88
int shdw_diag_spkbrk = 0;
// Sparkasse lane without any exception: a polling thread watches the
// framework's config singleton and clears the verdict byte before the
// predicate at +0x8ed0c reads it. No breakpoint, no thread-state rewrite.
int shdw_diag_spkfix = 0;
// Sparkasse syscall census without text or cell writes. The verdict byte is
// set to its pessimistic default by +0x4032a0; a one-shot breakpoint there
// then arms the framework's own dispatch stub (+0x430d9c) on the same thread
// so every syscall from that moment on is logged with its arguments. The
// stub is the only funnel SHIELD uses, so this seq is the detector's input.
#define SHDW_SPK_STUB 0x430d9c
#define SHDW_SPKSTUB_CAP 1500
int shdw_diag_spkstub = 0;
// Sparkasse: leave the terminate-or-continue wrapper (+0x8ecac) through its
// own epilogue instead of taking either branch. The non-zero verdict byte
// reaches the exit thunk; forcing the byte to zero reaches +0x817444, which
// poisons the thread state. Both are terminal, so this lane only answers
// whether SHIELD's +load chain can continue when the gate does not fire.
#define SHDW_SPK_DECISION 0x8ed1c
#define SHDW_SPK_EPILOGUE 0x8edcc
#define SHDW_SPKSKIP_CAP 40
// The verdict byte's store is +0x4032a0 with the next instruction at
// +0x4032a4; a breakpoint there writes the "validated" value before any
// reader runs.
#define SHDW_SPK_CTORFIX 0x4032a4
#define SHDW_SPK_CTORFIX_CAP 8
// Watch-only slot for the dispatch stub: the terminate call shows up here as
// a hit whose lr names the gate that made it. Armed on every thread by the
// sweep, so a helper-thread verdict is caught too.
#define SHDW_SPKSTUBW 0x430d9c
#define SHDW_SPKSTUBW_CAP 400
int shdw_diag_spkskip = 0;
// Watch-only: does the config decoder run at all before the gate? Site 0 is
// the call at +0x406e50 (the decoder's single static caller), site 1 is the
// decoder entry +0x4038a4. Zero hits proves the parse never happens on this
// launch; hits expose the message buffer and the fields the decoder needs.
#define SHDW_SPKDEC_CALL 0x406e50
#define SHDW_SPKDEC_ENTRY 0x4038a4
int shdw_diag_spkdec = 0;
// Watch-only: the decoder drove eight tag cases (0x49 0x4c 0x4d 0x23 0x3a
// 0x11 0x0a 0x0f) but never 0x19, the case that stores [obj+0x330]. Site 0 is
// the per-field loop of that caller; it dumps the serialized message the tags
// come from. Site 1 dumps each tag's payload string.
#define SHDW_SPKMSG_LOOP 0x406e44
#define SHDW_SPKMSG_DEC 0x4038a4
int shdw_diag_spkmsg = 0;
// The only untested branch: verdict byte 0 at the gate, with nothing else
// touched. The earlier byte-0 runs also skipped the wrapper, so their SIGILL
// cannot be attributed to the zero branch. Site 0 writes 0 just after the
// ctor's pessimistic store; site 1 logs the predicate's answer.
// Catch the killer itself: whatever reaches here gets logged with its LR.
#define SHDW_SPKZERO_CTOR 0x430d9c
// Gate getter: ldrb w0,[x0,#0x330]; ret. Trapping here fires BEFORE the
// load, so zeroing [x0+0x330] is what the caller actually reads. The old
// site (0x8ed10) sat after `blr x8`, too late to change the result.
#define SHDW_SPKZERO_PRED 0x4087a8
int shdw_diag_spkzero = 0;
// The three indirect calls of the gate wrapper: predicate (0x8ed0c), the
// w20!=0 branch (0x8ed4c) and the common call (0x8ed88). The munged table
// entries resolve to real functions at runtime; logging x8 before each blr
// names them. 0x8ed1c logs w20 so polarity is tied to the target.
#define SHDW_SPKGATE_PRED 0x8ed0c
#define SHDW_SPKGATE_NZ 0x8ed4c
#define SHDW_SPKGATE_COMMON 0x8ed84
#define SHDW_SPKGATE_DECISION 0x8ed1c
int shdw_diag_spkgate = 0;
// The terminate chain lives in code that is decrypted at runtime: static
// bytes at +0x811d98 do not match what executes. Reading the mapped pages at
// the moment of the gate yields the real instructions. One shot, no writes.
#define SHDW_SPKMEM_DEC 0x8ed1c
int shdw_diag_spkmem = 0;
// Hardware exec breakpoint on the instruction the dispatch cell points at.
// Every sensitive syscall in this image goes through [base+0x9caab8], so the
// trap names the probe stream without writing code or the cell. The cell is
// resolved at install, before the sweep arms it on every thread.
int shdw_diag_spksvc = 0;
// Forge CodeDirectory slot reads in memory; implies the syscall site.
int shdw_diag_spkforge = 0;
// One-shot: hash of the dyld cache page SHIELD verifies, memory vs file.
int shdw_diag_spkcache = 0;
// Sweep task threads and arm the ones created after install.
int shdw_diag_spkrearm = 0;
static int shdw_diag_spkrearm_started;
// Read-only observation without debug registers: thread_get_state is legal for
// the whole task and leaves no trace the target can check, so this lane sees
// the unperturbed startup. Every sample that lands inside the framework is
// logged once per (thread, pc) pair. Pref: Debug_SpkSample.
int shdw_diag_spksample = 0;
static int shdw_diag_spksample_started;
// Event-5 dispatcher call site: what the VM hands to 0x8ee40.
int shdw_diag_spkevt = 0;
// Compiled exit(1) entry: observed, or turned into a plain return.
int shdw_diag_spkexit = 0;
// SHDW_SPKBT: periodic frame-pointer walk of the thread that ran the ctor,
// after the gate. Tells whether a live-but-black window is a stuck main
// thread or a UI that simply never got a frame.
int shdw_diag_spkbt = 0;
// SHDW_SPKSCENE: PromonApplicationDelegate hands the connecting session a
// stub configuration (Chae2AiPSceneDelegate, zero methods, no window), which
// is the black screen. The real Swift SceneDelegate is still registered, so
// the hook returns a configuration that names it instead.
int shdw_diag_spkscene = 0;
static void shdw_diag_spkscene_try(void);
static mach_port_t shdw_spkbt_main = MACH_PORT_NULL;
static uintptr_t shdw_dbg_svc = 0;

static mach_port_t shdw_exc_port = MACH_PORT_NULL;
static int shdw_excwatch_started;
static volatile int shdw_exc_hits = 0;
static uintptr_t shdw_dbg_base = 0;
static int shdw_dbg_armed = 0;
static volatile int shdw_dbg_hits = 0;
// Bit n means site n is retired (one-shot sites) or must not be re-armed.
// Bit 0 dispatch, bit 1 prologue, bit 2 epilogue, bit 3 poison.
static volatile unsigned shdw_dbg_off = 0;
// Per-site hit counts: the inline-syscall thunks execute on every OZ syscall,
// so each one is retired after SHDW_SVC_CAP hits. An unbounded exception
// round-trip per syscall would slow the launch into the FrontBoard watchdog.
static volatile unsigned shdw_dbg_site_hits[16];
#define SHDW_SVC_CAP 1500
static mach_port_t shdw_exc_cur_thread = MACH_PORT_NULL;
// SHDW_SVC_SIGREAD: pending 32-byte pread buffer, peeked one syscall later.
static uintptr_t shdw_svc_sigbuf = 0;
static unsigned shdw_svc_sigth = 0;
// A VM entry/exit site is re-armed on its thread just after the reply, so the
// trapping instruction executes once with the breakpoint cleared.
static mach_port_t shdw_dbg_rearm_port = MACH_PORT_NULL;
static volatile int shdw_dbg_rearm_idx = -1;
// Data watchpoint on the slot that ends up holding the (fp=4, lr=0xc) pair,
// armed when the second-stage dispatch at 0x3602c is about to return into its
// block. Two 8-byte words cover the pair.
static uintptr_t shdw_hw_watch[2];
static int shdw_hw_watch_n;
static int shdw_hw_watch_hits;
static int shdw_diag_hwdbg_claim(exception_type_t type, exception_data_t code,
                                 mach_msg_type_number_t codeCnt,
                                 arm_thread_state64_t *st);
static void shdw_diag_hwdbg_tick(void);
static void shdw_diag_hwdbg_rearm(void);

// The PoisonPc fault is an EXC_BAD_ACCESS (PAC failure / bad branch), so the
// lane has to own that class too if the observer is to see lr and the stack of
// the jumping frame. Unclaimed exceptions are still declined, so the kernel
// delivers the same SIGILL afterwards.
#define SHDW_EXC_PORT_MASK \
    (EXC_MASK_BREAKPOINT | EXC_MASK_BAD_ACCESS | EXC_MASK_BAD_INSTRUCTION)
#define SHDW_EXC_PROBE_MASK                                              \
    (EXC_MASK_BREAKPOINT | EXC_MASK_BAD_ACCESS | EXC_MASK_BAD_INSTRUCTION | \
     EXC_MASK_ARITHMETIC)

static void shdw_diag_exc_task_probe(unsigned ms) {
    exception_mask_t masks[EXC_TYPES_COUNT];
    mach_port_t ports[EXC_TYPES_COUNT];
    exception_behavior_t beh[EXC_TYPES_COUNT];
    thread_state_flavor_t flav[EXC_TYPES_COUNT];
    mach_msg_type_number_t cnt = 0;

    memset(masks, 0, sizeof masks);
    kern_return_t kr = task_get_exception_ports(
        mach_task_self(), SHDW_EXC_PROBE_MASK, masks, &cnt, ports, beh, flav);
    shdw_diag_log("EXCPORTS t=%ums kr=%d cnt=%u", ms, (int)kr, (unsigned)cnt);

    if (kr != KERN_SUCCESS) {
        return;
    }
    for (mach_msg_type_number_t i = 0; i < cnt && i < EXC_TYPES_COUNT; i++) {
        if (!masks[i] || ports[i] == MACH_PORT_NULL) {
            continue;
        }
        shdw_diag_log("EXCPORTS t=%ums i=%u mask=%#x port=%#x ours=%d "
                      "beh=%d flav=%d", ms, (unsigned)i, (unsigned)masks[i],
                      (unsigned)ports[i], ports[i] == shdw_exc_port, (int)beh[i],
                      (int)flav[i]);
    }
}

static void shdw_diag_exc_thread_probe(unsigned ms) {
    thread_act_array_t list = NULL;
    mach_msg_type_number_t n = 0;

    if (task_threads(mach_task_self(), &list, &n) != KERN_SUCCESS || !list) {
        return;
    }
    for (mach_msg_type_number_t t = 0; t < n; t++) {
        exception_mask_t masks[EXC_TYPES_COUNT];
        mach_port_t ports[EXC_TYPES_COUNT];
        exception_behavior_t beh[EXC_TYPES_COUNT];
        thread_state_flavor_t flav[EXC_TYPES_COUNT];
        mach_msg_type_number_t cnt = 0;

        memset(masks, 0, sizeof masks);
        if (thread_get_exception_ports(list[t], SHDW_EXC_PROBE_MASK, masks, &cnt,
                                       ports, beh, flav) != KERN_SUCCESS) {
            continue;
        }
        for (mach_msg_type_number_t i = 0; i < cnt && i < EXC_TYPES_COUNT; i++) {
            if (!masks[i] || ports[i] == MACH_PORT_NULL) {
                continue;
            }
            shdw_diag_log("EXCTHREAD t=%ums th=%u i=%u mask=%#x port=%#x "
                          "beh=%d flav=%d", ms, (unsigned)t, (unsigned)i,
                          (unsigned)masks[i], (unsigned)ports[i], (int)beh[i],
                          (int)flav[i]);
        }
    }
    vm_deallocate(mach_task_self(), (vm_address_t)list, n * sizeof(thread_t));
}

static void shdw_diag_exc_report(exception_type_t type, exception_data_t code,
                                 int flavor, arm_thread_state64_t *st) {
    int n = __atomic_add_fetch(&shdw_exc_hits, 1, __ATOMIC_RELAXED);
    uintptr_t pc = (uintptr_t)arm_thread_state64_get_pc(*st);
    uint64_t *x = st->__x;
    Dl_info di = {0};
    char pcs[192];

    if (n > 40) {
        return;
    }
    shdw_diag_describe_short(pcs, sizeof pcs, (void *)pc);
    shdw_diag_log("EXCBRK n=%d type=%d flav=%d code=%#x/%#x pc=%s x0=%p x19=%p "
                  "sp=%p fp=%p lr=%p", n, (int)type, flavor,
                  (unsigned)code[0], (unsigned)code[1], pcs, (void *)x[0],
                  (void *)x[19], (void *)arm_thread_state64_get_sp(*st),
                  (void *)arm_thread_state64_get_fp(*st),
                  (void *)arm_thread_state64_get_lr(*st));

    if (pc < 0x10000 || !dladdr((void *)pc, &di) || !di.dli_fname) {
        return;
    }
    {
        const char *slash = strrchr(di.dli_fname, '/');
        shdw_diag_log("EXCBRKIMG n=%d image=%s+0x%lx", n,
                      slash ? slash + 1 : di.dli_fname,
                      (unsigned long)(pc - (uintptr_t)di.dli_fbase));
        if (!strstr(di.dli_fname, "OZLivenessSDK")) {
            return;
        }
    }

    uintptr_t base = (uintptr_t)di.dli_fbase;
    unsigned long off = (unsigned long)(pc - base);

    {
        if (off == 0x5fd474) {
            // The common VM abort: x19 is the once-slot value loaded from
            // OZ+0x105b868 at 0x5fd384, and 0x5fd3fc compares it with a
            // pointer computed from the step record. Both sides are dumped so
            // the mismatch can be named.
            uint32_t key = (uint32_t)shdw_diag_peek(base + 0x1094a20, 4);
            uint32_t idx = (uint32_t)(0u - key) + 0xd8143224u;
            uint32_t cell = idx + 0x23b;
            int64_t rec = (int64_t)(uint32_t)x[0] +
                          (int64_t)(int32_t)idx * 0x2c88;
            uint64_t v = rec > 0 ? shdw_diag_peek((uintptr_t)rec +
                                                  (uint64_t)cell * 8, 8) : 0;

            shdw_diag_log("EXCVERDICT n=%d x19=%p expected=%p slot860=%p "
                          "slot868=%p x0=%p key=%#x idx=%#x cell=%#x v=%#llx",
                          n, (void *)x[19], (void *)(uintptr_t)(v + 0x6c65bd68),
                          (void *)(uintptr_t)shdw_diag_peek(base + 0x105b860, 8),
                          (void *)(uintptr_t)shdw_diag_peek(base + 0x105b868, 8),
                          (void *)x[0], key, idx, cell,
                          (unsigned long long)v);
            shdw_diag_log("EXCVERDICT regs n=%d x1=%p x2=%p x8=%p x9=%p x10=%p "
                          "x20=%p x21=%p x22=%p x23=%p x24=%p x27=%p x28=%p fp=%p",
                          n, (void *)x[1], (void *)x[2], (void *)x[8],
                          (void *)x[9], (void *)x[10], (void *)x[20],
                          (void *)x[21], (void *)x[22], (void *)x[23],
                          (void *)x[24], (void *)x[27], (void *)x[28],
                          (void *)arm_thread_state64_get_fp(*st));
            shdw_diag_peek_words("excverdict", (uintptr_t)x[0], 0, 48);
            if (v >= 0x10000) {
                shdw_diag_peek_words("excverdict", (uintptr_t)v, 0, 32);
            }
        }
    }

    if (off != 0x5fd474) {
        uintptr_t ctx = (uintptr_t)x[19];
        uintptr_t p = (uintptr_t)shdw_diag_peek(ctx + 0x570, 8);
        uint64_t hash = shdw_diag_peek(ctx + 0x86c, 4);

        shdw_diag_log("EXCBREAKVM n=%d ctx=%p id=%#llx hash=%#llx seed=%#llx "
                      "len=%#llx p=%p next=%#llx limit=%#llx", n, (void *)ctx,
                      (unsigned long long)shdw_diag_peek(ctx + 0x59c, 4),
                      (unsigned long long)hash,
                      (unsigned long long)shdw_diag_peek(ctx + 0x69c, 4),
                      (unsigned long long)shdw_diag_peek(ctx + 0x6a0, 8),
                      (void *)p,
                      (unsigned long long)shdw_diag_peek(ctx + 0x860, 8),
                      (unsigned long long)shdw_diag_peek(ctx + 0x870, 8));
        shdw_diag_peek_words("excctx", ctx, 0x550, 64);
        shdw_diag_peek_words("excctx", ctx, 0x680, 64);
        shdw_diag_peek_words("excctx", ctx, 0x850, 64);

        uint64_t w[4] = {0};
        if (p >= 0x10000 && shdw_diag_read_words(p, w, sizeof w)) {
            const uint8_t *b = (const uint8_t *)w;
            uint32_t h = 0x9a9e49b1u;
            Dl_info pi = {0};
            const char *pname = "?";
            unsigned long poff = 0;

            for (int i = 0; i < 32; i++) {
                h = h * 33u ^ b[i];
            }
            if (dladdr((void *)p, &pi) && pi.dli_fname) {
                const char *slash = strrchr(pi.dli_fname, '/');
                pname = slash ? slash + 1 : pi.dli_fname;
                poff = (unsigned long)(p - (uintptr_t)pi.dli_fbase);
            }
            shdw_diag_log("EXCHASH n=%d p=%s+0x%lx rehash=%#x stored=%#x", n,
                          pname, poff, h, (unsigned)hash);
            shdw_diag_peek_words("exchash", p, 0, 32);
            shdw_diag_peek_words("exchash", p - 16, 0, 32);
        }
    }
}

static kern_return_t shdw_diag_exc_catch(exception_type_t type,
                                         exception_data_t code,
                                         mach_msg_type_number_t codeCnt,
                                         int *flavor, thread_state_t old_state,
                                         mach_msg_type_number_t oldCnt,
                                         thread_state_t new_state,
                                         mach_msg_type_number_t *newCnt) {
    (void)codeCnt;

    mach_msg_type_number_t cap = *newCnt;
    if (oldCnt > cap) {
        oldCnt = cap;
    }
    memcpy(new_state, old_state, (size_t)oldCnt * sizeof(natural_t));
    *newCnt = oldCnt;

    if (*flavor == ARM_THREAD_STATE64 && oldCnt >= ARM_THREAD_STATE64_COUNT) {
        arm_thread_state64_t *st = (arm_thread_state64_t *)new_state;

        if (shdw_diag_hwdbg_claim(type, code, codeCnt, st)) {
            *newCnt = oldCnt;
            return KERN_SUCCESS;
        }
        shdw_diag_exc_report(type, code, *flavor, st);
    }
    // Decline, exactly like ellekit does for a BRK outside its hook table:
    // the kernel then delivers SIGTRAP and the existing handler skips pc+4, so
    // the detector's own control flow is unchanged by this observation.
    *newCnt = 0;
    return KERN_FAILURE;
}

// Hand-rolled exception_raise_state_identity server (msg id 2403): the MIG
// router is not exported by the SDK headers, and the reply layout is small.
static boolean_t shdw_diag_exc_server(void) {
    static __Request__exception_raise_state_identity_t req;
    static __Reply__exception_raise_state_identity_t rep;

    memset(&req, 0, sizeof req);
    mach_msg_return_t mr = mach_msg(&req.Head, MACH_RCV_MSG, 0, sizeof req,
                                    shdw_exc_port, MACH_MSG_TIMEOUT_NONE,
                                    MACH_PORT_NULL);
    if (mr != MACH_MSG_SUCCESS) {
        shdw_diag_log("EXCRCV err=%#x", (unsigned)mr);
        struct timespec iv = {0, 10 * 1000 * 1000};
        nanosleep(&iv, NULL);
        return FALSE;
    }
    static int recvLogged;
    if (recvLogged < 6) {
        recvLogged++;
        shdw_diag_log("EXCRECV id=%u bits=%#x remote=%#x local=%#x desc=%u "
                      "thread=%#x task=%#x", (unsigned)req.Head.msgh_id,
                      (unsigned)req.Head.msgh_bits,
                      (unsigned)req.Head.msgh_remote_port,
                      (unsigned)req.Head.msgh_local_port,
                      (unsigned)req.msgh_body.msgh_descriptor_count,
                      (unsigned)req.thread.name, (unsigned)req.task.name);
    }
    if (req.Head.msgh_id != 2403) {
        shdw_diag_log("EXCMSG id=%u", (unsigned)req.Head.msgh_id);
        return TRUE;
    }

    memset(&rep, 0, sizeof rep);
    mach_msg_type_number_t newCnt = 1296;

    shdw_exc_cur_thread = req.thread.name;
    kern_return_t kr = shdw_diag_exc_catch(
        req.exception, req.code, req.codeCnt, &req.flavor,
        (thread_state_t)req.old_state, req.old_stateCnt,
        (thread_state_t)rep.new_state, &newCnt);
    shdw_exc_cur_thread = MACH_PORT_NULL;

    // Kernel exception messages carry the reply right (a send-once right) in
    // msgh_remote_port and the exception port itself in msgh_local_port, so the
    // reply must go back the "remote" way and consume that right.
    rep.Head.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
    rep.Head.msgh_remote_port = req.Head.msgh_remote_port;
    rep.Head.msgh_local_port = MACH_PORT_NULL;
    rep.Head.msgh_id = req.Head.msgh_id + 100;
    rep.Head.msgh_size = (mach_msg_size_t)(
        offsetof(__Reply__exception_raise_state_identity_t, new_state) +
        newCnt * sizeof(natural_t));
    rep.NDR = NDR_record;
    rep.RetCode = kr;
    rep.flavor = req.flavor;
    rep.new_stateCnt = newCnt;

    mr = mach_msg(&rep.Head, MACH_SEND_MSG, rep.Head.msgh_size, 0,
                  MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (mr != MACH_MSG_SUCCESS) {
        shdw_diag_log("EXCSEND err=%#x", (unsigned)mr);
    }
    shdw_diag_hwdbg_rearm();
    if (req.msgh_body.msgh_descriptor_count > 0) {
        mach_port_deallocate(mach_task_self(), req.thread.name);
    }
    if (req.msgh_body.msgh_descriptor_count > 1) {
        mach_port_deallocate(mach_task_self(), req.task.name);
    }
    return TRUE;
}

static void* shdw_diag_exc_recv_thread(void* arg) {
    (void)arg;
    for (;;) {
        shdw_diag_exc_server();
    }
    return NULL;
}

static void* shdw_diag_exc_watch_thread(void* arg) {
    (void)arg;
    static const unsigned marks[] = {0, 200, 600, 1000, 1400, 2000, 3000};
    // The observation lanes only need the first four seconds. The production
    // forge keeps the sweep alive for a minute: Dynatrace reclaims the
    // exception port during startup and OZ may probe again later, on threads
    // that did not exist when the first sweep ran.
    unsigned limit = shdw_diag_svcforge >= SHDW_FORGE_PROD ? 60000u : 4000u;

    for (unsigned ms = 0; ms <= limit; ms += 5) {
        if (ms) {
            struct timespec iv = {0, 5 * 1000 * 1000};
            nanosleep(&iv, NULL);
        }
        if (shdw_diag_excports) {
            for (size_t i = 0; i < sizeof marks / sizeof marks[0]; i++) {
                if (marks[i] == ms) {
                    shdw_diag_exc_task_probe(ms);
                    shdw_diag_exc_thread_probe(ms);
                }
            }
        }
        if ((shdw_diag_exccatch || shdw_diag_excwatch) &&
            shdw_exc_port != MACH_PORT_NULL) {
            exception_mask_t m = 0;
            mach_port_t p = MACH_PORT_NULL;
            exception_behavior_t b = 0;
            thread_state_flavor_t f = 0;
            mach_msg_type_number_t cnt = 1;

            if (task_get_exception_ports(mach_task_self(), SHDW_EXC_PORT_MASK,
                                         &m, &cnt, &p, &b, &f) == KERN_SUCCESS &&
                p != shdw_exc_port) {
                task_set_exception_ports(mach_task_self(), SHDW_EXC_PORT_MASK,
                                         shdw_exc_port, EXCEPTION_STATE_IDENTITY,
                                         ARM_THREAD_STATE64);
                shdw_diag_log("EXCREARM t=%ums prev=%#x", ms, (unsigned)p);
            }
        }
        shdw_diag_hwdbg_tick();
    }
    return NULL;
}

static void shdw_diag_install_excwatch(void) {
    if ((shdw_diag_exccatch || shdw_diag_excwatch) &&
        shdw_exc_port == MACH_PORT_NULL) {
        mach_port_t p = MACH_PORT_NULL;
        kern_return_t kr = mach_port_allocate(mach_task_self(),
                                              MACH_PORT_RIGHT_RECEIVE, &p);

        if (kr != KERN_SUCCESS) {
            shdw_diag_log("EXCINSTALL allocate kr=%d", (int)kr);
        } else if ((kr = mach_port_insert_right(mach_task_self(), p, p,
                                                MACH_MSG_TYPE_MAKE_SEND)) !=
                   KERN_SUCCESS) {
            shdw_diag_log("EXCINSTALL right kr=%d", (int)kr);
            mach_port_mod_refs(mach_task_self(), p, MACH_PORT_RIGHT_RECEIVE, -1);
        } else {
            exception_mask_t oldMask = 0;
            mach_port_t oldPort = MACH_PORT_NULL;
            exception_behavior_t oldBeh = 0;
            thread_state_flavor_t oldFlav = 0;
            mach_msg_type_number_t cnt = EXC_TYPES_COUNT;

            shdw_exc_port = p;
            if (task_get_exception_ports(mach_task_self(), SHDW_EXC_PORT_MASK,
                                         &oldMask, &cnt, &oldPort, &oldBeh,
                                         &oldFlav) != KERN_SUCCESS) {
                oldMask = 0;
                oldPort = MACH_PORT_NULL;
            }
            kr = task_set_exception_ports(mach_task_self(),
                                          SHDW_EXC_PORT_MASK, p,
                                          EXCEPTION_STATE_IDENTITY,
                                          ARM_THREAD_STATE64);
            shdw_diag_log("EXCINSTALL kr=%d port=%#x oldmask=%#x oldport=%#x "
                          "oldbeh=%d oldflav=%d", (int)kr, (unsigned)p,
                          (unsigned)oldMask, (unsigned)oldPort, (int)oldBeh,
                          (int)oldFlav);

            pthread_t th;
            pthread_attr_t attr;
            if (pthread_attr_init(&attr) == 0) {
                pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
                pthread_create(&th, &attr, shdw_diag_exc_recv_thread, NULL);
                pthread_attr_destroy(&attr);
            }
        }
    }
    if (!shdw_excwatch_started &&
        (shdw_diag_excports || shdw_diag_exccatch || shdw_diag_excwatch)) {
        pthread_t th;
        pthread_attr_t attr;

        shdw_excwatch_started = 1;
        if (pthread_attr_init(&attr) != 0) {
            return;
        }
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        pthread_create(&th, &attr, shdw_diag_exc_watch_thread, NULL);
        pthread_attr_destroy(&attr);
    }
}

// The forge lane must run without Debug_Diag: shdw_diag_install() returns
// early when diagnostics are off and would leave the exception watch (and the
// breakpoint sweep) unstarted. This installs only that part.
void shdw_diag_install_oz_forge(void) {
    if (!shdw_diag_svcforge && !shdw_diag_spkbrk) {
        return;
    }
    shdw_diag_excwatch = 1;
    shdw_diag_install_excwatch();
}

// Hardware breakpoints (pref: Debug_ExcWatch). Unlike a code patch these leave
// __text untouched, so the detector's self-check cannot see them: DBGBVR/DBGBCR
// are per-thread registers the kernel owns. The InSvc lane could never observe
// these inline-syscall thunks because patching the svc byte trips OZ's own text
// validator (0x48908) before the code runs; a debug register does not.
//   0xec3c  mov x16,x3; svc #0x80; ret   (number in x3, 3-arg call)
//   0xec18  mov x8,x1; mov x16,x8; svc   (number in x1, 1-arg call)
//   0xec5c  mov x8,x1; mov x16,x8; svc   (number in x1, 1-arg call)
//   0xec50  after the 0xec3c svc: x0 raw result, x8 carry-derived error
//   0x3aef0 tbz w28 of the first __mac_syscall consumer
//   0x451c4 tbnz w28 of the second consumer
//   0x26798 continuation taken when the syscall did not fail
//   0xfc3c  continuation taken when the first consumer saw the failure
// The census run showed 0xec3c carrying 381 (__mac_syscall: policy in x0,
// call=2, arg block in x2) and its result feeding a w28 branch in two VM
// callers, while the 1-arg thunks carried close(12) and unlink(<stack path>).
// Only six breakpoint registers are honoured by the kernel (sites above 5
// never trapped), so these six carry the live question: what the call returned
// and which continuation the VM took.
#define SHDW_DBG_BCR 0x1e1ULL
#define SHDW_DBG_SITE0 0xec3c
#define SHDW_DBG_SITE1 0x451c4
#define SHDW_DBG_SITE2 0x3aef0
#define SHDW_DBG_SITE3 0xec50
#define SHDW_DBG_SITE4 0x26798
#define SHDW_DBG_SITE5 0xfc3c
#define SHDW_DBG_SITES 6

// DBGWCR: E | LSC=0b10 (store only) | BAS=0xff (8 bytes). Load+store (0x1ff9)
// only ever produced the hot reader at the same pc, so the watch is store-only
// now: whichever instruction traps is the writer of the word.
#define SHDW_WCR_WATCH 0x1ff1ULL
// Distance from the dispatch entry sp (site 4) down to the saved (fp,lr) slot
// of the frame that returns into 0xc. The faulting thread always has
// sp == entry_sp - 0x90, and the 16-byte frame it returns through sits right
// below that sp, so the `stp x29,x30,[sp,#-0x10]!` of the fatal callee lands at
// entry_sp - 0xa0 (bcc-vmframe1.log VMFRAME frame=0x16d424620 == sp-0x50 with
// the (4,0xc) hit at sp-0x10).
#define SHDW_WATCH_OFF 0xa0ULL

static uintptr_t shdw_diag_find_oz(void) {
    uint32_t n = _dyld_image_count();

    for (uint32_t i = 0; i < n; i++) {
        const char *p = _dyld_get_image_name(i);

        if (p && strstr(p, (shdw_diag_spkbrk || shdw_diag_spkstub ||
                            shdw_diag_spkskip || shdw_diag_spkdec ||
                            shdw_diag_spkmsg || shdw_diag_spkzero ||
                            shdw_diag_spkgate || shdw_diag_spkmem ||
                            shdw_diag_spksvc || shdw_diag_spksample ||
                            shdw_diag_spkhash)
                               ? "Finanzstatusx"
                               : "OZLivenessSDK")) {
            return (uintptr_t)_dyld_get_image_header(i);
        }
    }
    return 0;
}

static uintptr_t shdw_dbg_site(int idx) {
    if (shdw_diag_spksvc) {
        // SHDW_SPKFORGE_THUNK: the cell target changes between launch stages
        // (an in-image table early, libsystem's pread later), so a breakpoint
        // on the resolved target goes stale and misses the worker thread's
        // slot reads. The thunk at +0x5bf160 is static code and every pread
        // issued by the framework enters through it.
        if (shdw_diag_spkforge) {
            if (idx == 1 && shdw_diag_spkevt && shdw_dbg_base) {
                return shdw_dbg_base + 0x8096d0;
            }
            if (idx == 2 && shdw_diag_spkexit && shdw_dbg_base) {
                return shdw_dbg_base + 0x430d9c;
            }
            return (idx == 0 && shdw_dbg_base) ? shdw_dbg_base + 0x5bf160 : 0;
        }
        // The cell is still null at ctor: the image writes it during its own
        // init, so the target is resolved lazily on each sweep pass until it
        // appears, then held.
        if (idx == 1 && shdw_diag_spkevt && shdw_dbg_base) {
            return shdw_dbg_base + 0x8096d0;
        }
        if (idx == 2 && shdw_diag_spkexit && shdw_dbg_base) {
            return shdw_dbg_base + 0x430d9c;
        }
        if (idx != 0) {
            return 0;
        }
        if (!shdw_dbg_svc && shdw_dbg_base) {
            shdw_dbg_svc = shdw_diag_peek(shdw_dbg_base + 0x9caab8, 8);
            if (shdw_dbg_svc) {
                shdw_diag_log("SHDW_SPKSVC_LATE target=%p",
                              (void *)shdw_dbg_svc);
                shdw_diag_peek_words("spcstub", shdw_dbg_svc, 0, 32);
            }
        }
        return shdw_dbg_svc;
    }
    if (shdw_diag_spkmem) {
        return idx == 0 ? shdw_dbg_base + SHDW_SPKMEM_DEC : 0;
    }
    if (shdw_diag_spkgate) {
        return idx == 0 ? shdw_dbg_base + SHDW_SPKGATE_PRED
                        : idx == 1 ? shdw_dbg_base + SHDW_SPKGATE_NZ
                        : idx == 2 ? shdw_dbg_base + SHDW_SPKGATE_COMMON
                        : idx == 3 ? shdw_dbg_base + SHDW_SPKGATE_DECISION : 0;
    }
    if (shdw_diag_spkzero) {
        return idx == 0 ? shdw_dbg_base + SHDW_SPKZERO_CTOR
                        : idx == 1 ? shdw_dbg_base + SHDW_SPKZERO_PRED : 0;
    }
    if (shdw_diag_spkmsg) {
        return idx == 0 ? shdw_dbg_base + SHDW_SPKMSG_LOOP
                        : idx == 1 ? shdw_dbg_base + SHDW_SPKMSG_DEC : 0;
    }
    if (shdw_diag_spkdec) {
        return idx == 0 ? shdw_dbg_base + SHDW_SPKDEC_CALL
                        : idx == 1 ? shdw_dbg_base + SHDW_SPKDEC_ENTRY : 0;
    }
    if (shdw_diag_spkskip) {
        return idx == 0 ? shdw_dbg_base + SHDW_SPK_DECISION
                        : idx == 1 ? shdw_dbg_base + SHDW_SPK_CTORFIX
                        : idx == 2 ? shdw_dbg_base + SHDW_SPKSTUBW : 0;
    }
    if (shdw_diag_spkstub) {
        // Slot 0 is one-shot on the verdict-byte store; slot 1 is the syscall
        // stub on the same thread, cleared and re-armed around every hit.
        return idx == 0 ? shdw_dbg_base + SHDW_SPK_CTOR
                        : idx == 1 ? shdw_dbg_base + SHDW_SPK_STUB
                                   : 0;
    }
    if (shdw_diag_spkbrk) {
        // One breakpoint only: a debug register left armed after the fix is
        // itself a tamper signal, so nothing else is watched in this lane.
        return idx == 0 ? shdw_dbg_base + SHDW_SPK_PRED_RET
                        : idx == 1 ? shdw_dbg_base + SHDW_SPK_POSTCALL
                                   : 0;
    }
    switch (idx) {
    case 0: return shdw_dbg_base + SHDW_DBG_SITE0;
    case 1: return shdw_dbg_base + SHDW_DBG_SITE1;
    case 2: return shdw_dbg_base + SHDW_DBG_SITE2;
    case 3: return shdw_dbg_base + SHDW_DBG_SITE3;
    case 4: return shdw_dbg_base + SHDW_DBG_SITE4;
    case 5: return shdw_dbg_base + SHDW_DBG_SITE5;
    default: return 0;
    }
}

// Sites 4/5 are dispatched by the record pool, so they can fire thousands of
// times. Every hit is recorded in this ring (cheap, no syscalls) and the ring
// is dumped when the fault arrives, which keeps the final hits even when the
// text log is capped. Layout per slot: site, pc, x0, x1, x8, x19, x21, x22,
// x23, x24, fp, sp, lr, [fp], [fp+8], [sp], x2, x3, x4, x5, x16. The last five
// are the syscall census words: x3/x1/x16 carries the number of the thunk that
// fired and x0..x5 are its arguments.
#define SHDW_HW_RING 256
#define SHDW_HW_WORDS 24
static uint64_t shdw_hw_ring[SHDW_HW_RING * SHDW_HW_WORDS];
static uint32_t shdw_hw_pos;

// Distinct (thunk, syscall number) pairs, one line each. The thunks are shared
// by every syscall OZ makes, so per-hit logging would bury the VM sites; the
// first sighting of a number is what names the syscalls on the fatal path.
#define SHDW_SVC_SLOTS 64
typedef struct {
    uint32_t idx;
    uint32_t num;
    uint32_t hits;
    uint32_t pad;
} shdw_svc_slot;
static shdw_svc_slot shdw_svc_slots[SHDW_SVC_SLOTS];
static uint32_t shdw_svc_used;

static unsigned shdw_svc_num(int idx, const arm_thread_state64_t *st) {
    // 0xec3c moves x3 into x16 itself; the other two thunks take x1. Once the
    // svc instruction is reached the number is already in x16.
    if (idx == 0) {
        return (unsigned)st->__x[3];
    }
    if (idx == 1 || idx == 2) {
        return (unsigned)st->__x[1];
    }
    return (unsigned)st->__x[16];
}

static void shdw_diag_svc_note(int idx, const arm_thread_state64_t *st,
                               uintptr_t pc, uintptr_t lr) {
    unsigned num = shdw_svc_num(idx, st);
    uint32_t used = __atomic_load_n(&shdw_svc_used, __ATOMIC_RELAXED);

    for (uint32_t i = 0; i < used; i++) {
        if (shdw_svc_slots[i].idx == (uint32_t)idx &&
            shdw_svc_slots[i].num == num) {
            __atomic_add_fetch(&shdw_svc_slots[i].hits, 1, __ATOMIC_RELAXED);
            return;
        }
    }
    if (used >= SHDW_SVC_SLOTS) {
        return;
    }
    shdw_svc_slots[used].idx = (uint32_t)idx;
    shdw_svc_slots[used].num = num;
    shdw_svc_slots[used].hits = 1;
    __atomic_store_n(&shdw_svc_used, used + 1, __ATOMIC_RELAXED);
    shdw_diag_log("SVCTHN idx=%d num=%u pc=%p lr=%p x0=%#llx x1=%#llx x2=%#llx "
                  "x3=%#llx x4=%#llx x5=%#llx x16=%#llx x8=%#llx",
                  idx, num, (void *)pc, (void *)lr,
                  (unsigned long long)st->__x[0],
                  (unsigned long long)st->__x[1],
                  (unsigned long long)st->__x[2],
                  (unsigned long long)st->__x[3],
                  (unsigned long long)st->__x[4],
                  (unsigned long long)st->__x[5],
                  (unsigned long long)st->__x[16],
                  (unsigned long long)st->__x[8]);
}

static void shdw_diag_hw_ring_add(int idx, uintptr_t pc, uintptr_t fp,
                                  uintptr_t sp, uintptr_t lr,
                                  const arm_thread_state64_t *st) {
    uint32_t slot = __atomic_add_fetch(&shdw_hw_pos, 1, __ATOMIC_RELAXED) %
                    SHDW_HW_RING;
    uint64_t *e = &shdw_hw_ring[slot * SHDW_HW_WORDS];

    e[0] = (uint64_t)idx;
    e[1] = pc;
    e[2] = st->__x[0];
    e[3] = st->__x[1];
    e[4] = st->__x[8];
    e[5] = st->__x[19];
    e[6] = st->__x[21];
    e[7] = st->__x[22];
    e[8] = st->__x[23];
    e[9] = st->__x[24];
    e[10] = fp;
    e[11] = sp;
    e[12] = lr;
    e[13] = shdw_diag_peek(fp, 8);
    e[14] = shdw_diag_peek(fp + 8, 8);
    e[15] = shdw_diag_peek(sp, 8);
    e[16] = st->__x[2];
    e[17] = st->__x[3];
    e[18] = st->__x[4];
    e[19] = st->__x[5];
    e[20] = st->__x[16];
}

static void shdw_diag_dump_hw_ring(void) {
    uint32_t pos = __atomic_load_n(&shdw_hw_pos, __ATOMIC_RELAXED);
    uint32_t cnt = pos < SHDW_HW_RING ? pos : SHDW_HW_RING;

    for (uint32_t k = 0; k < cnt; k++) {
        uint32_t slot = (pos - 1 - k) % SHDW_HW_RING;
        uint64_t *e = &shdw_hw_ring[slot * SHDW_HW_WORDS];

        shdw_diag_log("HWRING -%u idx=%llu pc=%#llx x0=%#llx x1=%#llx x8=%#llx "
                      "x19=%#llx x21=%#llx x22=%#llx x23=%#llx x24=%#llx "
                      "fp=%#llx sp=%#llx lr=%#llx f0=%#llx f1=%#llx s0=%#llx "
                      "x2=%#llx x3=%#llx x4=%#llx x5=%#llx x16=%#llx",
                      k, (unsigned long long)e[0], (unsigned long long)e[1],
                      (unsigned long long)e[2], (unsigned long long)e[3],
                      (unsigned long long)e[4], (unsigned long long)e[5],
                      (unsigned long long)e[6], (unsigned long long)e[7],
                      (unsigned long long)e[8], (unsigned long long)e[9],
                      (unsigned long long)e[10], (unsigned long long)e[11],
                      (unsigned long long)e[12], (unsigned long long)e[13],
                      (unsigned long long)e[14], (unsigned long long)e[15],
                      (unsigned long long)e[16], (unsigned long long)e[17],
                      (unsigned long long)e[18], (unsigned long long)e[19],
                      (unsigned long long)e[20]);
    }
    {
        uint32_t used = __atomic_load_n(&shdw_svc_used, __ATOMIC_RELAXED);

        for (uint32_t i = 0; i < used; i += 4) {
            char line[200];
            size_t pos2 = 0;

            line[0] = 0;
            for (uint32_t j = i; j < i + 4 && j < used; j++) {
                pos2 += (size_t)snprintf(line + pos2, sizeof line - pos2,
                                         " t%d#%u:%u", shdw_svc_slots[j].idx,
                                         shdw_svc_slots[j].num,
                                         shdw_svc_slots[j].hits);
                if (pos2 >= sizeof line) {
                    break;
                }
            }
            shdw_diag_log("SVCCENSUS%s", line);
        }
    }
    if (shdw_hw_watch_n) {
        shdw_diag_log("HWWATCH@FAULT w0=%p w1=%p hits=%d n=%d",
                      (void *)shdw_hw_watch[0], (void *)shdw_hw_watch[1],
                      shdw_hw_watch_hits, shdw_hw_watch_n);
        shdw_diag_peek_words("hwwfault", shdw_hw_watch[0] - 0x40, 0, 24);
    }
}

static void shdw_diag_hwdbg_state(arm_debug_state64_t *d) {
    unsigned off = shdw_dbg_off;
    int prod = shdw_diag_svcforge >= SHDW_FORGE_PROD;

    memset(d, 0, sizeof *d);
    for (int i = 0; i < SHDW_DBG_SITES; i++) {
        uintptr_t site = shdw_dbg_site(i);

        // The production lane only needs the syscall thunk itself: one
        // breakpoint register per thread, so the sweep is cheap and there is
        // no clear/rearm round-trip on the probe path.
        if (prod && i != 0) {
            continue;
        }
        if (!(off & (1u << i)) && site) {
            d->__bvr[i] = site;
            d->__bcr[i] = SHDW_DBG_BCR;
        }
    }
    // The periodic sweep rewrites this struct from scratch, so the watch must
    // be part of it or the sweep silently disarms it a few ms after arming.
    for (int i = 0; i < shdw_hw_watch_n; i++) {
        d->__wvr[i] = shdw_hw_watch[i];
        d->__wcr[i] = SHDW_WCR_WATCH;
    }
}

// The VM thread is not known in advance (the ctor thread may be a helper), so
// the state is written to every thread in the task and refreshed while the
// process starts.
static void shdw_diag_hwdbg_arm(void) {
    thread_act_array_t list = NULL;
    mach_msg_type_number_t n = 0;
    arm_debug_state64_t d;
    static unsigned logged_off = ~0u;
    int ok = 0;

    if (!shdw_dbg_base) {
        shdw_dbg_base = shdw_diag_find_oz();
    }
    if (!shdw_dbg_base) {
        return;
    }
    if (task_threads(mach_task_self(), &list, &n) != KERN_SUCCESS || !list) {
        return;
    }

    shdw_diag_hwdbg_state(&d);
    for (mach_msg_type_number_t i = 0; i < n; i++) {
        if (thread_set_state(list[i], ARM_DEBUG_STATE64, (thread_state_t)&d,
                             ARM_DEBUG_STATE64_COUNT) == KERN_SUCCESS) {
            ok++;
        }
        // Apple cores implement a small number of breakpoint registers; asking
        // for more silently drops the tail. Read one thread back so the arm
        // log states what the kernel actually holds instead of what was asked.
        if (i == 0 && !shdw_dbg_armed) {
            arm_debug_state64_t rb;
            mach_msg_type_number_t rc = ARM_DEBUG_STATE64_COUNT;

            memset(&rb, 0, sizeof rb);
            if (thread_get_state(list[i], ARM_DEBUG_STATE64,
                                 (thread_state_t)&rb, &rc) == KERN_SUCCESS) {
                shdw_diag_log("HWDBGRD bvr0=%#llx bvr4=%#llx bvr5=%#llx "
                              "bvr6=%#llx bvr7=%#llx bvr11=%#llx bcr0=%#llx "
                              "bcr4=%#llx bcr5=%#llx bcr6=%#llx bcr7=%#llx "
                              "bcr11=%#llx",
                              (unsigned long long)rb.__bvr[0],
                              (unsigned long long)rb.__bvr[4],
                              (unsigned long long)rb.__bvr[5],
                              (unsigned long long)rb.__bvr[6],
                              (unsigned long long)rb.__bvr[7],
                              (unsigned long long)rb.__bvr[11],
                              (unsigned long long)rb.__bcr[0],
                              (unsigned long long)rb.__bcr[4],
                              (unsigned long long)rb.__bcr[5],
                              (unsigned long long)rb.__bcr[6],
                              (unsigned long long)rb.__bcr[7],
                              (unsigned long long)rb.__bcr[11]);
            }
        }
        mach_port_deallocate(mach_task_self(), list[i]);
    }
    vm_deallocate(mach_task_self(), (vm_address_t)list, n * sizeof(thread_t));

    if (logged_off != shdw_dbg_off) {
        logged_off = shdw_dbg_off;
        shdw_diag_log("HWDBG arm base=%p threads=%u ok=%d off=%#x "
                      "s0=%p s1=%p s2=%p s3=%p s4=%p s5=%p bcr=%#llx",
                      (void *)shdw_dbg_base, (unsigned)n, ok, shdw_dbg_off,
                      (void *)(shdw_dbg_base + SHDW_DBG_SITE0),
                      (void *)(shdw_dbg_base + SHDW_DBG_SITE1),
                      (void *)(shdw_dbg_base + SHDW_DBG_SITE2),
                      (void *)(shdw_dbg_base + SHDW_DBG_SITE3),
                      (void *)(shdw_dbg_base + SHDW_DBG_SITE4),
                      (void *)(shdw_dbg_base + SHDW_DBG_SITE5),
                      (unsigned long long)SHDW_DBG_BCR);
    }
    shdw_dbg_armed = 1;
}

static void shdw_diag_hwdbg_tick(void) {
    static unsigned calls;
    unsigned period;

    if (!shdw_diag_excwatch || shdw_diag_spkstub) {
        return;
    }
    // The production lane must catch threads spawned after the previous
    // sweep, and the detectors probe within the first second of the launch.
    period = shdw_diag_svcforge >= SHDW_FORGE_PROD ? 5 : 20;
    // The dispatch cell is written during the image's own init; resolving it
    // on the next 20-tick pass leaves a >100 ms blind window over the whole
    // early syscall stream (jigsaw/bi/ii reads). Poll every tick instead.
    if (shdw_diag_spksvc) {
        period = 1; // SHDW_SPKSVC_TICK1
    }
    if ((calls++ % period) != 0) {
        return;
    }
    shdw_diag_hwdbg_arm();
}

// Names the image holding pc by walking the raw dyld table: dladdr is shadowed
// and does not resolve every shared-cache address for internal callers.
static const char *shdw_diag_pc_image(uintptr_t pc, unsigned long *off) {
    uint32_t n = _dyld_image_count();

    for (uint32_t i = 0; i < n; i++) {
        const struct mach_header_64 *h =
            (const struct mach_header_64 *)_dyld_get_image_header(i);
        const char *name = _dyld_get_image_name(i);
        const struct load_command *lc;
        uintptr_t lo;
        uintptr_t hi;
        uint64_t text_vmaddr = 0;

        if (!h || !name || h->magic != MH_MAGIC_64) {
            continue;
        }
        lo = (uintptr_t)h;
        hi = lo;
        lc = (const struct load_command *)(h + 1);
        for (uint32_t c = 0; c < h->ncmds; c++) {
            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *sg =
                    (const struct segment_command_64 *)lc;
                uintptr_t e;

                // The first segment on an executable is __PAGEZERO (vmaddr 0,
                // filesize 0), so only the segment that actually carries the
                // header at file offset 0 gives the slide base.
                if (text_vmaddr == 0 && sg->fileoff == 0 && sg->filesize != 0) {
                    text_vmaddr = sg->vmaddr;
                }
                // vmaddr is absolute while lo is the slid header address, so
                // subtract the first segment's vmaddr before adding.
                e = lo - (uintptr_t)text_vmaddr + (uintptr_t)sg->vmaddr +
                    (uintptr_t)sg->vmsize;
                if (e > hi) {
                    hi = e;
                }
            }
            lc = (const struct load_command *)((const char *)lc + lc->cmdsize);
        }
        if (pc >= lo && pc < hi) {
            const char *slash = strrchr(name, '/');

            *off = (unsigned long)(pc - lo);
            return slash ? slash + 1 : name;
        }
    }
    *off = 0;
    return "?";
}

static int shdw_diag_watch_claim(exception_data_t code,
                                 mach_msg_type_number_t codeCnt,
                                 const arm_thread_state64_t *st, int slot) {
    int hn = __atomic_add_fetch(&shdw_hw_watch_hits, 1, __ATOMIC_RELAXED);
    uintptr_t far = shdw_hw_watch[slot];
    uintptr_t pc = (uintptr_t)arm_thread_state64_get_pc(*st);

    if (hn <= 40) {
        unsigned long off = 0;
        const char *nm = shdw_diag_pc_image(pc, &off);

        shdw_diag_log("HWWATCH n=%d slot=%d far=%p code0=%#x codeCnt=%u "
                      "pc=%p %s+0x%lx lr=%p th=%#x x0=%p x1=%p x2=%p x3=%p "
                      "x8=%p x9=%p x10=%p x11=%p x19=%p x20=%p x21=%p "
                      "x22=%p x23=%p sp=%p fp=%p g0=%#llx g1=%#llx",
                      hn, slot, (void *)far, (unsigned)code[0],
                      (unsigned)codeCnt, (void *)pc, nm, off,
                      (void *)arm_thread_state64_get_lr(*st),
                      (unsigned)shdw_exc_cur_thread, (void *)st->__x[0],
                      (void *)st->__x[1], (void *)st->__x[2],
                      (void *)st->__x[3], (void *)st->__x[8],
                      (void *)st->__x[9], (void *)st->__x[10],
                      (void *)st->__x[11], (void *)st->__x[19],
                      (void *)st->__x[20], (void *)st->__x[21],
                      (void *)st->__x[22], (void *)st->__x[23],
                      (void *)arm_thread_state64_get_sp(*st),
                      (void *)arm_thread_state64_get_fp(*st),
                      (unsigned long long)shdw_diag_peek(shdw_hw_watch[0], 8),
                      (unsigned long long)shdw_diag_peek(shdw_hw_watch[1], 8));
        shdw_diag_peek_words("hwwatch", far - 0x20, 0, 16);
    }
    return 1;
}

// A hardware debug exception is claimed only when it lands exactly on one of
// our sites. The trap is taken before the instruction executes. The dispatch,
// prologue and epilogue sites are re-armed on the trapping thread as soon as
// it has moved past the instruction; the poison site is one-shot.
// Field 2 of the sandbox_check request block names the operation. The only
// probe this SDK issues is the file-existence test; forging anything else
// would hand back a wrong answer, so production requires this match.
static int shdw_diag_op_is_filetest(uintptr_t p) {
    static const char want[] = "file-test-existence";

    if (p < 0x10000) {
        return 0;
    }
    for (size_t i = 0; want[i]; i++) {
        if ((char)shdw_diag_peek(p + i, 1) != want[i]) {
            return 0;
        }
    }
    return 1;
}


// SHDW_SPKFORGE: SHIELD samples the app's CodeDirectory hash slots with
// 20-byte preads and compares them with the pages it has mapped. This install
// is decrypted, so the on-disk slots never matched the current bytes. Rather
// than rewrite the bundle (that panicked the kernel), the slot pread is
// answered from the exception handler with the hash of the page it names, and
// the svc is skipped. Nothing is written to disk.
typedef struct {
    int used;
    int fd;
    uint64_t dev;
    uint64_t ino;
    uint64_t slots_base;
    uint32_t n_code;
    uint32_t code_limit;
    uint32_t page_size;
} shdw_spk_cd_t;

static shdw_spk_cd_t shdw_spk_cds[8];
static unsigned shdw_spk_cds_rr = 0;
static unsigned shdw_spk_forge_hits = 0;

static uint32_t shdw_spk_le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static uint32_t shdw_spk_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

#define SHDW_SPK_ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static void shdw_spk_sha1_block(uint32_t h[5], const uint8_t *p) {
    uint32_t w[80];
    uint32_t a, b, c, d, e;
    int i;

    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t)p[i * 4] << 24) | ((uint32_t)p[i * 4 + 1] << 16) |
               ((uint32_t)p[i * 4 + 2] << 8) | (uint32_t)p[i * 4 + 3];
    }
    for (i = 16; i < 80; i++) {
        w[i] = SHDW_SPK_ROTL(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }
    a = h[0]; b = h[1]; c = h[2]; d = h[3]; e = h[4];
    for (i = 0; i < 80; i++) {
        uint32_t f, k, t;
        if (i < 20) {
            f = (b & c) | (~b & d); k = 0x5a827999u;
        } else if (i < 40) {
            f = b ^ c ^ d; k = 0x6ed9eba1u;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdcu;
        } else {
            f = b ^ c ^ d; k = 0xca62c1d6u;
        }
        t = SHDW_SPK_ROTL(a, 5) + f + e + k + w[i];
        e = d; d = c; c = SHDW_SPK_ROTL(b, 30); b = a; a = t;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
}

static void shdw_spk_sha1(const uint8_t *m, size_t len, uint8_t out[20]) {
    uint32_t h[5] = {0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u,
                     0xc3d2e1f0u};
    uint8_t tail[128];
    uint64_t bits = (uint64_t)len * 8;
    size_t i = 0, r, tl;
    int j;

    for (; i + 64 <= len; i += 64) {
        shdw_spk_sha1_block(h, m + i);
    }
    r = len - i;
    memcpy(tail, m + i, r);
    tail[r] = 0x80;
    tl = (r < 56) ? 64 : 128;
    memset(tail + r + 1, 0, tl - r - 1);
    for (j = 0; j < 8; j++) {
        tail[tl - 1 - j] = (uint8_t)(bits >> (8 * j));
    }
    shdw_spk_sha1_block(h, tail);
    if (tl == 128) {
        shdw_spk_sha1_block(h, tail + 64);
    }
    for (j = 0; j < 5; j++) {
        out[j * 4] = (uint8_t)(h[j] >> 24);
        out[j * 4 + 1] = (uint8_t)(h[j] >> 16);
        out[j * 4 + 2] = (uint8_t)(h[j] >> 8);
        out[j * 4 + 3] = (uint8_t)h[j];
    }
}

// Return the bytes the check would hash: the mapped image when the file is
// one of our images, the file otherwise.
static int shdw_spk_page(int fd, const char *path, uint64_t pgoff, uint8_t *buf,
                         size_t n) {
    uint32_t ic, i, k;

    if (path && path[0]) {
        ic = _dyld_image_count();
        for (i = 0; i < ic && i < 2048; i++) {
            const char *nm = _dyld_get_image_name(i);
            const struct mach_header_64 *ih;
            const struct load_command *lc;
            uintptr_t base, textva, slide;

            if (!nm || strcmp(nm, path)) continue;
            ih = (const struct mach_header_64 *)_dyld_get_image_header(i);
            if (!ih || ih->magic != MH_MAGIC_64) continue;
            base = (uintptr_t)ih;
            textva = 0;
            lc = (const struct load_command *)(ih + 1);
            for (k = 0; k < ih->ncmds && lc->cmdsize >= 8; k++) {
                if (lc->cmd == LC_SEGMENT_64) {
                    const struct segment_command_64 *sg =
                        (const struct segment_command_64 *)lc;
                    if (sg->fileoff == 0 && sg->filesize) {
                        textva = (uintptr_t)sg->vmaddr;
                    }
                }
                lc = (const struct load_command *)((const char *)lc +
                                                  lc->cmdsize);
            }
            if (textva > base) continue;
            slide = base - textva;
            lc = (const struct load_command *)(ih + 1);
            for (k = 0; k < ih->ncmds && lc->cmdsize >= 8; k++) {
                if (lc->cmd == LC_SEGMENT_64) {
                    const struct segment_command_64 *sg =
                        (const struct segment_command_64 *)lc;
                    if (pgoff >= sg->fileoff &&
                        pgoff + n <= sg->fileoff + sg->filesize) {
                        memcpy(buf, (const void *)((uintptr_t)sg->vmaddr + slide +
                                                   (pgoff - sg->fileoff)),
                               n);
                        return 1;
                    }
                }
                lc = (const struct load_command *)((const char *)lc +
                                                  lc->cmdsize);
            }
            break;
        }
    }
    return pread(fd, buf, n, (off_t)pgoff) == (ssize_t)n;
}

static void shdw_spk_parse(int fd, uint64_t dev, uint64_t ino) {
    shdw_spk_cd_t *e = NULL;
    uint8_t h[32], c[24], sb[12], ie[8], cd[44];
    uint64_t off, sig_off = 0;
    uint32_t ncmds, cnt, i;

    for (i = 0; i < 8; i++) {
        if (!shdw_spk_cds[i].used) {
            e = &shdw_spk_cds[i];
            break;
        }
    }
    if (!e) {
        e = &shdw_spk_cds[shdw_spk_cds_rr++ % 8];
    }
    memset(e, 0, sizeof *e);
    e->fd = fd;
    e->dev = dev;
    e->ino = ino;

    if (pread(fd, h, sizeof h, 0) != (ssize_t)sizeof h) return;
    if (shdw_spk_le32(h) != 0xfeedfacfu) return;
    ncmds = shdw_spk_le32(h + 16);
    off = 32;
    for (i = 0; i < ncmds && i < 4096; i++) {
        uint32_t cmd, sz;

        if (pread(fd, c, sizeof c, (off_t)off) != (ssize_t)sizeof c) return;
        cmd = shdw_spk_le32(c);
        sz = shdw_spk_le32(c + 4);
        if (sz < 8) return;
        if (cmd == 0x1d) {
            sig_off = shdw_spk_le32(c + 8);
        }
        off += sz;
    }
    if (!sig_off) return;
    if (pread(fd, sb, sizeof sb, (off_t)sig_off) != (ssize_t)sizeof sb) return;
    if (shdw_spk_be32(sb) != 0xfade0cc0u) return;
    cnt = shdw_spk_be32(sb + 8);
    for (i = 0; i < cnt && i < 16; i++) {
        uint64_t blob;
        uint32_t hash_off, nc, limit;
        uint8_t hs, ht, ps;

        if (pread(fd, ie, sizeof ie, (off_t)(sig_off + 12 + 8 * i)) !=
            (ssize_t)sizeof ie) {
            return;
        }
        // The index entry is (slotType, offset), not a blob magic: type 0 is
        // the primary CodeDirectory, 0x1000+ are alternates.
        blob = sig_off + shdw_spk_be32(ie + 4);
        if (pread(fd, cd, sizeof cd, (off_t)blob) != (ssize_t)sizeof cd) {
            return;
        }
        if (shdw_spk_be32(cd) != 0xfade0c02u) continue;
        hash_off = shdw_spk_be32(cd + 16);
        nc = shdw_spk_be32(cd + 28);
        limit = shdw_spk_be32(cd + 32);
        hs = cd[36];
        ht = cd[37];
        ps = cd[39];
        if (hs != 20 || ht != 1 || !nc || !limit) continue;
        e->used = 1;
        e->slots_base = blob + hash_off;
        e->n_code = nc;
        e->code_limit = limit;
        e->page_size = ps ? (1u << ps) : 4096u;
        return;
    }
}

static shdw_spk_cd_t *shdw_spk_cd_get(int fd, uint64_t dev, uint64_t ino) {
    unsigned i;

    for (i = 0; i < 8; i++) {
        shdw_spk_cd_t *e = &shdw_spk_cds[i];
        if (e->used && e->fd == fd && e->dev == dev && e->ino == ino) {
            return e;
        }
    }
    shdw_spk_parse(fd, dev, ino);
    for (i = 0; i < 8; i++) {
        shdw_spk_cd_t *e = &shdw_spk_cds[i];
        if (e->used && e->fd == fd && e->dev == dev && e->ino == ino) {
            return e;
        }
    }
    return NULL;
}

static int shdw_spk_try_forge(arm_thread_state64_t *st, unsigned num,
                              uintptr_t lr) {
    struct stat sb;
    shdw_spk_cd_t *e;
    uint64_t buf, len, off, pgoff;
    int64_t rel, idx;
    int fd;
    size_t n;
    uint8_t page[4096], dg[20];
    char path[1024];

    if (num != 153) return 0;
    fd = (int)st->__x[0];
    buf = (uint64_t)st->__x[1];
    len = (uint64_t)st->__x[2];
    off = (uint64_t)st->__x[3];
    if (fd < 0 || buf < 0x10000 || len > 0x100000) return 0;
    if (len == 20) {
        if (fstat(fd, &sb) != 0) goto pass;
        e = shdw_spk_cd_get(fd, (uint64_t)sb.st_dev, (uint64_t)sb.st_ino);
        if (!e) goto pass;
        rel = (int64_t)off - (int64_t)e->slots_base;
        if (rel < 0 || (rel % 20) != 0) goto pass;
        idx = rel / 20;
        if (idx < 0 || idx >= (int64_t)e->n_code) goto pass;
        pgoff = (uint64_t)idx * e->page_size;
        if (pgoff >= e->code_limit) goto pass;
        n = e->page_size;
        if (pgoff + n > e->code_limit) n = (size_t)(e->code_limit - pgoff);
        if (n > sizeof page) goto pass;
        path[0] = 0;
        if (fcntl(fd, F_GETPATH, path) != 0) path[0] = 0;
        if (!shdw_spk_page(fd, path, pgoff, page, n)) goto pass;
        shdw_spk_sha1(page, n, dg);
        memcpy((void *)(uintptr_t)buf, dg, 20);
        st->__x[0] = 20;
        // The wrapper checks carry right after the call (`b.lo` = success).
        st->__cpsr &= ~(1u << 29);
        shdw_diag_set_pc(st, lr);
        if (shdw_spk_forge_hits < 120) {
            shdw_spk_forge_hits++;
            shdw_diag_log("SPKFORGE fd=%d slot=%lld off=%#llx page=%#llx "
                          "n=%u path=%s", fd, (long long)idx,
                          (unsigned long long)off,
                          (unsigned long long)pgoff, (unsigned)n, path);
        }
        return 1;
    }
pass:
    if (shdw_diag_spkforge >= 2) {
        // SHDW_SPKFORGE_EMU: run the syscall here and resume in the caller,
        // leaving the breakpoint armed. Clearing it instead would reopen the
        // 10-20 ms rearm window right between the slot reads.
        static unsigned emu_hits;
        ssize_t rv = pread(fd, (void *)(uintptr_t)buf, (size_t)len,
                           (off_t)off);

        st->__x[0] = (uint64_t)rv;
        st->__cpsr &= ~(1u << 29);
        shdw_diag_set_pc(st, lr);
        if (len == 20 || emu_hits < 200) {
            emu_hits++;
            shdw_diag_log("SPKPASS th=%#x fd=%d buf=%#llx len=%#llx "
                          "off=%#llx rv=%lld lr=%p",
                          (unsigned)shdw_exc_cur_thread, fd,
                          (unsigned long long)buf, (unsigned long long)len,
                          (unsigned long long)off, (long long)rv, (void *)lr);
        }
        return 1;
    }
    return 0;
}

static int shdw_diag_hwdbg_claim(exception_type_t type, exception_data_t code,
                                 mach_msg_type_number_t codeCnt,
                                 arm_thread_state64_t *st) {
    uintptr_t pc = (uintptr_t)arm_thread_state64_get_pc(*st);
    uintptr_t fp;
    uintptr_t ctx;
    uintptr_t sp;
    uint64_t v0 = 0;
    uint64_t v1 = 0;
    int idx = -1;
    int n;
    int sig;
    int forged = 0;

    // This kernel reports hardware execution breakpoints as EXC_ARM_BREAKPOINT
    // (code[0]=1) with code[1] = the breakpoint VA; EXC_ARM_DA_DEBUG shows up
    // for data watchpoints. Both are accepted, but only on an exact site match.
    if (type != EXC_BREAKPOINT || codeCnt < 1 || !shdw_dbg_base ||
        (code[0] != EXC_ARM_BREAKPOINT && code[0] != EXC_ARM_DA_DEBUG)) {
        return 0;
    }
    // This port is reached through exception_raise_state_identity (id 2403),
    // whose code array is 32-bit even with MACH_EXCEPTION_CODES, so the far
    // address of a data watchpoint only carries its low half.
    if (shdw_hw_watch_n && codeCnt >= 1 &&
        (uint32_t)code[codeCnt >= 2 ? 1 : 0] ==
            (uint32_t)(shdw_hw_watch[0] & 0xffffffffULL)) {
        return shdw_diag_watch_claim(code, codeCnt, st, 0);
    }
    if (shdw_hw_watch_n && codeCnt >= 2 &&
        (uint32_t)code[1] == (uint32_t)(shdw_hw_watch[1] & 0xffffffffULL)) {
        return shdw_diag_watch_claim(code, codeCnt, st, 1);
    }
    for (int i = 0; i < SHDW_DBG_SITES; i++) {
        if (pc == shdw_dbg_site(i)) {
            idx = i;
            break;
        }
    }
    if (idx < 0) {
        return 0;
    }

    if (shdw_diag_spksvc) {
        unsigned hits = __atomic_add_fetch(&shdw_dbg_site_hits[idx], 1,
                                           __ATOMIC_RELAXED);
        unsigned num = (unsigned)st->__x[16];
        uintptr_t sv_lr = (uintptr_t)arm_thread_state64_get_lr(*st);
        uintptr_t sv_fp = (uintptr_t)arm_thread_state64_get_fp(*st);

        if (idx == 2 && shdw_diag_spkexit) {
            // Entry of the compiled exit(1): fires before its prologue, so a
            // plain `ret` to lr with x0=0 is a complete no-op.
            uintptr_t xlr = (uintptr_t)arm_thread_state64_get_lr(*st);

            shdw_diag_log("SPKEXIT n=%u code=%#llx lr=%p fp=%p sp=%p", hits,
                          (unsigned long long)st->__x[0], (void *)xlr,
                          (void *)arm_thread_state64_get_fp(*st),
                          (void *)arm_thread_state64_get_sp(*st));
            {
                uintptr_t wfp = (uintptr_t)arm_thread_state64_get_fp(*st);
                for (int fi = 0; fi < 24 && wfp >= 0x10000 &&
                                wfp < 0x800000000000ULL; fi++) {
                    uintptr_t prev = shdw_diag_peek(wfp, 8);
                    uintptr_t ret = shdw_diag_peek(wfp + 8, 8);
                    shdw_diag_log("SPKEXITSTK i=%d fp=%p ret=%#llx off=%#llx", fi,
                                  (void *)wfp, (unsigned long long)ret,
                                  (unsigned long long)(ret - shdw_dbg_base));
                    if (prev <= wfp) break;
                    wfp = prev;
                }
            }
            if (shdw_diag_spkexit >= 2 && hits <= 100) {
                shdw_diag_log("SPKEXITSKIP n=%u lr=%p", hits, (void *)xlr);
                shdw_diag_set_pc(st, xlr);
                st->__x[0] = 0;
                forged = 1;
                n = 0;
                goto spk_clear;
            }
            n = (int)hits;
            goto spk_clear;
        }

        if (idx == 1 && shdw_diag_spkevt) {
            if (shdw_diag_spkscene) {
                shdw_diag_spkscene_try();
            }
            // Reading only: x0 is the object the getter returned, x1 the word
            // the dispatcher will test, and the frame holds both inputs.
            uintptr_t fp = (uintptr_t)arm_thread_state64_get_fp(*st);
            uintptr_t r0 = (uintptr_t)st->__x[0];
            uintptr_t r1 = (uintptr_t)st->__x[1];
            uintptr_t arg = 0;

            if (fp >= 0x10000) {
                arg = shdw_diag_peek(fp - 0xe8, 8);
            }
            shdw_diag_log("SPKEVT5 n=%u obj=%p w0=%#llx x1=%p x1v=%#llx "
                          "arg=%p arg0=%#llx x8=%p lr=%p fp=%p sp=%p",
                          hits, (void *)r0, (unsigned long long)st->__x[0],
                          (void *)r1, (unsigned long long)(r1 >= 0x10000
                                                           ? shdw_diag_peek(r1, 8)
                                                           : 0),
                          (void *)arg,
                          (unsigned long long)(arg >= 0x10000
                                               ? shdw_diag_peek(arg, 8)
                                               : 0),
                          (void *)st->__x[8],
                          (void *)arm_thread_state64_get_lr(*st),
                          (void *)fp,
                          (void *)arm_thread_state64_get_sp(*st));
            shdw_spk_munged_dump("gate", 0x822fecULL);
            if (r0 >= 0x10000) {
                shdw_diag_peek_words("spkevtobj", r0, 0, 16);
            }
            if (r1 >= 0x10000 && hits <= 20) {
                shdw_diag_peek_words("spkevtp", r1, 0, 16);
            }
            if (shdw_diag_spkevt >= 3 && hits <= 200) {
                // Mode 3: the dispatcher's second argument is a C string
                // (0x948fc does strlen on it); an empty one is what makes
                // 0x8ee40 take its fatal branch. The VM left that field null,
                // so hand the callee a harmless message and let the event
                // report itself instead of skipping the call.
                static const char shdw_spk_evt_msg[] = "x";
                uintptr_t sptr = 0;
                int empty = 1;

                if (r1 >= 0x10000) {
                    sptr = shdw_diag_peek(r1, 8);
                }
                if (sptr >= 0x10000 && shdw_diag_peek(sptr, 1)) {
                    empty = 0;
                }
                if (empty) {
                    shdw_diag_log("SPKEVTFIX n=%u obj=%p str=%p -> %p", hits,
                                  (void *)r1, (void *)sptr,
                                  (void *)shdw_spk_evt_msg);
                    st->__x[1] = (uintptr_t)shdw_spk_evt_msg;
                }
                n = (int)hits;
                goto spk_clear;
            }
            if (shdw_diag_spkevt >= 2 && hits <= 200) {
                // Mode 2: resume at the instruction after the dispatcher call
                // (0x8096d0 mov w0,#5 / bl 0x8ee40). The VM loop continues
                // with the same status word it would have used anyway.
                shdw_diag_log("SPKEVTSKIP n=%u obj=%p x1v=%#llx", hits,
                              (void *)r0,
                              (unsigned long long)(r1 >= 0x10000
                                                   ? shdw_diag_peek(r1, 8)
                                                   : 0));
                shdw_diag_set_pc(st,
                                 (uintptr_t)arm_thread_state64_get_pc(*st) + 8);
                forged = 1;
                n = 0;
                goto spk_clear;
            }
            n = (int)hits;
            goto spk_clear;
        }

        // SHDW_SPKFORGE: answer the slot pread itself, then skip the svc.
        // SHDW_SPKFORGE_NUM: index 0 is the thunk entry, before `mov x16,#0x99`.
        if (shdw_diag_spkforge &&
            shdw_spk_try_forge(st, idx == 0 ? 153u : num, sv_lr)) {
            forged = 1;
            n = 0;
            goto spk_clear;
        }
        // The site stays armed; silence the census so the log stays readable.
        if (shdw_diag_spkforge && hits > 80) {
            n = 1;
            goto spk_clear;
        }

        if (hits <= 3000) {
            char srcloc[192]; // SHDW_SVC_SRCLOC
            srcloc[0] = 0;
            {
                uint32_t icount = _dyld_image_count();
                for(uint32_t ii = 0; ii < icount && ii < 1024; ii++) {
                    const struct mach_header_64* ih =
                        (const struct mach_header_64*)_dyld_get_image_header(ii);
                    if(!ih || ih->magic != MH_MAGIC_64) continue;
                    uintptr_t base = (uintptr_t)ih, textva = 0;
                    const struct load_command* lc =
                        (const struct load_command*)(ih + 1);
                    for(uint32_t k = 0; k < ih->ncmds && lc->cmdsize >= 8; k++) {
                        if(lc->cmd == LC_SEGMENT_64) {
                            const struct segment_command_64* sg =
                                (const struct segment_command_64*)lc;
                            if(sg->fileoff == 0 && sg->filesize != 0) textva = (uintptr_t)sg->vmaddr;
                        }
                        lc = (const struct load_command*)((const char*)lc + lc->cmdsize);
                    }
                    if(textva > base) continue;
                    uintptr_t slide = base - textva;
                    lc = (const struct load_command*)(ih + 1);
                    int inside = 0;
                    for(uint32_t k = 0; k < ih->ncmds && lc->cmdsize >= 8; k++) {
                        if(lc->cmd == LC_SEGMENT_64) {
                            const struct segment_command_64* sg =
                                (const struct segment_command_64*)lc;
                            uintptr_t lo = (uintptr_t)sg->vmaddr + slide;
                            if(sv_lr >= lo && sv_lr < lo + (uintptr_t)sg->vmsize) inside = 1;
                        }
                        lc = (const struct load_command*)((const char*)lc + lc->cmdsize);
                    }
                    if(inside) {
                        const char* nm = _dyld_get_image_name(ii);
                        snprintf(srcloc, sizeof srcloc, "%s+%#lx",
                                 nm ? strrchr(nm, '/') ? strrchr(nm, '/') + 1 : nm : "?",
                                 (unsigned long)(sv_lr - base));
                        break;
                    }
                }
            }
            shdw_diag_log("SPKSVC n=%u th=%#x nr=%u a0=%#llx a1=%#llx "
                          "a2=%#llx a3=%#llx a4=%#llx lr=%p fp=%p at=%s",
                          hits, (unsigned)shdw_exc_cur_thread, num,
                          (unsigned long long)st->__x[0],
                          (unsigned long long)st->__x[1],
                          (unsigned long long)st->__x[2],
                          (unsigned long long)st->__x[3],
                          (unsigned long long)st->__x[4], (void *)sv_lr,
                          (void *)sv_fp, srcloc);
            // SHDW_SVC_PATHS: access()/open() carry the path in x0. This is
            // the only place the detector's own file probes name themselves.
            if ((num == 33 || num == 5) && st->__x[0] >= 0x10000 &&
                hits <= 300) {
                const char *sp = (const char *)(uintptr_t)st->__x[0];
                char pbuf[256];
                size_t pi = 0;

                for (; pi + 1 < sizeof pbuf; pi++) {
                    char c = sp[pi];
                    pbuf[pi] = c;
                    if (!c) {
                        break;
                    }
                }
                pbuf[pi] = 0;
                shdw_diag_log("SPKPATH n=%u nr=%u path=%s", hits, num, pbuf);
            }
            if (num == 153 && st->__x[3] >= 0x1000000ULL && st->__x[3] != 0x1000000ULL) { // SHDW_SVC_BIGREAD
                char bgfd[1024];
                bgfd[0] = 0;
                if (fcntl((int)st->__x[0], F_GETPATH, bgfd) != 0) bgfd[0] = 0;
                shdw_diag_log("SPKSVCBIG fd=%u off=%#llx size=%#llx buf=%p path=%s",
                              (unsigned)st->__x[0],
                              (unsigned long long)st->__x[3],
                              (unsigned long long)st->__x[2],
                              (void *)(uintptr_t)st->__x[1], bgfd);
            }
            if (num == 153 && st->__x[2] == 0x20) { // SHDW_SVC_SIGREAD
                if (shdw_svc_sigbuf && shdw_svc_sigth == (unsigned)shdw_exc_cur_thread) {
                    shdw_diag_peek_words("spcsig", shdw_svc_sigbuf, 0, 8);
                }
                char svfd[1024];
                svfd[0] = 0;
                if (fcntl((int)st->__x[0], F_GETPATH, svfd) != 0) svfd[0] = 0;
                shdw_diag_log("SPKSVCSIG fd=%u off=%#llx buf=%p path=%s",
                              (unsigned)st->__x[0],
                              (unsigned long long)st->__x[3],
                              (void *)(uintptr_t)st->__x[1], svfd);
                shdw_svc_sigbuf = (uintptr_t)st->__x[1];
                shdw_svc_sigth = (unsigned)shdw_exc_cur_thread;
            } else if (shdw_svc_sigbuf && shdw_svc_sigth == (unsigned)shdw_exc_cur_thread) {
                shdw_diag_peek_words("spcsig", shdw_svc_sigbuf, 0, 8);
                shdw_svc_sigbuf = 0;
            }
            if(num == 0xFFFFFFD1u && st->__x[0] >= 0x100000000ULL) { // SHDW_SVC_MACHMSG
                shdw_diag_peek_words("spcmsg", (uintptr_t)st->__x[0], 0, 10);
            }
            if(num == 236 && st->__x[0] >= 0x100000000ULL) { // SHDW_SVC_SRCLOC
                shdw_diag_dump_ascii("spcpath", (uintptr_t)st->__x[0], 160);
                shdw_diag_dump_ascii("spcname", (uintptr_t)st->__x[1], 160);
                shdw_diag_log("SPKXATTR size=%llu val=%#x",
                              (unsigned long long)st->__x[3], (unsigned)st->__x[2] ? 0 : 0);
            }
            if ((num == 5 || num == 33 || num == 338 || num == 339 ||
                 num == 170 || num == 396 || num == 101 || num == 167 ||
                 num == 10) && st->__x[0] >= 0x100000000ULL) {
                shdw_diag_dump_ascii("spcpath", (uintptr_t)st->__x[0], 160);
            }
            if (sv_fp >= 0x100000000ULL) {
                shdw_diag_peek_words("spcfr", sv_fp, 0, 16);
            }
            n = (int)hits;
        } else {
            shdw_diag_log("SPKSVC capped hits=%u", hits);
            shdw_dbg_off |= 1u << idx;
            n = 30000;
        }
        goto spk_clear;
    }

    if (shdw_diag_spkmem) {
        unsigned hits = __atomic_add_fetch(&shdw_dbg_site_hits[idx], 1,
                                           __ATOMIC_RELAXED);

        if (hits == 1) {
            shdw_diag_log("SPKMEM base=%p", (void *)shdw_dbg_base);
            shdw_diag_dump_block("spkmemA", shdw_dbg_base + 0x808800, 0xc00);
            shdw_diag_dump_block("spkmemB", shdw_dbg_base + 0x811800, 0xc00);
            shdw_diag_dump_block("spkmemC", shdw_dbg_base + 0x817400, 0x400);
        }
        shdw_dbg_off |= 1u << idx;
        n = 30000;
        goto spk_clear;
    }

    if (shdw_diag_spkgate) {
        unsigned hits = __atomic_add_fetch(&shdw_dbg_site_hits[idx], 1,
                                           __ATOMIC_RELAXED);

        shdw_diag_log("SPKGATE idx=%d n=%u th=%#x lr=%p x0=%#llx x8=%p "
                      "x19=%p x20=%p x16=%#llx x17=%#llx", idx, hits,
                      (unsigned)shdw_exc_cur_thread,
                      (void *)arm_thread_state64_get_lr(*st),
                      (unsigned long long)st->__x[0], (void *)st->__x[8],
                      (void *)st->__x[19], (void *)st->__x[20],
                      (unsigned long long)st->__x[16],
                      (unsigned long long)st->__x[17]);
        if (idx == 1 && hits <= 2) {
            // What the guard stub will actually jump to, read without a write.
            uintptr_t cell = shdw_dbg_base + 0x9caab8;
            uint64_t v = shdw_diag_peek(cell, 8);

            shdw_diag_log("SPKCELL n=%u cell=%p val=%#llx", hits, (void *)cell,
                          (unsigned long long)v);
            shdw_diag_peek_words("spkcellw", cell, 0, 32);
            if (v >= 0x100000000ULL && v < 0x800000000000ULL) {
                shdw_diag_peek_words("spkcellt", (uintptr_t)v, 0, 32);
            }
        }
        n = hits >= 16 ? 30000 : (int)hits;
        goto spk_clear;
    }

    if (shdw_diag_spkzero) {
        unsigned hits = __atomic_add_fetch(&shdw_dbg_site_hits[idx], 1,
                                           __ATOMIC_RELAXED);

        if (idx == 0) {
            shdw_diag_log("SPKEXIT n=%u th=%#x lr=%p sp=%p fp=%p x0=%#llx "
                          "x19=%p x20=%p x8=%#llx", hits,
                          (unsigned)shdw_exc_cur_thread,
                          (void *)arm_thread_state64_get_lr(*st),
                          (void *)arm_thread_state64_get_sp(*st),
                          (void *)arm_thread_state64_get_fp(*st),
                          (unsigned long long)st->__x[0], (void *)st->__x[19],
                          (void *)st->__x[20],
                          (unsigned long long)st->__x[8]);
            shdw_dbg_off |= 1u << idx;
            n = 30000;
            goto spk_clear;
        }

        uintptr_t gobj = (uintptr_t)st->__x[0];
        uintptr_t gval = 0;

        if (gobj >= 0x100000000ULL && gobj < 0x800000000000ULL) {
            gval = shdw_diag_peek(gobj + 0x330, 1);
            if (gval) {
                *(volatile unsigned char *)(gobj + 0x330) = 0;
            }
        }
        shdw_diag_log("SPKZGET n=%u th=%#x obj=%p was=%#llx lr=%p sp=%p",
                      hits, (unsigned)shdw_exc_cur_thread, (void *)gobj,
                      (unsigned long long)gval,
                      (void *)arm_thread_state64_get_lr(*st),
                      (void *)arm_thread_state64_get_sp(*st));
        n = hits >= 64 ? 30000 : (int)hits;
        goto spk_clear;
    }

    if (shdw_diag_spkmsg) {
        unsigned hits = __atomic_add_fetch(&shdw_dbg_site_hits[idx], 1,
                                           __ATOMIC_RELAXED);

        if (idx == 0) {
            uintptr_t mobj = (uintptr_t)st->__x[19];
            uintptr_t buf = mobj >= 0x10000 ? shdw_diag_peek(mobj, 8) : 0;
            uintptr_t cur = mobj >= 0x10000 ? shdw_diag_peek(mobj + 8, 8) : 0;
            uintptr_t end = mobj >= 0x10000 ? shdw_diag_peek(mobj + 0x10, 8) : 0;

            shdw_diag_log("SPKMSG n=%u obj=%p buf=%p cur=%p end=%p "
                          "cursor=%#llx lr=%p", hits, (void *)mobj, (void *)buf,
                          (void *)cur, (void *)end,
                          (unsigned long long)st->__x[22],
                          (void *)arm_thread_state64_get_lr(*st));
            if (hits == 1 && buf >= 0x10000) {
                // peek_words refuses more than 64 bytes per call.
                for (int off = 0; off < 0x1c0; off += 0x40) {
                    shdw_diag_peek_words("spkmsgw", buf, (size_t)off, 0x40);
                }
                shdw_diag_dump_ascii("spkmsga", buf, 0x1c0);
            }
        } else {
            uintptr_t sp = (uintptr_t)arm_thread_state64_get_sp(*st);

            shdw_diag_log("SPKDECPAY n=%u tag=%#llx str=%p", hits,
                          (unsigned long long)st->__x[1], (void *)(sp + 0x10));
            if (hits <= 16) {
                shdw_diag_dump_ascii("spkpay", sp + 0x10, 48);
            }
        }
        n = hits >= 64 ? 30000 : (int)hits;
        goto spk_clear;
    }

    if (shdw_diag_spkdec) {
        unsigned hits = __atomic_add_fetch(&shdw_dbg_site_hits[idx], 1,
                                           __ATOMIC_RELAXED);
        uintptr_t obj = (uintptr_t)st->__x[0];

        if (idx == 0) {
            shdw_diag_log("SPKDECCALL n=%u th=%#x lr=%p sp=%p x0=%#llx "
                          "x1=%#llx x2=%#llx x3=%#llx x8=%#llx", hits,
                          (unsigned)shdw_exc_cur_thread,
                          (void *)arm_thread_state64_get_lr(*st),
                          (void *)arm_thread_state64_get_sp(*st),
                          (unsigned long long)st->__x[0],
                          (unsigned long long)st->__x[1],
                          (unsigned long long)st->__x[2],
                          (unsigned long long)st->__x[3],
                          (unsigned long long)st->__x[8]);
        } else {
            int live = obj >= 0x10000 && obj < 0x800000000000ULL;

            shdw_diag_log("SPKDECENTRY n=%u th=%#x lr=%p sp=%p obj=%p "
                          "x1=%#llx x2=%#llx f148=%#llx f590=%#llx f5c0=%#llx "
                          "f5f0=%#llx f650=%#llx f3a0=%#llx f400=%#llx "
                          "f430=%#llx", hits, (unsigned)shdw_exc_cur_thread,
                          (void *)arm_thread_state64_get_lr(*st),
                          (void *)arm_thread_state64_get_sp(*st), (void *)obj,
                          (unsigned long long)st->__x[1],
                          (unsigned long long)st->__x[2],
                          (unsigned long long)(live ? shdw_diag_peek(obj + 0x148, 8) : 0),
                          (unsigned long long)(live ? shdw_diag_peek(obj + 0x590, 8) : 0),
                          (unsigned long long)(live ? shdw_diag_peek(obj + 0x5c0, 8) : 0),
                          (unsigned long long)(live ? shdw_diag_peek(obj + 0x5f0, 8) : 0),
                          (unsigned long long)(live ? shdw_diag_peek(obj + 0x650, 8) : 0),
                          (unsigned long long)(live ? shdw_diag_peek(obj + 0x3a0, 8) : 0),
                          (unsigned long long)(live ? shdw_diag_peek(obj + 0x400, 8) : 0),
                          (unsigned long long)(live ? shdw_diag_peek(obj + 0x430, 8) : 0));
        }
        n = hits >= 64 ? 30000 : (int)hits;
        goto spk_clear;
    }

    if (shdw_diag_spkskip) {
        unsigned hits = __atomic_add_fetch(&shdw_dbg_site_hits[idx], 1,
                                           __ATOMIC_RELAXED);

        if (idx == 2) {
            shdw_diag_log("SPKSVCW n=%u th=%#x x16=%#llx x0=%#llx x1=%#llx "
                          "x2=%#llx x3=%#llx x8=%#llx lr=%p", hits,
                          (unsigned)shdw_exc_cur_thread,
                          (unsigned long long)st->__x[16],
                          (unsigned long long)st->__x[0],
                          (unsigned long long)st->__x[1],
                          (unsigned long long)st->__x[2],
                          (unsigned long long)st->__x[3],
                          (unsigned long long)st->__x[8],
                          (void *)arm_thread_state64_get_lr(*st));
            if (hits >= SHDW_SPKSTUBW_CAP) {
                shdw_dbg_off |= 1u << idx;
                n = 30000;
            } else {
                n = (int)hits;
            }
            goto spk_clear;
        }

        if (idx == 1) {
            // The pessimistic default was just stored. Replace it with the
            // value a completed validation would have written, before the
            // gate reads it.
            uintptr_t obj = (uintptr_t)st->__x[19];

            shdw_diag_log("SPKCTORFIX n=%u obj=%p before=%#llx", hits,
                          (void *)obj,
                          (unsigned long long)shdw_diag_peek(obj + 0x330, 1));
            if (obj >= 0x100000000ULL) {
                *(volatile unsigned char *)(obj + 0x330) = 0;
            }
            shdw_diag_log("SPKCTORFIX after=%#llx",
                          (unsigned long long)shdw_diag_peek(obj + 0x330, 1));
            n = hits >= SHDW_SPK_CTORFIX_CAP ? 30000 : (int)hits;
            goto spk_clear;
        }

        shdw_diag_log("SPKSKIP n=%u th=%#x lr=%p x0=%#llx x19=%p x20=%p "
                      "x21=%p x22=%p x23=%p x24=%p", hits,
                      (unsigned)shdw_exc_cur_thread,
                      (void *)arm_thread_state64_get_lr(*st),
                      (unsigned long long)st->__x[0], (void *)st->__x[19],
                      (void *)st->__x[20], (void *)st->__x[21],
                      (void *)st->__x[22], (void *)st->__x[23],
                      (void *)st->__x[24]);
        st->__x[0] = 0;
        if (hits <= 5) {
            shdw_diag_fp_walk("spkskip", (uintptr_t)arm_thread_state64_get_fp(*st),
                              (uintptr_t)arm_thread_state64_get_sp(*st));
        }
        shdw_diag_set_pc(st, shdw_dbg_base + SHDW_SPK_EPILOGUE);
        // Keep skipping: every call of this wrapper is a terminate gate. The
        // clear/rearm dance lets the caller continue and the next gate trap.
        // Past SHDW_SPKSKIP_CAP the lane goes quiet so a retry loop cannot
        // starve the thread into the launch watchdog.
        n = hits > SHDW_SPKSKIP_CAP ? 30000 : (int)hits;
        if (hits == SHDW_SPKSKIP_CAP + 1) {
            shdw_diag_log("SPKSKIP capped hits=%u", hits);
        }
        goto spk_clear;
    }

    if (shdw_diag_spkstub) {
        unsigned hits = __atomic_add_fetch(&shdw_dbg_site_hits[idx], 1,
                                           __ATOMIC_RELAXED);

        if (idx == 0) {
            // The pessimistic default just replaced whatever was there. Arm
            // the syscall stub for this thread and retire the one-shot slot
            // in the same state write, so the store is not re-trapped.
            arm_debug_state64_t d;
            mach_msg_type_number_t dcnt = ARM_DEBUG_STATE64_COUNT;
            kern_return_t gk = KERN_FAILURE;
            kern_return_t sk = KERN_FAILURE;

            memset(&d, 0, sizeof d);
            if (shdw_exc_cur_thread != MACH_PORT_NULL) {
                gk = thread_get_state(shdw_exc_cur_thread, ARM_DEBUG_STATE64,
                                      (thread_state_t)&d, &dcnt);
            }
            shdw_diag_log("SPKCTOR n=%u gk=%d th=%#x obj=%p byte=%#llx", hits,
                          (int)gk, (unsigned)shdw_exc_cur_thread,
                          (void *)st->__x[19],
                          (unsigned long long)shdw_diag_peek(
                              (uintptr_t)st->__x[19] + 0x330, 1));
            if (gk == KERN_SUCCESS) {
                d.__bvr[0] = 0;
                d.__bcr[0] = 0;
                d.__bvr[1] = shdw_dbg_base + SHDW_SPK_STUB;
                d.__bcr[1] = SHDW_DBG_BCR;
                sk = thread_set_state(shdw_exc_cur_thread, ARM_DEBUG_STATE64,
                                      (thread_state_t)&d,
                                      ARM_DEBUG_STATE64_COUNT);
            }
            shdw_diag_log("SPKSTUBARM sk=%d site=%p th=%#x", (int)sk,
                          (void *)(shdw_dbg_base + SHDW_SPK_STUB),
                          (unsigned)shdw_exc_cur_thread);
            return 1;
        }

        n = (int)hits;
        if (hits <= SHDW_SPKSTUB_CAP) {
            unsigned num = (unsigned)st->__x[16];
            uintptr_t lr = (uintptr_t)arm_thread_state64_get_lr(*st);

            shdw_diag_log("SPKSTUB n=%u num=%u x0=%#llx x1=%#llx x2=%#llx "
                          "x3=%#llx x4=%#llx x5=%#llx x8=%#llx lr=%p th=%#x",
                          hits, num, (unsigned long long)st->__x[0],
                          (unsigned long long)st->__x[1],
                          (unsigned long long)st->__x[2],
                          (unsigned long long)st->__x[3],
                          (unsigned long long)st->__x[4],
                          (unsigned long long)st->__x[5],
                          (unsigned long long)st->__x[8], (void *)lr,
                          (unsigned)shdw_exc_cur_thread);
            // Path-taking calls: name what the framework is looking at.
            if ((num == 5 || num == 33 || num == 338 || num == 339 ||
                 num == 170 || num == 396 || num == 101 || num == 167) &&
                st->__x[0] >= 0x100000000ULL) {
                shdw_diag_dump_ascii("spkpath", (uintptr_t)st->__x[0], 160);
            }
        } else if (hits == SHDW_SPKSTUB_CAP + 1) {
            shdw_diag_log("SPKSTUB capped hits=%u", hits);
        }
        goto spk_clear;
    }

    if (shdw_diag_spkbrk) {
        unsigned hits = __atomic_add_fetch(&shdw_dbg_site_hits[idx], 1,
                                           __ATOMIC_RELAXED);
        uintptr_t sr_sp = (uintptr_t)arm_thread_state64_get_sp(*st);
        uintptr_t sr_fp = (uintptr_t)arm_thread_state64_get_fp(*st);

        shdw_diag_log("SPKBRK idx=%d n=%u pc=%p lr=%p sp=%p fp=%p th=%#x "
                      "x0=%#llx x1=%#llx x2=%#llx x3=%#llx x4=%#llx x5=%#llx "
                      "x6=%#llx x7=%#llx x8=%#llx x16=%#llx x19=%p x20=%p "
                      "x21=%p x22=%p x23=%p x24=%p x27=%p x28=%#llx",
                      idx, hits, (void *)pc,
                      (void *)arm_thread_state64_get_lr(*st),
                      (void *)sr_sp, (void *)sr_fp,
                      (unsigned)shdw_exc_cur_thread,
                      (unsigned long long)st->__x[0],
                      (unsigned long long)st->__x[1],
                      (unsigned long long)st->__x[2],
                      (unsigned long long)st->__x[3],
                      (unsigned long long)st->__x[4],
                      (unsigned long long)st->__x[5],
                      (unsigned long long)st->__x[6],
                      (unsigned long long)st->__x[7],
                      (unsigned long long)st->__x[8],
                      (unsigned long long)st->__x[16],
                      (void *)st->__x[19], (void *)st->__x[20],
                      (void *)st->__x[21], (void *)st->__x[22],
                      (void *)st->__x[23], (void *)st->__x[24],
                      (void *)st->__x[27],
                      (unsigned long long)st->__x[28]);
        if (hits <= 1) {
            shdw_diag_peek_words("spkstk", sr_sp, 0, 40);
            if (idx == 0) {
                shdw_diag_fp_walk("spkexit", sr_fp, sr_sp);
            }
        }
        if (idx == 1 || idx == 4 || idx == 5) {
            uintptr_t obj = (uintptr_t)st->__x[19];

            shdw_diag_log("SPKFLAG idx=%d obj=%p byte=%#llx w0=%#llx",
                          idx, (void *)obj,
                          (unsigned long long)shdw_diag_peek(obj + 0x330, 1),
                          (unsigned long long)st->__x[0]);
        }
        // Register-only forge: the predicate has already returned at this site
        // (+0x8ed10 is `mov x20, x0`), so zeroing x0 skips the terminate call
        // without touching the config object. This tells a detected memory
        // write apart from the consequences of the taken branch.
        if (idx == 0) {
            shdw_diag_log("SPKREGFLAG before=%#llx obj=%p byte=%#llx",
                          (unsigned long long)st->__x[0], (void *)st->__x[20],
                          (unsigned long long)shdw_diag_peek(
                              (uintptr_t)st->__x[20] + 0x330, 1));
            st->__x[0] = 0;
        }
        if (idx == 1) {
            uintptr_t tgt = (uintptr_t)st->__x[8];
            uintptr_t desc = shdw_diag_peek(shdw_dbg_base + 0x99a1d0, 8);
            uintptr_t key = shdw_diag_peek(shdw_dbg_base + 0x99a190, 8);

            shdw_diag_log("SPKPOSTCALL tgt=%p desc=%#llx key=%#llx x0=%#llx "
                          "x19=%p x20=%p",
                          (void *)tgt, (unsigned long long)desc,
                          (unsigned long long)key,
                          (unsigned long long)st->__x[0],
                          (void *)st->__x[19], (void *)st->__x[20]);
        }
        // One-shot: the sweep must not re-add it on the next ten-thread pass,
        // and the rearm is skipped below.
        shdw_dbg_off |= 1u << idx;
        goto spk_clear;
    }

    n = __atomic_add_fetch(&shdw_dbg_hits, 1, __ATOMIC_RELAXED);
    fp = (uintptr_t)arm_thread_state64_get_fp(*st);
    ctx = (uintptr_t)st->__x[19];
    sp = (uintptr_t)arm_thread_state64_get_sp(*st);
    shdw_diag_hw_ring_add(idx, pc, fp, sp,
                          (uintptr_t)arm_thread_state64_get_lr(*st), st);
    {
        unsigned site_hits =
            __atomic_add_fetch(&shdw_dbg_site_hits[idx], 1, __ATOMIC_RELAXED);

        if (idx == 0) {
            uintptr_t blk = (uintptr_t)st->__x[2];
            uintptr_t w0 = shdw_diag_peek(blk, 8);
            uintptr_t w10 = shdw_diag_peek(blk + 0x10, 8);
            uintptr_t w20 = shdw_diag_peek(blk + 0x20, 8);
            int prod = shdw_diag_svcforge >= SHDW_FORGE_PROD;
            int forge = shdw_diag_svcforge && (unsigned)st->__x[3] == 381;

            // Production forges only the sandbox file-existence probe; any
            // other __mac_syscall runs for real (the breakpoint is cleared and
            // re-armed afterwards, as in the observation lane).
            if (prod) {
                forge = forge && shdw_diag_op_is_filetest(w10);
            } else {
                shdw_diag_svc_note(idx, st, pc,
                                   (uintptr_t)arm_thread_state64_get_lr(*st));
                // The arguments matter more than the hit count: the policy
                // name in x0 and the sandbox_check request block in x2, whose
                // fields point at the operation name and the tested path.
                if (site_hits <= 4) {
                    shdw_diag_dump_ascii("svcarg", (uintptr_t)st->__x[0], 128);
                    shdw_diag_peek_words("svcargw", (uintptr_t)st->__x[0], 0, 48);
                    shdw_diag_peek_words("svcx2", blk, 0, 64);
                    shdw_diag_dump_ascii("svcP0", w0, 96);
                    shdw_diag_peek_words("svcP0w", w0, 0, 48);
                    shdw_diag_dump_ascii("svcP10", w10, 64);
                    shdw_diag_dump_ascii("svcP20", w20, 64);
                }
            }
            if (forge) {
                // The block's first word points at the result word the kernel
                // fills in; write the forged answer there and return as if the
                // thunk had run with no error.
                uint32_t val = (shdw_diag_svcforge == 2) ? 0u : 2u;
                uintptr_t res = shdw_diag_peek(blk, 8);

                if (res >= 0x10000) {
                    *(volatile uint32_t *)res = val;
                }
                shdw_diag_log("SVCFORGE val=%u op=%p path=%p res=%p lr=%p",
                              val, (void *)w10, (void *)w20, (void *)res,
                              (void *)arm_thread_state64_get_lr(*st));
                shdw_diag_set_pc(st, (uintptr_t)arm_thread_state64_get_lr(*st));
                st->__x[0] = 0;
                st->__x[8] = 0;
                forged = 1;
            } else if (prod && (unsigned)st->__x[3] == 381) {
                shdw_diag_log("SVCSKIP op=%p", (void *)w10);
            }
        } else if (idx == 3) {
            // x16 still holds the number; x0 is the raw return (errno on
            // failure) and x8 the carry-derived error flag before csinv. The
            // request block and the two flag words the callers test are read
            // here, after the kernel had its say.
            shdw_diag_log("SVCRET num=%u x0=%#llx x8=%#llx x9=%#llx lr=%p",
                          (unsigned)st->__x[16],
                          (unsigned long long)st->__x[0],
                          (unsigned long long)st->__x[8],
                          (unsigned long long)st->__x[9],
                          (void *)(uintptr_t)arm_thread_state64_get_lr(*st));
            shdw_diag_peek_words("svcres", (uintptr_t)st->__x[2], 0, 64);
            if (ctx >= 0x10000) {
                shdw_diag_peek_words("svcflgA", ctx + 0x21e0, 0, 16);
                shdw_diag_peek_words("svcflgB", ctx + 0x2c20, 0, 16);
            }
        } else if (idx == 1 || idx == 2) {
            // w28 is the "the __mac_syscall failed" flag the caller branches on.
            shdw_diag_log("SVCFLAG site=%d x28=%#llx x0=%#llx x19=%p lr=%p",
                          idx, (unsigned long long)st->__x[28],
                          (unsigned long long)st->__x[0], (void *)ctx,
                          (void *)(uintptr_t)arm_thread_state64_get_lr(*st));
            shdw_diag_fp_walk(idx == 2 ? "chsvcA" : "chsvcB", fp, sp);
        } else if (site_hits <= 3) {
            shdw_diag_log("SVCCONT site=%d x0=%#llx x19=%p lr=%p",
                          idx, (unsigned long long)st->__x[0], (void *)ctx,
                          (void *)(uintptr_t)arm_thread_state64_get_lr(*st));
        }
        if (shdw_diag_svcforge < SHDW_FORGE_PROD &&
            site_hits == SHDW_SVC_CAP) {
            shdw_dbg_off |= 1u << idx;
            shdw_diag_log("SVCCAP idx=%d hits=%u retired", idx, site_hits);
        }
    }

    // The poisoned (fp,lr) pair is what a returning frame would use, so the
    // saved pair of the *current* frame ([x29]/[x29,#8]) is the value to watch
    // at every site. A saved lr under 0x10000 means the hand-off already
    // happened in this frame.
    v0 = shdw_diag_peek(fp, 8);
    v1 = shdw_diag_peek(fp + 8, 8);
    sig = (v0 < 0x10000 || v1 < 0x10000);

    if (idx >= 4 && n <= 600) {
        Dl_info di;
        uintptr_t tgt = (uintptr_t)st->__x[8];

        memset(&di, 0, sizeof di);
        dladdr((const void *)tgt, &di);
        shdw_diag_log("HWDBGHIT n=%d idx=%d sig=%d pc=%p th=%#x state=%#llx "
                      "fp=%p lr=%p sp=%p x0=%p x8=%p img=%s sym=%s v0=%#llx "
                      "v1=%#llx f0=%#llx f1=%#llx s0=%#llx s50=%#llx "
                      "s58=%#llx", n, idx, sig,
                      (void *)pc, (unsigned)shdw_exc_cur_thread,
                      (unsigned long long)(ctx ? shdw_diag_peek(ctx + 0x59c, 4)
                                               : 0),
                      (void *)fp, (void *)arm_thread_state64_get_lr(*st),
                      (void *)sp, (void *)st->__x[0], (void *)tgt,
                      di.dli_fname ? di.dli_fname : "?",
                      di.dli_sname ? di.dli_sname : "?",
                      (unsigned long long)v0, (unsigned long long)v1,
                      (unsigned long long)shdw_diag_peek(fp, 8),
                      (unsigned long long)shdw_diag_peek(fp + 8, 8),
                      (unsigned long long)shdw_diag_peek(sp, 8),
                      (unsigned long long)shdw_diag_peek(sp + 0x50, 8),
                      (unsigned long long)shdw_diag_peek(sp + 0x58, 8));
    }
    if (sig) {
        shdw_diag_peek_words("hwdbgsig", sp, 0, 160);
        if (ctx >= 0x10000) {
            shdw_diag_peek_words("hwdbgctx", ctx, 0x550, 64);
        }
    }

    // A forged hit already moved pc to the return address, so the breakpoint
    // can stay enabled on this thread: it will trap again only on the next
    // call, which is exactly what the production lane wants. Every other hit
    // is resumed at the site and needs the clear-then-rearm dance.
spk_clear:
    if (!forged) {
        if (n > 20000) {
            shdw_dbg_off |= 1u << idx;
        }
        {
            arm_debug_state64_t d;
            mach_msg_type_number_t cnt = ARM_DEBUG_STATE64_COUNT;
            kern_return_t gk = KERN_FAILURE;

            memset(&d, 0, sizeof d);
            if (shdw_exc_cur_thread != MACH_PORT_NULL) {
                gk = thread_get_state(shdw_exc_cur_thread, ARM_DEBUG_STATE64,
                                      (thread_state_t)&d, &cnt);
            }
            if (gk == KERN_SUCCESS) {
                kern_return_t sk;

                d.__bcr[idx] = 0;
                if (idx == 6 && shdw_hw_watch_n) {
                    d.__wvr[0] = shdw_hw_watch[0];
                    d.__wcr[0] = SHDW_WCR_WATCH;
                    d.__wvr[1] = shdw_hw_watch[1];
                    d.__wcr[1] = SHDW_WCR_WATCH;
                }
                sk = thread_set_state(shdw_exc_cur_thread, ARM_DEBUG_STATE64,
                                      (thread_state_t)&d,
                                      ARM_DEBUG_STATE64_COUNT);
                if (sk != KERN_SUCCESS) {
                    shdw_diag_log("HWDBGCLR idx=%d sk=%d", idx, (int)sk);
                } else if (idx == 6 && shdw_hw_watch_n) {
                    shdw_diag_log("HWARMSET w0=%#llx w1=%#llx wcr=%#llx",
                                  (unsigned long long)d.__wvr[0],
                                  (unsigned long long)d.__wvr[1],
                                  (unsigned long long)d.__wcr[0]);
                }
            } else {
                shdw_diag_log("HWDBGCLR idx=%d gk=%d", idx, (int)gk);
            }
        }
        if (!shdw_diag_spkbrk && n <= 20000 &&
            shdw_exc_cur_thread != MACH_PORT_NULL) {
            shdw_dbg_rearm_port = shdw_exc_cur_thread;
            shdw_dbg_rearm_idx = idx;
        }
    }
    return 1;
}

// Called from the exception thread after the reply, so the trapping thread has
// executed the instruction before its breakpoint is restored.
static void shdw_diag_hwdbg_rearm(void) {
    int idx = shdw_dbg_rearm_idx;
    mach_port_t th = shdw_dbg_rearm_port;
    uintptr_t site;
    arm_debug_state64_t d;
    mach_msg_type_number_t cnt = ARM_DEBUG_STATE64_COUNT;
    kern_return_t gk = -1;
    kern_return_t sk = -1;

    shdw_dbg_rearm_idx = -1;
    shdw_dbg_rearm_port = MACH_PORT_NULL;
    if (idx < 0 || th == MACH_PORT_NULL || !shdw_dbg_base) {
        return;
    }
    site = shdw_dbg_site(idx);
    for (int i = 0; i < 40; i++) {
        arm_thread_state64_t ts;
        mach_msg_type_number_t sc = ARM_THREAD_STATE64_COUNT;

        usleep(50);
        memset(&ts, 0, sizeof ts);
        if (thread_get_state(th, ARM_THREAD_STATE64, (thread_state_t)&ts,
                             &sc) != KERN_SUCCESS ||
            (uintptr_t)arm_thread_state64_get_pc(ts) != site) {
            break;
        }
    }
    memset(&d, 0, sizeof d);
    gk = thread_get_state(th, ARM_DEBUG_STATE64, (thread_state_t)&d, &cnt);
    if (gk == KERN_SUCCESS) {
        d.__bvr[idx] = site;
        d.__bcr[idx] = SHDW_DBG_BCR;
        sk = thread_set_state(th, ARM_DEBUG_STATE64, (thread_state_t)&d,
                              ARM_DEBUG_STATE64_COUNT);
    }
    // A thunk can be re-entered thousands of times; its census line and the
    // ring already carry the evidence, so only sample the rearm line there.
    {
        unsigned hits = shdw_dbg_site_hits[idx];

        if (idx >= 6 || hits <= 20 || (hits % 250) == 0) {
            shdw_diag_log("HWDBGREARM idx=%d th=%#x gk=%d sk=%d bcr=%#llx hits=%u",
                          idx, (unsigned)th, (int)gk, (int)sk,
                          (unsigned long long)d.__bcr[idx], hits);
        }
    }
}


// The detector's verdict code writes the doomed frame directly, with no
// trap to observe, so the only witness is where the failing thread actually
// executed. This lane samples every thread's PC a few thousand times a
// second into a ring and dumps the faulting thread's last samples when the
// fault arrives (pref: Debug_PcSample).
int shdw_diag_pcsample = 0;
int shdw_diag_pc_dump = 0;
uintptr_t shdw_wait_pc = 0;              // base+0x23f050, the VM wait spin
volatile uintptr_t shdw_wait_ctx = 0;    // x19 of the thread stuck there
volatile uint32_t shdw_wait_tid = 0;
volatile uint64_t shdw_wait_first_ns = 0;
volatile int shdw_wait_released = 0;
volatile int shdw_wait_done_logged = 0;
uint32_t shdw_diag_main_tid = 0;
static uint64_t shdw_diag_t0_ns = 0;

#define SHDW_PC_RING 16384

typedef struct {
    uint32_t tid;
    uint32_t pad;
    uint64_t pc;
    uint64_t sp;
    uint64_t fp;
    uint64_t lr;
    uint64_t x0;
    uint64_t x19;
    uint64_t x21;
    uint64_t x22;
    uint64_t x23;
    uint64_t x24;
    uint64_t ns;
} shdw_pc_sample;

static shdw_pc_sample shdw_pc_ring[SHDW_PC_RING];

static void shdw_diag_atexit_mark(void) {
    shdw_diag_log("ATEXIT fired");
}

static void* shdw_diag_pc_thread(void* arg) {
    (void)arg;
    int fast = (shdw_diag_pc_dump >= 2);
    const struct timespec iv = {0, fast ? 2000 * 1000 : 10 * 1000};
    uint32_t passes = 0;

    for (;;) {
        thread_act_array_t list = NULL;
        mach_msg_type_number_t count = 0;
        int dump_all = 0;

        if (shdw_diag_pc_dump) {
            passes++;
            dump_all = ((passes % (fast ? 1u : 20u)) == 0u);
        }

        if (task_threads(mach_task_self(), &list, &count) == KERN_SUCCESS && list) {
            for (mach_msg_type_number_t i = 0; i < count; i++) {
                arm_thread_state64_t st;
                mach_msg_type_number_t sc = ARM_THREAD_STATE64_COUNT;

                if (thread_get_state(list[i], ARM_THREAD_STATE64,
                                     (thread_state_t)&st, &sc) == KERN_SUCCESS) {
                    {
                        uintptr_t smpc = (uintptr_t)arm_thread_state64_get_pc(st);
                        if (shdw_wait_pc && !shdw_wait_ctx &&
                            (smpc == shdw_wait_pc ||
                             smpc == shdw_wait_pc + 4 ||
                             smpc == shdw_wait_pc + 8)) {
                            struct timespec wn;
                            uintptr_t w19 = (uintptr_t)st.__x[19];
                            clock_gettime(CLOCK_MONOTONIC, &wn);
                            shdw_wait_ctx = w19;
                            shdw_wait_tid = (uint32_t)list[i];
                            shdw_wait_first_ns = (uint64_t)wn.tv_sec * 1000000000ull +
                                                 (uint64_t)wn.tv_nsec;
                            shdw_diag_log("WAITSMP tid=%#x pc=%#lx x19=%p sp=%p"
                                          " lr=%#lx w4=%#llx w8=%#llx",
                                          (uint32_t)list[i],
                                          (unsigned long)(smpc - (shdw_wait_pc - 0x23f050)),
                                          (void *)w19,
                                          (void *)(uintptr_t)arm_thread_state64_get_sp(st),
                                          (unsigned long)arm_thread_state64_get_lr(st),
                                          (unsigned long long)shdw_diag_peek(w19 + 0x1b0, 4),
                                          (unsigned long long)shdw_diag_peek(w19 + 0x1b8, 1));
                        }
                    }
                    {
                        uintptr_t smpc = (uintptr_t)arm_thread_state64_get_pc(st);
                        uintptr_t vb = shdw_wait_pc ? (shdw_wait_pc - 0x23f050) : 0;

                        if(vb && smpc >= vb + 0x23ee38 && smpc < vb + 0x23f044) {
                            static uint32_t vmSeen[64];
                            static int vmSeenN;
                            uint32_t vt = (uint32_t)list[i];
                            int have = 0;

                            for(int k = 0; k < vmSeenN; k++) {
                                if(vmSeen[k] == vt) { have = 1; break; }
                            }
                            if(!have && vmSeenN < 64) {
                                vmSeen[vmSeenN++] = vt;
                                shdw_diag_log("VMSMP tid=%#x pc=+%#lx lr=%#lx"
                                              " x0=%p x19=%p",
                                              vt,
                                              (unsigned long)(smpc - vb),
                                              (unsigned long)(arm_thread_state64_get_lr(st) - vb),
                                              (void *)(uintptr_t)st.__x[0],
                                              (void *)(uintptr_t)st.__x[19]);
                            }
                        }
                    }
                    if (dump_all ||
                       (shdw_diag_pc_dump &&
                        (uint32_t)list[i] == shdw_diag_main_tid)) {
                        char spcs[160];
                        char slrs[160];
                        struct timespec now;
                        clock_gettime(CLOCK_MONOTONIC, &now);
                        uint64_t ns = (uint64_t)now.tv_sec * 1000000000ull +
                                      (uint64_t)now.tv_nsec;
                        shdw_diag_describe_short(
                            spcs, sizeof spcs,
                            (void *)(uintptr_t)arm_thread_state64_get_pc(st));
                        shdw_diag_describe_short(
                            slrs, sizeof slrs,
                            (void *)(uintptr_t)arm_thread_state64_get_lr(st));
                        shdw_diag_log("SMPL dt=%+.2fms tid=%#x pc=%s lr=%s x0=%p",
                                      shdw_diag_t0_ns
                                          ? ((double)ns - (double)shdw_diag_t0_ns) / 1e6
                                          : 0.0,
                                      (uint32_t)list[i], spcs, slrs,
                                      (void *)(uintptr_t)st.__x[0]);
                    }
                    uint32_t pos = __atomic_add_fetch(&shdw_pc_pos, 1, __ATOMIC_RELAXED);
                    shdw_pc_sample *s = &shdw_pc_ring[pos % SHDW_PC_RING];

                    s->tid = (uint32_t)list[i];
                    s->pc = arm_thread_state64_get_pc(st);
                    s->sp = arm_thread_state64_get_sp(st);
                    s->fp = arm_thread_state64_get_fp(st);
                    s->lr = arm_thread_state64_get_lr(st);
                    s->x0 = st.__x[0];
                    s->x19 = st.__x[19];
                    s->x21 = st.__x[21];
                    s->x22 = st.__x[22];
                    s->x23 = st.__x[23];
                    s->x24 = st.__x[24];
                    struct timespec ts;
                    clock_gettime(CLOCK_MONOTONIC, &ts);
                    s->ns = (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
                }
                mach_port_deallocate(mach_task_self(), list[i]);
            }
            vm_deallocate(mach_task_self(), (vm_address_t)list,
                          count * sizeof(thread_t));
        }

        {
            uintptr_t ctx = shdw_wait_ctx;

            if(ctx && !shdw_wait_done_logged &&
               shdw_diag_peek(ctx + 0x1b0, 4) != 1) {
                struct timespec wn;
                uint64_t stv = shdw_diag_peek(ctx + 0x1b0, 4);
                clock_gettime(CLOCK_MONOTONIC, &wn);
                shdw_wait_done_logged = 1;
                shdw_diag_log("WAITDONE ctx=%p state=%#llx flag4=%#llx"
                              " age=%.1fms",
                              (void *)ctx, (unsigned long long)stv,
                              (unsigned long long)shdw_diag_peek(ctx + 0x1b4, 1),
                              ((double)wn.tv_sec * 1e9 + (double)wn.tv_nsec
                               - (double)shdw_wait_first_ns) / 1e6);
            }
        }

        nanosleep(&iv, NULL);
    }

    return NULL;
}

void shdw_diag_pcsample_dump(const char *tag, uint32_t tid) {
    uint32_t cur = __atomic_load_n(&shdw_pc_pos, __ATOMIC_RELAXED);
    uint32_t mark = shdw_pc_mark;
    uint32_t pos = (mark && mark <= cur) ? mark : cur;
    unsigned printed = 0;

    shdw_diag_log("PCSAMPLE %s tid=%#x pos=%u", tag, tid, pos);

    for (uint32_t back = 1; back <= SHDW_PC_RING && printed < 400; back++) {
        shdw_pc_sample *s = &shdw_pc_ring[(pos - back) % SHDW_PC_RING];

        if (s->tid != tid || !s->pc) {
            continue;
        }
        {
            char pcs[128];
            char lrs[128];
            shdw_diag_describe_short(pcs, sizeof pcs, (void *)(uintptr_t)s->pc);
            shdw_diag_describe_short(lrs, sizeof lrs, (void *)(uintptr_t)s->lr);
            shdw_diag_log("PCSAMPLE -%u dt=%+.2fms pc=%s x0=%p x19=%p x21=%p"
                          " x22=%p x23=%p x24=%p sp=%p fp=%p lr=%s",
                          back, s->ns && shdw_pc_mark_ns
                                    ? ((double)s->ns - (double)shdw_pc_mark_ns) / 1e6
                                    : 0.0,
                          pcs, (void *)(uintptr_t)s->x0,
                          (void *)(uintptr_t)s->x19, (void *)(uintptr_t)s->x21,
                          (void *)(uintptr_t)s->x22, (void *)(uintptr_t)s->x23,
                          (void *)(uintptr_t)s->x24, (void *)(uintptr_t)s->sp,
                          (void *)(uintptr_t)s->fp, lrs);
            printed++;
        }
    }
}

static uintptr_t shdw_diag_image_base(const char *suffix);

static int shdw_diag_svc_arm_span(const char *label, uintptr_t base,
                                  uint64_t lo, uint64_t hi, int pass) {
    int armed = 0;
    vm_address_t cursor = (vm_address_t)(base + lo);
    vm_address_t limit = (vm_address_t)(base + hi);

    while(cursor < limit) {
        vm_address_t region = cursor;
        vm_size_t size = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t obj = MACH_PORT_NULL;
        kern_return_t kr = vm_region_64(mach_task_self(), &region, &size,
                                        VM_REGION_BASIC_INFO_64,
                                        (vm_region_info_t)&info, &count, &obj);

        if(obj != MACH_PORT_NULL) {
            mach_port_deallocate(mach_task_self(), obj);
        }
        if(kr != KERN_SUCCESS || size == 0) {
            break;
        }

        vm_address_t next = region + size;

        if((info.protection & VM_PROT_EXECUTE) && region < limit) {
            vm_address_t spanEnd = next < limit ? next : limit;

            if(vm_protect(mach_task_self(), region, size, FALSE,
                          VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY) == KERN_SUCCESS) {
                uint32_t *w = (uint32_t *)region;

                for(uintptr_t p = region; p + 4 <= spanEnd; p += 4) {
                    size_t idx = (size_t)((p - region) / 4);

                    if(w[idx] != 0xd4001001u) {
                        continue;
                    }

                    if(armed < 12 && p >= region + 16) {
                        shdw_diag_log("SVCARM %s pass=%d site=%#lx rva=%#lx"
                                      " p4=%08x %08x %08x %08x",
                                      label, pass, (unsigned long)p,
                                      (unsigned long)(p - base),
                                      *(volatile uint32_t *)(p - 16),
                                      *(volatile uint32_t *)(p - 12),
                                      *(volatile uint32_t *)(p - 8),
                                      *(volatile uint32_t *)(p - 4));
                    }
                    w[idx] = 0x00000000u;
                    armed++;
                }

                vm_protect(mach_task_self(), region, size, FALSE,
                           VM_PROT_READ | VM_PROT_EXECUTE);
                sys_icache_invalidate((void *)region, (size_t)(spanEnd - region));
            }
        }

        cursor = next;
    }

    return armed;
}

static void shdw_diag_svc_scan(int pass) {
    // Enable the UDF/SIGILL lane before the first site is rewritten: the app
    // reaches the dispatcher within tens of milliseconds of arming, and a hit
    // with the lane off is an unhandled SIGILL.
    __atomic_store_n(&shdw_insvc_on, 1, __ATOMIC_RELEASE);

    uintptr_t fb = shdw_diag_image_base("Finanzstatusx");
    uintptr_t mb = shdw_diag_image_base("BankingWhiteLabel");
    int fw = 0, jw = 0, maintext = 0;

    if(fb && pass <= 6) {
        fw = shdw_diag_svc_arm_span("fw", fb, 0, 0x9c0000, pass);
    }
    if(mb) {
        if(pass <= 6) {
            jw = shdw_diag_svc_arm_span("jw", mb, 0x5c58000, 0x5c58000 + 0x1c38000, pass);
        }

        if(pass == 0) {
            maintext = shdw_diag_svc_arm_span("main", mb, 0, 0x5c58000, pass);
        }
    }

    shdw_diag_log("SVCSCAN pass=%d fw=%d jw=%d main=%d", pass, fw, jw, maintext);
}

static void shdw_diag_cell_dump(uintptr_t base, int pass) {
    char line[1024];
    int pos = snprintf(line, sizeof line, "CELL pass=%d", pass);

    for(int i = 0xa80; i < 0xb40; i += 8) {
        uint64_t v = *(volatile uint64_t *)(base + 0x9ca000 + (uintptr_t)i);
        char s[96];

        shdw_diag_describe_short(s, sizeof s, (void *)(uintptr_t)v);
        pos += snprintf(line + pos, sizeof line - (size_t)pos, " %#x=%#llx(%s)",
                        i, (unsigned long long)v, s);
    }
    shdw_diag_log("%s", line);
}


static void shdw_diag_svc_gadget(const char *suffix, uint64_t rva) {
    uintptr_t base = shdw_diag_image_base(suffix);

    if(!base) {
        shdw_diag_log("GADGET no image %s", suffix);
        return;
    }

    const struct mach_header_64 *h = (const struct mach_header_64 *)base;
    uint64_t segVm = 0, segSz = 0;
    const struct load_command *lc = (const struct load_command *)(h + 1);

    for(uint32_t i = 0; i < h->ncmds; i++) {
        if(lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *sg = (const void *)lc;

            if(rva >= sg->vmaddr && rva < sg->vmaddr + sg->vmsize) {
                segVm = sg->vmaddr;
                segSz = sg->vmsize;
                break;
            }
        }
        lc = (const struct load_command *)((const char *)lc + lc->cmdsize);
    }

    if(!segSz) {
        shdw_diag_log("GADGET no seg rva=%#llx", (unsigned long long)rva);
        return;
    }

    uintptr_t site = base + rva;
    uint32_t orig = *(volatile uint32_t *)site;

    if(orig != 0xd4001001u) {
        shdw_diag_log("GADGET mismatch %#x rva=%#llx", orig, (unsigned long long)rva);
        return;
    }

    uint8_t *seg = (uint8_t *)(base + segVm);

    if(vm_protect(mach_task_self(), (vm_address_t)seg, (vm_size_t)segSz, FALSE,
                  VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY) != KERN_SUCCESS) {
        shdw_diag_log("GADGET prot fail rva=%#llx", (unsigned long long)rva);
        return;
    }

    *(volatile uint32_t *)site = 0x00000000u;
    sys_icache_invalidate((void *)site, sizeof(uint32_t));
    vm_protect(mach_task_self(), (vm_address_t)seg, (vm_size_t)segSz, FALSE,
               VM_PROT_READ | VM_PROT_EXECUTE);
    __atomic_store_n(&shdw_insvc_on, 1, __ATOMIC_RELEASE);
    shdw_diag_log("GADGET armed site=%p rva=%#llx seg=%#llx+%#llx", (void *)site,
                  (unsigned long long)rva, (unsigned long long)segVm,
                  (unsigned long long)segSz);
}

static void shdw_diag_svc_gadget_addr(const char *tag, uintptr_t site) {
    uint32_t orig = *(volatile uint32_t *)site;

    if(orig != 0xd4001001u) {
        shdw_diag_log("GADGETA %s mismatch %#x at %p", tag, orig, (void *)site);
        return;
    }
    {
        vm_address_t page = (vm_address_t)(site & ~0xfffull);
        kern_return_t kr = vm_protect(mach_task_self(), page, 0x4000, FALSE,
                                      VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
        if(kr != KERN_SUCCESS) {
            shdw_diag_log("GADGETA %s prot kr=%d", tag, kr);
            return;
        }
        *(volatile uint32_t *)site = 0x00000000u;
        sys_icache_invalidate((void *)site, sizeof(uint32_t));
        vm_protect(mach_task_self(), page, 0x4000, FALSE,
                   VM_PROT_READ | VM_PROT_EXECUTE);
    }
    __atomic_store_n(&shdw_insvc_on, 1, __ATOMIC_RELEASE);
    shdw_diag_log("GADGETA %s armed site=%p", tag, (void *)site);
}

static void shdw_diag_anon_scan(int pass) {
    // Report-only. The runtime-anonymous executable regions on this app are
    // dyld itself (its local syscall stubs) plus one 0x4000 stub page, and
    // patching dyld's text wedges the process, so nothing is armed here.
    int found = 0;
    vm_address_t addr = 1;

    for(int guard = 0; guard < 20000; guard++) {
        vm_size_t size = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t obj = MACH_PORT_NULL;
        kern_return_t kr = vm_region_64(mach_task_self(), &addr, &size,
                                        VM_REGION_BASIC_INFO_64,
                                        (vm_region_info_t)&info, &count, &obj);

        if(obj != MACH_PORT_NULL) {
            mach_port_deallocate(mach_task_self(), obj);
        }

        if(kr != KERN_SUCCESS || size == 0) {
            break;
        }

        if((info.protection & VM_PROT_EXECUTE) && size <= 0x2000000) {
            Dl_info di = {0};
            int owned = dladdr((void *)addr, &di) && di.dli_fbase &&
                        (uintptr_t)addr >= (uintptr_t)di.dli_fbase &&
                        (uintptr_t)addr < (uintptr_t)di.dli_fbase + 0x10000000ULL;

            if(!owned) {
                int hits = 0;

                for(uintptr_t p = addr; p + 4 <= addr + size; p += 4) {
                    if(*(volatile uint32_t *)p == 0xd4001001u) {
                        hits++;
                    }
                }

                if(hits) {
                    shdw_diag_log("ANONREG pass=%d region=%p size=%#lx prot=%d"
                                  " svc=%d name=%s", pass, (void *)addr,
                                  (unsigned long)size, (int)info.protection, hits,
                                  di.dli_fname ? di.dli_fname : "<none>");
                }
                found += hits;
            }
        }
        addr += size;
    }

    shdw_diag_log("ANONSCAN pass=%d hits=%d", pass, found);
}


// Promon SHIELD rebuilds the framework GOT into __DATA at +0x99c000 and points
// the stub island at that copy, so the on-disk slot addresses describe nothing.
// Read the runtime table and report what each entry actually is.
int shdw_diag_prm_dump = 0;
int shdw_diag_no_waitrel = 0;

// Cell shim (Debug_CellShim): the guard stub island loads its dispatch
// pointer from Finanzstatusx+0x9caab8. Replace that pointer with our own
// function, which logs the caller and then branches to whatever the app
// itself stored there, so the syscall path stays byte-for-byte identical.
int shdw_cell_shim_on = 0;
__attribute__((visibility("hidden"))) uint64_t shdw_cell_real;
static volatile uint32_t shdw_cell_calls;
// 1 when the pointer the app stored in the cell is a bare `svc #0x80; ret`
// thunk, i.e. the shim can execute the syscall itself and observe the result.
__attribute__((visibility("hidden"))) int shdw_cell_real_svc;
static volatile uint32_t shdw_cell_res;

static void shdw_cell_stack(uintptr_t sp);

__attribute__((noinline, used, visibility("hidden")))
void shdw_cell_note(long n, uintptr_t lr, uintptr_t sp, uintptr_t a0,
                    uintptr_t a1, uintptr_t a2, uintptr_t a3) {
    uint32_t c = __atomic_add_fetch(&shdw_cell_calls, 1, __ATOMIC_RELAXED);
    char path[192];
    int have = 0;

    if(n == 202) { // SPK65MIB: sysctl(name, namelen, ...) - dump the mib
        uint32_t m0 = 0, m1 = 0, m2 = 0, m3 = 0;
        if(a0 >= 0x10000) {
            m0 = (uint32_t)shdw_diag_peek(a0, 4);
            m1 = (uint32_t)shdw_diag_peek(a0 + 4, 4);
            m2 = (uint32_t)shdw_diag_peek(a0 + 8, 4);
            m3 = (uint32_t)shdw_diag_peek(a0 + 12, 4);
        }
        shdw_diag_log("CELLMIB k=%u lr=%#lx name=%#llx mib=%u,%u,%u,%u "
                      "oldp=%#llx oldlenp=%#llx", (unsigned)c,
                      (unsigned long)lr, (unsigned long long)a0, m0, m1, m2,
                      m3, (unsigned long long)a2, (unsigned long long)a3);
    }
    if(n == 1) {
        char l[160];
        shdw_diag_describe_short(l, sizeof l, (void *)lr);
        shdw_diag_log("CELLEXIT n=1 lr=%s cnt=%u real=%#llx", l, (unsigned)c,
                      (unsigned long long)shdw_cell_real);
        shdw_cell_stack(sp);
        return;
    }
    if(c > 800) {
        return;
    }
    switch(n) {
        case 5:
        case 33:
        case 58:
        case 64:
        case 65:
        case 66:
        case 128:
        case 136:
        case 169:
        case 217:
        case 338:
        case 344:
            have = shdw_insvc_cstr(a0, path, sizeof path);
            break;
        default:
            break;
    }
    if(have) {
        shdw_diag_log("CELLC k=%u n=%ld lr=%#lx a0=%#llx a1=%#llx a2=%#llx "
                      "a3=%#llx str=%s",
                      c, n, (unsigned long)lr, (unsigned long long)a0,
                      (unsigned long long)a1, (unsigned long long)a2,
                      (unsigned long long)a3, path);
    } else {
        shdw_diag_log("CELLC k=%u n=%ld lr=%#lx a0=%#llx a1=%#llx a2=%#llx "
                      "a3=%#llx",
                      c, n, (unsigned long)lr, (unsigned long long)a0,
                      (unsigned long long)a1, (unsigned long long)a2,
                      (unsigned long long)a3);
    }
}

// Syscall results, first three per number: the app's own file/entropy work
// is the only thing that can decide the verdict this early.
__attribute__((noinline, used, visibility("hidden")))
void shdw_cell_post(long n, uintptr_t lr, long r0, long r1, long cf) {
    uint32_t c = __atomic_add_fetch(&shdw_cell_res, 1, __ATOMIC_RELAXED);

    if(c > 800) {
        return;
    }
    shdw_diag_log("CELLR k=%u n=%ld lr=%#lx r0=%ld(%#lx) cf=%ld", c, n,
                  (unsigned long)lr, r0, (unsigned long)r0, cf);
}

// Called once, on the exit path only: walk the raw stack and name every
// word that points into a mapped image, so the caller chain into exit(1)
// is readable without a debugger.
static void shdw_cell_stack(uintptr_t sp) {
    uint64_t buf[96];
    vm_size_t got = 0;
    char line[900];
    int w = 0;
    int shown = 0;

    if(vm_read_overwrite(mach_task_self(), (vm_address_t)sp, sizeof buf,
                         (vm_address_t)buf, &got) != KERN_SUCCESS || !got) {
        shdw_diag_log("CELLSTK sp=%p unreadable", (void *)sp);
        return;
    }

    w += snprintf(line + w, sizeof line - (size_t)w,
                  "CELLSTK sp=%p w0=%#llx w1=%#llx w2=%#llx w3=%#llx",
                  (void *)sp, (unsigned long long)buf[0],
                  (unsigned long long)buf[1], (unsigned long long)buf[2],
                  (unsigned long long)buf[3]);
    for(vm_size_t i = 0; i + 8 <= got && shown < 20; i += 8) {
        uint64_t v = buf[i / 8];
        Dl_info info;

        if(v < 0x100000000ull || (v & 3)) {
            continue;
        }
        if(!dladdr((void *)(uintptr_t)v, &info) || !info.dli_fname) {
            continue;
        }
        if(strstr(info.dli_fname, "Finanzstatusx")) {
            w += snprintf(line + w, sizeof line - (size_t)w, " [%u]+%#llx",
                          (unsigned)(i / 8),
                          (unsigned long long)(v -
                          (uint64_t)(uintptr_t)info.dli_fbase));
            if(w > (int)sizeof line - 80) {
                shdw_diag_log("%s", line);
                w = snprintf(line, sizeof line, "CELLSTK cont");
            }
            shown++;
        }
    }
    shdw_diag_log("%s", line);
}

// Entered exactly like the framework's own dispatcher: x16 = syscall number,
// x0..x7 = args, x30 = return address inside the stub. Nothing here touches
// the flags before the branch, so the syscall's carry reaches the stub intact.
__attribute__((naked, noinline, used, visibility("hidden")))
void shdw_cell_shim(void) {
    __asm__ __volatile__(
        "stp  x29, x30, [sp, #-0x80]!\n"
        "mov  x29, sp\n"
        "stp  x0, x1, [sp, #0x10]\n"
        "stp  x2, x3, [sp, #0x20]\n"
        "stp  x4, x5, [sp, #0x30]\n"
        "stp  x6, x7, [sp, #0x40]\n"
        "stp  x8, x16, [sp, #0x50]\n"
        "add  x10, sp, #0x80\n"
        "str  x10, [sp, #0x60]\n"
        "mov  x0, x16\n"
        "mov  x1, x30\n"
        "ldr  x2, [sp, #0x60]\n"
        "ldr  x3, [sp, #0x10]\n"
        "ldr  x4, [sp, #0x18]\n"
        "ldr  x5, [sp, #0x20]\n"
        "ldr  x6, [sp, #0x28]\n"
        "bl   _shdw_cell_note\n"
        "ldr  x30, [sp, #0x08]\n"
        "ldp  x8, x16, [sp, #0x50]\n"
        "ldp  x6, x7, [sp, #0x40]\n"
        "ldp  x4, x5, [sp, #0x30]\n"
        "ldp  x2, x3, [sp, #0x20]\n"
        "ldp  x0, x1, [sp, #0x10]\n"
        "adrp x17, _shdw_cell_real_svc@PAGE\n"
        "ldr  w17, [x17, _shdw_cell_real_svc@PAGEOFF]\n"
        "cbz  w17, 1f\n"
        "svc  #0x80\n"
        "cset w9, cs\n"
        "stp  x0, x1, [sp, #-0x30]!\n"
        "stp  x8, x9, [sp, #0x10]\n"
        "str  x30, [sp, #0x20]\n"
        "mov  x2, x0\n"
        "mov  x3, x1\n"
        "mov  x0, x16\n"
        "ldr  x1, [sp, #0x20]\n"
        "ldr  x4, [sp, #0x18]\n"
        "bl   _shdw_cell_post\n"
        "ldp  x8, x9, [sp, #0x10]\n"
        "ldr  x30, [sp, #0x20]\n"
        "ldp  x0, x1, [sp], #0x30\n"
        "cmp  x9, #1\n"
        "ldp  x29, x30, [sp], #0x80\n"
        "ret\n"
        "1:\n"
        "ldp  x29, x30, [sp], #0x80\n"
        "adrp x17, _shdw_cell_real@PAGE\n"
        "ldr  x17, [x17, _shdw_cell_real@PAGEOFF]\n"
        "br   x17\n"
    );
}

static uintptr_t shdw_diag_image_base(const char *suffix);

static void shdw_diag_dump_span(const char *label, uintptr_t base, uint64_t lo,
                                uint64_t hi, int tag) {
    char path[512];
    const char *home = getenv("HOME");

    snprintf(path, sizeof path, "%s/Documents/spk_%s_%d.bin",
             home ? home : "/tmp", label, tag);

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);

    if(fd < 0) {
        shdw_diag_log("DMP open fail %s", path);
        return;
    }

    static uint8_t buf[65536];
    uint64_t off = 0, total = hi - lo;

    while(off < total) {
        size_t chunk = (size_t)(total - off < (uint64_t)sizeof buf
                                ? total - off : (uint64_t)sizeof buf);
        vm_size_t got = 0;
        kern_return_t kr = vm_read_overwrite(mach_task_self(),
                                             (vm_address_t)(base + lo + off),
                                             (vm_size_t)chunk,
                                             (vm_address_t)buf, &got);

        if(kr != KERN_SUCCESS || got == 0) {
            break;
        }

        ssize_t w = write(fd, buf, got);

        if(w <= 0) {
            break;
        }

        off += (uint64_t)w;
    }

    close(fd);
    shdw_diag_log("DMP %s tag=%d path=%s wrote=%llu/%llu", label, tag, path,
                  (unsigned long long)off, (unsigned long long)total);
}

static void* shdw_diag_wait_watchdog(void* arg) {
    (void)arg;

    for(int i = 0; i < 12000; i++) {
        struct timespec ts = {0, 5000000};
        nanosleep(&ts, NULL);

        uintptr_t ctx = shdw_wait_ctx;

        if(!ctx || shdw_wait_released) {
            continue;
        }

        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        uint64_t ns = (uint64_t)now.tv_sec * 1000000000ull + (uint64_t)now.tv_nsec;

        if(ns - shdw_wait_first_ns < 300000000ull) {
            continue;
        }

        uint64_t state = shdw_diag_peek(ctx + 0x1b0, 4);

        if(state != 1) {
            shdw_wait_released = 1;
            shdw_diag_log("WAITREL noop ctx=%p state=%#llx", (void *)ctx,
                          (unsigned long long)state);
            continue;
        }

        *(volatile uint32_t *)(ctx + 0x1b0) = 2;
        *(volatile uint8_t *)(ctx + 0x1b8) = 1;
        shdw_wait_released = 1;
        shdw_diag_log("WAITREL ctx=%p tid=%#x state=1->2 flag8=1 age=%.1fms",
                      (void *)ctx, shdw_wait_tid,
                      ((double)ns - (double)shdw_wait_first_ns) / 1e6);
    }

    return NULL;
}

static void shdw_diag_hex_at(const char *tag, uintptr_t addr, size_t len) {
    uint8_t buf[128];
    vm_size_t got = 0;
    char line[640];
    int pos = 0;

    if(len > sizeof buf) {
        len = sizeof buf;
    }
    if(vm_read_overwrite(mach_task_self(), (vm_address_t)addr, (vm_size_t)len,
                         (vm_address_t)buf, &got) != KERN_SUCCESS || !got) {
        shdw_diag_log("%s addr=%p unreadable", tag, (void *)addr);
        return;
    }
    pos += snprintf(line + pos, sizeof line - (size_t)pos, "%s addr=%p",
                    tag, (void *)addr);
    for(vm_size_t i = 0; i < got && pos < (int)sizeof line - 12; i++) {
        pos += snprintf(line + pos, sizeof line - (size_t)pos, " %02x", buf[i]);
    }
    shdw_diag_log("%s", line);
}

static void* shdw_diag_cell_watch(void* arg) {
    (void)arg;

    uintptr_t base = shdw_diag_image_base("Finanzstatusx");

    if(!base) {
        shdw_diag_log("CELLW no image");
        return NULL;
    }

    volatile uint64_t *cell = (volatile uint64_t *)(base + 0x9caab8);
    uint64_t gadget = (uint64_t)(base + 0x943108);

    if(shdw_cell_shim_on) {
        uint32_t w0 = 0;

        shdw_cell_real = (uint64_t)(uintptr_t)*cell;
        if(shdw_cell_real &&
           vm_read_overwrite(mach_task_self(), (vm_address_t)shdw_cell_real, 4,
                             (vm_address_t)&w0, &(vm_size_t){0}) ==
           KERN_SUCCESS) {
            // Only a bare `svc #0x80; ret` thunk can be executed by the shim
            // with identical semantics; anything else is forwarded as-is.
            shdw_cell_real_svc = (w0 == 0xd4001001u);
        }
        gadget = (uint64_t)(uintptr_t)shdw_cell_shim;
    }
    vm_address_t region = (vm_address_t)cell;
    vm_size_t size = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t obj = MACH_PORT_NULL;
    kern_return_t kr = vm_region_64(mach_task_self(), &region, &size,
                                    VM_REGION_BASIC_INFO_64,
                                    (vm_region_info_t)&info, &count, &obj);

    if(obj != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), obj);
    }

    shdw_diag_log("CELLW prot kr=%d max=%x cur=%x region=%p+%#lx",
                  kr, kr == KERN_SUCCESS ? info.protection : 0,
                  kr == KERN_SUCCESS ? info.protection : 0,
                  (void *)region, (unsigned long)size);

    if(kr == KERN_SUCCESS && !(info.protection & VM_PROT_WRITE)) {
        kr = vm_protect(mach_task_self(), region, size, FALSE,
                        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
        shdw_diag_log("CELLW mprotect kr=%d", kr);
    }

    uint64_t prev = *cell;
    char t0[128];
    shdw_diag_describe_short(t0, sizeof t0, (void *)(uintptr_t)prev);
    shdw_diag_log("CELLW start val=%#llx %s pin=%#llx",
                  (unsigned long long)prev, t0, (unsigned long long)gadget);

    for(int j = -16; j < 16; j += 2) {
        uint64_t a = *(volatile uint64_t *)((uintptr_t)cell + (uintptr_t)(j * 8));
        uint64_t b = *(volatile uint64_t *)((uintptr_t)cell + (uintptr_t)((j + 1) * 8));
        char ta[96], tb[96];
        shdw_diag_describe_short(ta, sizeof ta, (void *)(uintptr_t)a);
        shdw_diag_describe_short(tb, sizeof tb, (void *)(uintptr_t)b);
        shdw_diag_log("CELLN %+d=%#llx(%s) %+d=%#llx(%s)", j, (unsigned long long)a,
                      ta, j + 1, (unsigned long long)b, tb);
    }

    int foreign = 0;

    for(int i = 0; i < 50000; i++) {
        struct timespec ts = {0, 100000};
        nanosleep(&ts, NULL);

        uint64_t v = *cell;

        if(v == gadget) {
            continue;
        }

        if(shdw_cell_shim_on && v) {
            uint32_t w0 = 0;

            shdw_cell_real = v;
            if(vm_read_overwrite(mach_task_self(), (vm_address_t)v, 4,
                                 (vm_address_t)&w0, &(vm_size_t){0}) ==
               KERN_SUCCESS) {
                shdw_cell_real_svc = (w0 == 0xd4001001u);
                shdw_diag_log("CELLSVC val=%#llx w0=%#x emu=%d",
                              (unsigned long long)v, w0,
                              shdw_cell_real_svc);
            }
        }

        if(foreign < 3) {
            char t[128];
            shdw_diag_describe_short(t, sizeof t, (void *)(uintptr_t)v);
            shdw_diag_log("CELLPIN i=%d was=%#llx %s", i,
                          (unsigned long long)v, t);
            shdw_diag_hex_at("THUNKHEX", (uintptr_t)v, 64);
            foreign++;
        }

        *cell = gadget;
    }

    return NULL;
}

static void* shdw_diag_prm_thread(void* arg) {
    (void)arg;
    (void)shdw_diag_svc_gadget_addr;

    shdw_diag_svc_gadget("Finanzstatusx", 0x943108);
    {
        pthread_t cw;

        if(pthread_create(&cw, NULL, shdw_diag_cell_watch, NULL) == 0) {
            pthread_detach(cw);
        }
    }
    {
        uintptr_t wb = shdw_diag_image_base("Finanzstatusx");

        if(wb) {
            shdw_wait_pc = wb + 0x23f050;
            shdw_diag_log("WAITPC pc=%p", (void *)shdw_wait_pc);
        }
    }

    if(!shdw_diag_no_waitrel) {
        pthread_t ww;

        if(pthread_create(&ww, NULL, shdw_diag_wait_watchdog, NULL) == 0) {
            pthread_detach(ww);
        }
    }

    for(int pass = 0; pass < 40; pass++) {
        struct timespec ts = {0, (long)(pass == 0 ? 20 : 25) * 1000 * 1000};
        nanosleep(&ts, NULL);

        uintptr_t base = shdw_diag_image_base("Finanzstatusx");

        if(!base) {
            shdw_diag_log("PRM pass=%d no image", pass);
            continue;
        }

        if(pass == 2) {
            uintptr_t mb = shdw_diag_image_base("BankingWhiteLabel");

            if(mb) {
                shdw_diag_dump_span("jw", mb, 0x5c58000,
                                    0x5c58000 + 0x1c38000, pass);
            }
            shdw_diag_dump_span("fw", base, 0, 0x9c0000, pass);
        }

        shdw_diag_cell_dump(base, pass);

        if(pass == 4 || pass == 7 || pass == 9) {
            shdw_diag_anon_scan(pass);
        }

        if(pass < 0) {
            shdw_diag_svc_scan(pass);
        }

        volatile uint64_t *tab = (volatile uint64_t *)(base + 0x99c000);
        char line[1024];
        int pos = snprintf(line, sizeof line, "PRM pass=%d base=%p", pass,
                           (void *)base);

        for(int i = 0; i < 205; i++) {
            uint64_t v = tab[i];

            if(!v) {
                continue;
            }

            char s[96];
            shdw_diag_describe_short(s, sizeof s, (void *)(uintptr_t)v);
            pos += snprintf(line + pos, sizeof line - (size_t)pos,
                            " [%d]=%#llx(%s)", i, (unsigned long long)v, s);

            if(pos > (int)sizeof line - 150) {
                shdw_diag_log("%s", line);
                pos = snprintf(line, sizeof line, "PRM pass=%d cont", pass);
            }
        }
        shdw_diag_log("%s", line);
    }

    return NULL;
}

static void shdw_diag_install_cell_shim(void) {
    pthread_t th;
    pthread_attr_t attr;

    if(pthread_attr_init(&attr) != 0) {
        return;
    }
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&th, &attr, shdw_diag_cell_watch, NULL);
    pthread_attr_destroy(&attr);
}

static void shdw_diag_install_prm_dump(void) {
    pthread_t th;
    pthread_attr_t attr;

    if(pthread_attr_init(&attr) != 0) {
        return;
    }
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&th, &attr, shdw_diag_prm_thread, NULL);
    pthread_attr_destroy(&attr);
}

static void* shdw_diag_spkfix_thread(void* arg) {
    (void)arg;
    uintptr_t base = 0;

    for(int i = 0; i < 500 && !base; i++) {
        base = shdw_diag_image_base("Finanzstatusx");
        if(!base) {
            struct timespec ts = {0, 20 * 1000 * 1000};
            nanosleep(&ts, NULL);
        }
    }
    if(!base) {
        shdw_diag_log("SPKFIX no image");
        return NULL;
    }
    shdw_diag_log("SPKFIX start base=%p", (void *)base);

    uintptr_t g = base + 0x9b2200;
    uintptr_t last = 0;
    unsigned seen = 0;
    unsigned writes = 0;

    for(int i = 0; i < 200000; i++) {
        uintptr_t obj = (uintptr_t)shdw_diag_peek(g, 8);

        if(obj != last) {
            last = obj;
            if(seen < 40) {
                seen++;
                shdw_diag_log("SPKFIXP i=%d ptr=%p byte=%#llx", i, (void *)obj,
                              (unsigned long long)shdw_diag_peek(obj + 0x330,
                                                                 1));
            }
        }
        // The singleton lives in a 32K-aligned block; earlier values of the
        // global are other objects whose +0x330 must not be touched.
        if(obj >= 0x100000000ULL && (obj & 0x7fff) == 0) {
            uint64_t b = shdw_diag_peek(obj + 0x330, 1);

            if(b == 1) {
                *(volatile unsigned char *)(obj + 0x330) = 0;
                writes++;
                if(writes <= 20) {
                    shdw_diag_log("SPKFIX obj=%p i=%d w=%u after=%#llx",
                                  (void *)obj, i, writes,
                                  (unsigned long long)shdw_diag_peek(
                                      obj + 0x330, 1));
                }
            }
        }
        struct timespec ts = {0, 100 * 1000};
        nanosleep(&ts, NULL);
    }
    return NULL;
}

static void shdw_diag_install_spkfix(void) {
    pthread_t th;
    pthread_attr_t attr;

    if(pthread_attr_init(&attr) != 0) {
        return;
    }
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&th, &attr, shdw_diag_spkfix_thread, NULL);
    pthread_attr_destroy(&attr);
}

static void shdw_diag_install_spkskip(void) {
    arm_debug_state64_t d;
    mach_msg_type_number_t cnt = ARM_DEBUG_STATE64_COUNT;
    mach_port_t th = pthread_mach_thread_np(pthread_self());
    kern_return_t gk;
    kern_return_t sk;

    if (!shdw_dbg_base) {
        shdw_dbg_base = shdw_diag_find_oz();
    }
    if (!shdw_dbg_base) {
        shdw_diag_log("SPKSKIPBASE none");
        return;
    }
    memset(&d, 0, sizeof d);
    gk = thread_get_state(th, ARM_DEBUG_STATE64, (thread_state_t)&d, &cnt);
    d.__bvr[0] = shdw_dbg_base + SHDW_SPK_DECISION;
    d.__bcr[0] = SHDW_DBG_BCR;
    d.__bvr[1] = shdw_dbg_base + SHDW_SPK_CTORFIX;
    d.__bcr[1] = SHDW_DBG_BCR;
    sk = thread_set_state(th, ARM_DEBUG_STATE64, (thread_state_t)&d,
                          ARM_DEBUG_STATE64_COUNT);
    shdw_diag_log("SPKSKIPINSTALL base=%p th=%#x gk=%d sk=%d site=%p", 
                  (void *)shdw_dbg_base, (unsigned)th, (int)gk, (int)sk,
                  (void *)(shdw_dbg_base + SHDW_SPK_DECISION));
    shdw_diag_log("SPKSKIPINSTALL ctorfix=%p",
                  (void *)(shdw_dbg_base + SHDW_SPK_CTORFIX));
}

static void shdw_diag_install_spksvc(void) {
    arm_debug_state64_t d;
    mach_msg_type_number_t cnt = ARM_DEBUG_STATE64_COUNT;
    mach_port_t th = pthread_mach_thread_np(pthread_self());
    kern_return_t gk;
    kern_return_t sk;

    if (!shdw_dbg_base) {
        shdw_dbg_base = shdw_diag_find_oz();
    }
    if (!shdw_dbg_base) {
        shdw_diag_log("SPKSVCBASE none");
        return;
    }
    if (shdw_diag_spkforge) {
        shdw_dbg_svc = 0;
        shdw_diag_log("SPKFORGEARM base=%p site=%p mode=%d",
                      (void *)shdw_dbg_base,
                      (void *)(shdw_dbg_base + 0x5bf160),
                      shdw_diag_spkforge);
        goto spkforg_arm;
    }
    shdw_dbg_svc = shdw_diag_peek(shdw_dbg_base + 0x9caab8, 8);
    shdw_diag_log("SPKSVCINSTALL base=%p cell=%p target=%p",
                  (void *)shdw_dbg_base,
                  (void *)(shdw_dbg_base + 0x9caab8), (void *)shdw_dbg_svc);
    if (shdw_dbg_svc) {
        shdw_diag_peek_words("spcstub", shdw_dbg_svc, 0, 32);
    }
    if (!shdw_dbg_svc) {
        // The cell is written during the image's own init, after our ctor.
        // The stub table address was stable across processes in this boot,
        // and its first word is `svc #0x80`; verify before arming so a stale
        // address can never trap unrelated code.
        uintptr_t guess = (uintptr_t)0x1e2d25b3cULL;
        uint32_t first = (uint32_t)shdw_diag_peek(guess, 4);
        if (first == 0xd4001001u) {
            shdw_dbg_svc = guess;
            shdw_diag_log("SPKSVCARM_PRE target=%p first=%#x",
                          (void *)shdw_dbg_svc, first);
        } else {
            shdw_diag_log("SPKSVCARM_PRE skip guess=%p first=%#x",
                          (void *)guess, first);
            return;
        }
    }
spkforg_arm:
    memset(&d, 0, sizeof d);
    gk = thread_get_state(th, ARM_DEBUG_STATE64, (thread_state_t)&d, &cnt);
    d.__bvr[0] = shdw_dbg_site(0);
    d.__bcr[0] = SHDW_DBG_BCR;
    if (shdw_diag_spkevt && shdw_dbg_base) {
        d.__bvr[1] = shdw_dbg_base + 0x8096d0;
        d.__bcr[1] = SHDW_DBG_BCR;
    }
    if (shdw_diag_spkexit && shdw_dbg_base) {
        d.__bvr[2] = shdw_dbg_base + 0x430d9c;
        d.__bcr[2] = SHDW_DBG_BCR;
    }
    sk = thread_set_state(th, ARM_DEBUG_STATE64, (thread_state_t)&d,
                          ARM_DEBUG_STATE64_COUNT);
    shdw_diag_log("SPKSVCARM th=%#x gk=%d sk=%d site=%p evt=%p",
                  (unsigned)th, (int)gk, (int)sk, (void *)shdw_dbg_svc,
                  (void *)(shdw_diag_spkevt && shdw_dbg_base
                               ? shdw_dbg_base + 0x8096d0
                               : 0));
}

// The debug state is per thread: a framework thread created after install
// runs with no slots at all, so anything it does is invisible. Sweep the task
// and arm every thread that still has all slots empty.
static void shdw_diag_spk_arm_port(mach_port_t th) {
    arm_debug_state64_t d;
    arm_thread_state64_t ts;
    mach_msg_type_number_t cnt = ARM_DEBUG_STATE64_COUNT;
    mach_msg_type_number_t tcnt = ARM_THREAD_STATE64_COUNT;
    uintptr_t pc = 0;
    kern_return_t gk;
    kern_return_t sk;

    memset(&d, 0, sizeof d);
    gk = thread_get_state(th, ARM_DEBUG_STATE64, (thread_state_t)&d, &cnt);
    if (gk != KERN_SUCCESS) {
        if (shdw_diag_spkrearm > 1) {
            shdw_diag_log("SPKREARMSKIP th=%#x gk=%d", (unsigned)th, (int)gk);
        }
        return;
    }
    if (d.__bcr[0] || d.__bvr[0] || d.__bcr[1] || d.__bvr[1] ||
        d.__bcr[2] || d.__bvr[2]) {
        if (shdw_diag_spkrearm > 1) {
            shdw_diag_log("SPKREARMSKIP th=%#x busy bcr0=%#llx bvr0=%#llx "
                          "bcr1=%#llx bvr1=%#llx bcr2=%#llx bvr2=%#llx",
                          (unsigned)th, (unsigned long long)d.__bcr[0],
                          (unsigned long long)d.__bvr[0],
                          (unsigned long long)d.__bcr[1],
                          (unsigned long long)d.__bvr[1],
                          (unsigned long long)d.__bcr[2],
                          (unsigned long long)d.__bvr[2]);
        }
        return;
    }
    if (thread_get_state(th, ARM_THREAD_STATE64, (thread_state_t)&ts,
                         &tcnt) == KERN_SUCCESS) {
        pc = (uintptr_t)arm_thread_state64_get_pc(ts);
    }
    d.__bvr[0] = shdw_dbg_site(0);
    d.__bcr[0] = SHDW_DBG_BCR;
    if (shdw_diag_spkevt && shdw_dbg_base) {
        d.__bvr[1] = shdw_dbg_base + 0x8096d0;
        d.__bcr[1] = SHDW_DBG_BCR;
    }
    if (shdw_diag_spkexit && shdw_dbg_base) {
        d.__bvr[2] = shdw_dbg_base + 0x430d9c;
        d.__bcr[2] = SHDW_DBG_BCR;
    }
    sk = thread_set_state(th, ARM_DEBUG_STATE64, (thread_state_t)&d,
                          ARM_DEBUG_STATE64_COUNT);
    shdw_diag_log("SPKREARM th=%#x pc=%p sk=%d svc=%p", (unsigned)th,
                  (void *)pc, (int)sk, (void *)shdw_dbg_svc);
}


#define SHDW_SAMPLE_SLOTS 48

static void* shdw_diag_spksample_thread(void* arg) {
    (void)arg;

    unsigned char seen_th[SHDW_SAMPLE_SLOTS];
    uintptr_t seen_pc[SHDW_SAMPLE_SLOTS];
    unsigned seen_n = 0;
    unsigned logged = 0;
    unsigned heartbeat = 0;
    unsigned ozfail = 0;
    struct timespec tstart;

    clock_gettime(CLOCK_MONOTONIC, &tstart);
    shdw_diag_log("SAMPLTH start tid=%p", (void*)pthread_self());

    for (;;) {
        thread_act_array_t list = NULL;
        mach_msg_type_number_t n = 0;
        struct timespec iv = {0, 400 * 1000};

        nanosleep(&iv, NULL);

        if (!shdw_dbg_base) {
            shdw_dbg_base = shdw_diag_find_oz();
            if (!shdw_dbg_base) {
                if (ozfail < 3) {
                    shdw_diag_log("SAMPLOZ fail i=%u", ozfail);
                    ozfail++;
                }
                continue;
            }
            shdw_diag_log("SAMPLOZ base=%p", (void*)shdw_dbg_base);
        }
        if (task_threads(mach_task_self(), &list, &n) != KERN_SUCCESS) {
            continue;
        }
        for (mach_msg_type_number_t i = 0; i < n; i++) {
            arm_thread_state64_t ts;
            mach_msg_type_number_t cnt = ARM_THREAD_STATE64_COUNT;

            if (thread_get_state(list[i], ARM_THREAD_STATE64,
                                 (thread_state_t)&ts, &cnt) != KERN_SUCCESS) {
                continue;
            }
            uintptr_t pc = (uintptr_t)arm_thread_state64_get_pc(ts);
            uintptr_t lr = (uintptr_t)arm_thread_state64_get_lr(ts);
            uintptr_t sp = (uintptr_t)arm_thread_state64_get_sp(ts);

            {
                struct timespec tn;
                long ms;

                clock_gettime(CLOCK_MONOTONIC, &tn);
                ms = (tn.tv_sec - tstart.tv_sec) * 1000 +
                     (tn.tv_nsec - tstart.tv_nsec) / 1000000;
                if (ms >= 80 && logged < 8000) {
                    shdw_diag_log("SAMPLATE ms=%ld th=%#x pc=%p lr=%p sp=%p x0=%p x1=%p x2=%p x8=%p x19=%p x20=%p x21=%p fsx=%d",
                                  ms, (unsigned)(uintptr_t)list[i], (void*)pc,
                                  (void*)lr, (void*)sp,
                                  (void*)ts.__x[0], (void*)ts.__x[1],
                                  (void*)ts.__x[2], (void*)ts.__x[8],
                                  (void*)ts.__x[19], (void*)ts.__x[20],
                                  (void*)ts.__x[21],
                                  (pc >= shdw_dbg_base &&
                                   pc < shdw_dbg_base + 0x1100000ULL));
                    logged++;
                    continue;
                }
            }

            if (pc < shdw_dbg_base || pc >= shdw_dbg_base + 0x1100000ULL) {
                continue;
            }
            unsigned th = (unsigned)(uintptr_t)list[i];
            unsigned j, dup = 0;
            for (j = 0; j < seen_n; j++) {
                if (seen_th[j] == (th & 0xff) && seen_pc[j] == pc) {
                    dup = 1;
                    break;
                }
            }
            if (dup) {
                continue;
            }
            if (seen_n < SHDW_SAMPLE_SLOTS) {
                seen_th[seen_n] = (unsigned char)(th & 0xff);
                seen_pc[seen_n] = pc;
                seen_n++;
            }
            if (logged < 4000) {
                shdw_diag_log("SAMPL th=%#x pc=+%#lx lr=+%#lx sp=%p", th,
                              (unsigned long)(pc - shdw_dbg_base),
                              (unsigned long)(lr >= shdw_dbg_base
                                                  ? lr - shdw_dbg_base
                                                  : 0),
                              (void *)sp);
                logged++;
            }
        }
        if ((++heartbeat % 250) == 0 && logged < 4000) {
            shdw_diag_log("SAMPLHB threads=%u logged=%u", (unsigned)n, logged);
        }
        for (mach_msg_type_number_t i = 0; i < n; i++) {
            mach_port_deallocate(mach_task_self(), list[i]);
        }
        if (list) {
            vm_deallocate(mach_task_self(), (vm_address_t)list,
                          (vm_size_t)(n * sizeof(thread_t)));
        }
    }

    return NULL;
}

int shdw_diag_spkhash = 0;

static void shdw_diag_spkhash_run(void) {
    uintptr_t base = shdw_diag_find_oz();
    uintptr_t site;
    vm_address_t region;
    vm_size_t size = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t obj = MACH_PORT_NULL;
    kern_return_t kr;

    if (!base) {
        shdw_diag_log("SPKHASH no base");
        return;
    }
    site = base + 0x23cc3c;
    region = (vm_address_t)(site & ~(uintptr_t)0x3fff);
    kr = vm_region_64(mach_task_self(), &region, &size,
                      VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &count,
                      &obj);
    if (obj != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), obj);
    }
    shdw_diag_log("SPKHASH site=%#lx orig=%#x prot=%x kr=%d",
                  (unsigned long)site, (unsigned)*(volatile uint32_t *)site,
                  kr == KERN_SUCCESS ? info.protection : 0, kr);
    if (kr == KERN_SUCCESS && !(info.protection & VM_PROT_WRITE)) {
        kr = vm_protect(mach_task_self(), region, size, FALSE,
                        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
        shdw_diag_log("SPKHASH prot kr=%d", kr);
    }
    *(volatile uint32_t *)site = 0x52800008u;
    sys_icache_invalidate((void *)site, 4);
    shdw_diag_log("SPKHASH wrote now=%#x",
                  (unsigned)*(volatile uint32_t *)site);
}

static void shdw_diag_spkexitbt(void) {
    shdw_diag_log("EXITBT atexit fired pid=%d", (int)getpid());
    shdw_diag_backtrace("EXITBT");
}

static void shdw_diag_install_spksample(void) {
    pthread_t th;
    pthread_attr_t attr;

    if (shdw_diag_spksample_started) {
        return;
    }
    shdw_diag_spksample_started = 1;
    atexit(shdw_diag_spkexitbt);
    if (pthread_attr_init(&attr) != 0) {
        shdw_diag_log("SAMPLINST attr init failed");
        return;
    }
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    {
        int rv = pthread_create(&th, &attr, shdw_diag_spksample_thread, NULL);
        shdw_diag_log("SAMPLINST create rv=%d th=%p", rv, (void*)th);
    }
    pthread_attr_destroy(&attr);
}

// SHDW_SPKBT_UI: which window (if any) is attached to which scene. A live
// process idling in CFRunLoop with no window reads as a black screen. Every
// selector is guarded: a UIScene without -windows raises and aborts the app.
static id shdw_spkui_obj(id o, const char *name) {
    SEL sel = sel_registerName(name);

    if (!o || ![o respondsToSelector:sel]) {
        return (id)0;
    }
    return ((id (*)(id, SEL))objc_msgSend)(o, sel);
}

static long shdw_spkui_int(id o, const char *name) {
    SEL sel = sel_registerName(name);

    if (!o || ![o respondsToSelector:sel]) {
        return -1;
    }
    return (long)((NSInteger (*)(id, SEL))objc_msgSend)(o, sel);
}

static id shdw_spkui_idx(id o, const char *name, NSUInteger k) {
    SEL sel = sel_registerName(name);

    if (!o || ![o respondsToSelector:sel]) {
        return (id)0;
    }
    return ((id (*)(id, SEL, NSUInteger))objc_msgSend)(o, sel, k);
}


// SHDW_SPKBT_DEL: who is the app delegate and what does each scene delegate
// implement, plus which UISceneConfiguration the live session uses. A scene
// whose delegate lacks -scene:willConnectToSession:options: never builds a
// window, which presents as the black screen.
static void shdw_spkbt_methods(int i, const char *tag, Class c) {
    unsigned n = 0;
    Method *ms;
    char buf[512];
    size_t off = 0;

    if (!c) {
        shdw_diag_log("SPKMTH i=%d %s=-", i, tag);
        return;
    }
    ms = class_copyMethodList(c, &n);
    buf[0] = 0;
    for (unsigned k = 0; ms && k < n && k < 40; k++) {
        const char *nm = sel_getName(method_getName(ms[k]));
        int w = snprintf(buf + off, sizeof buf - off, "%s%s",
                         off ? "," : "", nm ? nm : "?");
        if (w <= 0 || (size_t)w >= sizeof buf - off) break;
        off += (size_t)w;
    }
    if (ms) free(ms);
    shdw_diag_log("SPKMTH i=%d %s n=%u %s", i, tag, n, buf);
}


static void shdw_spkbt_chain(int i, const char *tag, Class c) {
    for (int d = 0; c && d < 6; d++) {
        unsigned n = 0;
        Method *ms = class_copyMethodList(c, &n);
        int hasc = 0, hasw = 0;

        for (unsigned k = 0; ms && k < n; k++) {
            const char *nm = sel_getName(method_getName(ms[k]));

            if (!nm) continue;
            if (strcmp(nm, "scene:willConnectToSession:options:") == 0) hasc = 1;
            if (strcmp(nm, "application:didFinishLaunchingWithOptions:") == 0) hasw = 1;
        }
        if (ms) free(ms);
        shdw_diag_log("SPKCHN i=%d %s d=%d cls=%s n=%u willconnect=%d didfin=%d",
                      i, tag, d, class_getName(c), n, hasc, hasw);
        c = class_getSuperclass(c);
    }
}

static void shdw_spkbt_delegate(int i) {
    Class uia = objc_getClass("UIApplication");
    id app, del, scenes, arr, sc, sess, cfg, name;
    Class dcls = Nil;
    long nsc;

    if (!uia) return;
    app = shdw_spkui_obj((id)uia, "sharedApplication");
    if (!app) return;
    del = shdw_spkui_obj(app, "delegate");
    dcls = del ? object_getClass(del) : Nil;
    shdw_diag_log("SPKDEL i=%d delegate=%p cls=%s", i, (__bridge void *)del,
                  dcls ? class_getName(dcls) : "-");
    if (dcls) {
        shdw_spkbt_methods(i, "appdel", dcls);
        shdw_spkbt_chain(i, "appdel", dcls);
        shdw_diag_log("SPKDEL i=%d fin=%d cfg=%d",
                      i,
                      class_getInstanceMethod(dcls,
                          sel_registerName("application:didFinishLaunchingWithOptions:")) != NULL,
                      class_getInstanceMethod(dcls,
                          sel_registerName("application:configurationForConnectingSceneSession:options:")) != NULL);
    }
    scenes = shdw_spkui_obj(app, "connectedScenes");
    arr = shdw_spkui_obj(scenes, "allObjects");
    nsc = shdw_spkui_int(arr, "count");
    for (long k = 0; arr && k < nsc && k < 3; k++) {
        sc = shdw_spkui_idx(arr, "objectAtIndex:", (NSUInteger)k);
        del = shdw_spkui_obj(sc, "delegate");
        sess = shdw_spkui_obj(sc, "session");
        cfg = shdw_spkui_obj(sess, "configuration");
        name = shdw_spkui_obj(cfg, "name");
        {
            const char *cname = "-";
            if (name && [name respondsToSelector:@selector(UTF8String)]) {
                cname = [(NSString *)name UTF8String];
            }
            shdw_diag_log("SPKCFG i=%d k=%ld cfg=%s", i, k, cname ? cname : "-");
        }
        shdw_spkbt_methods(i, "scndel", del ? object_getClass(del) : Nil);
        shdw_spkbt_chain(i, "scndel", del ? object_getClass(del) : Nil);
        {
            id role = shdw_spkui_obj(sess, "role");
            const char *cr = "-";
            if (role && [role respondsToSelector:@selector(UTF8String)]) {
                cr = [(NSString *)role UTF8String];
            }
            shdw_diag_log("SPKROLE i=%d k=%ld role=%s", i, k, cr ? cr : "-");
        }
        {
            Class swift = objc_getClass("BankingWhiteLabel.SceneDelegate");
            shdw_diag_log("SPKSWIFT i=%d cls=%p", i, (__bridge void *)swift);
            if (swift) {
                unsigned mn = 0;
                Method *mm = class_copyMethodList(swift, &mn);
                char mb[400];
                size_t mo = 0;

                mb[0] = 0;
                for (unsigned mk = 0; mm && mk < mn && mk < 20; mk++) {
                    const char *nmv = sel_getName(method_getName(mm[mk]));
                    int mw = snprintf(mb + mo, sizeof mb - mo, "%s%s",
                                      mo ? "," : "", nmv ? nmv : "?");
                    if (mw <= 0 || (size_t)mw >= sizeof mb - mo) break;
                    mo += (size_t)mw;
                }
                if (mm) free(mm);
                shdw_diag_log("SPKSWIFIIMP i=%d will=%p n=%u [%s]", i,
                              (void *)class_getMethodImplementation(swift,
                                  sel_registerName("scene:willConnectToSession:options:")),
                              mn, mb);
                shdw_spkbt_chain(i, "swift", swift);
            }
        }
    }
}

static void shdw_spkbt_ui(int i) {
    Class cls = objc_getClass("UIApplication");
    id app;
    id win;
    id wins;
    id scenes;
    id arr;
    long nsc;
    long nwin;

    if (!cls) {
        shdw_diag_log("SPKUI i=%d no UIApplication", i);
        return;
    }
    app = shdw_spkui_obj((id)cls, "sharedApplication");
    if (!app) {
        shdw_diag_log("SPKUI i=%d no app", i);
        return;
    }
    win = shdw_spkui_obj(app, "keyWindow");
    wins = shdw_spkui_obj(app, "windows");
    nwin = shdw_spkui_int(wins, "count");
    shdw_diag_log("SPKUI i=%d app=%p win=%p wincls=%s hidden=%ld state=%ld "
                  "windows=%ld",
                  i, (__bridge void *)app, (__bridge void *)win,
                  win ? object_getClassName(win) : "-",
                  shdw_spkui_int(win, "isHidden"),
                  shdw_spkui_int(app, "applicationState"), nwin);

    scenes = shdw_spkui_obj(app, "connectedScenes");
    arr = shdw_spkui_obj(scenes, "allObjects");
    nsc = shdw_spkui_int(arr, "count");
    shdw_diag_log("SPKUI i=%d connectedScenes=%ld", i, nsc);
    for (long k = 0; arr && k < nsc && k < 4; k++) {
        id sc = shdw_spkui_idx(arr, "objectAtIndex:", (NSUInteger)k);
        id del = shdw_spkui_obj(sc, "delegate");
        id sw = shdw_spkui_obj(sc, "windows");
        long nsw = shdw_spkui_int(sw, "count");

        shdw_diag_log("SPKSCN i=%d k=%ld cls=%s act=%ld att=%ld wins=%ld "
                      "delcls=%s",
                      i, k, sc ? object_getClassName(sc) : "-",
                      shdw_spkui_int(sc, "activationState"),
                      shdw_spkui_int(sc, "attachmentState"), nsw,
                      del ? object_getClassName(del) : "-");
        for (long j = 0; sw && j < nsw && j < 2; j++) {
            id w = shdw_spkui_idx(sw, "objectAtIndex:", (NSUInteger)j);
            id rvc = shdw_spkui_obj(w, "rootViewController");

            shdw_diag_log("SPKWIN i=%d k=%ld j=%ld cls=%s hidden=%ld "
                          "level=%ld rootvc=%s",
                          i, k, j, w ? object_getClassName(w) : "-",
                          shdw_spkui_int(w, "isHidden"),
                          shdw_spkui_int(w, "windowLevel"),
                          rvc ? object_getClassName(rvc) : "-");
        }
    }
}

static void* shdw_diag_spkbt_thread(void* arg) {
    (void)arg;
    {
        struct timespec iv = {1, 0};
        nanosleep(&iv, NULL);
    }
    for (int i = 0; i < 150; i++) {
        arm_thread_state64_t ts;
        mach_msg_type_number_t cnt = ARM_THREAD_STATE64_COUNT;

        if (shdw_spkbt_main != MACH_PORT_NULL &&
            thread_get_state(shdw_spkbt_main, ARM_THREAD_STATE64,
                             (thread_state_t)&ts, &cnt) == KERN_SUCCESS) {
            uintptr_t pc = (uintptr_t)arm_thread_state64_get_pc(ts);
            uintptr_t lr = (uintptr_t)arm_thread_state64_get_lr(ts);
            uintptr_t sp = (uintptr_t)arm_thread_state64_get_sp(ts);
            uintptr_t fp = (uintptr_t)arm_thread_state64_get_fp(ts);

            char d0[192], d1[192];

            shdw_diag_describe_short(d0, sizeof d0, (void *)pc);
            shdw_diag_describe_short(d1, sizeof d1, (void *)lr);
            shdw_diag_log("SPKBT i=%d pc=%s lr=%s sp=%p fp=%p", i, d0, d1,
                          (void *)sp, (void *)fp);
            if (i < 3) {
                // SHDW_SPKBT_FRAMES: name the caller chain, not just offsets.
                uintptr_t cur = fp;

                for (int fi = 0; fi < 16 && cur >= sp && (cur & 7) == 0;
                     fi++) {
                    uint64_t w[2] = {0, 0};
                    vm_size_t out = 0;
                    char df[192];

                    if (vm_read_overwrite(mach_task_self(),
                                          (vm_address_t)cur, 16,
                                          (vm_address_t)w,
                                          &out) != KERN_SUCCESS || out != 16) {
                        break;
                    }
                    shdw_diag_describe_short(df, sizeof df, (void *)w[1]);
                    shdw_diag_log("SPKBTF i=%d f%p %s", fi, (void *)cur, df);
                    if (w[0] <= cur || (w[0] & 7)) {
                        break;
                    }
                    cur = (uintptr_t)w[0];
                }
            }
        } else {
            shdw_diag_log("SPKBT i=%d getstate fail", i);
        }
        if (shdw_diag_spkscene) shdw_diag_spkscene_try();
        shdw_spkbt_delegate(i);
        shdw_spkbt_ui(i);
        if (i == 0) {
            thread_act_array_t list = NULL;
            mach_msg_type_number_t tn = 0;

            if (task_threads(mach_task_self(), &list, &tn) == KERN_SUCCESS) {
                for (mach_msg_type_number_t ti = 0; ti < tn; ti++) {
                    arm_thread_state64_t t2;
                    mach_msg_type_number_t c2 = ARM_THREAD_STATE64_COUNT;
                    char dt[192];

                    if (thread_get_state(list[ti], ARM_THREAD_STATE64,
                                         (thread_state_t)&t2, &c2) !=
                        KERN_SUCCESS) {
                        continue;
                    }
                    shdw_diag_describe_short(
                        dt, sizeof dt,
                        (void *)(uintptr_t)arm_thread_state64_get_pc(t2));
                    shdw_diag_log("SPKBTTH th=%#x pc=%s",
                                  (unsigned)(uintptr_t)list[ti], dt);
                }
                for (mach_msg_type_number_t ti = 0; ti < tn; ti++) {
                    mach_port_deallocate(mach_task_self(), list[ti]);
                }
                vm_deallocate(mach_task_self(), (vm_address_t)list,
                              (vm_size_t)(tn * sizeof(thread_t)));
            }
        }
        {
            struct timespec iv = {2, 0};
            nanosleep(&iv, NULL);
        }
    }
    return NULL;
}


static IMP shdw_scene_imp_cfg = NULL;
static IMP shdw_scene_imp_dcls = NULL;
static IMP shdw_scene_imp_dname = NULL;
static int shdw_spkscene_state = 0;
static int shdw_scene_logs = 0;

static Class shdw_scene_swift(void) {
    return objc_getClass("BankingWhiteLabel.SceneDelegate");
}

static int shdw_scene_is_stub(Class c) {
    return c && strcmp(class_getName(c), "Chae2AiPSceneDelegate") == 0;
}

static id shdw_spkscene_msg0(id o, const char *name) {
    SEL sel = sel_registerName(name);

    if (!o || ![o respondsToSelector:sel]) return (id)0;
    return ((id (*)(id, SEL))objc_msgSend)(o, sel);
}

// UIKit asks the configuration object for the delegate class; SHIELD's
// configuration answers with its zero-method stub. Answer with the app's own
// Swift delegate instead, at the point UIKit reads it.
static Class shdw_scene_proxy_cls = Nil;
static id shdw_scene_swift_delegate = Nil;

// Proxy: SHIELD ships a zero-method scene-delegate class and populates it
// only on its own verdict path. Subclass it so UIKit still sees a class it
// owns, and forward every lifecycle callback to the app's real Swift
// delegate, which is what actually builds the window.
static id shdw_scene_forward(id self, SEL _cmd, SEL target) {
    if (shdw_scene_swift_delegate &&
        [shdw_scene_swift_delegate respondsToSelector:target]) {
        return shdw_scene_swift_delegate;
    }
    return (id)0;
}

static BOOL shdw_scene_responds(id self, SEL _cmd, SEL target) {
    Class sup = class_getSuperclass(object_getClass(self));
    IMP imp;

    // The delegate instance cannot be built before SHIELD finishes its own
    // launch wiring (constructing the Swift class earlier calls through a
    // null VM slot). Claim the callback anyway; willConnect builds it.
    if (target == sel_registerName("scene:willConnectToSession:options:")) {
        return YES;
    }
    if (shdw_scene_swift_delegate &&
        [shdw_scene_swift_delegate respondsToSelector:target]) {
        return YES;
    }
    imp = sup ? class_getMethodImplementation(sup, _cmd) : NULL;
    if (!imp) return NO;
    return ((BOOL (*)(id, SEL, SEL))imp)(self, _cmd, target);
}

__attribute__((unused)) static void shdw_scene_make_swift(void) {
    Class swift = shdw_scene_swift();

    if (shdw_scene_swift_delegate || !swift) return;
    shdw_scene_swift_delegate = ((id (*)(id, SEL))objc_msgSend)(
        (id)swift, sel_registerName("alloc"));
    shdw_scene_swift_delegate = ((id (*)(id, SEL))objc_msgSend)(
        shdw_scene_swift_delegate, sel_registerName("init"));
    shdw_diag_log("SPKSCNDEL inst=%p cls=%s", (__bridge void *)shdw_scene_swift_delegate,
                  shdw_scene_swift_delegate ? object_getClassName(shdw_scene_swift_delegate) : "-");
}

static id shdw_scene_testwin(id scene);
static void shdw_scene_direct(id scene, id session, id options);

// The munged-call dispatcher at +0x553b0 indexes a static table in __TEXT:
//   count = *(u64*)+0xa17c000; base = +0xa17c008; index = FNV1a(dist) % count
// Every entry is a trampoline (ldp x29,x30,[sp],#0x50; b real). Dump the live
// values so a file/memory difference points at whoever clobbers them.
void shdw_spk_munged_dump(const char *tag, uint64_t lr_off) {
    uintptr_t base = 0;
    uintptr_t slide = 0;
    uint32_t count = 0;
    uint64_t e0 = 0, e1 = 0, tramp = 0;
    const uint8_t *stub = 0;
    char nm[256] = "-";
    uint32_t n = _dyld_image_count();

    for (uint32_t i = 0; i < n && !base; i++) {
        const char *in = _dyld_get_image_name(i);
        size_t l;
        if (!in) continue;
        l = strlen(in);
        if (l < 16) continue;
        if (!strstr(in, "/BankingWhiteLabel.app/BankingWhiteLabel")) continue;
        base = (uintptr_t)_dyld_get_image_header(i);
        slide = (uintptr_t)_dyld_get_image_vmaddr_slide(i);
        snprintf(nm, sizeof nm, "%s[%u]", in, i);
        break;
    }
    if (!base) {
        shdw_diag_log("SPKMTAB %s no image (n=%u)", tag, n);
        return;
    }
    count = *(volatile uint32_t *)(base + 0xa17c000ULL);
    e0 = *(volatile uint64_t *)(base + 0xa17c008ULL);
    e1 = *(volatile uint64_t *)(base + 0xa17c010ULL);
    tramp = *(volatile uint64_t *)(base + 0x10f48ULL);
    stub = (const uint8_t *)(base + 0x553b0ULL);
    shdw_diag_log("SPKMTAB %s img=%s base=%p slide=%#lx magic=%08x count=%#x"
                  " e0=%#llx e1=%#llx tramp=%#llx stub=%02x%02x%02x%02x%02x%02x%02x%02x",
                  tag, nm, (void *)base, (unsigned long)slide,
                  *(volatile uint32_t *)base,
                  count, (unsigned long long)e0, (unsigned long long)e1,
                  (unsigned long long)tramp,
                  stub[0], stub[1], stub[2], stub[3],
                  stub[4], stub[5], stub[6], stub[7]);
    if (count && count < 0x1000000U) {
        uint64_t d = (uint64_t)0x553b0ULL - lr_off;
        uint64_t h = 0xcbf29ce484222325ULL;
        uint64_t idx, ent;
        int k;
        for (k = 0; k < 8; k++) {
            h ^= (d >> (k * 8)) & 0xffULL;
            h *= 0x100000001b3ULL;
        }
        idx = h % count;
        ent = *(volatile uint64_t *)(base + 0xa17c008ULL + idx * 8);
        shdw_diag_log("SPKMTAB %s d=%#llx h=%#llx idx=%#llx ent=%#llx",
                      tag, (unsigned long long)d, (unsigned long long)h,
                      (unsigned long long)idx, (unsigned long long)ent);
        if (idx > 2 && idx + 2 < count) {
            shdw_diag_log("SPKMTAB %s around=%#llx,%#llx,[%#llx],%#llx,%#llx",
                          tag,
                          (unsigned long long)*(volatile uint64_t *)(base + 0xa17c008ULL + (idx - 2) * 8),
                          (unsigned long long)*(volatile uint64_t *)(base + 0xa17c008ULL + (idx - 1) * 8),
                          (unsigned long long)ent,
                          (unsigned long long)*(volatile uint64_t *)(base + 0xa17c008ULL + (idx + 1) * 8),
                          (unsigned long long)*(volatile uint64_t *)(base + 0xa17c008ULL + (idx + 2) * 8));
        }
    } else {
        shdw_diag_log("SPKMTAB %s count unusable", tag);
    }
}

static void shdw_scene_willconnect(id self, SEL _cmd, id scene, id session,
                                   id options) {
    Class swift = shdw_scene_swift();

    shdw_diag_log("SPKSCNWILL scene=%p delcls=%s", (__bridge void *)scene,
                  swift ? class_getName(swift) : "-");
    shdw_spk_munged_dump("will", 0x822fecULL);
    shdw_scene_direct(scene, session, options);
    shdw_scene_testwin(scene);
}

// Construct the app's real Swift scene delegate without running its
// initializer (that path calls a null SHIELD dispatch slot) and let its own
// willConnect build the UI.
static void shdw_scene_direct(id scene, id session, id options) {
    Class swift = shdw_scene_swift();
    SEL sel = sel_registerName("scene:willConnectToSession:options:");
    id obj;
    IMP imp;

    if (!swift) {
        shdw_diag_log("SPKSCNDIRECT no class");
        return;
    }
    obj = ((id (*)(id, SEL))objc_msgSend)((id)swift, sel_registerName("alloc"));
    imp = class_getMethodImplementation(swift, sel);
    shdw_diag_log("SPKSCNDIRECT obj=%p imp=%p size=%zu", (__bridge void *)obj,
                  (void *)imp, class_getInstanceSize(swift));
    if (!obj || !imp) return;
    ((void (*)(id, SEL, id, id, id))imp)(obj, sel, scene, session, options);
    shdw_diag_log("SPKSCNDIRECT returned");
}

static id shdw_scene_testwin(id scene) {
    static id win = Nil;
    Class wc, vcc, colc;
    id vc, view, white;

    if (win) return win;
    wc = objc_getClass("UIWindow");
    vcc = objc_getClass("UIViewController");
    colc = objc_getClass("UIColor");
    if (!wc || !vcc || !colc) return (id)0;
    win = ((id (*)(id, SEL, id))objc_msgSend)(
        ((id (*)(id, SEL))objc_msgSend)((id)wc, sel_registerName("alloc")),
        sel_registerName("initWithWindowScene:"), scene);
    vc = ((id (*)(id, SEL))objc_msgSend)(
        ((id (*)(id, SEL))objc_msgSend)((id)vcc, sel_registerName("alloc")),
        sel_registerName("init"));
    view = ((id (*)(id, SEL))objc_msgSend)(vc, sel_registerName("view"));
    white = ((id (*)(id, SEL))objc_msgSend)((id)colc,
                                            sel_registerName("whiteColor"));
    if (view && white) {
        ((void (*)(id, SEL, id))objc_msgSend)(view,
            sel_registerName("setBackgroundColor:"), white);
    }
    ((void (*)(id, SEL, id))objc_msgSend)(win,
        sel_registerName("setRootViewController:"), vc);
    ((void (*)(id, SEL))objc_msgSend)(win, sel_registerName("makeKeyAndVisible"));
    shdw_diag_log("SPKSCNWIN win=%p vc=%s hidden=%ld", (__bridge void *)win,
                  vc ? object_getClassName(vc) : "-",
                  (long)((NSInteger (*)(id, SEL))objc_msgSend)(win,
                                                               sel_registerName("isHidden")));
    return win;
}

static Class shdw_scene_proxy_class(void) {
    Class base;
    Class p;

    if (shdw_scene_proxy_cls) return shdw_scene_proxy_cls;
    base = objc_getClass("Chae2AiPSceneDelegate");
    if (!base) return Nil;
    p = objc_allocateClassPair(base, "ShdwSparkasseSceneDelegate", 0);
    if (!p) {
        shdw_diag_log("SPKSCNPROXY alloc pair failed");
        return Nil;
    }
    class_addMethod(p, sel_registerName("scene:willConnectToSession:options:"),
                    (IMP)shdw_scene_willconnect, "v@:@@@");
    class_addMethod(p, sel_registerName("forwardingTargetForSelector:"),
                    (IMP)shdw_scene_forward, "@@::");
    class_addMethod(p, sel_registerName("respondsToSelector:"),
                    (IMP)shdw_scene_responds, "B@::");
    objc_registerClassPair(p);
    shdw_scene_proxy_cls = p;
    shdw_diag_log("SPKSCNPROXY cls=%s", class_getName(p));
    return p;
}

static Class shdw_spkscene_pick(void) {
    if (shdw_diag_spkscene >= 2) {
        Class p = shdw_scene_proxy_class();

        if (p) return p;
    }
    return shdw_scene_swift();
}

static Class shdw_spkscene_dcls(id self, SEL _cmd) {
    Class c = shdw_scene_imp_dcls
                  ? ((Class (*)(id, SEL))shdw_scene_imp_dcls)(self, _cmd)
                  : Nil;

    if (shdw_scene_is_stub(c)) {
        Class sw = shdw_spkscene_pick();

        if (sw) {
            if (shdw_scene_logs < 4) {
                shdw_scene_logs++;
                shdw_diag_log("SPKSCNCFG delegateClass %s -> %s",
                              class_getName(c), class_getName(sw));
            }
            return sw;
        }
    }
    return c;
}

static id shdw_spkscene_dname(id self, SEL _cmd) {
    id s = shdw_scene_imp_dname
                ? ((id (*)(id, SEL))shdw_scene_imp_dname)(self, _cmd)
                : (id)0;

    if (s && [s isKindOfClass:[NSString class]] &&
        [s isEqualToString:@"Chae2AiPSceneDelegate"]) {
        Class sw = shdw_scene_swift();

        if (sw) {
            if (shdw_scene_logs < 4) {
                shdw_scene_logs++;
                shdw_diag_log("SPKSCNCFG delegateClassName %s -> %s",
                              class_getName(sw), class_getName(sw));
            }
            return NSStringFromClass(sw);
        }
    }
    return s;
}

static id shdw_spkscene_cfg(id self, SEL _cmd, id session, id options) {
    id cfg = shdw_scene_imp_cfg
                  ? ((id (*)(id, SEL, id, id))shdw_scene_imp_cfg)(self, _cmd,
                                                                 session, options)
                  : (id)0;
    Class del = Nil;
    Class swift;
    id role, nc;

    if (cfg && [cfg respondsToSelector:@selector(delegateClass)]) {
        del = ((Class (*)(id, SEL))objc_msgSend)(cfg, sel_registerName("delegateClass"));
    }
    if (!shdw_scene_is_stub(del)) {
        return cfg;
    }
    swift = shdw_scene_swift();
    if (!swift) {
        shdw_diag_log("SPKSCNCFG no swift delegate class");
        return cfg;
    }
    role = shdw_spkscene_msg0(session, "role");
    nc = ((id (*)(id, SEL, id, id))objc_msgSend)(
             (id)objc_getClass("UISceneConfiguration"),
             sel_registerName("initWithName:sessionRole:"),
             (id)@"Default Configuration", role);
    if (!nc) {
        shdw_diag_log("SPKSCNCFG alloc failed");
        return cfg;
    }
    ((void (*)(id, SEL, Class))objc_msgSend)(
        nc, sel_registerName("setDelegateClass:"), swift);
    shdw_diag_log("SPKSCNCFG cfg stub=%s -> %s cfg=%p",
                  class_getName(del), class_getName(swift), (__bridge void *)nc);
    return nc;
}

static void shdw_diag_spkscene_try(void) {
    Class uisc;
    Class prom;
    Method m;

    if (!(shdw_spkscene_state & 3)) {
        uisc = objc_getClass("UISceneConfiguration");
        if (uisc && !shdw_scene_imp_dcls) {
            m = class_getInstanceMethod(uisc, sel_registerName("delegateClass"));
            if (m) {
                shdw_scene_imp_dcls = method_setImplementation(
                    m, (IMP)shdw_spkscene_dcls);
                shdw_spkscene_state |= 1;
                shdw_diag_log("SPKSCNCFG uikit delegateClass orig=%p",
                              (void *)shdw_scene_imp_dcls);
                {
                    Class sw = shdw_scene_swift();
                    if (sw) {
                        shdw_diag_log("SPKSCNIMP swift=%p init=%p alloc=%p new=%p",
                                      (__bridge void *)sw,
                                      (void *)class_getMethodImplementation(sw, sel_registerName("init")),
                                      (void *)class_getMethodImplementation(sw, sel_registerName("alloc")),
                                      (void *)class_getMethodImplementation(sw, sel_registerName("new")));
                    }
                }
            }
        }
        if (uisc && !shdw_scene_imp_dname) {
            m = class_getInstanceMethod(uisc, sel_registerName("delegateClassName"));
            if (m) {
                shdw_scene_imp_dname = method_setImplementation(
                    m, (IMP)shdw_spkscene_dname);
                shdw_spkscene_state |= 2;
                shdw_diag_log("SPKSCNCFG uikit delegateClassName orig=%p",
                              (void *)shdw_scene_imp_dname);
            }
        }
    }
    if (!(shdw_spkscene_state & 4)) {
        prom = objc_getClass("PromonApplicationDelegate");
        if (prom) {
            m = class_getInstanceMethod(
                prom,
                sel_registerName("application:configurationForConnectingSceneSession:options:"));
            if (m) {
                shdw_scene_imp_cfg = method_setImplementation(
                    m, (IMP)shdw_spkscene_cfg);
                shdw_spkscene_state |= 4;
                shdw_diag_log("SPKSCNCFG promon cfg orig=%p",
                              (void *)shdw_scene_imp_cfg);
            }
        }
    }
}

static void shdw_diag_install_spkbt(void) {
    pthread_t th;
    pthread_attr_t attr;
    static int started;

    if (started) {
        return;
    }
    started = 1;
    shdw_spkbt_main = pthread_mach_thread_np(pthread_self());
    if (pthread_attr_init(&attr) != 0) {
        shdw_diag_log("SPKBTINST attr init failed");
        return;
    }
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    {
        int rv = pthread_create(&th, &attr, shdw_diag_spkbt_thread, NULL);
        shdw_diag_log("SPKBTINST th=%#x rv=%d",
                      (unsigned)shdw_spkbt_main, rv);
    }
    pthread_attr_destroy(&attr);
}

static void* shdw_diag_spkrearm_thread(void* arg) {
    (void)arg;

    for (;;) {
        thread_act_array_t list = NULL;
        mach_msg_type_number_t n = 0;
        struct timespec iv = {0, 10 * 1000 * 1000};

        nanosleep(&iv, NULL);

        if (!shdw_dbg_base) {
            shdw_dbg_base = shdw_diag_find_oz();
        }
        if (!shdw_dbg_base) {
            continue;
        }
        if (!shdw_diag_spkforge && !shdw_dbg_svc) {
            shdw_dbg_svc = shdw_diag_peek(shdw_dbg_base + 0x9caab8, 8);
            if (!shdw_dbg_svc) {
                continue;
            }
            if ((uint32_t)shdw_diag_peek(shdw_dbg_svc, 4) != 0xd4001001u) {
                shdw_dbg_svc = 0;
                continue;
            }
            shdw_diag_log("SPKREARMSTUB target=%p", (void *)shdw_dbg_svc);
        }
        if (task_threads(mach_task_self(), &list, &n) != KERN_SUCCESS) {
            continue;
        }
        if (shdw_diag_spkrearm > 1) {
            static unsigned passes;
            if (passes < 40) {
                shdw_diag_log("SPKREARMPASS i=%u n=%u svc=%p",
                              passes, (unsigned)n, (void *)shdw_dbg_svc);
                passes++;
            }
        }
        for (mach_msg_type_number_t i = 0; i < n; i++) {
            shdw_diag_spk_arm_port(list[i]);
            mach_port_deallocate(mach_task_self(), list[i]);
        }
        if (list) {
            vm_deallocate(mach_task_self(), (vm_address_t)list,
                          (vm_size_t)(n * sizeof(thread_t)));
        }
    }

    return NULL;
}

static void shdw_diag_install_spkrearm(void) {
    pthread_t th;
    pthread_attr_t attr;

    if (shdw_diag_spkrearm_started) {
        return;
    }
    shdw_diag_spkrearm_started = 1;
    if (pthread_attr_init(&attr) != 0) {
        return;
    }
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&th, &attr, shdw_diag_spkrearm_thread, NULL);
    pthread_attr_destroy(&attr);
}

// SHIELD preads a SHA-256 CodeDirectory slot from
// .../dyld_shared_cache_arm64e.38 and compares it with the page it has
// mapped. Recompute the same page here, in this process, and report whether
// memory still matches what the file says it should be.
static void shdw_diag_spkcache_run(void) {
    static const char *kPath =
        "/System/Cryptexes/OS/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e.38";
    const long kPageOff = 0x1F00000L;
    const long kImgOff = 0x1E5D000L;
    uintptr_t hdr = 0;
    long slide = 0;
    uint32_t total = _dyld_image_count();
    for (uint32_t i = 0; i < total; i++) {
        const char *nm = _dyld_get_image_name(i);
        if (nm && strstr(nm, "libcorecrypto")) {
            hdr = (uintptr_t)_dyld_get_image_header(i);
            slide = (long)_dyld_get_image_vmaddr_slide(i);
            break;
        }
    }
    if (!hdr) {
        shdw_diag_log("SPKCACHE noimg images=%u", (unsigned)total);
        return;
    }
    uintptr_t va = hdr + (uintptr_t)(kPageOff - kImgOff);
    unsigned char *mem = (unsigned char *)malloc(0x4000);
    unsigned char *fm = (unsigned char *)malloc(0x4000);
    if (!mem || !fm) {
        shdw_diag_log("SPKCACHE nomem");
        free(mem);
        free(fm);
        return;
    }
    memcpy(mem, (const void *)va, 0x4000);
    int fd = open(kPath, O_RDONLY);
    if (fd < 0) {
        shdw_diag_log("SPKCACHE open errno=%d", errno);
        free(mem);
        free(fm);
        return;
    }
    ssize_t got = pread(fd, fm, 0x4000, kPageOff);
    close(fd);
    if (got != 0x4000) {
        shdw_diag_log("SPKCACHE pread r=%ld", (long)got);
        free(mem);
        free(fm);
        return;
    }
    size_t diff = 0;
    long first = -1;
    for (size_t i = 0; i < 0x4000; i++) {
        if (mem[i] != fm[i]) {
            if (first < 0) first = (long)i;
            diff++;
        }
    }
    shdw_diag_log("SPKCACHE hdr=%p slide=%#lx va=%p diff=%zu first=%ld mem0=%#x file0=%#x",
                  (void *)hdr, (unsigned long)slide, (void *)va, diff, first,
                  (unsigned)mem[0], (unsigned)fm[0]);
    free(mem);
    free(fm);
}

static void shdw_diag_install_spkmem(void) {
    arm_debug_state64_t d;
    mach_msg_type_number_t cnt = ARM_DEBUG_STATE64_COUNT;
    mach_port_t th = pthread_mach_thread_np(pthread_self());
    kern_return_t gk;
    kern_return_t sk;

    if (!shdw_dbg_base) {
        shdw_dbg_base = shdw_diag_find_oz();
    }
    if (!shdw_dbg_base) {
        shdw_diag_log("SPKMEMBASE none");
        return;
    }
    memset(&d, 0, sizeof d);
    gk = thread_get_state(th, ARM_DEBUG_STATE64, (thread_state_t)&d, &cnt);
    d.__bvr[0] = shdw_dbg_base + SHDW_SPKMEM_DEC;
    d.__bcr[0] = SHDW_DBG_BCR;
    sk = thread_set_state(th, ARM_DEBUG_STATE64, (thread_state_t)&d,
                          ARM_DEBUG_STATE64_COUNT);
    shdw_diag_log("SPKMEMINSTALL base=%p th=%#x gk=%d sk=%d", 
                  (void *)shdw_dbg_base, (unsigned)th, (int)gk, (int)sk);
}

static void shdw_diag_install_spkgate(void) {
    arm_debug_state64_t d;
    mach_msg_type_number_t cnt = ARM_DEBUG_STATE64_COUNT;
    mach_port_t th = pthread_mach_thread_np(pthread_self());
    kern_return_t gk;
    kern_return_t sk;

    if (!shdw_dbg_base) {
        shdw_dbg_base = shdw_diag_find_oz();
    }
    if (!shdw_dbg_base) {
        shdw_diag_log("SPKGATEBASE none");
        return;
    }
    memset(&d, 0, sizeof d);
    gk = thread_get_state(th, ARM_DEBUG_STATE64, (thread_state_t)&d, &cnt);
    d.__bvr[0] = shdw_dbg_base + SHDW_SPKGATE_PRED;
    d.__bcr[0] = SHDW_DBG_BCR;
    d.__bvr[1] = shdw_dbg_base + SHDW_SPKGATE_NZ;
    d.__bcr[1] = SHDW_DBG_BCR;
    d.__bvr[2] = shdw_dbg_base + SHDW_SPKGATE_COMMON;
    d.__bcr[2] = SHDW_DBG_BCR;
    d.__bvr[3] = shdw_dbg_base + SHDW_SPKGATE_DECISION;
    d.__bcr[3] = SHDW_DBG_BCR;
    sk = thread_set_state(th, ARM_DEBUG_STATE64, (thread_state_t)&d,
                          ARM_DEBUG_STATE64_COUNT);
    shdw_diag_log("SPKGATEINSTALL base=%p th=%#x gk=%d sk=%d", 
                  (void *)shdw_dbg_base, (unsigned)th, (int)gk, (int)sk);
}

static void shdw_diag_install_spkzero(void) {
    arm_debug_state64_t d;
    mach_msg_type_number_t cnt = ARM_DEBUG_STATE64_COUNT;
    mach_port_t th = pthread_mach_thread_np(pthread_self());
    kern_return_t gk;
    kern_return_t sk;

    if (!shdw_dbg_base) {
        shdw_dbg_base = shdw_diag_find_oz();
    }
    if (!shdw_dbg_base) {
        shdw_diag_log("SPKZEROBASE none");
        return;
    }
    memset(&d, 0, sizeof d);
    gk = thread_get_state(th, ARM_DEBUG_STATE64, (thread_state_t)&d, &cnt);
    d.__bvr[0] = shdw_dbg_base + SHDW_SPKZERO_CTOR;
    d.__bcr[0] = SHDW_DBG_BCR;
    d.__bvr[1] = shdw_dbg_base + SHDW_SPKZERO_PRED;
    d.__bcr[1] = SHDW_DBG_BCR;
    sk = thread_set_state(th, ARM_DEBUG_STATE64, (thread_state_t)&d,
                          ARM_DEBUG_STATE64_COUNT);
    shdw_diag_log("SPKZEROINSTALL base=%p th=%#x gk=%d sk=%d ctor=%p pred=%p",
                  (void *)shdw_dbg_base, (unsigned)th, (int)gk, (int)sk,
                  (void *)(shdw_dbg_base + SHDW_SPKZERO_CTOR),
                  (void *)(shdw_dbg_base + SHDW_SPKZERO_PRED));
}

static void shdw_diag_install_spkmsg(void) {
    arm_debug_state64_t d;
    mach_msg_type_number_t cnt = ARM_DEBUG_STATE64_COUNT;
    mach_port_t th = pthread_mach_thread_np(pthread_self());
    kern_return_t gk;
    kern_return_t sk;

    if (!shdw_dbg_base) {
        shdw_dbg_base = shdw_diag_find_oz();
    }
    if (!shdw_dbg_base) {
        shdw_diag_log("SPKMSGBASE none");
        return;
    }
    memset(&d, 0, sizeof d);
    gk = thread_get_state(th, ARM_DEBUG_STATE64, (thread_state_t)&d, &cnt);
    d.__bvr[0] = shdw_dbg_base + SHDW_SPKMSG_LOOP;
    d.__bcr[0] = SHDW_DBG_BCR;
    d.__bvr[1] = shdw_dbg_base + SHDW_SPKMSG_DEC;
    d.__bcr[1] = SHDW_DBG_BCR;
    sk = thread_set_state(th, ARM_DEBUG_STATE64, (thread_state_t)&d,
                          ARM_DEBUG_STATE64_COUNT);
    shdw_diag_log("SPKMSGINSTALL base=%p th=%#x gk=%d sk=%d loop=%p dec=%p",
                  (void *)shdw_dbg_base, (unsigned)th, (int)gk, (int)sk,
                  (void *)(shdw_dbg_base + SHDW_SPKMSG_LOOP),
                  (void *)(shdw_dbg_base + SHDW_SPKMSG_DEC));
}

static void shdw_diag_install_spkdec(void) {
    arm_debug_state64_t d;
    mach_msg_type_number_t cnt = ARM_DEBUG_STATE64_COUNT;
    mach_port_t th = pthread_mach_thread_np(pthread_self());
    kern_return_t gk;
    kern_return_t sk;

    if (!shdw_dbg_base) {
        shdw_dbg_base = shdw_diag_find_oz();
    }
    if (!shdw_dbg_base) {
        shdw_diag_log("SPKDECBASE none");
        return;
    }
    memset(&d, 0, sizeof d);
    gk = thread_get_state(th, ARM_DEBUG_STATE64, (thread_state_t)&d, &cnt);
    d.__bvr[0] = shdw_dbg_base + SHDW_SPKDEC_CALL;
    d.__bcr[0] = SHDW_DBG_BCR;
    d.__bvr[1] = shdw_dbg_base + SHDW_SPKDEC_ENTRY;
    d.__bcr[1] = SHDW_DBG_BCR;
    sk = thread_set_state(th, ARM_DEBUG_STATE64, (thread_state_t)&d,
                          ARM_DEBUG_STATE64_COUNT);
    shdw_diag_log("SPKDECINSTALL base=%p th=%#x gk=%d sk=%d call=%p entry=%p",
                  (void *)shdw_dbg_base, (unsigned)th, (int)gk, (int)sk,
                  (void *)(shdw_dbg_base + SHDW_SPKDEC_CALL),
                  (void *)(shdw_dbg_base + SHDW_SPKDEC_ENTRY));
}

static void shdw_diag_install_spkstub(void) {
    arm_debug_state64_t d;
    mach_msg_type_number_t cnt = ARM_DEBUG_STATE64_COUNT;
    mach_port_t th = pthread_mach_thread_np(pthread_self());
    kern_return_t gk;
    kern_return_t sk;

    if (!shdw_dbg_base) {
        shdw_dbg_base = shdw_diag_find_oz();
    }
    if (!shdw_dbg_base) {
        shdw_diag_log("SPKSTUBBASE none");
        return;
    }
    memset(&d, 0, sizeof d);
    gk = thread_get_state(th, ARM_DEBUG_STATE64, (thread_state_t)&d, &cnt);
    d.__bvr[0] = shdw_dbg_base + SHDW_SPK_CTOR;
    d.__bcr[0] = SHDW_DBG_BCR;
    sk = thread_set_state(th, ARM_DEBUG_STATE64, (thread_state_t)&d,
                          ARM_DEBUG_STATE64_COUNT);
    shdw_diag_log("SPKSTUBINSTALL base=%p th=%#x gk=%d sk=%d bvr0=%#llx "
                  "bcr0=%#llx", (void *)shdw_dbg_base, (unsigned)th, (int)gk,
                  (int)sk, (unsigned long long)d.__bvr[0],
                  (unsigned long long)d.__bcr[0]);
}

static void shdw_diag_install_pcsample(void) {
    pthread_t th;
    pthread_attr_t attr;

    if(!shdw_wait_pc) {
        uintptr_t wb = shdw_diag_image_base("Finanzstatusx");

        if(wb) {
            shdw_wait_pc = wb + 0x23f050;
            shdw_diag_log("WAITPC pc=%p (sampler)", (void *)shdw_wait_pc);
        }
    }

    if (pthread_attr_init(&attr) != 0) {
        return;
    }
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&th, &attr, shdw_diag_pc_thread, NULL);
    pthread_attr_destroy(&attr);
}

// Image table for offline symbolization of the raw fault stack. Only the
// non-system images: the dyld/system ones never appear in a detector frame of
// interest and would bury the map in noise.
static void shdw_diag_log_image_map(void) {
    uint32_t count = _dyld_image_count();

    for(uint32_t i = 0; i < count; i++) {
        const struct mach_header* header = _dyld_get_image_header(i);
        const char* name = _dyld_get_image_name(i);

        if(!header || !name) {
            continue;
        }
        if(!strncmp(name, "/usr/lib/", 9) || !strncmp(name, "/System/", 8)) {
            continue;
        }

        shdw_diag_log("diag: img[%u] base=0x%016llx %s", (unsigned)i,
                      (unsigned long long)(uintptr_t)header, name);
    }
}

static void shdw_diag_hook(SHDWHookSession *hooks, const char *name,
                           void *replacement, void **out_old) {
    void *target = dlsym(RTLD_DEFAULT, name);
    static void *seen[16];
    static int seen_count = 0;

    if (!target) {
        shdw_diag_log("diag: %s not found", name);
        return;
    }

    for (int i = 0; i < seen_count; i++) {
        if (seen[i] == target) {
            shdw_diag_log("diag: %s aliases an already-hooked target", name);
            return;
        }
    }

    if ([hooks hookFunction:target withReplacement:replacement
                 outOldPtr:out_old]) {
        shdw_diag_log("diag: inline %s @ %p", name, target);
        if (seen_count < 16) {
            seen[seen_count++] = target;
        }
        return;
    }

    NSString *symbol = [NSString stringWithUTF8String:name];

    if ([hooks hookRebindSymbol:symbol
                withReplacement:replacement
                       outOldPtr:out_old]) {
        shdw_diag_log("diag: rebind %s", name);
        if (seen_count < 16) {
            seen[seen_count++] = target;
        }
        return;
    }

    shdw_diag_log("diag: FAILED to hook %s", name);
}

// Heartbeat sampler: one line per tick with the PC and LR of every thread.
// Exists to catch the state right before an external kill (pref: Debug_Heartbeat).
int shdw_diag_heartbeat = 0;
static mach_port_t shdw_diag_main_port;

static void* shdw_diag_hb_thread(void* arg) {
    (void)arg;
    const struct timespec iv = {0, 5 * 1000 * 1000};
    unsigned tick = 0;

    for(;;) {
        thread_act_array_t list = NULL;
        mach_msg_type_number_t count = 0;

        kern_return_t kr = task_threads(mach_task_self(), &list, &count);
        shdw_diag_log("hb t=%u n=%u kr=%d", tick, (unsigned)count, (int)kr);
        tick++;

        if(kr == KERN_SUCCESS && list) {
            for(mach_msg_type_number_t i = 0; i < count; i++) {
                arm_thread_state64_t st;
                mach_msg_type_number_t sc = ARM_THREAD_STATE64_COUNT;

                if(thread_get_state(list[i], ARM_THREAD_STATE64,
                                    (thread_state_t)&st, &sc) == KERN_SUCCESS) {
                    char d[120];
                    char e[120];
                    shdw_diag_describe_short(d, sizeof d, (void*)arm_thread_state64_get_pc(st));
                    shdw_diag_describe_short(e, sizeof e, (void*)arm_thread_state64_get_lr(st));
                    shdw_diag_log("hb th=%u%s pc=%s lr=%s", (unsigned)i,
                                  (shdw_diag_main_port && list[i] == shdw_diag_main_port) ? "*" : "",
                                  d, e);
                }
                mach_port_deallocate(mach_task_self(), list[i]);
            }
            vm_deallocate(mach_task_self(), (vm_address_t)list,
                          count * sizeof(thread_t));
        }

        if (shdw_diag_main_port && tick % 40 == 1) {
            shdw_diag_walk_thread(shdw_diag_main_port, "main");
        }
        nanosleep(&iv, NULL);
    }

    return NULL;
}

static void shdw_diag_atexit_marker(void) {
    shdw_diag_log("atexit reached");
}

static void shdw_diag_install_heartbeat(void) {
    pthread_t th;
    pthread_attr_t attr;

    if(pthread_main_np() == 1) {
        shdw_diag_main_port = pthread_mach_thread_np(pthread_self());
    }

    if(pthread_attr_init(&attr) != 0) {
        return;
    }
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&th, &attr, shdw_diag_hb_thread, NULL);
    pthread_attr_destroy(&attr);
    atexit(shdw_diag_atexit_marker);
}

int shdw_diag_objc_dump = 0;

static void shdw_diag_objc_dump_run(void) {
    int count = objc_getClassList(NULL, 0);
    if (count <= 0) {
        return;
    }
    Class *all = (Class *)calloc((size_t)count, sizeof(Class));
    if (!all) {
        return;
    }
    count = objc_getClassList(all, count);
    shdw_diag_log("ODUMP classes=%d", count);
    for (int i = 0; i < count; i++) {
        const char *name = class_getName(all[i]);
        if (!name) {
            continue;
        }
        if (!strstr(name, "SecureDeviceKit") && !strstr(name, "Jailbreak") &&
            !strstr(name, "Rooted") && !strstr(name, "PureLiveSDK") &&
            !strstr(name, "Tamper") && !strstr(name, "Integrity") &&
            !strstr(name, "DeviceSupport") && !strstr(name, "Detect")) {
            continue;
        }
        Class super = class_getSuperclass(all[i]);
        shdw_diag_log("ODUMP cls %s super=%s", name,
                      super ? class_getName(super) : "-");
        unsigned mc = 0;
        Method *ml = class_copyMethodList(all[i], &mc);
        for (unsigned j = 0; j < mc; j++) {
            shdw_diag_log("ODUMP   m %s @ %p", sel_getName(method_getName(ml[j])),
                          (void *)method_getImplementation(ml[j]));
        }
        free(ml);
        unsigned ic = 0;
        Ivar *il = class_copyIvarList(all[i], &ic);
        for (unsigned j = 0; j < ic; j++) {
            shdw_diag_log("ODUMP   i %s %s", ivar_getName(il[j]),
                          ivar_getTypeEncoding(il[j]) ?: "?");
        }
        free(il);
    }
    free(all);
    shdw_diag_log("ODUMP done");
}

void shdw_diag_install(void) {
    if (!shdw_diag_enabled) {
        return;
    }

    shdw_diag_main_tid = (uint32_t)pthread_mach_thread_np(pthread_self());
    {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        shdw_diag_t0_ns = (uint64_t)now.tv_sec * 1000000000ull +
                          (uint64_t)now.tv_nsec;
    }
    if (shdw_diag_pc_dump) {
        atexit(shdw_diag_atexit_mark);
    }

    if (shdw_diag_trace_only && !shdw_diag_exit_trace) {
        shdw_diag_snapshot_images();
        shdw_diag_log("diag: trace-only install");
        return;
    }

    SHDWHookSession *hooks = [SHDWHookCoordinator shdw_sharedHookSession];

    if (!hooks) {
        shdw_diag_log("diag: no hook session");
        return;
    }

    shdw_diag_hook(hooks, "exit", (void *)replaced_diag_exit,
                   (void **)&shdw_diag_exit);
    shdw_diag_hook(hooks, "_exit", (void *)replaced_diag__exit,
                   (void **)&shdw_diag__exit);
    shdw_diag_hook(hooks, "_Exit", (void *)replaced_diag__exit,
                   (void **)&shdw_diag__exit);
    shdw_diag_hook(hooks, "abort", (void *)replaced_diag_abort,
                   (void **)&shdw_diag_abort);
    shdw_diag_hook(hooks, "raise", (void *)replaced_diag_raise,
                   (void **)&shdw_diag_raise);
    shdw_diag_hook(hooks, "pthread_kill", (void *)replaced_diag_pthread_kill,
                   (void **)&shdw_diag_pthread_kill);
    shdw_diag_hook(hooks, "__assert_rtn", (void *)replaced_diag_assert_rtn,
                   (void **)&shdw_diag_assert_rtn);
    shdw_diag_hook(hooks, "os_crash", (void *)replaced_diag_os_crash,
                   (void **)&shdw_diag_os_crash);
    shdw_diag_hook(hooks, "pthread_exit", (void *)replaced_diag_pthread_exit,
                   (void **)&shdw_diag_pthread_exit);
    shdw_diag_hook(hooks, "task_terminate", (void *)replaced_diag_task_terminate,
                   (void **)&shdw_diag_task_terminate);
    shdw_diag_hook(hooks, "thread_terminate",
                   (void *)replaced_diag_thread_terminate,
                   (void **)&shdw_diag_thread_terminate);
    shdw_diag_hook(hooks, "killpg", (void *)replaced_diag_killpg,
                   (void **)&shdw_diag_killpg);
    shdw_diag_hook(hooks, "kill", (void *)replaced_diag_kill,
                   (void **)&shdw_diag_kill);
    shdw_diag_hook(hooks, "proc_exit", (void *)replaced_diag_proc_exit,
                   (void **)&shdw_diag_proc_exit);
    shdw_diag_hook(hooks, "abort_with_payload",
                   (void *)replaced_diag_abort_with_payload,
                   (void **)&shdw_diag_abort_with_payload);

    shdw_diag_self_pid = getpid();
    shdw_diag_hook(hooks, "getpid", (void *)replaced_diag_getpid,
                   (void **)&shdw_diag_getpid_orig);
    shdw_diag_hook(hooks, "_NSGetExecutablePath", (void *)replaced_diag_nsgetpath,
                   (void **)&shdw_diag_nsgetpath);
    shdw_diag_hook(hooks, "unmount", (void *)replaced_diag_unmount,
                   (void **)&shdw_diag_unmount);
    shdw_diag_hook(hooks, "task_get_state", (void *)replaced_diag_task_get_state,
                   (void **)&shdw_diag_task_get_state);

    // Before arming: a stub patched while other threads run can trap
    // immediately, and with the default disposition that is a plain crash.
    if (!shdw_diag_no_signals && !shdw_diag_trace_only) {
        shdw_diag_install_signals();
    }

    if (shdw_diag_exit_probe) {
        shdw_diag_install_exit_probe();
    }

    if (shdw_diag_exit_brk) {
        shdw_diag_install_exit_brk();
    }

    if (shdw_diag_heartbeat) {
        shdw_diag_install_heartbeat();
    }

    if (shdw_diag_sigwatch) {
        shdw_diag_install_sigwatch();
    }

    if (shdw_diag_slotwatch) {
        shdw_diag_install_slotwatch();
    }

    if (shdw_diag_sigrearm) {
        shdw_diag_install_sigrearm();
    }

    if (shdw_diag_pcsample) {
        shdw_diag_install_pcsample();
    }

    if (shdw_diag_spkfix) {
        shdw_diag_install_spkfix();
    }

    if (shdw_diag_excports || shdw_diag_exccatch || shdw_diag_excwatch) {
        shdw_diag_install_excwatch();
    }

    if (shdw_diag_spkstub) {
        shdw_diag_install_spkstub();
    }

    if (shdw_diag_spkskip) {
        shdw_diag_install_spkskip();
    }

    if (shdw_diag_spkdec) {
        shdw_diag_install_spkdec();
    }

    if (shdw_diag_spkmsg) {
        shdw_diag_install_spkmsg();
    }

    if (shdw_diag_spkzero) {
        shdw_diag_install_spkzero();
    }

    if (shdw_diag_spkgate) {
        shdw_diag_install_spkgate();
    }

    if (shdw_diag_spkmem) {
        shdw_diag_install_spkmem();
    }

    if (shdw_diag_spkcache) {
        shdw_diag_spkcache_run();
    }

    if (shdw_diag_spksvc) {
        shdw_diag_install_spksvc();
    }

    if (shdw_diag_spkrearm) {
        shdw_diag_install_spkrearm();
    }

    if (shdw_diag_spksample) {
        shdw_diag_install_spksample();
    }

    if (shdw_diag_spkbt) {
        shdw_diag_install_spkbt();
    }

    if (shdw_diag_spkscene) {
        shdw_diag_spkscene_try();
    }

    if (shdw_diag_spkhash) {
        shdw_diag_spkhash_run();
    }

    if (!shdw_diag_trace_only) {
        shdw_diag_snapshot_images();
        shdw_diag_log_image_map();
    }
    if(shdw_cell_shim_on) {
        shdw_diag_install_cell_shim();
    }
    if(shdw_diag_prm_dump) {
        shdw_diag_install_prm_dump();
    }

    shdw_diag_log("diag: install done trace_only=%d exit_trace=%d",
                  shdw_diag_trace_only, shdw_diag_exit_trace);

    // Which loader-injected images actually ended up mapped: the injection
    // pass runs after install, so sample it once the loader has returned.
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)3 * NSEC_PER_SEC),
                   dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
        uint32_t total = _dyld_image_count();
        int hit = 0;
        for (uint32_t i = 0; i < total; i++) {
            const char *p = _dyld_get_image_name(i);
            if (p && strstr(p, "TweakInject")) {
                shdw_diag_log("LOADED img[%u] %s", i, p);
                hit++;
            }
        }
        shdw_diag_log("LOADED tweaks=%d total=%u", hit, total);
        if (shdw_diag_objc_dump) {
            shdw_diag_objc_dump_run();
        }
    });
}

int shdw_diag_syscall_lane = 0;
int shdw_diag_mem_trace = 0;
int shdw_diag_path_trace = 0;
int shdw_diag_fs_all = 0;

static int shdw_diag_marker_hit(const char *path) {
    static const char *const marks[] = {
        "addons", "binpack", "bootstrap", "cycript", "cydia", "dopamine",
        "ellekit", "frida", "hooker", "jbroot", "jail", "procursus",
        "sileo", "substrate", "substitute", "tweak", "shadow", "apt",
        "sshd", "bash", "/jb", "preboot", "roothide", "/root", "include",
        NULL
    };
    if (!path || !path[0]) {
        return 0;
    }
    for (int i = 0; marks[i]; i++) {
        if (strcasestr(path, marks[i])) {
            return 1;
        }
    }
    return 0;
}

// One line per distinct probe/image the app is allowed to observe, so a
// detector loop cannot flood the log.
#define SHDW_DIAG_SEEN_MAX 1024
static char shdw_diag_seen[SHDW_DIAG_SEEN_MAX][224];
static int shdw_diag_seen_count = 0;

static int shdw_diag_seen_before(const char *key) {
    if (!key) {
        return 1;
    }
    for (int i = 0; i < shdw_diag_seen_count; i++) {
        if (strcmp(shdw_diag_seen[i], key) == 0) {
            return 1;
        }
    }
    if (shdw_diag_seen_count < SHDW_DIAG_SEEN_MAX) {
        strlcpy(shdw_diag_seen[shdw_diag_seen_count++], key,
                sizeof(shdw_diag_seen[0]));
    }
    return 0;
}

#define SHDW_DIAG_FS_ALL_MAX 60000
static int shdw_diag_fs_all_count = 0;

void shdw_diag_fs_probe(const char *api, const char *path) {
    if (shdw_diag_fs_all) {
        if (__sync_fetch_and_add(&shdw_diag_fs_all_count, 1) >= SHDW_DIAG_FS_ALL_MAX) {
            return;
        }
        shdw_diag_log("FSALL %s %s", api ? api : "?", path ? path : "(null)");
        return;
    }
    if (!shdw_diag_path_trace || !shdw_diag_marker_hit(path)) {
        return;
    }
    char key[224];
    snprintf(key, sizeof(key), "F %s %s", api ? api : "?", path);
    if (shdw_diag_seen_before(key)) {
        return;
    }
    shdw_diag_log("FSPROBE %s %s", api, path);
}

void shdw_diag_dyld_image(const char *api, int idx, const char *path) {
    if (!shdw_diag_path_trace) {
        return;
    }
    char key[224];
    snprintf(key, sizeof(key), "D %s %d %s", api ? api : "?", idx,
             path ? path : "(null)");
    if (shdw_diag_seen_before(key)) {
        return;
    }
    shdw_diag_log("DYIMG %s %d %s", api, idx, path ? path : "(null)");
}

void shdw_diag_dyld_count(unsigned seen, unsigned truth) {
    if (!shdw_diag_path_trace) {
        return;
    }
    char key[96];
    snprintf(key, sizeof(key), "C %u %u", seen, truth);
    if (shdw_diag_seen_before(key)) {
        return;
    }
    shdw_diag_log("DYIMG count seen=%u true=%u", seen, truth);
}

// State trace: replace one branch inside a detector's dispatch loop with a
// jump to a stub that samples the interpreter context and then continues to
// the original branch target, so the detector's control flow is unchanged.
// 512 slots, no locks; the stub runs on the detector's own thread and only
// touches scratch registers plus its own stack slots.
__attribute__((visibility("hidden"))) uint32_t shdw_state_ring[8192 + 1];
__attribute__((visibility("hidden"))) void *shdw_state_probe_resume;
static int shdw_diag_probe_on = 0;

extern void sys_icache_invalidate(void *start, size_t len);

__attribute__((naked)) static void shdw_state_probe_entry(void) {
    __asm__ __volatile__(
        "stp x0, x1, [sp, #-32]!\n"
        "stp x16, x17, [sp, #16]\n"
        "adrp x16, _shdw_state_ring@PAGE\n"
        "add  x16, x16, _shdw_state_ring@PAGEOFF\n"
        "add  x16, x16, #8, lsl #12\n"
        "ldr  w17, [x16]\n"
        "add  w17, w17, #1\n"
        "and  w17, w17, #0x1ff\n"
        "str  w17, [x16]\n"
        "sub  x16, x16, #8, lsl #12\n"
        "lsl  x17, x17, #6\n"
        "add  x17, x17, x16\n"
        "str  x19, [x17]\n"
        "ldr  w0, [x19, #0x6c]\n"
        "str  w0, [x17, #8]\n"
        "ldr  w0, [x19, #0x304]\n"
        "str  w0, [x17, #12]\n"
        "ldr  x0, [x19, #0x2620]\n"
        "str  x0, [x17, #16]\n"
        "ldr  x0, [x19, #0x27a8]\n"
        "str  x0, [x17, #24]\n"
        "ldr  x0, [x19, #0x458]\n"
        "str  x0, [x17, #32]\n"
        "ldr  w0, [x19, #0x450]\n"
        "str  w0, [x17, #40]\n"
        "ldr  x0, [x19, #0x25c0]\n"
        "str  x0, [x17, #44]\n"
        "ldr  x0, [x19, #0x25f8]\n"
        "str  x0, [x17, #52]\n"
        "ldp  x16, x17, [sp, #16]\n"
        "ldp  x0, x1, [sp], #32\n"
        "adrp x16, _shdw_state_probe_resume@PAGE\n"
        "ldr  x16, [x16, _shdw_state_probe_resume@PAGEOFF]\n"
        "br   x16\n");
}

static uintptr_t shdw_diag_image_base(const char *suffix) {
    uint32_t count = _dyld_image_count();
    size_t slen = strlen(suffix);

    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        size_t nlen;

        if (!name) {
            continue;
        }
        nlen = strlen(name);
        if (nlen >= slen && strcmp(name + nlen - slen, suffix) == 0) {
            return (uintptr_t)_dyld_get_image_header(i);
        }
    }

    return 0;
}

// Funnel probe: retarget each branch that leads into a detector's verdict
// funnel at a stub that snapshots every general-purpose register plus the top
// of the stack, then jumps to the branch's original target. Control flow is
// unchanged; only the sample ring records what the check compared.
#define SHDW_FUNNEL_MAX 6
#define SHDW_FUNNEL_RING 32
#define SHDW_FUNNEL_STACK 20

typedef struct {
    uint64_t x[31];
    uint64_t sp;
    uint64_t lr;
    uint64_t id;
    uint64_t stack[SHDW_FUNNEL_STACK];
} shdw_funnel_sample;

__attribute__((visibility("hidden"))) void *shdw_funnel_resume[SHDW_FUNNEL_MAX];
static shdw_funnel_sample shdw_funnel_ring[SHDW_FUNNEL_RING];
static volatile uint32_t shdw_funnel_pos;
static volatile uint32_t shdw_funnel_hits;
static int shdw_funnel_on;

void shdw_funnel_capture(uint64_t *frame, uint64_t id) {
    if (!__atomic_load_n(&shdw_funnel_on, __ATOMIC_ACQUIRE)) {
        return;
    }
    uint32_t slot = __atomic_add_fetch(&shdw_funnel_pos, 1, __ATOMIC_RELAXED) % SHDW_FUNNEL_RING;
    shdw_funnel_sample *s = &shdw_funnel_ring[slot];
    for (unsigned i = 0; i < 31; i++) {
        s->x[i] = frame[i];
    }
    s->lr = frame[30];
    s->sp = (uint64_t)(uintptr_t)frame + 0x150;
    s->id = id;
    for (unsigned i = 0; i < SHDW_FUNNEL_STACK; i++) {
        s->stack[i] = ((const uint64_t *)(uintptr_t)s->sp)[i];
    }
    uint32_t n = __atomic_add_fetch(&shdw_funnel_hits, 1, __ATOMIC_RELAXED);
    if (id >= 100) {
        Dl_info callee = {0};
        Dl_info record = {0};
        const char *calleeName = "?";
        const char *recordName = "?";
        uintptr_t calleeOff = 0;
        uintptr_t recordOff = 0;
        if (dladdr((void *)(uintptr_t)frame[21], &callee) && callee.dli_fname) {
            calleeName = callee.dli_fname;
            calleeOff = (uintptr_t)frame[21] - (uintptr_t)callee.dli_fbase;
        }
        if (dladdr((void *)(uintptr_t)frame[0], &record) && record.dli_fname) {
            recordName = record.dli_fname;
            recordOff = (uintptr_t)frame[0] - (uintptr_t)record.dli_fbase;
        }
        shdw_diag_log("OZCALL id=%llu callee=%s+0x%lx x0=%s+0x%lx x1=%p x19=%p"
                      " x22=%p x23=%p lr=%p",
                      (unsigned long long)id, calleeName, (unsigned long)calleeOff,
                      recordName, (unsigned long)recordOff, (void *)(uintptr_t)frame[1],
                      (void *)(uintptr_t)frame[19], (void *)(uintptr_t)frame[22],
                      (void *)(uintptr_t)frame[23], (void *)(uintptr_t)frame[30]);
    }
    if (n <= 8) {
        shdw_diag_log("FUNNEL hit=%u id=%llu x0=%p x1=%p x8=%#llx x19=%p x21=%p"
                      " x22=%p x23=%p x24=%p x27=%p sp=%p lr=%p",
                      n, (unsigned long long)id, (void *)(uintptr_t)frame[0],
                      (void *)(uintptr_t)frame[1], (unsigned long long)frame[8],
                      (void *)(uintptr_t)frame[19], (void *)(uintptr_t)frame[21],
                      (void *)(uintptr_t)frame[22], (void *)(uintptr_t)frame[23],
                      (void *)(uintptr_t)frame[24], (void *)(uintptr_t)frame[27],
                      (void *)(uintptr_t)s->sp, (void *)(uintptr_t)s->lr);
    }
}

void shdw_funnel_dump(const char *tag) {
    uint32_t hits = __atomic_load_n(&shdw_funnel_hits, __ATOMIC_RELAXED);
    if (!hits) {
        return;
    }
    uint32_t pos = __atomic_load_n(&shdw_funnel_pos, __ATOMIC_RELAXED);
    shdw_diag_log("FUNNEL %s hits=%u", tag, hits);
    for (unsigned k = 0; k < 6 && k < hits; k++) {
        shdw_funnel_sample *s = &shdw_funnel_ring[(pos - 1 - k) % SHDW_FUNNEL_RING];
        char lrs[128];
        shdw_diag_describe_short(lrs, sizeof lrs, (void *)(uintptr_t)s->lr);
        shdw_diag_log("FUNNEL -%u id=%llu x0=%p x1=%p x8=%#llx x9=%#llx x19=%p"
                      " x20=%p x21=%p x22=%p x23=%p x24=%p x25=%p x26=%p"
                      " x27=%p x28=%p sp=%p lr=%s",
                      k + 1, (unsigned long long)s->id, (void *)(uintptr_t)s->x[0],
                      (void *)(uintptr_t)s->x[1], (unsigned long long)s->x[8],
                      (unsigned long long)s->x[9], (void *)(uintptr_t)s->x[19],
                      (void *)(uintptr_t)s->x[20], (void *)(uintptr_t)s->x[21],
                      (void *)(uintptr_t)s->x[22], (void *)(uintptr_t)s->x[23],
                      (void *)(uintptr_t)s->x[24], (void *)(uintptr_t)s->x[25],
                      (void *)(uintptr_t)s->x[26], (void *)(uintptr_t)s->x[27],
                      (void *)(uintptr_t)s->x[28], (void *)(uintptr_t)s->sp, lrs);
        char words[320];
        int used = 0;
        for (unsigned i = 0; i < SHDW_FUNNEL_STACK && used < (int)sizeof words; i++) {
            used += snprintf(words + used, sizeof words - (size_t)used, " %#llx",
                             (unsigned long long)s->stack[i]);
        }
        shdw_diag_log("FUNNEL -%u stk%s", k, words);
    }
}

#define SHDW_FUNNEL_SAVE                                                       \
    "stp  x0, x1, [sp, #0x00]\n"                                               \
    "stp  x2, x3, [sp, #0x10]\n"                                               \
    "stp  x4, x5, [sp, #0x20]\n"                                               \
    "stp  x6, x7, [sp, #0x30]\n"                                               \
    "stp  x8, x9, [sp, #0x40]\n"                                               \
    "stp  x10, x11, [sp, #0x50]\n"                                             \
    "stp  x12, x13, [sp, #0x60]\n"                                             \
    "stp  x14, x15, [sp, #0x70]\n"                                             \
    "stp  x16, x17, [sp, #0x80]\n"                                             \
    "stp  x18, x19, [sp, #0x90]\n"                                             \
    "stp  x20, x21, [sp, #0xa0]\n"                                             \
    "stp  x22, x23, [sp, #0xb0]\n"                                             \
    "stp  x24, x25, [sp, #0xc0]\n"                                             \
    "stp  x26, x27, [sp, #0xd0]\n"                                             \
    "stp  x28, x29, [sp, #0xe0]\n"                                             \
    "str  x30, [sp, #0xf0]\n"

#define SHDW_FUNNEL_LOAD                                                       \
    "ldp  x0, x1, [sp, #0x00]\n"                                               \
    "ldp  x2, x3, [sp, #0x10]\n"                                               \
    "ldp  x4, x5, [sp, #0x20]\n"                                               \
    "ldp  x6, x7, [sp, #0x30]\n"                                               \
    "ldp  x8, x9, [sp, #0x40]\n"                                               \
    "ldp  x10, x11, [sp, #0x50]\n"                                             \
    "ldp  x12, x13, [sp, #0x60]\n"                                             \
    "ldp  x14, x15, [sp, #0x70]\n"                                             \
    "ldp  x16, x17, [sp, #0x80]\n"                                             \
    "ldp  x18, x19, [sp, #0x90]\n"                                             \
    "ldp  x20, x21, [sp, #0xa0]\n"                                             \
    "ldp  x22, x23, [sp, #0xb0]\n"                                             \
    "ldp  x24, x25, [sp, #0xc0]\n"                                             \
    "ldp  x26, x27, [sp, #0xd0]\n"                                             \
    "ldp  x28, x29, [sp, #0xe0]\n"                                             \
    "ldr  x30, [sp, #0xf0]\n"

#define SHDW_FUNNEL_STUB(n, off)                                               \
    __attribute__((naked, noinline, used, visibility("hidden")))               \
    static void shdw_funnel_stub##n(void) {                                    \
        __asm__ __volatile__("sub  sp, sp, #0x150\n" SHDW_FUNNEL_SAVE          \
                             "mov  x0, sp\n"                                   \
                             "mov  w1, #" #n "\n"                              \
                             "bl   _shdw_funnel_capture\n"                     \
                             SHDW_FUNNEL_LOAD                                  \
                             "add  sp, sp, #0x150\n"                           \
                             "adrp x16, _shdw_funnel_resume@PAGE\n"            \
                             "add  x16, x16, _shdw_funnel_resume@PAGEOFF\n"    \
                             "ldr  x16, [x16, #" #off "]\n"                    \
                             "br   x16\n");                                    \
    }

SHDW_FUNNEL_STUB(0, 0)
SHDW_FUNNEL_STUB(1, 8)
SHDW_FUNNEL_STUB(2, 16)
SHDW_FUNNEL_STUB(3, 24)
SHDW_FUNNEL_STUB(4, 32)
SHDW_FUNNEL_STUB(5, 40)

static void (*const shdw_funnel_stubs[SHDW_FUNNEL_MAX])(void) = {
    shdw_funnel_stub0, shdw_funnel_stub1, shdw_funnel_stub2,
    shdw_funnel_stub3, shdw_funnel_stub4, shdw_funnel_stub5,
};

// Record-processor call probe. The dispatcher around OZ+0x36018 loads the
// per-record check function into x21, calls it, and reads the verdict from x0
// at the continuation. Snapshotting both sides names the failing record's
// processor and its answer; both stubs replay the instruction they replace so
// control flow and the return address the callee sees are unchanged.
__attribute__((visibility("hidden"))) void *shdw_oz_call_resume_pre;
__attribute__((visibility("hidden"))) void *shdw_oz_call_resume_post;

__attribute__((naked, noinline, used, visibility("hidden")))
static void shdw_oz_call_pre(void) {
    __asm__ __volatile__("sub  sp, sp, #0x150\n" SHDW_FUNNEL_SAVE
                         "mov  x0, sp\n"
                         "mov  w1, #100\n"
                         "bl   _shdw_funnel_capture\n"
                         SHDW_FUNNEL_LOAD
                         "add  sp, sp, #0x150\n"
                         "mov  x1, x20\n"
                         "adrp x16, _shdw_oz_call_resume_pre@PAGE\n"
                         "add  x16, x16, _shdw_oz_call_resume_pre@PAGEOFF\n"
                         "ldr  x16, [x16]\n"
                         "br   x16\n");
}

__attribute__((naked, noinline, used, visibility("hidden")))
static void shdw_oz_call_post(void) {
    __asm__ __volatile__("sub  sp, sp, #0x150\n" SHDW_FUNNEL_SAVE
                         "mov  x0, sp\n"
                         "mov  w1, #101\n"
                         "bl   _shdw_funnel_capture\n"
                         SHDW_FUNNEL_LOAD
                         "add  sp, sp, #0x150\n"
                         "mov  x8, #-1\n"
                         "adrp x16, _shdw_oz_call_resume_post@PAGE\n"
                         "add  x16, x16, _shdw_oz_call_resume_post@PAGEOFF\n"
                         "ldr  x16, [x16]\n"
                         "br   x16\n");
}

static int shdw_funnel_segment(const struct mach_header_64 *header,
                               uintptr_t offset, uint64_t *vmaddr,
                               uint64_t *vmsize) {
    if (!header || header->magic != MH_MAGIC_64) {
        return 0;
    }
    const struct load_command *command = (const struct load_command *)(header + 1);
    const uint8_t *end = (const uint8_t *)command + header->sizeofcmds;
    for (uint32_t i = 0; i < header->ncmds; i++) {
        if ((const uint8_t *)command + sizeof(*command) > end ||
            command->cmdsize < sizeof(*command) ||
            (const uint8_t *)command + command->cmdsize > end) {
            return 0;
        }
        if (command->cmd == LC_SEGMENT_64 &&
            command->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *segment = (const void *)command;
            if (offset >= segment->vmaddr && offset < segment->vmaddr + segment->vmsize) {
                *vmaddr = segment->vmaddr;
                *vmsize = segment->vmsize;
                return 1;
            }
        }
        command = (const struct load_command *)((const uint8_t *)command + command->cmdsize);
    }
    return 0;
}

static uint64_t shdw_funnel_region(const void *address) {
    vm_address_t addr = (vm_address_t)address;
    vm_size_t size = 0;
    natural_t depth = 0;
    vm_region_submap_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
    if (vm_region_recurse_64(mach_task_self(), &addr, &size, &depth,
                             (vm_region_recurse_info_t)&info, &count) != KERN_SUCCESS) {
        return 0;
    }
    return (uint64_t)size;
}

void shdw_diag_funnel_probe(const char *spec) {
    if (!shdw_diag_enabled || !spec || !spec[0]) {
        return;
    }
    char work[512];
    strlcpy(work, spec, sizeof work);
    char *save = NULL;
    char *image = strtok_r(work, ";", &save);
    if (!image) {
        shdw_diag_log("FUNNEL bad spec %s", spec);
        return;
    }
    uintptr_t base = shdw_diag_image_base(image);
    if (!base) {
        shdw_diag_log("FUNNEL no image %s", image);
        return;
    }
    int armed = 0;
    for (int id = 0; id < SHDW_FUNNEL_MAX; id++) {
        char *tok = strtok_r(NULL, ";", &save);
        if (!tok) {
            break;
        }
        char *colon = strchr(tok, ':');
        if (!colon) {
            shdw_diag_log("FUNNEL bad pair %s", tok);
            continue;
        }
        *colon = '\0';
        uintptr_t siteRVA = (uintptr_t)strtoul(tok, NULL, 16);
        uintptr_t resumeRVA = (uintptr_t)strtoul(colon + 1, NULL, 16);
        if (!siteRVA || !resumeRVA) {
            shdw_diag_log("FUNNEL bad pair %s:%s", tok, colon + 1);
            continue;
        }
        uintptr_t site = base + siteRVA;
        uintptr_t resume = base + resumeRVA;
        uint32_t orig = *(const uint32_t *)site;
        if ((orig & 0xfc000000u) != 0x14000000u) {
            shdw_diag_log("FUNNEL site %p not b: %#x", (void *)site, orig);
            continue;
        }
        uintptr_t stub = (uintptr_t)shdw_funnel_stubs[id];
        intptr_t delta = (intptr_t)(stub - site);
        if ((delta & 3) || delta < -0x8000000LL || delta > 0x7FFFFFCLL) {
            shdw_diag_log("FUNNEL out of range id=%d site=%p stub=%p", id,
                          (void *)site, (void *)stub);
            continue;
        }
        uint64_t vmaddr = 0, vmsize = 0;
        if (!shdw_funnel_segment((const struct mach_header_64 *)base, siteRVA,
                                 &vmaddr, &vmsize) || !vmsize) {
            shdw_diag_log("FUNNEL seg lookup fail off=%#lx", (unsigned long)siteRVA);
            continue;
        }
        uint8_t *segment = (uint8_t *)base + vmaddr;
        uint64_t before = shdw_funnel_region((const void *)base);
        if (vm_protect(mach_task_self(), (vm_address_t)segment, (vm_size_t)vmsize,
                       FALSE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY) != KERN_SUCCESS) {
            shdw_diag_log("FUNNEL seg prot fail site=%p len=0x%llx", (void *)site,
                          (unsigned long long)vmsize);
            continue;
        }
        shdw_funnel_resume[id] = (void *)resume;
        *(volatile uint32_t *)site = 0x14000000u | ((uint32_t)(delta >> 2) & 0x03ffffffu);
        sys_icache_invalidate((void *)site, sizeof(uint32_t));
        vm_protect(mach_task_self(), (vm_address_t)segment, (vm_size_t)vmsize, FALSE,
                   VM_PROT_READ | VM_PROT_EXECUTE);
        uint64_t after = shdw_funnel_region((const void *)base);
        shdw_diag_log("FUNNEL armed id=%d site=%p -> %p resume=%p seg=0x%llx+0x%llx"
                      " region=0x%llx->0x%llx",
                      id, (void *)site, (void *)stub, (void *)resume,
                      (unsigned long long)vmaddr, (unsigned long long)vmsize,
                      (unsigned long long)before, (unsigned long long)after);
        armed++;
    }
    if (armed) {
        __atomic_store_n(&shdw_funnel_on, 1, __ATOMIC_RELEASE);
    }
    shdw_diag_log("FUNNEL done armed=%d base=%p", armed, (void *)base);
}

// Arm the record-processor call probe on one detector image. Both sites are
// patched inside a single COW window over the containing segment, then the
// segment is restored to R-X, so the Mach region layout the detector's own
// vm_region query observes stays intact (see the segment-COW note above).
void shdw_diag_oz_call_probe(const char *imageSuffix) {
    if (!shdw_diag_enabled || !imageSuffix || !imageSuffix[0]) {
        return;
    }
    uintptr_t base = shdw_diag_image_base(imageSuffix);
    if (!base) {
        shdw_diag_log("OZCALL no image %s", imageSuffix);
        return;
    }
    static const struct {
        const char *name;
        uintptr_t rva;
        uintptr_t resumeRVA;
        uint32_t expect;
        void *stub;
        void **resume;
    } sites[2] = {
        { "pre", 0x36024, 0x36028, 0xaa1403e1u, (void *)shdw_oz_call_pre,
          &shdw_oz_call_resume_pre },
        { "post", 0x3602c, 0x36030, 0x92800008u, (void *)shdw_oz_call_post,
          &shdw_oz_call_resume_post },
    };
    uintptr_t site0 = base + sites[0].rva;
    for (unsigned i = 0; i < 2; i++) {
        uint32_t orig = *(const uint32_t *)(base + sites[i].rva);
        if (orig != sites[i].expect) {
            shdw_diag_log("OZCALL site %s mismatch %#x", sites[i].name, orig);
            return;
        }
    }
    uint64_t vmaddr = 0, vmsize = 0;
    if (!shdw_funnel_segment((const struct mach_header_64 *)base, sites[0].rva,
                             &vmaddr, &vmsize) || !vmsize) {
        shdw_diag_log("OZCALL seg lookup fail");
        return;
    }
    uint8_t *segment = (uint8_t *)base + vmaddr;
    uint64_t before = shdw_funnel_region((const void *)base);
    if (vm_protect(mach_task_self(), (vm_address_t)segment, (vm_size_t)vmsize,
                   FALSE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY) != KERN_SUCCESS) {
        shdw_diag_log("OZCALL seg prot fail len=0x%llx", (unsigned long long)vmsize);
        return;
    }
    for (unsigned i = 0; i < 2; i++) {
        uintptr_t site = base + sites[i].rva;
        uintptr_t stub = (uintptr_t)sites[i].stub;
        intptr_t delta = (intptr_t)(stub - site);
        if ((delta & 3) || delta < -0x8000000LL || delta > 0x7FFFFFCLL) {
            shdw_diag_log("OZCALL out of range %s site=%p stub=%p", sites[i].name,
                          (void *)site, (void *)stub);
            continue;
        }
        *sites[i].resume = (void *)(base + sites[i].resumeRVA);
        *(volatile uint32_t *)site = 0x14000000u | ((uint32_t)(delta >> 2) & 0x03ffffffu);
        sys_icache_invalidate((void *)site, sizeof(uint32_t));
    }
    vm_protect(mach_task_self(), (vm_address_t)segment, (vm_size_t)vmsize, FALSE,
               VM_PROT_READ | VM_PROT_EXECUTE);
    uint64_t after = shdw_funnel_region((const void *)base);
    shdw_diag_log("OZCALL armed site=%p resume=%p seg=0x%llx+0x%llx region=0x%llx->0x%llx",
                  (void *)site0, (void *)(base + sites[0].resumeRVA),
                  (unsigned long long)vmaddr, (unsigned long long)vmsize,
                  (unsigned long long)before, (unsigned long long)after);
    __atomic_store_n(&shdw_funnel_on, 1, __ATOMIC_RELEASE);
}

// Replace every inline `svc #0x80` in one detector image with `udf #0`.
// The whole __text segment is made COW-writable once, scanned and patched,
// then restored to R-X, so the Mach region layout the detector's own
// vm_region query observes does not change.
void shdw_diag_insvc_probe(const char *imageSuffix, uint64_t rangeStart,
                           uint64_t rangeEnd, int entryMode) {
    if (!shdw_diag_enabled || !imageSuffix || !imageSuffix[0]) {
        return;
    }
    uintptr_t base = shdw_diag_image_base(imageSuffix);
    if (!base) {
        shdw_diag_log("INSVC no image %s", imageSuffix);
        return;
    }

    const struct mach_header_64 *header = (const struct mach_header_64 *)base;
    if (header->magic != MH_MAGIC_64) {
        shdw_diag_log("INSVC bad header %p", (void *)base);
        return;
    }
    uint64_t textAddr = 0, textSize = 0, segVmaddr = 0, segVmsize = 0;
    const struct load_command *command = (const struct load_command *)(header + 1);
    const uint8_t *end = (const uint8_t *)command + header->sizeofcmds;
    for (uint32_t i = 0; i < header->ncmds; i++) {
        if ((const uint8_t *)command + sizeof(*command) > end ||
            command->cmdsize < sizeof(*command) ||
            (const uint8_t *)command + command->cmdsize > end) {
            break;
        }
        if (command->cmd == LC_SEGMENT_64 &&
            command->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *segment = (const void *)command;
            const struct section_64 *sects = (const struct section_64 *)(segment + 1);
            for (uint32_t j = 0; j < segment->nsects; j++) {
                if (strncmp(sects[j].sectname, "__text", 16) == 0) {
                    textAddr = sects[j].addr;
                    textSize = sects[j].size;
                    segVmaddr = segment->vmaddr;
                    segVmsize = segment->vmsize;
                }
            }
        }
        command = (const struct load_command *)((const uint8_t *)command + command->cmdsize);
    }
    if (!textAddr || !textSize || !segVmsize) {
        shdw_diag_log("INSVC no __text base=%p", (void *)base);
        return;
    }

    uint8_t *segment = (uint8_t *)(base + segVmaddr);
    if (vm_protect(mach_task_self(), (vm_address_t)segment, (vm_size_t)segVmsize,
                   FALSE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY) != KERN_SUCCESS) {
        shdw_diag_log("INSVC seg prot fail len=0x%llx", (unsigned long long)segVmsize);
        return;
    }
    uint32_t *words = (uint32_t *)(base + textAddr);
    size_t count = (size_t)(textSize / 4);
    size_t hits = 0;
    for (size_t i = 0; i < count; i++) {
        uint64_t off = textAddr + (uint64_t)i * 4;
        if (off < rangeStart || off >= rangeEnd) {
            continue;
        }
        if (words[i] == 0xd4001001u) {
            if (entryMode && i > 0) {
                // udf #1, deliberately not the value the handler replays.
                words[i - 1] = 0x00000001u;
            } else {
                words[i] = 0x00000000u;
            }
            hits++;
        }
    }
    vm_protect(mach_task_self(), (vm_address_t)segment, (vm_size_t)segVmsize, FALSE,
               VM_PROT_READ | VM_PROT_EXECUTE);
    sys_icache_invalidate((void *)(base + textAddr), (size_t)textSize);

    shdw_diag_log("INSVC armed sites=%zu range=0x%llx:0x%llx base=%p"
                  " text=0x%llx+0x%llx seg=0x%llx+0x%llx",
                  hits, (unsigned long long)rangeStart, (unsigned long long)rangeEnd,
                  (void *)base, (unsigned long long)textAddr,
                  (unsigned long long)textSize, (unsigned long long)segVmaddr,
                  (unsigned long long)segVmsize);
    if (hits > 20000) {
        shdw_diag_log("INSVC abort: implausible site count %zu", hits);
        return;
    }
    __atomic_store_n(&shdw_insvc_on, 1, __ATOMIC_RELEASE);
}

static uint64_t shdw_diag_read_u64(uintptr_t addr);


static void shdw_diag_dump_state_ring(void) {
    if (!shdw_diag_probe_on) {
        return;
    }

    uint32_t pos = shdw_state_ring[8192] & 0x1ff;
    shdw_diag_log("STATE pos=%u", pos);

    for (unsigned i = 0; i < 512; i++) {
        unsigned slot = (pos - 1 - i) & 0x1ff;
        uint32_t *e = &shdw_state_ring[slot * 16];
        uint64_t ctx = ((uint64_t)e[1] << 32) | e[0];
        uint64_t cur = ((uint64_t)e[5] << 32) | e[4];
        uint64_t slot27 = ((uint64_t)e[7] << 32) | e[6];
        uint64_t a = ((uint64_t)e[9] << 32) | e[8];
        uint64_t b = ((uint64_t)e[12] << 32) | e[11];
        uint64_t nxt = ((uint64_t)e[14] << 32) | e[13];
        uint64_t val27 = shdw_diag_read_u64((uintptr_t)slot27);
        shdw_diag_log("STATE -%u ctx=%#llx state=%u idx=%u cur=%#llx slot27=%#llx"
                      " v27=%#llx a=%#llx left=%u b=%#llx nxt=%#llx",
                      i + 1, (unsigned long long)ctx, e[2], e[3],
                      (unsigned long long)cur, (unsigned long long)slot27,
                      (unsigned long long)val27, (unsigned long long)a, e[10],
                      (unsigned long long)b, (unsigned long long)nxt);
    }
}

static uint64_t shdw_diag_read_u64(uintptr_t addr) {
    uint64_t value = 0;
    vm_size_t out = 0;

    if (addr && vm_read_overwrite(mach_task_self(), (vm_address_t)addr,
                                  (vm_size_t)sizeof value,
                                  (vm_address_t)&value, &out) == KERN_SUCCESS &&
        out == sizeof value) {
        return value;
    }
    return 0;
}

// The detector keeps a pair of cursors plus a remaining-byte counter; dump the
// three words plus the bytes on both sides of a failing byte compare.
static void shdw_diag_dump_state_compare(uintptr_t ctx) {
    if (!ctx || !shdw_diag_probe_on) {
        return;
    }

    uintptr_t remaining = (uintptr_t)shdw_diag_read_u64(ctx + 0x450);
    uintptr_t a = (uintptr_t)shdw_diag_read_u64(ctx + 0x458);
    uintptr_t b = (uintptr_t)shdw_diag_read_u64(ctx + 0x25c0);
    uintptr_t idx = (uintptr_t)shdw_diag_read_u64(ctx + 0x304);
    char as[256];
    char bs[256];

    shdw_diag_describe_short(as, sizeof as, (void *)a);
    shdw_diag_describe_short(bs, sizeof bs, (void *)b);
    shdw_diag_log("CMP left=%lu a=%p{%s} b=%p{%s}", (unsigned long)remaining,
                  (void *)a, as, (void *)b, bs);
    shdw_diag_log("CMPC ctx=%p idx=%lu limit=%lu n1=%lu n2=%lu", (void *)ctx,
                  (unsigned long)idx,
                  (unsigned long)shdw_diag_read_u64(ctx + 0x2604),
                  (unsigned long)shdw_diag_read_u64(ctx + 0x468),
                  (unsigned long)shdw_diag_read_u64(ctx + 0x474));

    uint32_t count = _dyld_image_count();
    const char *name = idx < count ? _dyld_get_image_name((uint32_t)idx) : NULL;
    const char *prev =
        idx > 0 && idx - 1 < count ? _dyld_get_image_name((uint32_t)idx - 1) : NULL;
    const void *hdr = idx < count ? (const void *)_dyld_get_image_header((uint32_t)idx) : NULL;
    shdw_diag_log("CMPD count=%u name=%s prev=%s hdr=%p", count,
                  name ? name : "(null)", prev ? prev : "(null)", hdr);
    shdw_diag_dyld_snapshot_dump("at", (uint32_t)idx);
    shdw_diag_dyld_snapshot_dump("n1", (uint32_t)idx + 1);
    shdw_diag_dyld_snapshot_dump("p1", (uint32_t)idx - 1);

    if (a > 64) {
        shdw_diag_peek_words("cmpA", a - 64, 0, 64);
        shdw_diag_peek_words("cmpA", a, 0, 64);
        shdw_diag_peek_words("cmpA", a + 32, 0, 64);
    }
    if (b > 32) {
        shdw_diag_peek_words("cmpB", b - 32, 0, 64);
        shdw_diag_peek_words("cmpB", b, 0, 32);
    }

    // Load-command walk: 0x27a8 holds the address of a VM stack slot that
    // carries the current Mach-O pointer, 0x2620 the dereferenced copy and
    // 0x25f8 the command it inspects. 0x1f68/0x1f60 are the header/ncmds
    // returned by the dyld API path.
    uintptr_t p27a8 = (uintptr_t)shdw_diag_read_u64(ctx + 0x27a8);
    uintptr_t walk = p27a8 ? (uintptr_t)shdw_diag_read_u64(p27a8) : 0;
    uintptr_t cur = (uintptr_t)shdw_diag_read_u64(ctx + 0x2620);
    uintptr_t nxt = (uintptr_t)shdw_diag_read_u64(ctx + 0x25f8);
    uintptr_t hdrW = (uintptr_t)shdw_diag_read_u64(ctx + 0x1f68);
    uintptr_t ncmdsW = (uintptr_t)shdw_diag_read_u64(ctx + 0x1f60);
    uintptr_t lim = (uintptr_t)shdw_diag_read_u64(ctx + 0x478);
    uintptr_t b84 = (uintptr_t)shdw_diag_read_u64(ctx + 0xb84);
    shdw_diag_log("WALK p27a8=%p walk=%p cur=%p nxt=%p lim=%p", (void *)p27a8,
                  (void *)walk, (void *)cur, (void *)nxt, (void *)lim);
    shdw_diag_log("WALKH hdr=%p ncmds=%lu b84=%p", (void *)hdrW,
                  (unsigned long)ncmdsW, (void *)b84);
    if (p27a8) {
        shdw_diag_peek_words("walk", p27a8 - 0x20, 0, 0x60);
    }
    if (walk) {
        uint64_t first = shdw_diag_read_u64(walk);
        shdw_diag_log("WALKM magic=%08x cputype=%08x cur_cmd=%08x cur_size=%08x",
                      (unsigned)(first & 0xffffffffu),
                      (unsigned)(first >> 32),
                      (unsigned)shdw_diag_read_u64(cur),
                      (unsigned)(shdw_diag_read_u64(cur) >> 32));
    }

    // The SDK builds its own (header, slide) array at 0x1ee0 from the dyld
    // API; if the walk cursor is in it, tell which slot carried it.
    uintptr_t hdrArr = (uintptr_t)shdw_diag_read_u64(ctx + 0x1ee0);
    uintptr_t hdrArrN = (uintptr_t)shdw_diag_read_u64(ctx + 0x1ee8);
    if (hdrArr && hdrArrN && hdrArrN < 65536) {
        long hit = -1;
        for (uintptr_t i = 0; i < hdrArrN; i++) {
            if ((uintptr_t)shdw_diag_read_u64(hdrArr + i * 16) == cur) {
                hit = (long)i;
                break;
            }
        }
        shdw_diag_log("ARR base=%p n=%lu cur_hit=%ld", (void *)hdrArr,
                      (unsigned long)hdrArrN, hit);
    }

    // Does the raw dlsym() pointer for the dyld entry points bypass the hooks?
    // If so, the first images come back unfiltered and match the walk cursor.
    typedef const void *(*shdw_raw_hdr_fn)(uint32_t);
    shdw_raw_hdr_fn rawHdr =
        (shdw_raw_hdr_fn)dlsym(RTLD_DEFAULT, "_dyld_get_image_header");
    if (rawHdr) {
        char syms[256];
        shdw_diag_describe_short(syms, sizeof syms, (void *)rawHdr);
        shdw_diag_log("RAWSYM _dyld_get_image_header=%p{%s}", (void *)rawHdr, syms);
        for (uint32_t i = 0; i < 4; i++) {
            const void *rv = rawHdr(i);
            char rs[256];
            shdw_diag_describe_short(rs, sizeof rs, (void *)rv);
            shdw_diag_log("RAWH idx=%u hdr=%p{%s}", i, rv, rs);
        }
    }
    typedef const void *(*shdw_raw_infos_fn)(void);
    shdw_raw_infos_fn rawInfos =
        (shdw_raw_infos_fn)dlsym(RTLD_DEFAULT, "_dyld_get_all_image_infos");
    if (rawInfos) {
        uintptr_t infos = (uintptr_t)rawInfos();
        uint32_t icount = (uint32_t)shdw_diag_read_u64(infos + 4);
        uintptr_t iarr = (uintptr_t)shdw_diag_read_u64(infos + 8);
        shdw_diag_log("RAWA infos=%p count=%u arr=%p", (void *)infos, icount,
                      (void *)iarr);
        for (uint32_t i = 0; i < 4 && i < icount; i++) {
            uintptr_t base = (uintptr_t)shdw_diag_read_u64(iarr + i * 24);
            char rs[256];
            shdw_diag_describe_short(rs, sizeof rs, (void *)base);
            shdw_diag_log("RAWA idx=%u base=%p{%s}", i, (void *)base, rs);
        }
    }
}

void shdw_diag_state_probe(const char *spec) {
    if (!shdw_diag_enabled || !spec || !spec[0]) {
        return;
    }

    char work[256];
    strlcpy(work, spec, sizeof work);

    char *bar = strrchr(work, '|');
    if (!bar) {
        shdw_diag_log("STATE bad spec %s", spec);
        return;
    }
    *bar = '\0';
    uintptr_t resumeRVA = (uintptr_t)strtoul(bar + 1, NULL, 16);

    bar = strrchr(work, '|');
    if (!bar) {
        shdw_diag_log("STATE bad spec %s", spec);
        return;
    }
    *bar = '\0';
    uintptr_t siteRVA = (uintptr_t)strtoul(bar + 1, NULL, 16);

    uintptr_t base = shdw_diag_image_base(work);
    if (!base) {
        shdw_diag_log("STATE no image %s", work);
        return;
    }

    uintptr_t site = base + siteRVA;
    uintptr_t resume = base + resumeRVA;
    uintptr_t stub = (uintptr_t)shdw_state_probe_entry;
    intptr_t delta = (intptr_t)(stub - site);

    if (!siteRVA || !resumeRVA || (delta & 3) || delta < -0x8000000LL ||
        delta > 0x7FFFFFCLL) {
        shdw_diag_log("STATE out of range base=%p site=%p stub=%p delta=%ld",
                      (void *)base, (void *)site, (void *)stub, (long)delta);
        return;
    }

    uint32_t orig = *(const uint32_t *)site;
    if ((orig & 0xfc000000u) != 0x14000000u) {
        shdw_diag_log("STATE site %p is not b: %#x", (void *)site, orig);
        return;
    }

    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0) {
        page = 0x4000;
    }
    vm_address_t pageAddr = (vm_address_t)(site & ~((uintptr_t)page - 1));
    vm_size_t pageSize = (vm_size_t)page;

    // Code-signed __TEXT cannot be made writable in place; VM_PROT_COPY turns
    // the page into a private copy, same as the svc-site patch lane.
    kern_return_t kr = vm_protect(mach_task_self(), pageAddr, pageSize, FALSE,
                                  VM_PROT_READ | VM_PROT_WRITE |
                                      VM_PROT_COPY);
    if (kr != KERN_SUCCESS) {
        kr = vm_protect(mach_task_self(), pageAddr, pageSize, FALSE,
                        VM_PROT_READ | VM_PROT_WRITE);
    }
    if (kr != KERN_SUCCESS) {
        shdw_diag_log("STATE protect failed site=%p kr=%d", (void *)site,
                      (int)kr);
        return;
    }

    shdw_state_probe_resume = (void *)resume;
    __atomic_store_n(&shdw_diag_probe_on, 1, __ATOMIC_RELEASE);
    __atomic_store_n((uint32_t *)site,
                     0x14000000u | ((uint32_t)(delta >> 2) & 0x03ffffffu),
                     __ATOMIC_RELEASE);
    sys_icache_invalidate((void *)site, 4);

    vm_protect(mach_task_self(), pageAddr, pageSize, FALSE,
               VM_PROT_READ | VM_PROT_EXECUTE);
    sys_icache_invalidate((void *)pageAddr, (size_t)pageSize);

    shdw_diag_log("STATE armed site=%p -> %p resume=%p orig=%#x",
                  (void *)site, (void *)stub, (void *)resume, orig);
}

// --- Diagnostic lane: environment fingerprint dump (pref: Debug_EnvDump) ---
// One-shot snapshot of the OS-visible state a userspace RASP can read without
// calling any hooked API: csops flags, MACF sysctls, mount table, environ,
// own Mach-O load commands and whether own __TEXT can be made writable.
int shdw_diag_envdump_flag = 0;

extern int csops(pid_t pid, unsigned int ops, void* useraddr, size_t usersize);
extern int proc_pidpath(int pid, void* buffer, uint32_t buffersize);
extern char** environ;

static void shdw_envdump_sysctl(const char* name) {
    char buf[256];
    size_t len = sizeof buf;
    memset(buf, 0, sizeof buf);
    int r = sysctlbyname(name, buf, &len, NULL, 0);
    if(r != 0) {
        shdw_diag_log("ENVDUMP sysctl %s errno=%d", name, errno);
        return;
    }
    unsigned long long v = 0;
    if(len >= 8) memcpy(&v, buf, 8);
    else if(len >= 4) { uint32_t w = 0; memcpy(&w, buf, 4); v = w; }
    else if(len >= 2) { uint16_t h = 0; memcpy(&h, buf, 2); v = h; }
    else if(len >= 1) { v = (unsigned char) buf[0]; }
    shdw_diag_log("ENVDUMP sysctl %s = %llu (len=%zu)", name, v, len);
}

void shdw_diag_envdump_run(void) {
    if(!shdw_diag_envdump_flag) {
        return;
    }

    uint32_t flags = 0;
    int cr = csops(getpid(), 0 /* CS_OPS_STATUS */, &flags, sizeof flags);
    shdw_diag_log("ENVDUMP csops ret=%d flags=0x%08x valid=%d hard=%d kill=%d restrict=%d enforce=%d require_lv=%d get_task_allow=%d debugged=%d platform=%d",
                  cr, flags,
                  !!(flags & 0x00000001), !!(flags & 0x00000100),
                  !!(flags & 0x00000200), !!(flags & 0x00000800),
                  !!(flags & 0x00001000), !!(flags & 0x00002000),
                  !!(flags & 0x00800000), !!(flags & 0x10000000),
                  !!(flags & 0x04000000));

    {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        uint32_t rflags = 0;
        errno = 0;
        long rr = syscall(169 /* SYS_csops */, getpid(), 0,
                          (void *)&rflags, sizeof rflags);
        shdw_diag_log("ENVDUMP rawcsops169 ret=%ld errno=%d flags=0x%08x",
                      rr, errno, rflags);
        uint32_t aflags = 0;
        errno = 0;
        long ar = syscall(170 /* SYS_csops_audittoken */, getpid(), 0,
                          (void *)&aflags, sizeof aflags, 0, 0);
        shdw_diag_log("ENVDUMP rawcsops170 ret=%ld errno=%d flags=0x%08x",
                      ar, errno, aflags);
#pragma clang diagnostic pop
    }

    shdw_envdump_sysctl("security.mac.proc_enforce");
    shdw_envdump_sysctl("security.mac.vnode_enforce");
    shdw_envdump_sysctl("kern.cs_enforcement");
    shdw_envdump_sysctl("kern.secure_kernel");
    shdw_envdump_sysctl("kern.securelevel");
    shdw_envdump_sysctl("kern.development");

    {
        int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid() };
        struct kinfo_proc kp;
        size_t len = sizeof kp;
        memset(&kp, 0, sizeof kp);
        if(sysctl(mib, 4, &kp, &len, NULL, 0) == 0) {
            shdw_diag_log("ENVDUMP proc p_flag=0x%x traced=%d",
                          kp.kp_proc.p_flag, !!(kp.kp_proc.p_flag & 0x800));
        } else {
            shdw_diag_log("ENVDUMP proc sysctl errno=%d", errno);
        }
    }

    {
        int n = 0;
        for(char** e = environ; e && *e; e++) {
            n++;
            if(strstr(*e, "DYLD") || strstr(*e, "SSafe") || strstr(*e, "JB") ||
               strstr(*e, "jb") || strstr(*e, "SHADOW") || strstr(*e, "Shadow") ||
               strstr(*e, "ellekit") || strstr(*e, "ElleKit") || strstr(*e, "Inject")) {
                shdw_diag_log("ENVDUMP environ %s", *e);
            }
        }
        shdw_diag_log("ENVDUMP environ count=%d", n);
    }

    {
        struct statfs* mnt = NULL;
        int n = getfsstat(NULL, 0, MNT_NOWAIT);
        if(n > 0) {
            mnt = (struct statfs*) malloc(sizeof(struct statfs) * n);
            if(mnt) {
                n = getfsstat(mnt, sizeof(struct statfs) * n, MNT_NOWAIT);
                for(int i = 0; i < n; i++) {
                    if(strstr(mnt[i].f_mntonname, "jb") || strstr(mnt[i].f_mntonname, "preboot") ||
                       strstr(mnt[i].f_mntfromname, "jb") || strstr(mnt[i].f_mntfromname, "preboot") ||
                       strstr(mnt[i].f_mntonname, "dopamine")) {
                        shdw_diag_log("ENVDUMP mount %s on %s flags=0x%x",
                                      mnt[i].f_mntfromname, mnt[i].f_mntonname,
                                      (unsigned) mnt[i].f_flags);
                    }
                }
                shdw_diag_log("ENVDUMP mounts total=%d", n);
                free(mnt);
            }
        } else {
            shdw_diag_log("ENVDUMP getfsstat errno=%d", errno);
        }
    }

    {
        const struct mach_header_64* mh = (const struct mach_header_64*) _dyld_get_image_header(0);
        if(mh) {
            int haveRestrict = 0, cryptid = -1;
            const struct load_command* lc = (const struct load_command*) (mh + 1);
            for(uint32_t i = 0; i < mh->ncmds; i++) {
                if(lc->cmd == LC_SEGMENT_64) {
                    const struct segment_command_64* sc = (const struct segment_command_64*) lc;
                    if(!strcmp(sc->segname, "__RESTRICT")) haveRestrict = 1;
                } else if(lc->cmd == 0x2c) {
                    const uint32_t* raw = (const uint32_t*) lc;
                    cryptid = (int) raw[4];
                }
                lc = (const struct load_command*) ((const char*) lc + lc->cmdsize);
            }
            shdw_diag_log("ENVDUMP mainexe flags=0x%x ncmds=%u restrict=%d cryptid=%d pie=%d",
                          mh->flags, mh->ncmds, haveRestrict, cryptid, !!(mh->flags & 0x200000));
        }
    }

    {
        uintptr_t base = (uintptr_t) _dyld_get_image_header(0);
        if(base) {
            kern_return_t kr = vm_protect(mach_task_self(), base, 0x4000, false,
                                          VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
            shdw_diag_log("ENVDUMP text_writable kr=%d (%s)", kr,
                          kr == KERN_SUCCESS ? "WRITABLE" : "denied");
            if(kr == KERN_SUCCESS) {
                vm_protect(mach_task_self(), base, 0x4000, false,
                           VM_PROT_READ | VM_PROT_EXECUTE);
            }
        }
    }

    {
        char path[PATH_MAX];
        int ppid = getppid();
        int r = proc_pidpath(ppid, path, sizeof path);
        shdw_diag_log("ENVDUMP parent pid=%d proc_pidpath=%d path=%s", ppid, r, r > 0 ? path : "-");
    }

    {
        mach_port_t port = MACH_PORT_NULL;
        kern_return_t kr = task_get_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, &port);
        shdw_diag_log("ENVDUMP bootstrap kr=%d port=%u", kr, (unsigned) port);
        if(kr == KERN_SUCCESS && port != MACH_PORT_NULL) {
            mach_port_deallocate(mach_task_self(), port);
        }
    }

    shdw_diag_log("ENVDUMP end");
}

