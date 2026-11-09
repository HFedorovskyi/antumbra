#import "../Diag.h"

#import <dlfcn.h>
#import <libkern/OSCacheControl.h>
#import <mach/mach.h>
#import <mach/vm_region.h>
#import <stdint.h>
#import <string.h>
#import <unistd.h>

// Diagnostic lane for the termination paths the rebind hooks cannot reach.
// These are stubs in libsystem_kernel with no re-export slot: neither an
// inline hook nor a rebind lands on them, and a plain `b` from ShadowCore
// cannot reach them either (the shared cache sits far outside the +-128 MB
// branch window). Take a zeroed padding slot inside the stub's own code page,
// put the reporter plus a self-contained copy of the syscall there, and patch
// only the first word of the stub.
//
// The stubs are `mov x16,#SYS_x; svc #0x80; b.eq <errno path>`, so the tail
// cannot be copied verbatim (its conditional branch is PC-relative). The
// trampoline rebuilds the syscall from the decoded number instead.

#if defined(__arm64__)

int shdw_diag_exit_probe = 0;

#define SHDW_TRAMP_BYTES 64
#define SHDW_PROBE_MAX 8

typedef struct {
    const char* name;
    void* hit;
    uintptr_t slot;
    void (*orig)(uintptr_t, uintptr_t, uintptr_t, uintptr_t);
} shdw_probe_t;

static shdw_probe_t shdw_probes[SHDW_PROBE_MAX];
static int shdw_probe_count;
static int shdw_probe_installed;

static uintptr_t shdw_page_size(void) {
    static uintptr_t cached = 0;

    if(!cached) {
        long v = sysconf(_SC_PAGESIZE);
        cached = v > 0 ? (uintptr_t)v : 0x4000;
    }

    return cached;
}

static int shdw_is_branch(uint32_t insn) {
    return (insn & 0xFC000000u) == 0x14000000u;
}

static int shdw_is_svc(uint32_t insn) {
    return (insn & 0xFFE0001Fu) == 0xD4000001u;
}

// movz/movk into x16 or w16, the two ways a stub materializes the number.
static int shdw_is_x16_mov(uint32_t insn) {
    uint32_t rd = insn & 0x1Fu;
    uint32_t op = insn & 0xFF800000u;
    return rd == 16 && (op == 0xD2800000u || op == 0x52800000u ||
                        op == 0xF2800000u || op == 0x72800000u);
}

static uint32_t shdw_movz64(uint16_t imm16, int hw) {
    return 0xD2800000u | ((uint32_t)hw << 21) | ((uint32_t)imm16 << 5) | 16u;
}

static uint32_t shdw_movk64(uint16_t imm16, int hw) {
    return 0xF2800000u | ((uint32_t)hw << 21) | ((uint32_t)imm16 << 5) | 16u;
}

// A tail-call thunk in libsystem_c can stand in front of the kernel stub.
// Follow unconditional branches until the real stub body shows up.
static void* shdw_resolve_thunk(void* p) {
    for(int i = 0; i < 8 && p; i++) {
        uint32_t insn = 0;
        memcpy(&insn, p, sizeof insn);
        if(!shdw_is_branch(insn)) {
            return p;
        }
        int32_t off = (int32_t)(insn & 0x03FFFFFFu);
        if(off & 0x02000000) {
            off |= ~0x03FFFFFF;
        }
        p = (void*)((uintptr_t)p + ((intptr_t)off << 2));
    }

    return 0;
}

// The shared cache is mapped as one huge region, so there is no free page to
// claim anywhere near these stubs. Look for a run of zeroed words (udf
// padding, which no function can fall into) inside the code pages instead.
// Every read is bounded by the mapping that actually backs it: scanning off
// the end of a region is a fault, and a fault here reaches the substrate's
// exception handler before it reaches us.
static uintptr_t shdw_pad_slot(uintptr_t target) {
    uintptr_t pg = shdw_page_size();
    uintptr_t limit = target + (1ULL << 20);
    mach_port_t self = mach_task_self();

    uintptr_t p = target + 12;

    while(p + SHDW_TRAMP_BYTES <= limit) {
        vm_address_t start = (vm_address_t)p;
        vm_size_t size = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t object = MACH_PORT_NULL;

        if(vm_region_64(self, &start, &size, VM_REGION_BASIC_INFO_64,
                        (vm_region_info_t)&info, &count, &object) != KERN_SUCCESS) {
            break;
        }
        if(object != MACH_PORT_NULL) {
            mach_port_deallocate(self, object);
        }

        uintptr_t rend = (uintptr_t)start + (uintptr_t)size;

        if((info.protection & VM_PROT_READ) == 0) {
            p = rend > p ? rend : p + pg;
            continue;
        }

        uintptr_t stop = rend < limit ? rend : limit;

        for(; p + SHDW_TRAMP_BYTES <= stop; p += 4) {
            int used = 0;
            for(int i = 0; i < shdw_probe_count; i++) {
                if(shdw_probes[i].slot == p) {
                    used = 1;
                }
            }
            if(used) {
                continue;
            }

            const volatile uint32_t* w = (const volatile uint32_t*)p;
            if(w[0] == 0 && w[1] == 0 && w[2] == 0 && w[3] == 0) {
                return p;
            }
        }

        p = stop;
    }

    uintptr_t page = target & ~(pg - 1);

    for(p = page; p + SHDW_TRAMP_BYTES <= target; p += 4) {
        int used = 0;
        for(int i = 0; i < shdw_probe_count; i++) {
            if(shdw_probes[i].slot == p) {
                used = 1;
            }
        }
        if(used) {
            continue;
        }

        const volatile uint32_t* w = (const volatile uint32_t*)p;
        if(w[0] == 0 && w[1] == 0 && w[2] == 0 && w[3] == 0) {
            return p;
        }
    }

    return 0;
}

static kern_return_t shdw_protect(uintptr_t page, vm_prot_t prot) {
#if defined(__arm64__)
    // mach_vm_protect is mach trap -14. Issue the trap from this image
    // instead of calling libsystem's stub: that stub shares a page with the
    // syscall entry points we patch, and remapping the page the calling
    // thread is executing in faults the thread on trap return.
    register uintptr_t x0 __asm__("x0") = (uintptr_t)mach_task_self();
    register uintptr_t x1 __asm__("x1") = page;
    register uintptr_t x2 __asm__("x2") = shdw_page_size();
    register uintptr_t x3 __asm__("x3") = 0;
    register uintptr_t x4 __asm__("x4") = (uintptr_t)prot;
    register int64_t x16 __asm__("x16") = -14;

    __asm__ volatile("svc #0x80"
                     : "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3), "+r"(x4), "+r"(x16)
                     :
                     : "memory", "cc");

    return (kern_return_t)x0;
#else
    return vm_protect(mach_task_self(), (vm_address_t)page,
                      (vm_size_t)shdw_page_size(), FALSE, prot);
#endif
}

static void shdw_probe_fire(int index, uintptr_t a0) {
    shdw_probe_t* probe = &shdw_probes[index];
    char caller[512];

    shdw_diag_describe(caller, sizeof caller, __builtin_return_address(0));
    shdw_diag_log("KILLTRAP %s(0x%llx) caller=%s", probe->name,
                  (unsigned long long)a0, caller);
    shdw_diag_backtrace(probe->name);

    if(probe->orig) {
        probe->orig(a0, 0, 0, 0);
    }

    __builtin_trap();
}

static void shdw_hit_exit(int status) { shdw_probe_fire(0, (uintptr_t)(unsigned)status); }
static void shdw_hit_exit2(int status) { shdw_probe_fire(1, (uintptr_t)(unsigned)status); }
static void shdw_hit_task(uintptr_t task) { shdw_probe_fire(2, task); }
static void shdw_hit_thread(uintptr_t thread) { shdw_probe_fire(3, thread); }

// Returns 1 when the stub was patched.
static int shdw_patch_stub(shdw_probe_t* probe, void* handler) {
    void* raw = dlsym(RTLD_DEFAULT, probe->name);
    void* target = shdw_resolve_thunk(raw);

    shdw_diag_log("exitprobe: %s begin raw=%p target=%p", probe->name, raw, target);

    if(!target) {
        shdw_diag_log("exitprobe: %s not found", probe->name);
        return 0;
    }

    uint32_t head[4];
    memcpy(head, target, sizeof head);

    uint64_t sysno = 0;
    int seen_mov = 0;
    int svc_at = -1;

    for(int i = 0; i < 4; i++) {
        uint32_t insn = head[i];

        if(shdw_is_svc(insn)) {
            svc_at = i;
            break;
        }

        if(!shdw_is_x16_mov(insn)) {
            shdw_diag_log("exitprobe: %s unexpected stub at %p (%08x %08x %08x %08x)",
                          probe->name, target, head[0], head[1], head[2], head[3]);
            return 0;
        }

        int is_movk = (int)((insn >> 29) & 1u);
        int hw = (int)((insn >> 21) & 3u);
        uint64_t imm = (uint64_t)((insn >> 5) & 0xFFFFu) << (hw * 16);

        if(is_movk) {
            sysno = (sysno & ~(0xFFFFULL << (hw * 16))) | imm;
        } else {
            sysno = imm;
        }
        seen_mov = 1;
    }

    if(!seen_mov || svc_at < 0) {
        shdw_diag_log("exitprobe: %s undecodable stub at %p", probe->name, target);
        return 0;
    }

    shdw_diag_log("exitprobe: %s decoded sysno=%llu", probe->name,
                  (unsigned long long)sysno);

    uintptr_t slot = shdw_pad_slot((uintptr_t)target);

    shdw_diag_log("exitprobe: %s slot=%p", probe->name, (void*)slot);

    if(!slot) {
        shdw_diag_log("exitprobe: %s no padding slot near %p", probe->name, target);
        return 0;
    }

    int64_t delta = (int64_t)slot - (int64_t)(uintptr_t)target;

    if(delta < -0x8000000LL || delta > 0x7FFFFFCLL) {
        shdw_diag_log("exitprobe: %s slot %p out of branch range", probe->name,
                      (void*)slot);
        return 0;
    }

    uint32_t code[8];
    int idx = 0;

    code[idx++] = 0x58000050u;                       // ldr x16, #8
    code[idx++] = 0xD61F0200u;                       // br x16
    int literal_at = idx;
    idx += 2;

    int stub_at = idx;

    code[idx++] = shdw_movz64((uint16_t)(sysno & 0xFFFFu), 0);
    code[idx++] = shdw_movk64((uint16_t)((sysno >> 16) & 0xFFFFu), 1);
    code[idx++] = shdw_movk64((uint16_t)((sysno >> 32) & 0xFFFFu), 2);
    code[idx++] = 0xD4001001u;                       // svc #0x80
    code[idx++] = 0xD65F03C0u;                       // ret

    uint8_t buf[SHDW_TRAMP_BYTES];
    memset(buf, 0, sizeof buf);
    memcpy(buf, code, (size_t)idx * sizeof(uint32_t));

    uint64_t literal = (uint64_t)(uintptr_t)handler;
    memcpy(buf + literal_at * 4, &literal, sizeof literal);

    uintptr_t slot_page = slot & ~(shdw_page_size() - 1);
    uintptr_t stub_page = (uintptr_t)target & ~(shdw_page_size() - 1);

    if(shdw_protect(slot_page, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY) !=
       KERN_SUCCESS) {
        shdw_diag_log("exitprobe: %s slot page not writable", probe->name);
        return 0;
    }

    memcpy((void*)slot, buf, sizeof buf);
    sys_icache_invalidate((void*)slot, sizeof buf);

    if(slot_page != stub_page) {
        shdw_protect(slot_page, VM_PROT_READ | VM_PROT_EXECUTE);
    }

    kern_return_t kr = vm_protect(mach_task_self(), (vm_address_t)stub_page,
                                  (vm_size_t)shdw_page_size(), FALSE,
                                  VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);

    if(kr != KERN_SUCCESS) {
        kr = vm_protect(mach_task_self(), (vm_address_t)stub_page,
                        (vm_size_t)shdw_page_size(), FALSE,
                        VM_PROT_READ | VM_PROT_WRITE);
    }

    if(kr != KERN_SUCCESS) {
        shdw_diag_log("exitprobe: %s stub page not writable (kr=%d)", probe->name,
                      (int)kr);
        return 0;
    }

    uint32_t branch = 0x14000000u | ((uint32_t)(delta >> 2) & 0x03FFFFFFu);
    memcpy(target, &branch, sizeof branch);
    sys_icache_invalidate(target, sizeof branch);

    vm_protect(mach_task_self(), (vm_address_t)stub_page,
               (vm_size_t)shdw_page_size(), FALSE,
               VM_PROT_READ | VM_PROT_EXECUTE);

    probe->slot = slot;
    probe->orig = (void (*)(uintptr_t, uintptr_t, uintptr_t, uintptr_t))(
        slot + (uintptr_t)stub_at * 4);

    shdw_diag_log("exitprobe: %s @ %p -> %p sysno=%llu", probe->name, target,
                  (void*)slot, (unsigned long long)sysno);
    return 1;
}

// BRK variant of the stub probe: no trampoline, no forwarding. The call
// traps in place, and the signal handler attributes the trap by address,
// logs the caller, and resumes at the return address. That finds a
// termination reached through a pointer no rebind could redirect, and
// neutralizes it in the same step.
int shdw_diag_exit_brk = 0;

typedef struct {
    const char* name;
    uintptr_t target;
} shdw_brk_entry_t;

#define SHDW_BRK_MAX 32

static shdw_brk_entry_t shdw_brk_entries[SHDW_BRK_MAX];
static int shdw_brk_entry_count;

// Called from the SIGTRAP handler: a trap at an armed first word belongs to
// the function named here.
const char* shdw_diag_brk_lookup(uintptr_t pc) {
    for(int i = 0; i < shdw_brk_entry_count; i++) {
        if(shdw_brk_entries[i].target == pc) {
            return shdw_brk_entries[i].name;
        }
    }

    return 0;
}

static void shdw_brk_stub(const char* name) {
    void* raw = dlsym(RTLD_DEFAULT, name);
    void* target = shdw_resolve_thunk(raw);

    shdw_diag_log("exitbrk: %s raw=%p target=%p", name, raw, target);

    if(!target) {
        return;
    }

    for(int i = 0; i < shdw_brk_entry_count; i++) {
        if(shdw_brk_entries[i].target == (uintptr_t)target) {
            shdw_diag_log("exitbrk: %s shares %p with %s", name, target,
                          shdw_brk_entries[i].name);
            return;
        }
    }

    if(shdw_brk_entry_count >= SHDW_BRK_MAX) {
        shdw_diag_log("exitbrk: %s no table slot", name);
        return;
    }

    uintptr_t page = (uintptr_t)target & ~((uintptr_t)shdw_page_size() - 1);

    // Keep execute on the page for the whole edit: another thread can be
    // fetching from the same page while the first word is rewritten, and a
    // brief W-without-X window turns that fetch into a protection fault.
    if(shdw_protect(page, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE |
                          VM_PROT_COPY) != KERN_SUCCESS &&
       shdw_protect(page, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY) !=
           KERN_SUCCESS &&
       shdw_protect(page, VM_PROT_READ | VM_PROT_WRITE) != KERN_SUCCESS) {
        shdw_diag_log("exitbrk: %s page not writable", name);
        return;
    }

    uint32_t brk = 0xD4200000u | (0x42u << 5);
    memcpy(target, &brk, sizeof brk);
    sys_icache_invalidate(target, sizeof brk);

    shdw_protect(page, VM_PROT_READ | VM_PROT_EXECUTE);

    shdw_brk_entries[shdw_brk_entry_count].name = name;
    shdw_brk_entries[shdw_brk_entry_count].target = (uintptr_t)target;
    shdw_brk_entry_count++;

    shdw_diag_log("exitbrk: %s armed at %p", name, target);
}

void shdw_diag_install_exit_brk(void) {
    shdw_brk_stub("exit");
    shdw_brk_stub("_exit");
    shdw_brk_stub("_Exit");
    shdw_brk_stub("abort");
    shdw_brk_stub("__abort_with_payload");
    shdw_brk_stub("abort_with_payload");
    shdw_brk_stub("raise");
    shdw_brk_stub("kill");
    shdw_brk_stub("killpg");
    shdw_brk_stub("pthread_kill");
    shdw_brk_stub("proc_exit");
    shdw_brk_stub("task_terminate");
    shdw_brk_stub("thread_terminate");
    shdw_brk_stub("os_crash");
    shdw_brk_stub("__assert_rtn");
}

void shdw_diag_install_exit_probe(void) {
    if(shdw_probe_installed) {
        return;
    }
    shdw_probe_installed = 1;

    shdw_probes[0] = (shdw_probe_t){ "_exit", (void*)shdw_hit_exit, 0, 0 };
    shdw_probes[1] = (shdw_probe_t){ "_Exit", (void*)shdw_hit_exit2, 0, 0 };
    shdw_probes[2] = (shdw_probe_t){ "task_terminate", (void*)shdw_hit_task, 0, 0 };
    shdw_probes[3] = (shdw_probe_t){ "thread_terminate", (void*)shdw_hit_thread, 0, 0 };
    shdw_probe_count = 4;

    for(int i = 0; i < shdw_probe_count; i++) {
        shdw_patch_stub(&shdw_probes[i], shdw_probes[i].hit);
    }
}

#else

void shdw_diag_install_exit_probe(void) {}

const char* shdw_diag_brk_lookup(uintptr_t pc) {
    (void)pc;
    return 0;
}

#endif
