#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach/mach.h>
#import <mach/vm_page_size.h>
#import <limits.h>
#import "hooks/Diag.h"
#import <string.h>
#import <stdlib.h>

// Installers that carry an App Store bundle onto a jailbroken device decrypt
// the executable pages and then leave their mark in the Mach-O header: the
// load command's cryptid drops to 0 and MH_PIE is cleared. A stock App Store
// install keeps cryptid=1 and MH_PIE set. Fraud SDKs compare the header they
// can read at objectFileOffset against that stock shape, so the tell survives
// even when the jailbreak runtime is not running. Normalize the in-memory
// header back to the stock shape; the vnode and the kernel's own copy stay
// untouched, so page-in decryption is unaffected.

static void* shdw_ip_writable_pages(void* addr, size_t len, vm_prot_t* savedProt,
                                    vm_address_t* outPage, vm_size_t* outSpan) {
    mach_vm_address_t page = (mach_vm_address_t)addr & ~(mach_vm_address_t)(vm_page_size - 1);
    mach_vm_address_t end = ((mach_vm_address_t)addr + len + vm_page_size - 1) &
                            ~(mach_vm_address_t)(vm_page_size - 1);
    vm_address_t region = (vm_address_t)page;
    vm_size_t regionSize = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t infoCount = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t objectName = MACH_PORT_NULL;

    *savedProt = VM_PROT_READ;
    if(vm_region_64(mach_task_self(), &region, &regionSize, VM_REGION_BASIC_INFO_64,
                    (vm_region_info_t)&info, &infoCount, &objectName) == KERN_SUCCESS) {
        *savedProt = info.protection;
    }
    if(objectName != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), objectName);
    }
    *outPage = (vm_address_t)page;
    *outSpan = (vm_size_t)(end - page);

    if((*savedProt & VM_PROT_WRITE) != 0) {
        return addr;
    }
    kern_return_t kr = vm_protect(mach_task_self(), (vm_address_t)page, (vm_size_t)(end - page),
                                  FALSE, *savedProt | VM_PROT_WRITE | VM_PROT_COPY);
    if(kr != KERN_SUCCESS) {
        kr = vm_protect(mach_task_self(), (vm_address_t)page, (vm_size_t)(end - page),
                        FALSE, *savedProt | VM_PROT_WRITE);
    }
    return kr == KERN_SUCCESS ? addr : NULL;
}

static void shdw_ip_restore(vm_address_t page, vm_size_t span, vm_prot_t savedProt) {
    if((savedProt & VM_PROT_WRITE) == 0) {
        vm_protect(mach_task_self(), page, span, FALSE, savedProt);
    }
}

static int shdw_ip_normalize_image(const struct mach_header_64* mh) {
    if(!mh || mh->magic != MH_MAGIC_64) {
        return 0;
    }

    size_t range = sizeof(struct mach_header_64) + mh->sizeofcmds;
    vm_prot_t savedProt = VM_PROT_READ;
    vm_address_t page = 0;
    vm_size_t span = 0;
    if(!shdw_ip_writable_pages((void*)mh, range, &savedProt, &page, &span)) {
        return 0;
    }

    struct mach_header_64* hdr = (struct mach_header_64*)mh;
    uint32_t oldFlags = hdr->flags;
    if((hdr->flags & MH_PIE) == 0) {
        hdr->flags |= MH_PIE;
    }

    const struct load_command* lc = (const struct load_command*)((const char*)mh + sizeof(struct mach_header_64));
    for(uint32_t i = 0; i < mh->ncmds && (const char*)lc + sizeof(struct load_command) <= (const char*)mh + range; i++) {
        if(lc->cmd == LC_ENCRYPTION_INFO || lc->cmd == LC_ENCRYPTION_INFO_64) {
            // Same field at the same offset in both variants.
            uint32_t* cryptid = (uint32_t*)((char*)lc + 16);
            if(*cryptid == 0) {
                *cryptid = 1;
            }
            shdw_diag_log("PROVIMG mh=%p flags %#x -> %#x cryptid=%u", mh, oldFlags, hdr->flags, *cryptid); // SHDW_PROV_LOG
        }
        if(lc->cmdsize < sizeof(struct load_command)) {
            break;
        }
        lc = (const struct load_command*)((const char*)lc + lc->cmdsize);
    }

    shdw_ip_restore(page, span, savedProt);
    return 1;
}

// Only the app's own images: the bundle root is everything up to and including
// ".app/", so the executable and every embedded framework/vendor dylib at
// ObjectFileOffset share the normalization.
static int shdw_ip_under_bundle(const char* path, const char* root) {
    return path && root && root[0] && strncmp(path, root, strlen(root)) == 0;
}

void shdw_image_provenance_normalize(void) {
    char exe[PATH_MAX];
    uint32_t exeSize = sizeof(exe);
    if(_NSGetExecutablePath(exe, &exeSize) != 0) {
        return;
    }
    char* app = strstr(exe, ".app/");
    if(!app) {
        return;
    }
    size_t rootLen = (size_t)(app - exe) + 5;   // include ".app/"
    char root[PATH_MAX];
    if(rootLen >= sizeof(root)) {
        return;
    }
    memcpy(root, exe, rootLen);
    root[rootLen] = '\0';

    uint32_t count = _dyld_image_count();
    int patched = 0;
    for(uint32_t i = 0; i < count; i++) {
        const char* name = _dyld_get_image_name(i);
        if(!shdw_ip_under_bundle(name, root)) {
            continue;
        }
        patched += shdw_ip_normalize_image((const struct mach_header_64*)_dyld_get_image_header(i));
    }
    shdw_diag_log("IMGNORM patched=%d", patched);
}
