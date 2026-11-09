#ifndef shadow_hooks_late_image_slots_h
#define shadow_hooks_late_image_slots_h

// Import-slot rebinder for images dyld adds after Shadow installed.
//
// A rebind only rewrites the slots of images already loaded at install time.
// An image dlopen'd later keeps its own imports intact, and a detector
// framework's initializer runs right after the add-image notification — one
// sysctl(KERN_PROCARGS2) or _dyld_get_image_name call from there reads the raw
// env dump / jailbreak paths, and _dyld_get_image_name's filtered list is
// contradicted by the caller's own image list.
//
// HookKit cannot cover this: its caller-image scope is a snapshot taken at
// analysis time, so a freshly added header answers "the image imports no such
// symbol" even when the import is right there (and a shared-cache image
// refuses EXACT_HEADER scope outright). This walk reads the image's own load
// commands instead — the authoritative record of which slot holds which
// symbol — and hands every matching slot to the caller's store callback.
//
// Both binding formats are handled: the classic LC_DYLD_INFO bind opcode
// stream (what tweak dylibs built by theos still carry) and
// LC_DYLD_CHAINED_FIXUPS (app frameworks and system images).
//
// Plain C over the in-memory mach_header so the host test harness can drive
// it with synthetic and real images: no mach, dyld, or Foundation dependency.

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define SHDW_LATE_MAX_SEGMENTS 24

// Local mirrors of the loader structures the walk reads. The fields used here
// are ABI-stable and identical across SDKs; keeping local copies lets the
// host test build without an Apple SDK.
typedef struct {
  uint32_t magic;
  uint32_t cputype;
  uint32_t cpusubtype;
  uint32_t filetype;
  uint32_t ncmds;
  uint32_t sizeofcmds;
  uint32_t flags;
  uint32_t reserved;
} shdw_late_mach_header64;

typedef struct {
  uint32_t cmd;
  uint32_t cmdsize;
  char segname[16];
  uint64_t vmaddr;
  uint64_t vmsize;
  uint64_t fileoff;
  uint64_t filesize;
  int32_t maxprot;
  int32_t initprot;
  uint32_t nsects;
  uint32_t flags;
} shdw_late_segment64;

typedef struct {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t dataoff;
  uint32_t datasize;
} shdw_late_linkedit_lc;

typedef struct {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t rebase_off;
  uint32_t rebase_size;
  uint32_t bind_off;
  uint32_t bind_size;
  uint32_t weak_bind_off;
  uint32_t weak_bind_size;
  uint32_t lazy_bind_off;
  uint32_t lazy_bind_size;
  uint32_t export_off;
  uint32_t export_size;
} shdw_late_dyld_info_lc;

typedef struct {
  uint32_t fixups_version;
  uint32_t starts_offset;
  uint32_t imports_offset;
  uint32_t symbols_offset;
  uint32_t imports_count;
  uint32_t imports_format;
  uint32_t symbols_format;
} shdw_late_chained_header;

typedef struct {
  uint32_t size;
  uint16_t page_size;
  uint16_t pointer_format;
  uint64_t segment_offset;
  uint32_t max_valid_pointer;
  uint16_t page_count;
  // page_start[page_count] follows at byte 22 (flexible array, 8-byte struct
  // alignment must not be used to find it).
} shdw_late_starts_in_segment;

#define SHDW_LATE_MH_MAGIC_64 0xfeedfacfu
#define SHDW_LATE_LC_SEGMENT_64 0x19u
#define SHDW_LATE_LC_DYLD_INFO 0x22u
#define SHDW_LATE_LC_DYLD_INFO_ONLY 0x80000022u
#define SHDW_LATE_LC_DYLD_CHAINED_FIXUPS 0x80000034u

// dyld_chained_starts_in_segment.page_start sentinels.
#define SHDW_LATE_CHAINED_START_NONE 0xFFFFu
#define SHDW_LATE_CHAINED_START_MULTI 0x8000u

// Replacement lookup: return the pointer that must occupy a slot bound to
// `symbol`, or NULL to leave it alone. The name is exactly as spelled in the
// image's bind record (leading underscore included).
typedef void *(*shdw_late_lookup_fn)(const char *symbol, void *ctx);

// Store: write `replacement` into `slot` (a live, mapped cell inside the
// image). Returns 1 when the cell was changed, 0 when it already held the
// replacement or the write could not be made. The caller owns protection
// changes and any journal bookkeeping.
typedef uint32_t (*shdw_late_store_fn)(uintptr_t slot, void *replacement,
                                       void *ctx);

typedef struct {
  const void *mh;
  uintptr_t base;
  uint64_t slide;
  uint64_t text_vmaddr;
  const shdw_late_segment64 *seg[SHDW_LATE_MAX_SEGMENTS];
  uint32_t nseg;
  const shdw_late_dyld_info_lc *dyld_info;
  const shdw_late_linkedit_lc *chained;
} shdw_late_image_t;

static inline int shdw_late_uleb(const uint8_t **pp, const uint8_t *end,
                                 uint64_t *out) {
  uint64_t result = 0;
  uint32_t shift = 0;
  const uint8_t *p = *pp;
  while (p < end) {
    uint8_t byte = *p++;
    if (shift < 64) {
      result |= ((uint64_t)(byte & 0x7f)) << shift;
    }
    shift += 7;
    if (!(byte & 0x80)) {
      *pp = p;
      *out = result;
      return 1;
    }
  }
  return 0;
}

static inline int shdw_late_sleb(const uint8_t **pp, const uint8_t *end,
                                 int64_t *out) {
  uint64_t result = 0;
  uint32_t shift = 0;
  const uint8_t *p = *pp;
  while (p < end) {
    uint8_t byte = *p++;
    if (shift < 64) {
      result |= ((uint64_t)(byte & 0x7f)) << shift;
    }
    shift += 7;
    if (!(byte & 0x80)) {
      if (shift < 64 && (byte & 0x40)) {
        result |= (~(uint64_t)0) << shift;
      }
      *pp = p;
      *out = (int64_t)result;
      return 1;
    }
  }
  return 0;
}

static inline void shdw_late_image_parse(shdw_late_image_t *image,
                                         const void *mh) {
  memset(image, 0, sizeof(*image));
  image->mh = mh;
  image->base = (uintptr_t)mh;
  const shdw_late_mach_header64 *h = (const shdw_late_mach_header64 *)mh;
  if (h->magic != SHDW_LATE_MH_MAGIC_64) {
    return;
  }
  const uint8_t *p = (const uint8_t *)mh + sizeof(*h);
  const uint8_t *end = p + h->sizeofcmds;
  for (uint32_t i = 0; i < h->ncmds; i++) {
    if (p + 8 > end) {
      break;
    }
    const uint32_t cmd = *(const uint32_t *)p;
    const uint32_t cmdsize = *(const uint32_t *)(p + 4);
    if (cmdsize < 8 || p + cmdsize > end) {
      break;
    }
    if (cmd == SHDW_LATE_LC_SEGMENT_64 &&
        cmdsize >= sizeof(shdw_late_segment64)) {
      if (image->nseg < SHDW_LATE_MAX_SEGMENTS) {
        image->seg[image->nseg++] = (const shdw_late_segment64 *)p;
      }
    } else if (cmd == SHDW_LATE_LC_DYLD_INFO_ONLY ||
               cmd == SHDW_LATE_LC_DYLD_INFO) {
      if (cmdsize >= sizeof(shdw_late_dyld_info_lc)) {
        image->dyld_info = (const shdw_late_dyld_info_lc *)p;
      }
    } else if (cmd == SHDW_LATE_LC_DYLD_CHAINED_FIXUPS) {
      if (cmdsize >= sizeof(shdw_late_linkedit_lc)) {
        image->chained = (const shdw_late_linkedit_lc *)p;
      }
    }
    p += cmdsize;
  }

  for (uint32_t i = 0; i < image->nseg; i++) {
    if (memcmp(image->seg[i]->segname, "__TEXT", 6) == 0) {
      image->text_vmaddr = image->seg[i]->vmaddr;
      break;
    }
  }
  image->slide = image->base - image->text_vmaddr;
}

// Mapped address of [fileoff, fileoff+size) inside one of the image's
// segments, or NULL when the range is not fully file-backed.
static inline const uint8_t *shdw_late_file_ptr(const shdw_late_image_t *image,
                                                uint64_t fileoff,
                                                uint64_t size) {
  for (uint32_t i = 0; i < image->nseg; i++) {
    const shdw_late_segment64 *s = image->seg[i];
    if (fileoff >= s->fileoff && fileoff - s->fileoff <= s->filesize &&
        size <= s->filesize - (fileoff - s->fileoff)) {
      return (const uint8_t *)(image->slide + s->vmaddr +
                               (fileoff - s->fileoff));
    }
  }
  return NULL;
}

// Only data segments can hold import slots; anything else means the walk
// produced a bogus address, and writing there would corrupt the image.
static inline int shdw_late_slot_in_image(const shdw_late_image_t *image,
                                          uintptr_t slot) {
  for (uint32_t i = 0; i < image->nseg; i++) {
    const shdw_late_segment64 *s = image->seg[i];
    uintptr_t start = (uintptr_t)(image->slide + s->vmaddr);
    if (slot < start || s->vmsize < sizeof(void *) ||
        slot - start > s->vmsize - sizeof(void *)) {
      continue;
    }
    if (memcmp(s->segname, "__DATA", 6) == 0 ||
        memcmp(s->segname, "__AUTH", 6) == 0) {
      return 1;
    }
  }
  return 0;
}

static inline uint32_t shdw_late_bind(shdw_late_image_t *image, uint64_t vmaddr,
                                      const char *symbol,
                                      shdw_late_lookup_fn lookup,
                                      shdw_late_store_fn store, void *ctx) {
  if (!symbol || !symbol[0]) {
    return 0;
  }
  uintptr_t slot = (uintptr_t)(image->slide + vmaddr);
  if (!shdw_late_slot_in_image(image, slot)) {
    return 0;
  }
  void *replacement = lookup(symbol, ctx);
  if (!replacement) {
    return 0;
  }
  return store(slot, replacement, ctx) ? 1 : 0;
}

// Classic LC_DYLD_INFO bind opcode stream. Used for both the eager bind
// stream (__got) and the lazy one (__la_symbol_ptr): a lazily bound call
// re-enters dyld's stub and would resolve the real symbol past Shadow's
// rebind, so those cells are rewritten too. dyld terminates every lazy entry
// with DONE and resumes at the next sequence, so DONE only ends the walk on
// the eager stream — treating it as terminal left every lazy call stub
// unbound until dyld_stub_binder resolved it for real.
static inline uint32_t shdw_late_walk_bind_stream(
    shdw_late_image_t *image, uint32_t fileoff, uint32_t filesize, int lazy,
    shdw_late_lookup_fn lookup, shdw_late_store_fn store, void *ctx) {
  if (!fileoff || !filesize) {
    return 0;
  }
  const uint8_t *p = shdw_late_file_ptr(image, fileoff, filesize);
  if (!p) {
    return 0;
  }
  const uint8_t *end = p + filesize;

  uint32_t applied = 0;
  uint64_t addr = 0;
  uint32_t seg_index = 0;
  const char *symbol = NULL;

  while (p < end) {
    uint8_t byte = *p++;
    uint8_t op = byte & 0xF0;
    uint8_t imm = byte & 0x0F;
    uint64_t value = 0;

    switch (op) {
    case 0x00: // DONE
      if (lazy) {
        // End of one lazy sequence; dyld restarts at the next opcode.
        continue;
      }
      return applied;
    case 0x10: // SET_DYLIB_ORDINAL_IMM
      break;
    case 0x20: // SET_DYLIB_ORDINAL_ULEB
      if (!shdw_late_uleb(&p, end, &value)) {
        return applied;
      }
      break;
    case 0x30: // SET_DYLIB_SPECIAL_IMM
      break;
    case 0x40: { // SET_SYMBOL_TRAILING_FLAGS_IMM
      const uint8_t *start = p;
      while (p < end && *p) {
        p++;
      }
      if (p >= end) {
        return applied;
      }
      symbol = (const char *)start;
      p++;
      break;
    }
    case 0x50: // SET_TYPE_IMM
      break;
    case 0x60: { // SET_ADDEND_SLEB
      int64_t addend = 0;
      if (!shdw_late_sleb(&p, end, &addend)) {
        return applied;
      }
      break;
    }
    case 0x70: // SET_SEGMENT_AND_OFFSET_ULEB
      seg_index = imm;
      if (!shdw_late_uleb(&p, end, &value) || seg_index >= image->nseg) {
        return applied;
      }
      addr = image->seg[seg_index]->vmaddr + value;
      break;
    case 0x80: // ADD_ADDR_ULEB
      if (!shdw_late_uleb(&p, end, &value)) {
        return applied;
      }
      addr += value;
      break;
    case 0x90: // DO_BIND
      applied += shdw_late_bind(image, addr, symbol, lookup, store, ctx);
      addr += sizeof(void *);
      break;
    case 0xA0: // DO_BIND_ADD_ADDR_ULEB
      if (!shdw_late_uleb(&p, end, &value)) {
        return applied;
      }
      applied += shdw_late_bind(image, addr, symbol, lookup, store, ctx);
      addr += sizeof(void *) + value;
      break;
    case 0xB0: // DO_BIND_ADD_ADDR_IMM_SCALED
      applied += shdw_late_bind(image, addr, symbol, lookup, store, ctx);
      addr += sizeof(void *) + (uint64_t)imm * sizeof(void *);
      break;
    case 0xC0: { // DO_BIND_ULEB_TIMES_SKIPPING_ULEB
      uint64_t count = 0;
      uint64_t skip = 0;
      if (!shdw_late_uleb(&p, end, &count) || !shdw_late_uleb(&p, end, &skip)) {
        return applied;
      }
      for (uint64_t i = 0; i < count && p <= end; i++) {
        applied += shdw_late_bind(image, addr, symbol, lookup, store, ctx);
        addr += sizeof(void *) + skip;
      }
      break;
    }
    default:
      return applied;
    }
  }
  return applied;
}

static inline const char *
shdw_late_import_name(const shdw_late_chained_header *header, uint32_t ordinal,
                      const uint8_t *data, const uint8_t *data_end) {
  if (ordinal >= header->imports_count) {
    return NULL;
  }
  const uint8_t *imports = data + header->imports_offset;
  const uint8_t *symbols = data + header->symbols_offset;
  uint32_t name_offset = 0;

  if (header->imports_format == 1) { // DYLD_CHAINED_IMPORT
    if (imports + (uint64_t)(ordinal + 1) * 4 > data_end) {
      return NULL;
    }
    name_offset = ((const uint32_t *)imports)[ordinal] >> 9;
  } else if (header->imports_format == 2) { // DYLD_CHAINED_IMPORT_ADDEND
    if (imports + (uint64_t)(ordinal + 1) * 8 > data_end) {
      return NULL;
    }
    name_offset = ((const uint32_t *)imports)[ordinal * 2] >> 9;
  } else if (header->imports_format == 3) { // DYLD_CHAINED_IMPORT_ADDEND64
    if (imports + (uint64_t)(ordinal + 1) * 16 > data_end) {
      return NULL;
    }
    // Little-endian: the low word is lib_ordinal/weak/reserved, the high word
    // is name_offset.
    name_offset = ((const uint32_t *)imports)[ordinal * 4 + 1];
  } else {
    return NULL;
  }

  if (symbols + name_offset >= data_end) {
    return NULL;
  }
  const char *name = (const char *)(symbols + name_offset);
  if (!memchr(name, 0, (size_t)(data_end - (const uint8_t *)name))) {
    return NULL;
  }
  return name;
}

static inline uint32_t
shdw_late_walk_chain(shdw_late_image_t *image, uintptr_t loc, uint16_t format,
                     const shdw_late_chained_header *h, const uint8_t *data,
                     const uint8_t *data_end, shdw_late_lookup_fn lookup,
                     shdw_late_store_fn store, void *ctx) {
  uint32_t applied = 0;
  for (uint32_t step = 0; step < 4096; step++) {
    if (!shdw_late_slot_in_image(image, loc)) {
      break;
    }
    uint64_t value = *(const uint64_t *)loc;
    uint64_t ordinal = 0;
    uint64_t next = 0;
    uint32_t stride = 8;
    int is_bind = 0;

    switch (format) {
    case 1:  // DYLD_CHAINED_PTR_ARM64E
    case 7:  // DYLD_CHAINED_PTR_ARM64E_KERNEL
    case 9:  // DYLD_CHAINED_PTR_ARM64E_USERLAND
    case 10: // DYLD_CHAINED_PTR_ARM64E_FIRMWARE
    case 11: // DYLD_CHAINED_PTR_ARM64E_USERLAND24
    case 12: // DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE
      is_bind = (int)((value >> 62) & 1);
      next = (value >> 51) & 0x7FF;
      stride = 8;
      ordinal = (format == 11) ? (value & 0xFFFFFF) : (value & 0xFFFF);
      break;
    case 2: // DYLD_CHAINED_PTR_64
    case 6: // DYLD_CHAINED_PTR_64_OFFSET
      is_bind = (int)((value >> 63) & 1);
      next = (value >> 51) & 0xFFF;
      stride = 4;
      ordinal = value & 0xFFFFFF;
      break;
    default:
      return applied;
    }

    if (is_bind) {
      const char *symbol =
          shdw_late_import_name(h, (uint32_t)ordinal, data, data_end);
      if (symbol) {
        uintptr_t slot = loc;
        if (shdw_late_slot_in_image(image, slot)) {
          void *replacement = lookup(symbol, ctx);
          if (replacement) {
            applied += store(slot, replacement, ctx) ? 1 : 0;
          }
        }
      }
    }

    if (!next) {
      break;
    }
    loc += next * stride;
  }
  return applied;
}

static inline uint32_t shdw_late_walk_chained(shdw_late_image_t *image,
                                              shdw_late_lookup_fn lookup,
                                              shdw_late_store_fn store,
                                              void *ctx) {
  const shdw_late_linkedit_lc *lc = image->chained;
  if (!lc || !lc->dataoff || lc->datasize < sizeof(shdw_late_chained_header)) {
    return 0;
  }
  const uint8_t *data = shdw_late_file_ptr(image, lc->dataoff, lc->datasize);
  if (!data) {
    return 0;
  }
  const uint8_t *data_end = data + lc->datasize;
  const shdw_late_chained_header *h = (const shdw_late_chained_header *)data;
  if (h->fixups_version != 0 || h->symbols_format != 0) {
    return 0;
  }
  if (h->starts_offset + 4 > lc->datasize) {
    return 0;
  }
  uint32_t seg_count = *(const uint32_t *)(data + h->starts_offset);
  if (seg_count > image->nseg ||
      h->starts_offset + 4 + (uint64_t)seg_count * 4 > lc->datasize) {
    return 0;
  }
  const uint8_t *starts = data + h->starts_offset;
  const uint32_t *seg_info = (const uint32_t *)(starts + 4);
  const uint8_t *starts_end = data_end;

  uint32_t applied = 0;
  for (uint32_t si = 0; si < seg_count; si++) {
    // seg_info_offset is relative to the starts_in_image struct, not to the
    // fixups header.
    uint32_t info_offset = seg_info[si];
    const uint8_t *ss_bytes = starts + info_offset;
    if (!info_offset || ss_bytes < starts ||
        (uint64_t)(starts_end - ss_bytes) < 22) {
      continue;
    }
    const shdw_late_starts_in_segment *ss =
        (const shdw_late_starts_in_segment *)ss_bytes;
    if (ss->page_size == 0 ||
        (uint64_t)(starts_end - ss_bytes) < 22 + (uint64_t)ss->page_count * 2) {
      continue;
    }
    const uint16_t *page_start = (const uint16_t *)((const uint8_t *)ss + 22);
    uintptr_t seg_base = image->base + (uintptr_t)ss->segment_offset;

    for (uint32_t page = 0; page < ss->page_count; page++) {
      uint16_t start = page_start[page];
      if (start == SHDW_LATE_CHAINED_START_NONE) {
        continue;
      }
      if (start & SHDW_LATE_CHAINED_START_MULTI) {
        // Overflow list: page_start[start & 0x7FFF] onward until NONE.
        uint32_t idx = start & 0x7FFF;
        while (idx < ss->page_count &&
               page_start[idx] != SHDW_LATE_CHAINED_START_NONE) {
          applied += shdw_late_walk_chain(
              image,
              seg_base + (uintptr_t)page * ss->page_size + page_start[idx],
              ss->pointer_format, h, data, data_end, lookup, store, ctx);
          idx++;
        }
        continue;
      }
      applied += shdw_late_walk_chain(
          image, seg_base + (uintptr_t)page * ss->page_size + start,
          ss->pointer_format, h, data, data_end, lookup, store, ctx);
    }
  }
  return applied;
}

// Rebind every import slot of the image whose symbol the lookup resolves,
// returning how many cells were changed. Safe to call from an add-image
// callback: it reads only the image's own mapped bytes.
static inline uint32_t shdw_late_image_rebind(const void *mh,
                                              shdw_late_lookup_fn lookup,
                                              shdw_late_store_fn store,
                                              void *ctx) {
  if (!mh || !lookup || !store) {
    return 0;
  }
  shdw_late_image_t image;
  shdw_late_image_parse(&image, mh);
  if (!image.nseg) {
    return 0;
  }
  uint32_t applied = 0;
  const shdw_late_dyld_info_lc *info = image.dyld_info;
  if (info) {
    applied += shdw_late_walk_bind_stream(
        &image, info->bind_off, info->bind_size, 0, lookup, store, ctx);
    applied +=
        shdw_late_walk_bind_stream(&image, info->lazy_bind_off,
                                   info->lazy_bind_size, 1, lookup, store, ctx);
  }
  applied += shdw_late_walk_chained(&image, lookup, store, ctx);
  return applied;
}

#endif
