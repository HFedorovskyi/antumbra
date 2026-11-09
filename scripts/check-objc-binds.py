#!/usr/bin/env python3
"""Fail when an arm64e image has unauthenticated ObjC class reference binds.

iOS 18 libobjc authenticates class references while mapping an arm64e image:
map_images_nolock -> readClass -> missingWeakSuperclass traps on a plain BIND,
so a bundle whose superclass slots are not BIND_AUTH brk's before any +load.
The Mach-O ABI subtype does not reveal this -- only the chained-fixup auth bit
does -- hence a dedicated check next to the subtype assertions.
"""
import struct
import sys

CHAINED_FIXUPS = 0x80000034
SEGMENT_64 = 0x19
CPU_TYPE_ARM64 = 0x0100000C
CPU_SUBTYPE_ARM64E = 2
CPU_SUBTYPE_PTRAUTH_ABI = 0x80000000
ARM64E_FMTS = {1, 7, 9, 10, 12}


def slice_for(data, require_auth_abi):
    if struct.unpack('>I', data[:4])[0] != 0xCAFEBABE:
        return data
    count = struct.unpack('>I', data[4:8])[0]
    off = 8
    for _ in range(count):
        _, subtype, start, size, _ = struct.unpack('>5I', data[off:off + 20])
        if (subtype & ~CPU_SUBTYPE_PTRAUTH_ABI) == CPU_SUBTYPE_ARM64E:
            if require_auth_abi and (subtype & CPU_SUBTYPE_PTRAUTH_ABI):
                return data[start:start + size]
            if not require_auth_abi:
                return data[start:start + size]
        off += 20
    return None


class Image:
    def __init__(self, data):
        self.data = data
        cputype, cpusubtype = struct.unpack('<II', data[4:12])
        ncmds = struct.unpack('<I', data[16:20])[0]
        self.new_abi = cpusubtype == (CPU_SUBTYPE_PTRAUTH_ABI | CPU_SUBTYPE_ARM64E)
        self.ok_cpu = cputype == CPU_TYPE_ARM64
        self.segments = {}
        self.sections = {}
        self.fixups = None
        off = 32
        for _ in range(ncmds):
            cmd, size = struct.unpack('<II', data[off:off + 8])
            if cmd == SEGMENT_64:
                name = data[off + 8:off + 24].rstrip(b'\0').decode()
                va, vsize, foff, fsize = struct.unpack('<QQQQ', data[off + 24:off + 56])
                nsects = struct.unpack('<I', data[off + 64:off + 68])[0]
                self.segments[name] = (va, vsize, foff, fsize)
                sect = off + 72
                for _ in range(nsects):
                    sname = data[sect:sect + 16].rstrip(b'\0').decode()
                    seg = data[sect + 16:sect + 32].rstrip(b'\0').decode()
                    addr, ssize = struct.unpack('<QQ', data[sect + 32:sect + 48])
                    self.sections[seg + ',' + sname] = (addr, ssize)
                    sect += 80
            elif cmd == CHAINED_FIXUPS:
                self.fixups = struct.unpack('<II', data[off + 8:off + 16])
            off += size

    def read(self, va, size):
        for seg_va, _, foff, fsize in self.segments.values():
            if seg_va <= va < seg_va + fsize:
                start = foff + (va - seg_va)
                return self.data[start:start + size]
        return None

    def cstr(self, va):
        out = b''
        while len(out) < 512:
            byte = self.read(va + len(out), 1)
            if not byte or byte == b'\0':
                return out.decode('utf-8', 'replace')
            out += byte
        return ''


def walk_fixups(image):
    """Return {address: (kind, target_or_ordinal)} for every chained entry."""
    if image.fixups is None:
        return None
    base, _ = image.fixups
    _, starts_off, imports_off, symbols_off, imports_count, ifmt, _ = struct.unpack(
        '<7I', image.data[base:base + 28])
    entries = {}
    start = base + starts_off
    seg_count = struct.unpack('<I', image.data[start:start + 4])[0]
    for seg_index in range(seg_count):
        seg_off = struct.unpack('<I', image.data[start + 4 + 4 * seg_index:start + 8 + 4 * seg_index])[0]
        if not seg_off:
            continue
        head = start + seg_off
        _, page_size, fmt, seg_base, _, page_count = struct.unpack(
            '<IHHQIH', image.data[head:head + 22])
        if fmt not in ARM64E_FMTS:
            continue
        stride = 4 if fmt in (3, 4, 5) else 8
        page_starts = struct.unpack('<%dH' % page_count, image.data[head + 22:head + 22 + 2 * page_count])
        for page_index, page_start in enumerate(page_starts):
            if page_start == 0xFFFF:
                continue
            page = seg_base + page_index * page_size
            if page_start & 0x8000:
                cursor = head + (page_start & 0x7FFF)
                offsets = []
                while True:
                    value = struct.unpack('<H', image.data[cursor:cursor + 2])[0]
                    cursor += 2
                    if value == 0:
                        break
                    offsets.append(value)
            else:
                offsets = [page_start]
            for extra in offsets:
                va = page + extra
                while True:
                    raw = struct.unpack('<Q', image.read(va, 8))[0]
                    auth = (raw >> 63) & 1
                    bind = (raw >> 62) & 1
                    nxt = (raw >> 51) & 0x7FF
                    if auth and bind:
                        entries[va] = ('BIND_AUTH', raw & 0xFFFF)
                    elif auth:
                        entries[va] = ('REBASE_AUTH', raw & 0xFFFFFFFF)
                    elif bind:
                        entries[va] = ('BIND', raw & (0xFFFFFF if fmt == 12 else 0xFFFF))
                    else:
                        entries[va] = ('REBASE', raw & 0x7FFFFFFFFFF)
                    if nxt == 0:
                        break
                    va += nxt * stride
    return entries, imports_off, symbols_off, imports_count, ifmt, base


def import_name(image, imports_off, symbols_off, ifmt, base, ordinal):
    if ifmt == 1:
        raw = struct.unpack('<I', image.data[base + imports_off + 4 * ordinal:
                                              base + imports_off + 4 * ordinal + 4])[0]
        sym_off = (raw >> 9) & 0x7FFFF
    elif ifmt == 2:
        raw = struct.unpack('<II', image.data[base + imports_off + 8 * ordinal:
                                               base + imports_off + 8 * ordinal + 8])[0]
        sym_off = (raw >> 9) & 0x7FFFF
    else:
        raw = struct.unpack('<Q', image.data[base + imports_off + 16 * ordinal:
                                             base + imports_off + 16 * ordinal + 8])[0]
        sym_off = (raw >> 9) & 0x7FFFF
    start = base + symbols_off + sym_off
    return image.data[start:].split(b'\0')[0].decode('utf-8', 'replace')


def deref(entries, va):
    entry = entries.get(va)
    if not entry:
        return None
    kind, target = entry
    if kind == 'REBASE':
        return target
    return None


def main(argv):
    if len(argv) < 2:
        print('usage: %s MACH-O [--allow-missing-classlist]' % argv[0], file=sys.stderr)
        return 2
    path = argv[1]
    allow_missing = '--allow-missing-classlist' in argv
    with open(path, 'rb') as handle:
        raw = handle.read()
    data = slice_for(raw, require_auth_abi=True)
    if data is None:
        print('%s: no arm64e slice' % path, file=sys.stderr)
        return 1
    image = Image(data)
    if not image.ok_cpu:
        print('%s: not arm64' % path, file=sys.stderr)
        return 1
    if not image.new_abi:
        print('%s: old ABI slice, authenticated binds not expected' % path)
        return 0
    walked = walk_fixups(image)
    if walked is None:
        print('%s: no LC_DYLD_CHAINED_FIXUPS' % path, file=sys.stderr)
        return 1
    entries, imports_off, symbols_off, imports_count, ifmt, base = walked
    classlist = image.sections.get('__DATA_CONST,__objc_classlist') or \
        image.sections.get('__DATA,__objc_classlist')
    if not classlist or classlist[1] == 0:
        if allow_missing:
            print('%s: no __objc_classlist (allowed)' % path)
            return 0
        print('%s: no __objc_classlist' % path, file=sys.stderr)
        return 1

    violations = []
    checked = 0
    auth_binds = 0
    for index in range(classlist[1] // 8):
        slot = classlist[0] + index * 8
        cls = deref(entries, slot)
        if cls is None:
            violations.append('classlist[%d] @%#x is %s, not a pointer rebase'
                              % (index, slot, entries.get(slot, ('GAP',))[0]))
            continue
        checked += 1
        sup_va = cls + 8
        sup_entry = entries.get(sup_va)
        if sup_entry is None:
            continue
        kind, target = sup_entry
        if kind == 'BIND_AUTH':
            auth_binds += 1
            continue
        if kind == 'BIND':
            symbol = import_name(image, imports_off, symbols_off, ifmt, base, target)
            violations.append('class @%#x superclass bind %s is plain BIND, not BIND_AUTH'
                              % (cls, symbol))

    if violations:
        for line in violations:
            print('%s: %s' % (path, line), file=sys.stderr)
        print('%s: FAILED -- %d unauthenticated ObjC class reference(s); compile this '
              'bundle with clang 21 and -fptrauth-objc-isa -fptrauth-objc-class-ro '
              '-fptrauth-objc-interface-sel' % (path, len(violations)), file=sys.stderr)
        return 1
    print('%s: OK -- %d class(es), %d authenticated superclass bind(s)' % (path, checked, auth_binds))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
