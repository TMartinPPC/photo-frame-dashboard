#!/usr/bin/env python3
"""Build the PF1007L root-ADB boot patch from YOUR OWN verified eMMC backup.

Usage (from the repository root):
  python3 -I scripts/a33-uboot/boot-patch.py backups/a33-emmc-full.img 172032

The second argument is the boot partition's start sector on your unit. Find it
by parsing your own partition table; do not copy it from another unit.

Writes diagnostics/a33-boot-patch/:
  orig-header.bin, new-header.bin       first sectors of the boot image
  orig-ramdisk.bin, new-ramdisk.bin     the padded ramdisk slot
  plan.json                             sectors, sizes and CRC-32s (plus SHA-256s)
  write-boot.cmd / write-boot.scr       guarded U-Boot write script (FEL payloads)
  restore-boot.cmd / restore-boot.scr   guarded undo: writes the original bytes back

With --sd as a third argument, also writes sd-write-boot.cmd/.scr and
sd-restore-boot.cmd/.scr: the same guards, but the payloads are fatload'ed from
the card's FAT partition and verified with `hash sha256` instead of `crc32 -v`.
Use these on units where large FEL uploads corrupt, with the Route S SD-boot
U-Boot build (needs CONFIG_CMD_FAT, CONFIG_FAT_WRITE, CONFIG_CMD_HASH,
CONFIG_SHA256 — all in a33.config). Every sector, size and digest in the
generated script comes from this run; do not hand-edit or reuse across units.

Nothing here touches a device. The U-Boot script only writes when every payload
matches its CRC-32 and the eMMC still holds the original bytes from your backup.
"""

import gzip
import hashlib
import json
import struct
import sys
import time
import zlib
from pathlib import Path

SECTOR = 512
REPO = Path(__file__).resolve().parents[2]
OUT = REPO / "diagnostics/a33-boot-patch"

# DRAM load addresses used by write-boot.cmd (U-Boot itself runs from 0x4A000000).
ADDR = {"orig_header": 0x50000000, "orig_ramdisk": 0x51000000,
        "new_header": 0x52000000, "new_ramdisk": 0x53000000,
        "read_header": 0x54000000, "read_ramdisk": 0x55000000}

OLD_ACTION = (b"on property:sys.usb.config=mass_storage\n"
              b"    write /sys/class/android_usb/android0/enable\t0\n"
              b"    write /sys/class/android_usb/android0/idVendor\t1f3a\n"
              b"    write /sys/class/android_usb/android0/idProduct\t1000\n"
              b"    write /sys/class/android_usb/android0/functions\t${sys.usb.config}\n"
              b"    write /sys/class/android_usb/android0/enable \t1\n"
              b"    setprop sys.usb.state ${sys.usb.config}\n")
NEW_ACTION = (b"on property:sys.usb.config=mass_storage\n"
              b"    write /sys/class/android_usb/android0/enable 0\n"
              b"    write /sys/class/android_usb/android0/idVendor 1f3a\n"
              b"    write /sys/class/android_usb/android0/idProduct 1002\n"
              b"    write /sys/class/android_usb/android0/functions mass_storage,adb\n"
              b"    write /sys/class/android_usb/android0/enable 1\n"
              b"    start adbd\n"
              b"    setprop sys.usb.state ${sys.usb.config}\n")


def fail(message):
    sys.exit(f"STOP: {message}")


def partitions(image):
    """MBR primary + extended/logical partitions as (start, sectors)."""
    def entries(block):
        return [(block[446 + i * 16 + 4], *struct.unpack_from("<II", block, 446 + i * 16 + 8))
                for i in range(4)]

    image.seek(0)
    mbr = image.read(SECTOR)
    if mbr[510:] != b"\x55\xaa":
        fail("no MBR signature")
    found, extended = [], None
    for kind, start, count in entries(mbr):
        if kind in (0x05, 0x0F):
            extended = start
        elif kind:
            found.append((start, count))
    ebr = extended
    while ebr is not None:
        image.seek(ebr * SECTOR)
        first, second = entries(image.read(SECTOR))[:2]
        found.append((ebr + first[1], first[2]))
        ebr = extended + second[1] if second[0] else None
    return found


def parse_boot(boot):
    magic, kernel_size, _, ramdisk_size, _, second_size, _, _, page = struct.unpack_from("<8s8I", boot, 0)
    if magic != b"ANDROID!":
        fail("not an Android boot image at that sector")
    if page != 2048 or second_size != 0 or boot[40:44] != bytes(4):
        fail("unexpected page size, second stage or header version")
    pad = lambda n: (n + page - 1) // page * page
    kernel = boot[page:page + kernel_size]
    ramdisk_offset = page + pad(kernel_size)
    ramdisk = boot[ramdisk_offset:ramdisk_offset + ramdisk_size]
    digest = hashlib.sha1()
    for part in (kernel, ramdisk, b""):
        digest.update(part)
        digest.update(struct.pack("<I", len(part)))
    if boot[576:596] != digest.digest() or boot[596:608] != bytes(12):
        fail("boot image ID does not match its contents")
    if ramdisk[:2] != b"\x1f\x8b":
        fail("ramdisk is not gzip")
    return kernel, ramdisk_offset, pad(ramdisk_size), gzip.decompress(ramdisk)


def cpio_records(cpio):
    """newc records as (name, header, name_and_padding, data)."""
    offset, records = 0, []
    while True:
        header = cpio[offset:offset + 110]
        if header[:6] != b"070701":
            fail(f"bad cpio header at {offset}")
        file_size, name_size = int(header[54:62], 16), int(header[94:102], 16)
        name = cpio[offset + 110:offset + 110 + name_size - 1]
        data_offset = (offset + 110 + name_size + 3) & ~3
        records.append((name, header, cpio[offset + 110:data_offset],
                        cpio[data_offset:data_offset + file_size]))
        offset = (data_offset + file_size + 3) & ~3
        if name == b"TRAILER!!!":
            return records, cpio[offset:]


def patch_cpio(cpio):
    records, tail = cpio_records(cpio)
    out, changed = bytearray(), 0
    for name, header, name_part, data in records:
        if name == b"init.sun8i.usb.rc":
            if data.count(OLD_ACTION) != 1:
                fail("the stock mass_storage action was not found exactly once")
            data = data.replace(OLD_ACTION, NEW_ACTION)
            header = header[:54] + b"%08X" % len(data) + header[62:]
            changed += 1
        record = header + name_part
        out += record + data + bytes(-(len(record) + len(data)) % 4)
    if changed != 1:
        fail("init.sun8i.usb.rc not found")
    return bytes(out + tail)


def build(boot):
    kernel, ramdisk_offset, slot, cpio = parse_boot(boot)
    new_cpio = patch_cpio(cpio)
    ramdisk = min((gzip.compress(new_cpio, compresslevel=level, mtime=0) for level in range(1, 10)), key=len)
    if len(ramdisk) > slot:
        fail(f"patched ramdisk ({len(ramdisk)}) does not fit the original slot ({slot})")
    digest = hashlib.sha1()
    for part in (kernel, ramdisk, b""):
        digest.update(part)
        digest.update(struct.pack("<I", len(part)))
    new = bytearray(boot)
    struct.pack_into("<I", new, 16, len(ramdisk))
    new[576:608] = digest.digest() + bytes(12)
    new[ramdisk_offset:ramdisk_offset + slot] = ramdisk + bytes(slot - len(ramdisk))
    return bytes(new), ramdisk_offset, slot


def verify(old, new, ramdisk_offset, slot):
    """Independent re-parse: one rc file changed, nothing outside header + slot."""
    _, _, _, old_cpio = parse_boot(old)
    _, _, _, new_cpio = parse_boot(new)
    old_records, _ = cpio_records(old_cpio)
    new_records, _ = cpio_records(new_cpio)
    if [r[0] for r in old_records] != [r[0] for r in new_records]:
        fail("cpio file list or order changed")
    changed = [o[0] for o, n in zip(old_records, new_records) if o[1:] != n[1:]]
    if changed != [b"init.sun8i.usb.rc"]:
        fail(f"unexpected cpio changes: {changed}")
    header_diffs = [i for i in range(ramdisk_offset) if old[i] != new[i]]
    if not header_diffs or not all(16 <= i < 20 or 576 <= i < 596 for i in header_diffs):
        fail("header changed outside the ramdisk size and image ID")
    if old[ramdisk_offset + slot:] != new[ramdisk_offset + slot:]:
        fail("bytes after the ramdisk slot changed")
    # The image ID ends at byte 595: the header write must cover two sectors, not one.
    return (header_diffs[-1] // SECTOR) + 1


def script_image(text):
    """Legacy U-Boot script image, as `mkimage -A arm -T script -C none` makes it."""
    body = struct.pack(">II", len(text), 0) + text
    header = bytearray(struct.pack(">IIIIIIIBBBB32s", 0x27051956, 0, int(time.time()), len(body),
                                   0, 0, zlib.crc32(body), 5, 2, 6, 0, b""))
    struct.pack_into(">I", header, 4, zlib.crc32(header))
    return bytes(header) + body


def sd_script(name, expect, write, header_sector, header_sectors, ramdisk_sector,
              ramdisk_sectors, header_bytes, slot, p6_sectors, payloads, sha):
    """Same guard chain as guarded_script(), payloads from the card, sha256 checks.

    Runs under the Route S SD-boot U-Boot (no ums, no crc32 -v): fatload each
    payload from the card's FAT partition, `hash sha256`-verify it, compare the
    eMMC against the expected bytes, write the ramdisk, read it back, then write
    the header last. Ends by re-reading the whole partition, hashing it and
    writing a33-status.txt to the card for the host to compare.
    """
    def checks():
        out = []
        for kind in ("orig", "new"):
            for part, size in (("header", header_bytes), ("ramdisk", slot)):
                addr, fname = ADDR[f"{kind}_{part}"], f"{kind}-{part}.bin"
                out.append(f'if fatload mmc 0:1 {addr:#x} {fname}; then test ${{filesize}} = {size:x} || setenv fl_ok size; else setenv fl_ok no-{fname}; fi')
                out.append(f'if test ${{fl_ok}} = yes; then hash sha256 {addr:#x} {size:#x} {sha[f"{kind}_{part}"]} || setenv fl_ok sha-{fname}; else setenv fl_ok skip-{fname}; fi')
                out.append(f'if test ${{fl_ok}} != yes; then setenv w_result "REFUSED_{fname} ${{fl_ok}}"; env export -t ${{e}}; fatwrite mmc 0:1 ${{e}} a33-status.txt ${{filesize}}; exit; fi')
        return out

    cmp_checks = [f"cmp.b {ADDR[f'{expect}_{part}']:#x} {ADDR['read_' + part]:#x} {size:#x}"
                  for part, size in (("header", header_bytes), ("ramdisk", slot))]
    return f"""# {name} for the PF1007L: payloads from the SD card (no FEL upload, no ums).
# Values (sectors, sizes, digests) were generated by boot-patch.py --sd from a
# verified dump on this unit. Regenerate for every unit; never reuse or edit.
# Payload files must sit in the card's FAT partition next to this script.
mmc dev 1
setenv fl_ok yes
{chr(10).join(checks())}
mmc read {ADDR['read_header']:#x} {header_sector:#x} {header_sectors:#x}
mmc read {ADDR['read_ramdisk']:#x} {ramdisk_sector:#x} {ramdisk_sectors:#x}
if {' && '.join(cmp_checks)}; then
  if mmc write {ADDR[f'{write}_ramdisk']:#x} {ramdisk_sector:#x} {ramdisk_sectors:#x}; then
    mmc read {ADDR['read_ramdisk']:#x} {ramdisk_sector:#x} {ramdisk_sectors:#x}
    if cmp.b {ADDR[f'{write}_ramdisk']:#x} {ADDR['read_ramdisk']:#x} {slot:#x}; then
      if mmc write {ADDR[f'{write}_header']:#x} {header_sector:#x} {header_sectors:#x}; then
        setenv w_result OK_WRITTEN
        mmc read 0x48000000 {header_sector:#x} {p6_sectors:#x}
        hash sha256 0x48000000 {p6_sectors * SECTOR:#x} p6_hash_after
      else
        setenv w_result FAIL_HEADER_WRITE
      fi
    else
      setenv w_result FAIL_RAMDISK_READBACK
    fi
  else
    setenv w_result FAIL_RAMDISK_WRITE
  fi
else
  setenv w_result REFUSED_P6_NOT_EXPECTED_CONTENT
fi
env export -t ${{e}}
fatwrite mmc 0:1 ${{e}} a33-status.txt ${{filesize}}
"""


def main():
    args = sys.argv[1:]
    make_sd = "--sd" in args
    args = [a for a in args if a != "--sd"]
    if len(args) != 2 or (len(sys.argv) > 3 and not make_sd):
        sys.exit(__doc__)
    image_path, boot_sector = Path(args[0]), int(args[1])
    with open(image_path, "rb") as image:
        sizes = {start: count for start, count in partitions(image)}
        if boot_sector not in sizes:
            fail("that sector is not the start of a partition in this image")
        image.seek(boot_sector * SECTOR)
        old = image.read(sizes[boot_sector] * SECTOR)

    new, ramdisk_offset, slot = build(old)
    header_sectors = verify(old, new, ramdisk_offset, slot)
    header_bytes = header_sectors * SECTOR
    if old[header_bytes:ramdisk_offset] != new[header_bytes:ramdisk_offset]:
        fail("bytes between the header write and the ramdisk slot changed")

    OUT.mkdir(parents=True, exist_ok=True)
    payloads = {
        "orig_header": old[:header_bytes], "new_header": new[:header_bytes],
        "orig_ramdisk": old[ramdisk_offset:ramdisk_offset + slot],
        "new_ramdisk": new[ramdisk_offset:ramdisk_offset + slot],
    }
    for name, data in payloads.items():
        (OUT / f"{name.replace('_', '-')}.bin").write_bytes(data)
    crc = {name: f"{zlib.crc32(data):08x}" for name, data in payloads.items()}

    header_sector, ramdisk_sector = boot_sector, boot_sector + ramdisk_offset // SECTOR
    ramdisk_sectors = slot // SECTOR

    def guarded_script(title, expect, write):
        """Write `write` payloads only if all CRCs match and the flash holds `expect`."""
        checks = [f"crc32 -v {ADDR[f'{kind}_{part}']:#x} {size:#x} {crc[f'{kind}_{part}']}"
                  for kind in ("orig", "new") for part, size in (("header", header_bytes), ("ramdisk", slot))]
        checks += [f"cmp.b {ADDR[f'{expect}_header']:#x} {ADDR['read_header']:#x} {header_bytes:#x}",
                   f"cmp.b {ADDR[f'{expect}_ramdisk']:#x} {ADDR['read_ramdisk']:#x} {slot:#x}"]
        return f"""# {title}. Load the payloads with sunxi-fel first:
#   {ADDR['orig_header']:#x} orig-header.bin    {ADDR['orig_ramdisk']:#x} orig-ramdisk.bin
#   {ADDR['new_header']:#x} new-header.bin     {ADDR['new_ramdisk']:#x} new-ramdisk.bin
# Writes only if every payload matches its CRC-32 AND the eMMC holds the {expect} bytes.
mmc dev 1
mmc read {ADDR['read_header']:#x} {header_sector:#x} {header_sectors:#x}
mmc read {ADDR['read_ramdisk']:#x} {ramdisk_sector:#x} {ramdisk_sectors:#x}
# Stop at the first failure: the header is written last, and only if the ramdisk write
# succeeded and reads back byte-for-byte. The host's verify step then shows exactly which
# range is wrong. A failed write still needs the restore procedure.
if {' && '.join(checks)}; then
  if mmc write {ADDR[f'{write}_ramdisk']:#x} {ramdisk_sector:#x} {ramdisk_sectors:#x} && mmc read {ADDR['read_ramdisk']:#x} {ramdisk_sector:#x} {ramdisk_sectors:#x} && cmp.b {ADDR[f'{write}_ramdisk']:#x} {ADDR['read_ramdisk']:#x} {slot:#x}; then
    mmc write {ADDR[f'{write}_header']:#x} {header_sector:#x} {header_sectors:#x}
  fi
fi
ums 0 mmc 1
"""

    sha = {name: hashlib.sha256(data).hexdigest() for name, data in payloads.items()}
    for name, title, expect, write in (("write-boot", "PF1007L boot patch", "orig", "new"),
                                       ("restore-boot", "Undo the PF1007L boot patch", "new", "orig")):
        script = guarded_script(title, expect, write)
        (OUT / f"{name}.cmd").write_text(script)
        (OUT / f"{name}.scr").write_bytes(script_image(script.encode()))
        if make_sd:
            sd = sd_script(name, expect, write, header_sector, header_sectors,
                           ramdisk_sector, ramdisk_sectors, header_bytes, slot,
                           sizes[boot_sector], payloads, sha)
            (OUT / f"sd-{name}.cmd").write_text(sd)
            (OUT / f"sd-{name}.scr").write_bytes(script_image(sd.encode()))
    plan = {
        "writes": [
            {"sector": ramdisk_sector, "sectors": ramdisk_sectors, "file": "new-ramdisk.bin"},
            {"sector": header_sector, "sectors": header_sectors, "file": "new-header.bin"},
        ],
        "crc32": crc,
        "sha256": sha,
    }
    (OUT / "plan.json").write_text(json.dumps(plan, indent=2) + "\n")

    print(f"Boot image at sector {boot_sector}: ramdisk slot {slot} bytes at +{ramdisk_offset}")
    print(f"Write ranges: ramdisk [{ramdisk_sector}, {ramdisk_sector + ramdisk_sectors}), "
          f"header [{header_sector}, {header_sector + header_sectors})")
    print("Checks passed: one cpio file changed; header changes limited to ramdisk size + ID.")
    print(f"Wrote {OUT}")


if __name__ == "__main__":
    main()
