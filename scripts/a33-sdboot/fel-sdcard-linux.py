"""Linux port of scripts/a33-sdboot/fel-sdcard.py prepare (Windows-only upstream).
Writes the SD-boot U-Boot image to the card's boot area at byte 8192, with the same
guards: MBR, no GPT, partitions >= 1 MiB, refuses an existing non-stub boot image,
pads to a sector boundary with the card's own bytes, double-reads before, compares
after. Refuses to proceed if anything unexpected.

Usage: sudo env CARD=/dev/sdX IMAGE=diagnostics/a33-sdboot/u-boot-sunxi-with-spl.bin \
         python3 -I /tmp/opencode/pf1007l-sdcard-prepare.py
Run from the repository root.
"""
import hashlib, os, stat, struct, sys
from pathlib import Path

STUB_SHA256 = "2ccec08a026840571f3804671ba72afae840db27112a43f2b1f122075bc808bc"
PREFIX = 4 * 1024 * 1024
OFFSET, STUB_LEN = 8192, 8192
MIN_START = 2048  # sectors (1 MiB)
AREA_END = MIN_START * 512

def die(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)

card = Path(os.environ['CARD']).resolve(strict=True)
if not stat.S_ISBLK(card.stat().st_mode):
    die("not a block device")
image_path = Path(os.environ['IMAGE'])
data = image_path.read_bytes()
if data[4:12] != b"eGON.BT0":
    die(f"{image_path} has no eGON.BT0 header")
if OFFSET + len(data) > AREA_END:
    die(f"{image_path} is {len(data)} bytes; it would run past 1 MiB into the partition")

fd = os.open(card, os.O_RDONLY)
try:
    before = os.read(fd, PREFIX)
    if len(before) != PREFIX:
        die(f"short read: {len(before)} bytes")
    before2 = os.pread(fd, PREFIX, 0)
finally:
    os.close(fd)
if before2 != before:
    die("two reads of the first 4 MiB differ")
if before[510:512] != b"\x55\xaa":
    die("no MBR signature")
parts = [before[446 + i * 16:462 + i * 16] for i in range(4)]
used = [p for p in parts if p[4]]
if not used or any(p[4] == 0xEE for p in used):
    die("empty or GPT-protective partition table")
starts = [struct.unpack_from("<I", p, 8)[0] for p in used]
if min(starts) < MIN_START:
    die(f"a partition starts at sector {min(starts)}, before 1 MiB")

stub = Path('diagnostics/sunxi-tools/bin/fel-sdboot.sunxi')
existing = before[OFFSET:OFFSET + STUB_LEN]
is_stub = existing[4:12] == b"eGON.BT0" and hashlib.sha256(existing).hexdigest() == STUB_SHA256
known = set()
for kb in [Path('diagnostics/a33-sdboot/u-boot-sunxi-with-spl.bin'),
           Path('diagnostics/a33-sdboot-12mhz/u-boot-sunxi-with-spl.bin')]:
    if kb.exists():
        known.add(hashlib.sha256(kb.read_bytes()[:STUB_LEN]).hexdigest())
known.add(STUB_SHA256)
if existing[4:12] == b"eGON.BT0" and hashlib.sha256(existing).hexdigest() not in known:
    die("another boot image is already at 8 KiB; use a new card")

end = OFFSET + len(data)
end_padded = -(-end // 512) * 512
region = data + before[end:end_padded]
if before[OFFSET:end_padded] == region:
    print("Image already present; nothing to do.")
    sys.exit(0)

print(f"Partitions start at sectors {starts}; writing {len(region)} bytes at 8192 "
      f"(ends at {end_padded}, partition starts at {min(starts) * 512}).")
fd = os.open(card, os.O_RDWR)
try:
    os.lseek(fd, OFFSET, os.SEEK_SET)
    n = os.write(fd, region)
    os.fsync(fd)
finally:
    os.close(fd)
if n != len(region):
    die(f"short write: {n}")
fd = os.open(card, os.O_RDONLY)
try:
    after = os.pread(fd, PREFIX, 0)
finally:
    os.close(fd)
expected = before[:OFFSET] + region + before[end_padded:]
if after != expected:
    die("readback mismatch after write; do not use this card")
changed = sum(x != y for x, y in zip(before[OFFSET:end_padded], region))
print(f"Verified: image in place at 8192-{end_padded - 1} ({changed} bytes changed), "
      "nothing else in the first 4 MiB changed.")
print(f"U-Boot image sha256 {hashlib.sha256(data).hexdigest()}")
