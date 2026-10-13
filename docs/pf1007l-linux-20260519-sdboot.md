# PF1007L, Linux host, FL-AIMOR-OS.0.20260519: Route S dump at 12 MHz and a boot patch written from the SD card

Unit report for a PF1007L on `YHK.F-null-A33-1001-D1024-PF1007L-FL-AIMOR-OS.0.20260519`
rooted on 2026-10-12. Two things are new here:

1. The full Route S dump (32/32 chunks verified) on a **Linux host** with the
   **12 MHz** eMMC fix, and a Linux port of the card-writing step
   ([`scripts/a33-sdboot/fel-sdcard-linux.py`](../../scripts/a33-sdboot/fel-sdcard-linux.py)).
2. The Route U boot patch was written with the **payloads loaded from the SD
   card** (`fatload`) instead of FEL upload, because this unit corrupts large
   FEL uploads. `boot-patch.py --sd` generates the guarded script with every
   sector, size and SHA-256 taken from the run against your own dump; only the
   payload transport differs from the FEL scripts.

Nothing in this report changes the repository's route preferences. Route S's
hash guard still only accepts the January image, and this report does not edit
it — the SD-card *dump* (section 6 of the SD card guide) is read-only and works
on any firmware, which is exactly what was used here.

## Report

```text
About model / firmware:   Model PF1007L; YHK.F-null-A33-1001-D1024-PF1007L-FL-AIMOR-OS.0.20260519
                          fingerprint AEEZO/astar_m86_8723cs/astar-m86_8723cs:6.0.1/MOB30R/20260519:eng/test-keys
AiMOR version:            6.0.78
Ports (DC jack, or USB-C only): USB-C only, TF slot
Cable and port that gave USB data: USB-A to USB-C data cable. Worked on a front-panel port and a
                          rear motherboard port; a second data-rated cable behaved the same
T3 USB IDs seen / adb devices output: 1f3a:1000 "Android"; adb devices empty
T3b network ADB result (port 5555): connection refused
T4 sunxi-fel version output: 1f3a:efe8; AWUSBFEX soc=00001667(A33) 00000001 ver=0001 44 08
T5 check-dump stage / chunks: stage finished, emmc_dev ok, all 32 chunks ok — after the 12 MHz fix
eMMC size in sectors:     30,777,344 (name 016G92)
Boot partition start sector: 172032 (env 139264, system 237568, recovery 2400256: all match)
Boot image SHA-256 (sector 172032, 31,028 sectors): 9a6e2456952f3dc2b99e64ea021321397bdc824364b5c8b42f503f847261630a
                          (same as #24)
Route used and result:    Route U patch, payloads carried on the SD card. 1f3a:1002, adb -d shell id = uid=0(root)
Host OS:                  Arch Linux (omarchy), adb 37.0.0
First failed step and its exact output: (see "The USB gadget fails under U-Boot" below)
```

## The USB gadget fails under U-Boot; FEL upload corrupts payloads

Three different USB devices from U-Boot failed to enumerate on this unit, on a
front-panel port and a rear motherboard port, with two data-rated cables:

| Gadget | USB ID | Failure |
| --- | --- | --- |
| `ums` (read-only build) | — | descriptor read / address setup fails, `error -71`, device leaves the bus |
| fastboot download gadget (seen briefly) | `1f3a:1010` | same `-71` sequence |
| Boot ROM FEL | `1f3a:efe8` | **works, every time** |
| ADB under the Android kernel | `1f3a:1002` | **works, every time** (after the patch) |

So the peripheral controller is fine; U-Boot's gadget bring-up is what fails.
This matches "ums never enumerates on May 20260519 — unsolved" (#36) and the
reset/drop reports (#16, #19, #24). The 4-bit/26 MHz DT change alone did not
make `ums` enumerate here.

The second finding narrows #24's "FEL payload readback timed out": on this
unit, uploading the ~9.7 MB of patch payloads with several `sunxi-fel write`
commands silently corrupted the data. The on-device guards did their job:

```text
p6 read back after the write attempt == byte-identical to the verified dump p6
(result: nothing written; the crc32 -v / cmp.b guard chain refused)
```

A repeated `sunxi-fel version` right before the payload run stayed correct, so
the corruption is in the large bulk transfers, not the control path. This is
why the write below moves payloads over the SD card instead.

## The card step on Linux

`fel-sdcard.py` now runs on Linux (previously Windows-only):

```sh
sudo python3 -I scripts/a33-sdboot/fel-sdcard.py list
sudo python3 -I scripts/a33-sdboot/fel-sdcard.py prepare /dev/sdX <exact-bytes> [image]
```

It keeps every Windows guard and adds the Linux-specific ones the platform
needs: the card must be on a USB/removable reader (`lsblk` `tran=usb` or
`rm=1` — SATA/NVMe disks are listed but refused), must be fully unmounted, must
match the exact byte size given on the command line, and the typed
confirmation is `WRITE /dev/sdX`. The write itself is unchanged: MBR only, no
partition before 1 MiB, boot-area write at byte 8192 only, double-read before,
readback compare after.

## SD-boot dump at 12 MHz (Linux)

Built from `scripts/a33-sdboot/build.sh` inputs (pinned U-Boot
e50b1e8715011def8aff1588081a2649a2c6cd47, `Sinlinx_SinA33_defconfig` +
`a33.config`) with one local change, following the fix table in
[pf1007l-start-here.md](pf1007l-start-here.md#u-boot-settings-that-fixed-ums-problems):

```diff
 &mmc2 {
 	non-removable;
 	cap-mmc-hw-reset;
+	max-frequency = <12000000>;
 	status = "okay";
 };
```

With that, the dump completed on the first run: `stage finished`, all 32 chunks
`ok`, PC-side hashes equal to the frame-computed hashes. At stock speed the
same run stopped at chunk 05 with `FAIL second read`. The dump (2 GiB) covers
p6 (boot), p7 (system, complete 1 GiB) and p9 (recovery).

Two build notes for reproducing:

- `merge_config.sh` failed in this container environment (`dash` cannot create
  the output files it assumes); appending `a33.config`'s directives to
  `.config` and re-running `olddefconfig`, then re-verifying every directive
  (as `build.sh` already does), is equivalent.
- `CONFIG_CRC32_VERIFY=y` is required for `crc32 -v` and is **not** in
  `a33.config`. The Route U defconfig sets it, the SD-boot config does not.
  The `--sd` scripts therefore use `hash sha256` (CONFIG_CMD_HASH and
  CONFIG_SHA256 are in `a33.config`), which also verifies its digest.

## Writing the patch from the SD card

After the dump was verified, `boot-patch.py` was run against the assembled
image. It accepted the May image (structure check, not a hash check) and
reported the May ramdisk slot:

```text
ramdisk slot 4853760 bytes at +10143744
Write ranges: ramdisk [191844, 201324), header [172032, 172034)
```

`boot-patch.py --sd` (new) generates `sd-write-boot.cmd/.scr` and
`sd-restore-boot.cmd/.scr` from the run against your own dump. The guard chain,
on-device:

1. `fatload` all four payloads from the card's FAT partition; refuse any short
   load (`${filesize}` checked)
2. `hash sha256` on each payload against the digest from this `boot-patch.py`
   run (the SD-boot build has no `crc32 -v`)
3. `cmp.b` of both p6 regions against the original bytes — refuse if p6 is not
   the verified original
4. `mmc write` the ramdisk, `mmc read` it back, `cmp.b` — only then write the
   2-sector header
5. re-read the whole p6, `hash sha256`, and record the hash in
   `a33-status.txt` on the card

Every sector, size and digest in the generated script comes from the
`boot-patch.py` run; there is nothing to hand-edit and nothing to reuse across
units.

Result on this unit: `w_result=OK_WRITTEN` and
`p6_hash_after=fb23e82ee0345eb15bbdac87ecb722860d4561f7c8a9975e6d3399f5f2948988`,
equal to the value the host computed from the verified dump before writing.
After removing the card, Android booted, USB showed `1f3a:1002`, and
`adb -d shell id` returned `uid=0(root)`.

An independent second verification (a p6-only dump script run again from the
card after the write) read p6 twice and hashed it to the same value. The card
kept the SD-boot U-Boot in its boot area afterwards, as the undo path.

## "Thomas's room" / `com.android.gl2jni`

This unit ships a preinstalled privileged app with a decoy name: the label is
"Thomas's room", the package is `com.android.gl2jni` (the Android NDK OpenGL
sample's package name), and it lives at `/system/priv-app/tomas/tomas.apk`
(5,037,784 bytes). Inspecting the APK: one dex implementing the stock
GLSurfaceView sample and one native `libgl2jni.so`; permissions are only
storage read/write and wake lock; **no INTERNET permission**, no receivers or
services. It appears to be a leftover vendor demo. It was left enabled on this
unit; `pm disable com.android.gl2jni` is available if a future owner prefers.

## After root (this unit)

- Wi-Fi MAC randomizes per boot (AIC8800, as reported before); a router
  static-DHCP entry therefore matches only one boot. The adb-over-Wi-Fi
  discovery used here scans the subnet for port 5555.
- `persist.adb.tcp.port=5555` + `adb tcpip 5555` gives wireless root adb that
  survives reboots on this firmware.
- `adb reboot` **hangs** on this unit (power-cycled instead), as documented.
- WebView 106.0.5249.126 swap worked with the same procedure as #8, including
  the `lib/arm/*.so` extraction; `dumpsys` reports 106 and pages render.
- The stock dashboard runs from `file:///sdcard/dashboard/` in the kiosk
  WebView; inline `<script type="module">` works on `file://`, external module
  scripts and `/root`-relative paths do not (CORS/root resolution).
- Weather APIs over HTTPS fail in the WebView (Android 6 trust store, no
  ISRG Root X1); a plain-HTTP JSON proxy on the LAN was used instead.
