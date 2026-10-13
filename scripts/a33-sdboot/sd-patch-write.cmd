# PF1007L: guarded boot (p6) patch write with payloads carried on the SD card.
# Same guards as the Route U write-boot.cmd (crc32 -v on every payload, p6 must
# still hold the original bytes, ramdisk readback before the header write), but
# the payloads are fatload'ed from the card instead of uploaded with sunxi-fel.
# For units where large FEL uploads corrupt (see
# docs/pf1007l-linux-20260519-sdboot.md). Build with mkimage -A arm -T script.
# Copy to the card as a33.scr, with the four payload .bin files from
# diagnostics/a33-boot-patch/. Run from the SD-boot U-Boot build (needs
# CONFIG_CRC32_VERIFY=y, CONFIG_CMD_FAT=y, CONFIG_FAT_WRITE=y).
#
# SECTOR AND SIZE VALUES BELOW ARE FROM plan.json OF THE UNIT REPORTED ABOVE:
#   ramdisk range [191844, 201324)  = 0x2ed64, 9480 sectors = 0x2508
#   header range  [172032, 172034)  = 0x2a000, 2 sectors
#   payload sizes: header 0x400, ramdisk 0x4a1000
# RECOMPUTE THEM WITH boot-patch.py AGAINST YOUR OWN VERIFIED DUMP. Do not
# write another unit's ranges.

setenv e 0x47000000
setenv a33_stage started
env export -t ${e}
fatwrite mmc 0:1 ${e} a33-status.txt ${filesize}

setenv fl_ok yes
if fatload mmc 0:1 0x50000000 orig-header.bin; then test ${filesize} = 400 || setenv fl_ok size; else setenv fl_ok no-orig-header; fi
if test ${fl_ok} = yes; then if fatload mmc 0:1 0x51000000 orig-ramdisk.bin; then test ${filesize} = 4a1000 || setenv fl_ok size; else setenv fl_ok no-orig-ramdisk; fi; fi
if test ${fl_ok} = yes; then if fatload mmc 0:1 0x52000000 new-header.bin; then test ${filesize} = 400 || setenv fl_ok size; else setenv fl_ok no-new-header; fi; fi
if test ${fl_ok} = yes; then if fatload mmc 0:1 0x53000000 new-ramdisk.bin; then test ${filesize} = 4a1000 || setenv fl_ok size; else setenv fl_ok no-new-ramdisk; fi; fi
if test ${fl_ok} != yes; then setenv w_result "REFUSED_FATLOAD ${fl_ok}"; env export -t ${e}; fatwrite mmc 0:1 ${e} a33-status.txt ${filesize}; exit; fi

# CRC-32 values are from plan.json; recompute for your payloads
if crc32 -v 0x50000000 0x400 <ORIG-HEADER-CRC> && crc32 -v 0x51000000 0x4a1000 <ORIG-RAMDISK-CRC> && crc32 -v 0x52000000 0x400 <NEW-HEADER-CRC> && crc32 -v 0x53000000 0x4a1000 <NEW-RAMDISK-CRC>; then
  setenv crc_ok yes
else
  setenv crc_ok no
fi
if test ${crc_ok} != yes; then setenv w_result "REFUSED_CRC ${crc_ok}"; env export -t ${e}; fatwrite mmc 0:1 ${e} a33-status.txt ${filesize}; exit; fi

# The eMMC must still hold the original bytes
mmc dev 1
mmc read 0x54000000 0x2a000 0x2
mmc read 0x55000000 0x2ed64 0x2508
if cmp.b 0x50000000 0x54000000 0x400 && cmp.b 0x51000000 0x55000000 0x4a1000; then
  setenv orig_ok yes
else
  setenv orig_ok no
fi
if test ${orig_ok} != yes; then setenv w_result "REFUSED_P6_NOT_EXPECTED_CONTENT ${orig_ok}"; env export -t ${e}; fatwrite mmc 0:1 ${e} a33-status.txt ${filesize}; exit; fi

# Write the ramdisk, read it back, compare; only then write the header
if mmc write 0x53000000 0x2ed64 0x2508; then
  mmc read 0x55000000 0x2ed64 0x2508
  if cmp.b 0x53000000 0x55000000 0x4a1000; then
    setenv rd_ok yes
  else
    setenv rd_ok no
  fi
  if test ${rd_ok} = yes; then
    if mmc write 0x52000000 0x2a000 0x2; then
      setenv w_result OK_WRITTEN
      # Read the whole p6 back and hash it; the host compares this hash with the
      # expected patched p6 it computed from the verified dump
      mmc read 0x48000000 0x2a000 0x10000
      hash sha256 0x48000000 0x2000000 p6_hash_after
    else
      setenv w_result FAIL_HEADER_WRITE
    fi
  else
    setenv w_result FAIL_RAMDISK_READBACK
  fi
else
  setenv w_result FAIL_RAMDISK_WRITE
fi

env export -t ${e}
fatwrite mmc 0:1 ${e} a33-status.txt ${filesize}
