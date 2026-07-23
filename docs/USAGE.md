# Using `intel_ma`

A practical, end-to-end guide: from *"does my machine even have an Intel ME?"*
to reading a firmware dump, auditing its locks, and neutering the Management
Engine.

If you only want the flag reference, see the [README](../README.md). This
document is the walkthrough.

---

## 0. Do I have an Intel ME at all?

Short answer: if you have an Intel chipset from roughly 2008 onward, **yes** -
even if nothing shows up in `dmesg`.

The ME lives on the PCH (chipset), not the CPU, and it runs whether or not the
OS ever talks to it. Grepping `dmesg` for `ME`/`CSME` finds nothing because the
kernel driver is called **`mei`** (Management Engine Interface), and it only
logs when it binds. Absence of a log line is **not** absence of the engine.

Check for the interface the ME exposes to the host:

```sh
# The MEI/HECI PCI function - this is the ME talking to the OS
lspci -nn | grep -iE 'MEI|HECI|Management Engine|Communication controller'

# Kernel driver + device nodes
lsmod | grep mei
ls -l /dev/mei*        # /dev/mei0 exists => the ME is present and answering
```

Or let `intel_ma` do all of that in one shot - it probes the PCI bus, the
device node, and the kernel's sysfs state:

```sh
# Live probe of the running machine (Linux only, no root needed)
intel_ma mei
```

```console
$ intel_ma mei
PCI            : 0000:00:16.0 8086:51e0 (class 078000) - HECI/MEI
/dev/mei0      : present (mei driver bound, engine answering)
dev_state      : ENABLED
fw_ver         : 16.0.15.1620  [CSME 16]  (code)
               : 16.0.15.1620  [CSME 16]  (recovery)
               : 16.0.15.1624  [CSME 16]  (FITC)
fw_status      : 90000245 00f10506 00000020 00004000 00021f03 446003c9
```

This reads only what the OS already exposes - the HECI PCI function under
`/sys/bus/pci/devices`, `/dev/mei0`, and `/sys/class/mei/mei0/{dev_state,fw_ver,fw_status}`
- so it needs no root, no ioctl, and no `/dev/mem`. The PCI line alone proves
the engine exists even when no `mei` driver is bound. It is **Linux only**: on
macOS/FreeBSD the command reports "unsupported" and exits non-zero.

There are then two different ways to read the ME's version, answering different
questions:

- **The *running* engine, live** - the `intel_ma mei` output above (or, over the
  HECI ioctl mechanism instead of sysfs, `me_cleaner`'s companion
  `sudo intelmetool -m`).
- **The version baked into a firmware image** - plus generation, partitions,
  signature, and locks. This needs a dump (next steps).

Neither `dmesg`/`lspci` nor the live `mei` probe tells you what is *inside* the
firmware, whether it is signed, or which vendor locks are set. For that you need
the flash contents - which is where the rest of this tool comes in.

> **Kaby Lake / Core i5-7200U and friends:** these are CSME 11.x parts. The ME
> is definitely there. `dmesg | grep -i me` returning nothing is expected.

---

## 1. Get a firmware image

`intel_ma` works on a file, not on live hardware. You need one of:

- a **full SPI dump** (the whole flash chip - descriptor + ME + BIOS + GbE), or
- a **bare ME/TXE region** image, or
- the vendor's **BIOS update** (sometimes carries a usable region).

### Software dump (fast, but usually incomplete on modern laptops)

```sh
sudo flashrom -p internal -r dump.bin
```

**Reality check:** on most OEM laptops from ~2016 on, this does **not** give you
a full image. The flash descriptor forbids the host CPU from reading the ME
region, so `flashrom` aborts:

```
Reading flash... Cannot read 0x001000 bytes at 0x4b7000: Input/output error
read_flash: failed to read (00000000..0x1ffffff).
```

That is the descriptor lock working as intended, not a broken cable. When it
happens you can still pull the regions the host *is* allowed to see - usually
the BIOS region - with an IFD-aware read:

```sh
# Read only the BIOS region (works even when the ME region is locked out)
sudo flashrom -p internal --ifd -i bios -r bios.bin
```

That BIOS-only image is enough for `bios`, `fit`, and `locks`, but **not** for
`info`/`check`/`clean`, which need the descriptor + ME region. For those you
need a hardware dump.

### Hardware dump (authoritative)

The only way to get a guaranteed-complete image is an external SPI programmer
clipped to the flash chip (CH341A/CH347, FlashcatUSB, Raspberry Pi, …):

```sh
# example with a CH341A and flashrom; chip name from `flashrom --flash-name`
sudo flashrom -p ch341a_spi -r dump.bin
sudo flashrom -p ch341a_spi -r dump2.bin   # dump twice, compare - they must match
cmp dump.bin dump2.bin && echo "consistent read"
```

**Always keep the original dump untouched.** Work on copies. A bad flash can
brick the board, and the original is your only way back.

---

## 2. Inspect before you touch anything

Start read-only. Every command below only *reads* the file.

```sh
# What is this image? Descriptor, regions, $FPT partitions, ME version.
intel_ma info dump.bin
```

`info` tells you whether the file is a full SPI dump or a bare ME region, where
the ME region sits, the `$FPT` partition layout, and the detected generation
(ME 6 Ignition, ME 6-10, CSME 11-16, TXE, SPS).

```sh
# Verify the ME firmware's own RSA signature and internal layout.
intel_ma check dump.bin
```

`check` does everything `info` does, plus validates the FTPR partition's
2048-bit RSA signature against its embedded public key. Use it to confirm a
dump is intact (and later, to confirm your cleaned image is still structurally
sane).

---

## 3. Audit the locks

Before you consider reflashing, find out what will fight you.

```sh
# One-shot inventory of every vendor lock on the image.
intel_ma locks dump.bin
```

This reports:

- **Boot Guard** - if enforced, the CPU verifies the BIOS against a key fused
  into the chipset. Flashing an unsigned/modified BIOS on such a board **will
  not boot** (and can brick it). This is the single most important thing to
  know before flashing.
- **BIOS Guard (AMI PFAT)** - write-protection layer on the BIOS region.
- **Secure Boot** - key material present in the image.
- **FLMSTR access matrix** - which masters (CPU, ME, GbE) can read/write which
  flash regions. Flags the common case where the **ME can write your BIOS
  region**.

```sh
# Parse the Firmware Interface Table: microcode, ACMs, and Boot Guard status.
intel_ma fit dump.bin
```

> If `locks`/`fit` say Boot Guard is **enforced**, do not flash a modified
> image via software. You can still inspect, extract, and study - but modifying
> and reflashing needs a hardware programmer and, on fused Boot Guard, may not
> be possible at all without hardware consequences.

---

## 4. Look at the other regions (optional)

```sh
# UEFI firmware volumes and FFS modules; decompresses EFI/Tiano + LZMA.
intel_ma bios dump.bin

# Pull any legacy PCI option ROMs (video BIOS, etc.) out to a directory.
intel_ma bios dump.bin --extract-roms ./roms

# Intel LAN NVM: MAC address, active bank, per-bank checksum, controller model.
intel_ma gbe dump.bin

# On an AMD image instead: parse the PSP (FET, $PSP/$BHD directories, entries).
# The PSP is on-die and fuse-enforced, so this side is inspect-only.
intel_ma amd dump.bin
```

---

## 5. Neuter the ME

Once you understand the image and its locks, `clean` produces a stripped and
soft-disabled version. **It never touches the input unless you tell it to** -
pass `-O` to write a separate file (recommended); without `-O` it edits in
place.

```sh
# Minimal: strip non-essential ME partitions, keep the file editable in place.
intel_ma clean me.bin -O me_clean.bin

# Recommended full deblob on a FULL SPI dump:
#   -S strip + set the HAP/AltMeDisable soft-disable bit
#   -r relocate FTPR to the top of the ME region
#   -d drop the ME's read/write access to the other flash regions
intel_ma clean dump.bin -S -r -d -O dump_clean.bin

# ME-only image: keep MFS, strip the rest, truncate the empty tail.
intel_ma clean me.bin -w MFS -t -O me_small.bin
```

Key flags (full list in the README):

| Flag | Meaning |
|------|---------|
| `-O, --output <file>` | write result to a separate file (don't edit in place) |
| `-S, --soft-disable` | strip **and** set the HAP/AltMeDisable bit (full dump) |
| `-s, --soft-disable-only` | only set the HAP bit, strip nothing |
| `-r, --relocate` | move FTPR to the top of the ME region |
| `-d, --descriptor` | remove ME R/W access to other regions (full dump) |
| `-t, --truncate` | cut the empty tail (ME-only image or with `-M`) |
| `-w, --whitelist` | comma-separated partitions to keep (e.g. `MFS`) |
| `-b, --blacklist` | comma-separated partitions to remove |
| `-M, --extract-me` / `-D, --extract-descriptor` | carve a region out to a file |

After cleaning, **re-inspect the output** to confirm it's still well-formed:

```sh
intel_ma info  dump_clean.bin
intel_ma check dump_clean.bin
```

---

## 6. Flash it back

This tool produces the image; it does not flash. Use `flashrom` with the same
programmer you dumped with:

```sh
# Verify size matches the chip, then write and read back to confirm.
sudo flashrom -p ch341a_spi -w dump_clean.bin
```

**Reality check before you write:**

- Boot Guard enforced? A modified BIOS region won't boot - see step 3.
- Keep the original dump. If the board won't POST, reflash the original with
  the hardware programmer to recover.
- On many boards the ME region is descriptor-locked; a *software* `flashrom -w`
  will refuse or silently skip it. A hardware programmer bypasses that.

---

## Library use

Everything the CLI does is available as a library.

```rust
let mut buf = std::fs::read("firmware.bin")?;

// Read-only analysis
let info = intel_ma::analyze(&buf)?;

// Strip + soft-disable, mutating `buf` in place
let report = intel_ma::clean(&mut buf, &intel_ma::Options {
    soft_disable: true,
    ..Default::default()
})?;

std::fs::write("firmware_clean.bin", &buf)?;
```

---

## A real worked example (locked OEM laptop)

Run on an actual 12th-gen laptop (i7-12700H, Alder Lake, AMI Aptio). A full
`flashrom -p internal -r` failed on the ME region (the I/O error shown above),
so this is a BIOS-region-only extract - exactly the common locked-board case.

```console
$ intel_ma bios bios.bin
BIOS region: 15 firmware volume(s), 446 files, 357 modules (PE32/TE)
Vendor: AMI Aptio
efi-compress: expanded 23 compressed section(s) (25102 KiB); 0 could not be decoded
...
3 PCI option ROM(s):
  8086:0406 Intel 65536 bytes [video BIOS]
  8086:2822 Intel 121856 bytes
  10ec:2600 unknown 57344 bytes

$ intel_ma fit bios.bin
FIT @ 0x1e90980  version 0100  6 entries
  Microcode Update             addr=0x00ffe91000 ...
  Startup ACM                  addr=0x00fff40000 ...
  Boot Guard Key Manifest      addr=0x00ffef9b00 size=0x00000355 ...
  Boot Guard Boot Policy       addr=0x00ffef9080 size=0x00000489 ...
Microcode updates: 2

$ intel_ma locks bios.bin
Boot Guard      : CONFIGURED (Key Manifest / Boot Policy present in FIT)
                  - Boot Guard Key Manifest @ 0xffef9b00
                  - Boot Guard Boot Policy @ 0xffef9080
                  note: real enforcement is set in the PCH fuses (FPFs) at the
                        factory - not in this image, unreadable from a dump. On OEM
                        boards assume fused ON; flashing cannot change it.
BIOS Guard      : present (AMI PFAT capsule) - BIOS region write-protected ...
Descriptor      : none (BIOS-only image or no flash descriptor)
```

Read that `locks` line carefully. **CONFIGURED** means the Boot Guard manifests
are present in the flash - the board is *set up* for Boot Guard. It does **not**
mean the tool measured the fuse. Actual enforcement is decided by the PCH's
Field Programmable Fuses (FPFs), which are burned by the OEM at manufacturing,
are one-time-programmable, and are **not part of the SPI image** - no dump can
read them. On a consumer OEM board, assume it is fused on.

Crucially: **a BIOS flash cannot turn Boot Guard on or off.** Burning FPFs
requires the ME to be in manufacturing mode, which the factory closes before
the machine ships. If you flashed your BIOS and now see Boot Guard "configured",
that state predates your flash by years - you didn't cause it and can't undo it
in software.

## Answering the original question

> *"How do I determine on Linux whether the Intel ME/TXE/CSME is present?"*

`dmesg` is the wrong tool - check `lspci` for the MEI/HECI function and
`/dev/mei0` for the driver (step 0). To learn the firmware's version, signature,
and locks, dump the SPI flash (step 1) and run `intel_ma info` / `locks` on it
(steps 2-3). For a Kaby Lake machine like the Core i5-7200U, the ME is present
by design - the question is only what it's running and how it's locked, and
that's exactly what this tool reports.
