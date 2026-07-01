# intel_ma - Intel: Management Absent

Inspect and deblob the management firmware that ships below your operating
system. `intel_ma` strips and neuters the Intel ME/TXE/CSME, inspects the AMD
PSP, and audits the vendor locks (Boot Guard, BIOS Guard, Secure Boot) on a
flash image.

Disabling the Intel Management Engine *is* making management absent. Hence the name.

## Status

A library (`src/lib.rs`) with a thin CLI (`src/main.rs`).

Supported:

- Image detection: ME/TXE region images and full SPI dumps (Intel Flash Descriptor)
- `$FPT` partition table parsing; FTPR/CODE location; IFWI `$CPD` discovery
- Generations 1-7: ME 6 Ignition, ME 6-10 (AltMeDisable), CSME 11-16 (HAP), plus TXE and SPS variants
- Partition removal with white/blacklist, FPT checksum repair, EFFS flag clear
- Module removal: gen2 (`$MME`, LLUT/Huffman) and gen3 (`$CPD`)
- FTPR relocation (`-r`) and truncation (`-t`)
- HAP / AltMeDisable / meDisable soft-disable (`-S` / `-s`)
- Descriptor hardening: drop ME R/W to other regions (`-d`)
- Descriptor / ME extraction (`-D` / `-M`)
- FTPR RSA signature verification (2048-bit modpow + SHA-256)
- **FIT parsing** (microcode, ACMs) with **Boot Guard detection** - warns before
  you flash an unsigned image onto a Boot-Guard-enforced board
- **`locks`** - one-shot inventory of every vendor lock: Boot Guard, BIOS Guard
  (AMI PFAT), Secure Boot key material, and the FLMSTR descriptor access matrix
  (flags when the ME can write your BIOS region)
- **AMD PSP** - parse the Embedded Firmware Structure / FET and the
  `$PSP`/`$BHD` directories (bootloader, public key, SMU, ABL, APCB/APOB, ...).
  The PSP is on-die and fuse-enforced, so this side is inspect-only
- **BIOS region** (`bios`) - walk UEFI firmware volumes and FFS files, listing
  modules; decompresses EFI/Tiano and LZMA sections via the `efi-compress` crate.
  Detects legacy PCI option ROMs (video BIOS) and can extract them with
  `--extract-roms <dir>`
- **GbE region** (`gbe`) - the Intel LAN NVM: MAC address, per-bank checksum and
  the active bank, and the LAN controller model (I217/I218/I219, 82577/82579).
  Accepts a full dump or a bare `flashregion_3_gbe.bin`

## Usage

```sh
# Inspect an image
intel_ma info  firmware.bin

# Verify integrity (FTPR RSA signature, layout)
intel_ma check firmware.bin

# Parse the FIT - list microcode/ACMs and detect Boot Guard before flashing
intel_ma fit firmware.bin

# Inventory every vendor lock: Boot Guard, BIOS Guard, Secure Boot, descriptor
intel_ma locks firmware.bin

# Inspect AMD PSP firmware (FET, directories, entries)
intel_ma amd firmware.bin

# Walk the BIOS region: UEFI volumes, modules (decompresses EFI/Tiano + LZMA)
intel_ma bios firmware.bin

# Extract any PCI option ROMs / video BIOS to a directory
intel_ma bios firmware.bin --extract-roms ./roms

# Read the GbE region: MAC, LAN controller, NVM banks
intel_ma gbe firmware.bin

# Strip and neuter the ME. Writes in place unless -O is given.
intel_ma clean firmware.bin -O cleaned.bin

# Full deblob: strip + relocate + HAP soft-disable + descriptor hardening
intel_ma clean dump.bin -S -r -d -O cleaned.bin

# Keep an extra partition (e.g. MFS), then truncate an ME-only image
intel_ma clean me.bin -w MFS -t -O me_small.bin
```

### `clean` flags

| Flag | Meaning |
|------|---------|
| `-O, --output` | write to a separate file |
| `-S, --soft-disable` | also set MeAltDisable/HAP bit (full dump) |
| `-s, --soft-disable-only` | only set MeAltDisable/HAP bit (full dump) |
| `-r, --relocate` | move FTPR to the top of the ME region |
| `-t, --truncate` | truncate the empty tail (ME-only image / `-M`) |
| `-k, --keep-modules` | don't remove FTPR modules |
| `-w, --whitelist` | comma-separated extra partitions to keep |
| `-b, --blacklist` | comma-separated partitions to remove |
| `-d, --descriptor` | drop ME R/W access to other flash regions |
| `-D, --extract-descriptor` | write the flash descriptor to a file |
| `-M, --extract-me` | write the ME firmware to a file |

## Build & test

```sh
cargo build --release
cargo test
cargo clippy --all-targets
```

## Library

```rust
let mut buf = std::fs::read("firmware.bin")?;
let info = intel_ma::analyze(&buf)?;          // read-only analysis
let report = intel_ma::clean(&mut buf, &intel_ma::Options {
    soft_disable: true,
    ..Default::default()
})?;
```

## Disclaimer

For research, right-to-repair and firmware-liberation work on hardware you own.
Flashing a bad image can brick a board - keep a known-good dump and a hardware
programmer (CH347 / FlashcatUSB / external SPI) on hand.

## Credits

Builds on the research and reference implementations of
[`me_cleaner`](https://github.com/corna/me_cleaner) (Intel ME) and
[PSPTool](https://github.com/PSPReverse/PSPTool) (AMD PSP), both GPL-3.

And a thank-you to the [coreboot](https://www.coreboot.org/) team and community,
whose work to replace proprietary firmware is what makes management absent in
the first place.

## In memory of MINIX

Thanks to **Andrew S. Tanenbaum**, author of [MINIX](https://www.minix3.org/):
the OS that Intel stole to build the Intel ME.

MINIX 3 runs on the Management Engine's core inside billions of machines -
quietly the most widely deployed operating system in the known universe. The real MINIX 3
runs thousands of NetBSD packages (Doom included); the build Intel embedded is
stripped to a blind, screenless core with no userland - it could run Doom, but
Intel gave it nothing to draw on. The OS was never the prisoner. Intel built
the cell.
Its author was never asked, never credited, and never even informed; he found
out from the news, and wrote Intel [an open
letter](https://www.cs.vu.nl/~ast/intel/) about it.

## License

GPL-3.0-or-later.
