//! intel_ma CLI.

mod lingo;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use intel_ma::cleaner::{self, Options};

#[derive(Parser)]
#[command(name = "intel_ma", version, about = lingo::ABOUT)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[command(about = lingo::INFO_ABOUT)]
    Info(InfoArgs),
    #[command(about = lingo::CHECK_ABOUT)]
    Check(InfoArgs),
    #[command(about = lingo::CLEAN_ABOUT)]
    Clean(CleanArgs),
    #[command(about = lingo::FIT_ABOUT)]
    Fit(InfoArgs),
    #[command(about = lingo::LOCKS_ABOUT)]
    Locks(InfoArgs),
    #[command(about = lingo::AMD_ABOUT)]
    Amd(InfoArgs),
    #[command(about = lingo::BIOS_ABOUT)]
    Bios(BiosArgs),
    #[command(about = lingo::GBE_ABOUT)]
    Gbe(InfoArgs),
}

#[derive(Args)]
struct InfoArgs {
    /// ME/TXE image or full SPI dump.
    file: PathBuf,
}

#[derive(Args)]
struct BiosArgs {
    /// ME/TXE image or full SPI dump.
    file: PathBuf,

    /// Write any PCI option ROMs (video BIOS, ...) found to this directory.
    #[arg(long = "extract-roms", value_name = "DIR")]
    extract_roms: Option<PathBuf>,
}

#[derive(Args)]
struct CleanArgs {
    /// ME/TXE image or full SPI dump.
    file: PathBuf,

    /// Save the modified image to this file instead of editing in place.
    #[arg(short = 'O', long = "output")]
    output: Option<PathBuf>,

    /// Also set the MeAltDisable/HAP bit (requires a full dump).
    #[arg(
        short = 'S',
        long = "soft-disable",
        conflicts_with = "soft_disable_only"
    )]
    soft_disable: bool,

    /// Only set the MeAltDisable/HAP bit (requires a full dump).
    #[arg(short = 's', long = "soft-disable-only")]
    soft_disable_only: bool,

    /// Relocate the FTPR partition to the top of the ME region.
    #[arg(short = 'r', long = "relocate")]
    relocate: bool,

    /// Truncate the empty part of the firmware (ME-only image or with --extract-me).
    #[arg(short = 't', long = "truncate")]
    truncate: bool,

    /// Don't remove the FTPR modules, even when possible.
    #[arg(short = 'k', long = "keep-modules")]
    keep_modules: bool,

    /// Comma-separated extra partitions to keep (e.g. MFS).
    #[arg(short = 'w', long = "whitelist", conflicts_with = "blacklist")]
    whitelist: Option<String>,

    /// Comma-separated partitions to remove (overrides the default list).
    #[arg(short = 'b', long = "blacklist")]
    blacklist: Option<String>,

    /// Remove ME/TXE R/W access to the other flash regions (requires a full dump).
    #[arg(short = 'd', long = "descriptor")]
    descriptor: bool,

    /// Extract the flash descriptor to this file.
    #[arg(short = 'D', long = "extract-descriptor")]
    extract_descriptor: Option<PathBuf>,

    /// Extract the ME firmware to this file.
    #[arg(short = 'M', long = "extract-me")]
    extract_me: Option<PathBuf>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Info(a) => run_info(&a.file, false),
        Command::Check(a) => run_info(&a.file, true),
        Command::Clean(a) => run_clean(a),
        Command::Fit(a) => run_fit(&a.file),
        Command::Locks(a) => run_locks(&a.file),
        Command::Amd(a) => run_amd(&a.file),
        Command::Bios(a) => run_bios(&a.file, a.extract_roms.as_deref()),
        Command::Gbe(a) => run_gbe(&a.file),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run_info(path: &Path, check: bool) -> intel_ma::Result<()> {
    let buf = std::fs::read(path)?;
    let a = match cleaner::analyze(&buf) {
        Ok(a) => a,
        // No descriptor and no $FPT: image has no Intel ME (not a failure).
        Err(intel_ma::Error::UnknownImage) => {
            println!("No Intel ME here - no flash descriptor or $FPT in this image");
            println!("(a BIOS-region extract, or hardware from before it became a service)");
            return Ok(());
        }
        Err(e) => return Err(e),
    };

    if a.full_image {
        println!("{}", lingo::FULL_IMAGE);
    } else {
        println!("{}", lingo::ME_IMAGE);
    }
    if let Some(d) = &a.descriptor {
        println!(
            " descriptor : {:08x}:{:08x}",
            d.fd.start,
            d.fd.end.saturating_sub(1)
        );
        println!(
            " bios       : {:08x}:{:08x}",
            d.bios.start,
            d.bios.end.saturating_sub(1)
        );
        println!(
            " me         : {:08x}:{:08x}",
            d.me.start,
            d.me.end.saturating_sub(1)
        );
    }
    if a.me_disabled {
        println!("{}", lingo::ME_ALREADY_GONE);
        return Ok(());
    }

    if a.fpt_candidates.len() > 1 {
        let locs: Vec<String> = a
            .fpt_candidates
            .iter()
            .map(|o| format!("{:#x}", a.me.start + o))
            .collect();
        println!(
            "{} $FPT candidates: {}",
            a.fpt_candidates.len(),
            locs.join(", ")
        );
    }
    if let Some(fpt) = &a.fpt {
        println!("Found FPT header at {:#x}", a.me.start + fpt.offset);
        println!(
            "Found {} partition(s):  (start = absolute file offset)",
            fpt.entries
        );
        for p in &fpt.partitions {
            println!(
                "  {:<4} start={:#010x} len={:#010x} flags={:#010x}",
                p.name_str(),
                a.me.start + p.start as usize,
                p.length,
                p.flags
            );
        }
    }
    if let Some(ftpr) = &a.ftpr {
        let base = a.me.start + ftpr.offset as usize;
        println!(
            "FTPR partition: {:#x} - {:#x}{}",
            base,
            base + ftpr.length as usize,
            if ftpr.is_ifwi { " (IFWI)" } else { "" }
        );
    }
    if let (Some(v), Some(g)) = (&a.version, a.generation) {
        println!("{}", lingo::squatter_line(&v.to_string(), g));
    }
    if !a.pubkey_md5.is_empty() {
        match &a.pubkey_match {
            Some((variant, versions)) => println!(
                "Public key match: Intel {}, firmware versions {}",
                variant,
                versions.join(", ")
            ),
            None => println!(
                "WARNING: unknown public key {} (assuming Intel {})",
                a.pubkey_md5, a.variant
            ),
        }
    }

    // Best-effort Boot Guard heads-up for full images.
    if a.full_image
        && let Ok(fit) = intel_ma::fit::Fit::parse(&buf)
        && fit.has_boot_guard()
    {
        println!("{}", lingo::vendor_lock(true));
    }

    if check {
        match (a.generation, &a.ftpr) {
            (Some(1), _) => println!("Generation 1: no FTPR RSA signature to check"),
            (_, Some(ftpr)) => {
                let valid = intel_ma::manifest::check_partition_signature(
                    &a.me,
                    &buf,
                    ftpr.offset as usize + a.ftpr_mn2_offset,
                )?;
                println!(
                    "{}",
                    if valid {
                        lingo::DEED_VALID
                    } else {
                        lingo::DEED_INVALID
                    }
                );
                if !valid {
                    return Err(intel_ma::Error::InvalidSignature);
                }
            }
            (_, None) => println!("Cannot verify: no FTPR partition located"),
        }
    }

    for w in &a.warnings {
        println!("note: {w}");
    }
    Ok(())
}

fn run_fit(path: &Path) -> intel_ma::Result<()> {
    let buf = std::fs::read(path)?;
    let fit = intel_ma::fit::Fit::parse(&buf)?;

    println!(
        "FIT @ {:#x}  version {:04x}  {} entries",
        fit.offset,
        fit.version,
        fit.entries.len()
    );
    for e in &fit.entries {
        println!(
            "  {:<28} addr={:#012x} size={:#010x} ver={:04x} {}",
            e.entry_type.name(),
            e.address,
            e.size,
            e.version,
            if e.checksum_valid { "cksum" } else { "-" }
        );
    }
    println!("Microcode updates: {}", fit.microcode_count());
    println!();
    if fit.has_boot_guard() {
        println!("{}", lingo::vendor_lock(false));
    } else {
        println!("{}", lingo::NO_VENDOR_LOCK);
    }
    Ok(())
}

fn run_bios(path: &Path, extract_roms: Option<&Path>) -> intel_ma::Result<()> {
    let buf = std::fs::read(path)?;
    let img = intel_ma::bios::parse(&buf);

    if img.volumes.is_empty() {
        match img.vendor {
            Some(v) => println!("No UEFI firmware volumes; vendor: {v}"),
            None => println!("No UEFI firmware volumes found in this image"),
        }
        print_option_roms(&img.option_roms);
        extract_option_roms(&img.option_roms, extract_roms)?;
        return Ok(());
    }

    println!(
        "BIOS region: {} firmware volume(s), {} files, {} modules (PE32/TE)",
        img.volumes.len(),
        img.files,
        img.modules
    );
    println!("Vendor: {}", img.vendor.unwrap_or("unknown"));
    println!(
        "efi-compress: expanded {} compressed section(s) ({} KiB); {} could not be decoded",
        img.decompressed_sections,
        img.decompressed_bytes / 1024,
        img.lzma_sections
    );

    // Distinct module UI-string names.
    let mut names = img.names.clone();
    names.sort();
    names.dedup();
    if !names.is_empty() {
        println!("{} named components, e.g.:", names.len());
        for n in names.iter().take(24) {
            println!("  {n}");
        }
        if names.len() > 24 {
            println!("  ... and {} more", names.len() - 24);
        }
    }
    print_option_roms(&img.option_roms);
    extract_option_roms(&img.option_roms, extract_roms)?;
    Ok(())
}

fn print_option_roms(roms: &[intel_ma::bios::OptionRom]) {
    if roms.is_empty() {
        return;
    }
    println!("{} PCI option ROM(s):", roms.len());
    for r in roms {
        let kind = if r.is_display() { " [video BIOS]" } else { "" };
        println!(
            "  {:04x}:{:04x} {} {} bytes{}",
            r.vendor,
            r.device,
            r.vendor_name(),
            r.size,
            kind
        );
    }
}

/// Write each option ROM to `dir`, disambiguating same-ID ROMs with an index.
fn extract_option_roms(
    roms: &[intel_ma::bios::OptionRom],
    dir: Option<&Path>,
) -> intel_ma::Result<()> {
    let Some(dir) = dir else { return Ok(()) };
    if roms.is_empty() {
        return Ok(());
    }
    std::fs::create_dir_all(dir)?;
    let mut seen: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for r in roms {
        let stem = r.file_stem();
        let n = seen.entry(stem.clone()).or_insert(0);
        let name = if *n == 0 {
            format!("{stem}.rom")
        } else {
            format!("{stem}_{n}.rom")
        };
        *n += 1;
        let path = dir.join(&name);
        std::fs::write(&path, &r.data)?;
        println!("  extracted {} ({} bytes)", path.display(), r.data.len());
    }
    Ok(())
}

fn run_gbe(path: &Path) -> intel_ma::Result<()> {
    use intel_ma::descriptor::{self, Descriptor};

    let buf = std::fs::read(path)?;
    let sig = descriptor::FD_SIGNATURE;
    let sig_at_zero = buf.get(0..4) == Some(&sig);
    let has_fd = sig_at_zero || buf.get(0x10..0x14) == Some(&sig);

    // Full dump carries the region in its descriptor; an ifdtool-extracted
    // flashregion_3_gbe.bin is the bare region itself.
    let (region_start, region): (usize, &[u8]) = if has_fd {
        let d = Descriptor::parse(&buf, sig_at_zero);
        if d.gbe.is_empty() || d.gbe.end > buf.len() {
            println!("No GbE region in this descriptor (platform has no Intel LAN)");
            return Ok(());
        }
        (d.gbe.start, d.gbe.all(&buf))
    } else {
        (0, &buf[..])
    };

    let Some(gbe) = intel_ma::gbe::parse(region) else {
        println!("GbE region @ {region_start:#x} is too small to parse");
        return Ok(());
    };

    println!(
        "GbE region @ {:#x} ({:#x} B, {} bank{})",
        region_start,
        gbe.size,
        gbe.banks.len(),
        if gbe.banks.len() == 1 { "" } else { "s" }
    );
    for (i, b) in gbe.banks.iter().enumerate() {
        let active = if gbe.active == Some(i) {
            " (active)"
        } else {
            ""
        };
        let cksum = if b.checksum_valid { "OK" } else { "INVALID" };
        let mac = if b.mac_blank() {
            "blank".to_string()
        } else if b.mac_default() {
            format!("{} (Intel default)", fmt_mac(&b.mac))
        } else {
            fmt_mac(&b.mac)
        };
        println!("  bank {i}{active}: checksum {cksum}");
        println!("    MAC:        {mac}");
        match b.controller() {
            Some(name) => println!("    controller: 8086:{:04x} ({name})", b.device_id),
            None => println!("    controller: 8086:{:04x} (unknown)", b.device_id),
        }
        println!(
            "    subsystem:  {:04x}:{:04x}",
            b.subsystem_vendor, b.subsystem_device
        );
    }
    if gbe.active.is_none() {
        println!("warning: no bank has a valid checksum - NIC may not initialize");
    }
    Ok(())
}

fn fmt_mac(mac: &[u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn run_amd(path: &Path) -> intel_ma::Result<()> {
    let buf = std::fs::read(path)?;
    match intel_ma::amd::parse(&buf) {
        None => {
            println!("No AMD PSP firmware here (no Embedded Firmware Structure / FET found)");
        }
        Some(fw) => {
            match fw.fet_offset {
                Some(o) => println!(
                    "AMD PSP firmware - FET @ {:#x}, assumed ROM size {} MiB",
                    o,
                    fw.rom_size / (1024 * 1024)
                ),
                None => println!(
                    "AMD directories found (no FET), assumed ROM size {} MiB",
                    fw.rom_size / (1024 * 1024)
                ),
            }
            println!("{} director(ies):", fw.directories.len());
            for d in &fw.directories {
                if d.is_combo {
                    println!(
                        "  {} combo directory @ {:#x} ({} sub-dirs)",
                        d.magic_str(),
                        d.offset,
                        d.count
                    );
                    continue;
                }
                println!(
                    "  {} @ {:#x}  {} entries{}",
                    d.magic_str(),
                    d.offset,
                    d.entries.len(),
                    if d.is_bios { " [BIOS]" } else { "" }
                );
                for e in &d.entries {
                    println!(
                        "      type {:#04x} {:<26} size={:#08x} @ {:#08x}",
                        e.type_id,
                        e.name_for(d.is_bios),
                        e.size,
                        e.location
                    );
                }
            }
            let has = |t: u8| {
                fw.directories
                    .iter()
                    .any(|d| !d.is_bios && d.entries.iter().any(|e| e.type_id == t))
            };
            println!();
            if has(0x00) {
                println!(
                    "🔒  AMD root of trust: AMD_PUBLIC_KEY present - PSP verifies the boot chain"
                );
            }
            if has(0x0b) {
                println!("    SOFT_FUSE_CHAIN present - holds the PSP debug / disable soft-fuses");
            }
            println!(
                "    The PSP lives on-die and is fuse-enforced: it cannot be evicted, only read."
            );
        }
    }
    Ok(())
}

fn run_locks(path: &Path) -> intel_ma::Result<()> {
    let buf = std::fs::read(path)?;
    // Descriptor/generation help with FLMSTR; absence is fine for the rest.
    let (descriptor, generation) = match cleaner::analyze(&buf) {
        Ok(a) => (a.descriptor, a.generation),
        Err(_) => (None, None),
    };
    let report = intel_ma::locks::LockReport::scan(&buf, descriptor.as_ref(), generation);

    println!("== Locks on this house ==");

    if report.boot_guard {
        println!("Boot Guard      : ENFORCED (vendor signs the firmware)");
        for e in &report.boot_guard_entries {
            println!("                  - {e}");
        }
    } else {
        println!("Boot Guard      : open (no Key Manifest / Boot Policy in FIT)");
    }

    println!(
        "BIOS Guard      : {}",
        if report.bios_guard_pfat {
            "present (AMI PFAT capsule) - BIOS region write-protected by signed updates"
        } else {
            "not detected"
        }
    );

    if report.secure_boot_keys.is_empty() {
        println!("Secure Boot     : no key material found (best-effort)");
    } else {
        println!(
            "Secure Boot     : keys provisioned - {} (best-effort)",
            report.secure_boot_keys.join(", ")
        );
    }

    match &report.descriptor {
        Some(d) => {
            println!(
                "Descriptor      : FLMSTR v{} access matrix",
                if d.v2 { "2" } else { "1" }
            );
            for m in &d.masters {
                println!(
                    "                  {:<9} read [{}]  write [{}]",
                    m.name,
                    region_list(m.read),
                    region_list(m.write)
                );
            }
            if d.fully_unlocked {
                println!(
                    "                  ✓ fully unlocked - every region reflashable (coreboot / liberated)"
                );
            } else if d.me_writes_bios {
                println!(
                    "                  ⚠ ME can WRITE the BIOS region (clean -d removes this)"
                );
            }
        }
        None => println!("Descriptor      : none (BIOS-only image or no flash descriptor)"),
    }

    println!();
    if report.any_enforcement() {
        println!("{}", lingo::vendor_lock(false));
    } else {
        println!("Verdict: no enforced vendor locks detected - the doors are open.");
    }
    Ok(())
}

/// Render a region access bitmask as a list of region names.
fn region_list(mask: u16) -> String {
    use intel_ma::locks::REGIONS;
    let names: Vec<&str> = (0..REGIONS.len())
        .filter(|i| mask & (1 << i) != 0)
        .map(|i| REGIONS[i])
        .collect();
    if names.is_empty() {
        "-".to_string()
    } else {
        names.join(",")
    }
}

fn run_clean(args: CleanArgs) -> intel_ma::Result<()> {
    let mut buf = std::fs::read(&args.file)?;

    let opts = Options {
        soft_disable: args.soft_disable,
        soft_disable_only: args.soft_disable_only,
        relocate: args.relocate,
        truncate: args.truncate,
        keep_modules: args.keep_modules,
        whitelist: split_list(args.whitelist.as_deref()),
        blacklist: split_list(args.blacklist.as_deref()),
        descriptor: args.descriptor,
        extract_descriptor: args.extract_descriptor.is_some(),
        extract_me: args.extract_me.is_some(),
    };

    let report = cleaner::clean(&mut buf, &opts)?;
    for line in &report.log {
        println!("{line}");
    }

    write_extract(
        report.extracted_descriptor.as_ref(),
        args.extract_descriptor.as_ref(),
        "descriptor",
    )?;
    write_extract(
        report.extracted_me.as_ref(),
        args.extract_me.as_ref(),
        "ME image",
    )?;
    if let Some(valid) = report.signature_valid {
        println!(
            "{}",
            if valid {
                lingo::DEED_VALID
            } else {
                lingo::DEED_INVALID
            }
        );
    }

    let out = args.output.as_deref().unwrap_or(&args.file);
    std::fs::write(out, &buf)?;
    println!("{}", lingo::house_reclaimed(&out.display().to_string()));
    Ok(())
}

/// Write an extracted blob to its output path, if both are present.
fn write_extract(
    data: Option<&Vec<u8>>,
    path: Option<&PathBuf>,
    label: &str,
) -> std::io::Result<()> {
    if let (Some(data), Some(path)) = (data, path) {
        std::fs::write(path, data)?;
        println!("Extracted {label} to {}", path.display());
    }
    Ok(())
}

fn split_list(s: Option<&str>) -> Vec<String> {
    match s {
        Some(s) if !s.is_empty() => s.split(',').map(|x| x.trim().to_string()).collect(),
        _ => Vec::new(),
    }
}
