//! Analysis and cleaning flow.

use crate::bytes::{u24_le, u32_le};
use crate::descriptor::{self, Descriptor};
use crate::error::{Error, Result};
use crate::fpt::{self, Fpt, Ftpr};
use crate::manifest::{self, Version};
use crate::modules::{self, MIN_FTPR_OFFSET, SPARED_BLOCKS};
use crate::pubkeys;
use crate::region::{BLOCK, Region};

/// Static facts about an image, independent of any modification.
#[derive(Debug, Clone)]
pub struct Analysis {
    pub full_image: bool,
    pub sig_at_zero: bool,
    pub descriptor: Option<Descriptor>,
    pub me: Region,
    pub me_disabled: bool,
    pub generation: Option<u8>,
    pub variant: String,
    pub version: Option<Version>,
    pub fpt: Option<Fpt>,
    pub ftpr: Option<Ftpr>,
    pub ftpr_mn2_offset: usize,
    pub pubkey_md5: String,
    pub pubkey_match: Option<(&'static str, Vec<String>)>,
    /// Region-relative offsets of every `$FPT` candidate found.
    pub fpt_candidates: Vec<usize>,
    /// Non-fatal problems encountered while parsing (shown by `info`).
    pub warnings: Vec<String>,
}

/// Options controlling [`clean`].
#[derive(Debug, Clone, Default)]
pub struct Options {
    pub soft_disable: bool,
    pub soft_disable_only: bool,
    pub relocate: bool,
    pub truncate: bool,
    pub keep_modules: bool,
    pub whitelist: Vec<String>,
    pub blacklist: Vec<String>,
    pub descriptor: bool,
    pub extract_descriptor: bool,
    pub extract_me: bool,
}

/// Outcome of a [`clean`] run.
#[derive(Debug, Default)]
pub struct Report {
    pub log: Vec<String>,
    pub generation: Option<u8>,
    pub end_addr: Option<usize>,
    pub truncated_to: Option<usize>,
    pub extracted_descriptor: Option<Vec<u8>>,
    pub extracted_me: Option<Vec<u8>>,
    pub signature_valid: Option<bool>,
}

macro_rules! logln {
    ($log:expr, $($arg:tt)*) => { $log.push(format!($($arg)*)) };
}

/// Identify the image and parse everything we can without modifying it.
pub fn analyze(buf: &[u8]) -> Result<Analysis> {
    if buf.len() < 0x14 {
        return Err(Error::UnknownImage);
    }
    let magic0 = &buf[0..4];
    let magic10 = &buf[0x10..0x14];

    let mut a = Analysis {
        full_image: false,
        sig_at_zero: false,
        descriptor: None,
        me: Region::new(0, 0),
        me_disabled: false,
        generation: None,
        variant: String::new(),
        version: None,
        fpt: None,
        ftpr: None,
        ftpr_mn2_offset: 0,
        pubkey_md5: String::new(),
        pubkey_match: None,
        fpt_candidates: Vec::new(),
        warnings: Vec::new(),
    };

    if magic0 == descriptor::FPT_MAGIC || magic10 == descriptor::FPT_MAGIC {
        // ME/TXE region image, no descriptor.
        a.me = Region::new(0, buf.len());
    } else if magic0 == descriptor::FD_SIGNATURE || magic10 == descriptor::FD_SIGNATURE {
        a.full_image = true;
        a.sig_at_zero = magic0 == descriptor::FD_SIGNATURE;
        let d = Descriptor::parse(buf, a.sig_at_zero);
        a.me = d.me;
        if a.sig_at_zero {
            a.generation = Some(1);
        }
        if d.me.is_empty() {
            a.me_disabled = true;
        }
        a.descriptor = Some(d);
    } else {
        return Err(Error::UnknownImage);
    }

    if a.me.is_empty() {
        return Ok(a);
    }

    let me = a.me;
    let me_data = me.all(buf);

    // CSME images can carry primary + backup tables; don't abort on multiplicity here.
    let candidates = fpt::find_all_fpt(me_data);
    a.fpt_candidates = candidates.clone();
    if candidates.is_empty() {
        a.warnings.push("no $FPT found in ME region".into());
        return Ok(a);
    }
    if candidates.len() > 1 {
        let locs: Vec<String> = candidates
            .iter()
            .map(|o| format!("{:#x}", me.start + o))
            .collect();
        a.warnings.push(format!(
            "{} $FPT candidates: {}",
            candidates.len(),
            locs.join(", ")
        ));
    }

    // Prefer the candidate holding an FTPR/CODE partition; else first parseable table.
    let mut chosen: Option<(usize, Fpt, Ftpr)> = None;
    let mut first_parsed: Option<(usize, Fpt)> = None;
    for &off in &candidates {
        let Ok(parsed) = fpt::parse_fpt(&me, buf, off) else {
            continue;
        };
        if first_parsed.is_none() {
            first_parsed = Some((off, parsed.clone()));
        }
        if let Ok(ftpr) = fpt::find_ftpr(&parsed, me_data) {
            chosen = Some((off, parsed, ftpr));
            break;
        }
    }

    let (parsed, ftpr) = match chosen {
        Some((_, parsed, ftpr)) => (parsed, ftpr),
        None => {
            if let Some((_, parsed)) = first_parsed {
                a.fpt = Some(parsed);
            }
            a.warnings
                .push("no FTPR partition found in any $FPT; skipping ME version".into());
            return Ok(a);
        }
    };

    if ftpr.is_code {
        a.generation = Some(1);
    }
    a.fpt = Some(parsed);
    a.ftpr = Some(ftpr);

    // Manifest/version parsing is best-effort; a failure downgrades to a warning.
    if let Err(e) = resolve_manifest(&me, buf, &mut a, ftpr) {
        a.warnings.push(format!("manifest: {e}"));
    }
    Ok(a)
}

/// Resolve FTPR manifest offset, generation, version and public key into `a`.
fn resolve_manifest(me: &Region, buf: &[u8], a: &mut Analysis, ftpr: Ftpr) -> Result<()> {
    let ftpr_offset = ftpr.offset as usize;
    let mut ftpr_mn2_offset = 0usize;

    if me.read(buf, ftpr_offset, 4)? == b"$CPD" {
        a.generation = Some(3);
        let num_entries = me.read_u32(buf, ftpr_offset + 0x4)? as usize;

        // ME >= 15 inserts 4 extra bytes; detect by probing for "FTPR.man".
        let probe = me.read(buf, ftpr_offset + 0x14, 0x8)?;
        let entries_base = if probe == b"FTPR.man" {
            ftpr_offset + 0x14
        } else {
            ftpr_offset + 0x10
        };

        let mut found = None;
        for i in 0..num_entries {
            let data = me.read(buf, entries_base + i * 0x18, 0x18)?;
            let name = {
                let end = data[0x0..0xc].iter().position(|&c| c == 0).unwrap_or(0xc);
                String::from_utf8_lossy(&data[0x0..end]).into_owned()
            };
            let off = u24_le(data, 0xc) as usize;
            if name == "FTPR.man" {
                found = Some(off);
                break;
            }
        }
        match found {
            Some(off) => {
                manifest::check_mn2_tag(me, buf, ftpr_offset + off, a.generation)?;
                ftpr_mn2_offset = off;
            }
            None => return Err(Error::FtprManifestNotFound),
        }
    } else {
        manifest::check_mn2_tag(me, buf, ftpr_offset, a.generation)?;
        if a.generation.is_none() {
            a.generation = Some(2);
        }
    }

    let version = manifest::read_version(me, buf, ftpr_offset + ftpr_mn2_offset)?;
    a.generation = Some(match version.0[0] {
        12 => 4,
        14 => 5,
        15 => 6,
        16 => 7,
        _ => a.generation.unwrap_or(2),
    });
    a.version = Some(version);

    a.pubkey_md5 = manifest::pubkey_md5(me, buf, ftpr_offset + ftpr_mn2_offset)?;
    if let Some((variant, vers)) = pubkeys::lookup(&a.pubkey_md5) {
        a.variant = variant.to_string();
        a.pubkey_match = Some((variant, vers.iter().map(|s| s.to_string()).collect()));
    } else {
        a.variant = if version.0[0] >= 6 { "ME" } else { "TXE" }.to_string();
    }

    a.ftpr_mn2_offset = ftpr_mn2_offset;
    Ok(())
}

/// Read the per-generation disable strap; returns `(name, is_set, abs_offset, bit)` for gen >= 2.
fn read_disable_status(
    buf: &[u8],
    d: &Descriptor,
    generation: u8,
) -> Option<(String, bool, usize, u32)> {
    let db = descriptor::disable_bit(generation)?;
    let abs = d.fpsba + db.strap_off;
    let strap = u32_le(buf, abs);
    let set = strap & (1 << db.bit) != 0;
    Some((db.name.to_string(), set, abs, db.bit))
}

/// Perform the cleaning operation on an owned image buffer.
pub fn clean(buf: &mut Vec<u8>, opts: &Options) -> Result<Report> {
    let a = analyze(buf)?;
    let mut report = Report {
        generation: a.generation,
        ..Default::default()
    };

    // Option validation
    if a.fpt_candidates.len() > 1 {
        return Err(Error::MultipleFpt);
    }
    if !a.full_image
        && (opts.descriptor
            || opts.extract_descriptor
            || opts.extract_me
            || opts.soft_disable
            || opts.soft_disable_only)
    {
        return Err(Error::RequiresFullDump {
            op: "-d/-D/-M/-S/-s",
        });
    }
    if opts.soft_disable_only && (opts.relocate || opts.truncate) {
        return Err(Error::BadOptions("-s can't be used with -r or -t".into()));
    }
    if (!opts.whitelist.is_empty() || !opts.blacklist.is_empty()) && opts.relocate {
        return Err(Error::BadOptions(
            "relocation is not supported with custom whitelist or blacklist".into(),
        ));
    }

    let me = a.me;
    let me_len = me.len();
    let generation = a.generation;
    let d = a.descriptor;

    // Disable-bit status (full dump)
    if let Some(d) = &d {
        match generation {
            Some(1) => {
                for (ba, name) in [(d.fisba, "ICHSTRP0"), (d.fmsba, "MCHSTRP0")] {
                    let strap = u32_le(buf, ba);
                    if strap & 1 != 0 {
                        logln!(report.log, "The meDisable bit in {} is SET", name);
                    } else {
                        logln!(
                            report.log,
                            "The meDisable bit in {} is NOT SET, setting it now...",
                            name
                        );
                        buf[ba..ba + 4].copy_from_slice(&(strap | 1).to_le_bytes());
                    }
                }
            }
            Some(g) => {
                if let Some((name, set, _, _)) = read_disable_status(buf, d, g) {
                    logln!(
                        report.log,
                        "The {} is {}",
                        name,
                        if set { "SET" } else { "NOT SET" }
                    );
                }
            }
            None => {}
        }
    }

    // Generation 1: wipe and disable the ME region
    if generation == Some(1)
        && !me.is_empty()
        && let Some(d) = &d
    {
        logln!(report.log, "Disabling the ME region...");
        buf[d.frba + 0x8..d.frba + 0xc].copy_from_slice(&0x1fffu32.to_le_bytes());
        logln!(report.log, "Wiping the ME region...");
        me.fill_all(buf, 0xff)?;
    }

    if me.is_empty() {
        logln!(
            report.log,
            "The ME region in this image has already been disabled"
        );
    }

    let (fpt, ftpr) = match (&a.fpt, &a.ftpr) {
        (Some(f), Some(t)) => (f, *t),
        _ => {
            return Ok(report);
        }
    };
    let mut ftpr_offset = ftpr.offset as usize;
    let ftpr_length = ftpr.length as usize;
    let variant = a.variant.as_str();
    let version = a.version.expect("version present when fpt present");

    // ME 6 Ignition: wipe everything
    let mut me6_ignition = false;
    if generation == Some(2) && !opts.soft_disable_only && variant == "ME" && version.0[0] == 6 {
        let num_modules = me.read_u32(buf, ftpr_offset + 0x20)? as usize;
        let probe_off = ftpr_offset + 0x290 + (num_modules + 1) * 0x60;
        if let Ok(data) = me.read(buf, probe_off, 0xc)
            && &data[0x0..0x4] == b"$SKU"
            && data[0x8..0xc] == [0, 0, 0, 0]
        {
            logln!(
                report.log,
                "ME 6 Ignition firmware detected, removing everything..."
            );
            me.fill_all(buf, 0xff)?;
            me6_ignition = true;
        }
    }

    if generation != Some(1) {
        if !opts.soft_disable_only && !me6_ignition {
            if generation.map(|g| g >= 4).unwrap_or(false) {
                logln!(
                    report.log,
                    "Module removal is not currently supported on IFWI firmware."
                );
            } else {
                let end_addr = remove_partitions_and_modules(
                    buf,
                    &me,
                    fpt,
                    generation,
                    variant,
                    version,
                    me_len,
                    ftpr_offset,
                    ftpr_length,
                    opts,
                    &mut ftpr_offset,
                    &mut report,
                )?;
                report.end_addr = end_addr;

                if let Some(mut end_addr) = end_addr
                    && end_addr > 0
                {
                    end_addr = (end_addr / BLOCK + 1) * BLOCK + SPARED_BLOCKS * BLOCK;
                    report.end_addr = Some(end_addr);
                    logln!(
                        report.log,
                        "The ME minimum size should be {0} bytes ({0:#x} bytes)",
                        end_addr
                    );

                    if me.start > 0 {
                        logln!(
                            report.log,
                            "The ME region can be reduced up to:\n {:08x}:{:08x} me",
                            me.start,
                            me.start + end_addr - 1
                        );
                    } else if opts.truncate {
                        logln!(report.log, "Truncating file at {:#x}...", end_addr);
                        buf.truncate(end_addr);
                        report.truncated_to = Some(end_addr);
                    }
                }
            }
        }

        // Soft disable (set HAP / AltMeDisable)
        if (opts.soft_disable || opts.soft_disable_only)
            && generation.is_some()
            && let Some(d) = &d
            && let Some((name, _, abs, bit)) = read_disable_status(buf, d, generation.unwrap())
        {
            logln!(report.log, "Setting the {} to disable Intel ME...", name);
            let strap = u32_le(buf, abs);
            buf[abs..abs + 4].copy_from_slice(&(strap | (1 << bit)).to_le_bytes());
        }
    }

    // Descriptor: drop ME R/W access to other regions
    if opts.descriptor
        && let Some(d) = &d
    {
        logln!(
            report.log,
            "Removing ME/TXE R/W access to the other flash regions..."
        );
        let flmstr2 = if generation == Some(3) {
            0x0040_0500u32
        } else {
            let v = u32_le(buf, d.fmba + 0x4);
            (v | 0x0404_0000) & 0x0404_ffff
        };
        buf[d.fmba + 0x4..d.fmba + 0x8].copy_from_slice(&flmstr2.to_le_bytes());
    }

    // Extraction
    if opts.extract_descriptor
        && let Some(d) = &d
    {
        let mut desc = d.fd.extract(buf, d.fd.len())?;
        if opts.truncate
            && let Some(end_addr) = report.end_addr
        {
            if d.bios.start == me.end {
                let flreg1 = descriptor::start_end_to_flreg(me.start + end_addr, d.bios.end);
                let frba = d.frba;
                desc[frba + 0x4..frba + 0x8].copy_from_slice(&flreg1.to_le_bytes());
                if generation != Some(1) {
                    let flreg2 = descriptor::start_end_to_flreg(me.start, me.start + end_addr);
                    desc[frba + 0x8..frba + 0xc].copy_from_slice(&flreg2.to_le_bytes());
                }
                logln!(
                    report.log,
                    "Modified extracted descriptor regions for truncation"
                );
            } else {
                logln!(
                    report.log,
                    "WARNING: BIOS region start ({:#x}) != ME region end ({:#x}); descriptor regions not auto-adjusted",
                    d.bios.start,
                    me.end
                );
            }
        }
        report.extracted_descriptor = Some(desc);
    }

    if generation != Some(1) && opts.extract_me {
        let size = if opts.truncate {
            report.end_addr.unwrap_or(me_len)
        } else {
            me_len
        };
        let me_image = me.extract(buf, size)?;
        report.extracted_me = Some(me_image);
    }

    // Signature verification
    if generation != Some(1) && !me6_ignition {
        let valid = manifest::check_partition_signature(&me, buf, ftpr_offset + a.ftpr_mn2_offset)?;
        report.signature_valid = Some(valid);
        if !valid {
            return Err(Error::InvalidSignature);
        }
    }

    Ok(report)
}

/// Partition removal + FPT checksum fix + FTPR module pass; returns retained-data end addr.
#[allow(clippy::too_many_arguments)]
fn remove_partitions_and_modules(
    buf: &mut [u8],
    me: &Region,
    fpt: &Fpt,
    generation: Option<u8>,
    variant: &str,
    version: Version,
    me_len: usize,
    ftpr_offset: usize,
    ftpr_length: usize,
    opts: &Options,
    ftpr_offset_out: &mut usize,
    report: &mut Report,
) -> Result<Option<usize>> {
    let fpt_off = fpt.offset;
    logln!(report.log, "Reading partitions list...");

    let mut whitelist: Vec<String> = vec!["FTPR".to_string()];
    let blacklist = opts.blacklist.clone();
    if blacklist.is_empty() {
        whitelist.extend(opts.whitelist.iter().cloned());
    }

    let mut kept: Vec<u8> = Vec::new();
    let mut kept_names: Vec<String> = Vec::new();
    let mut extra_part_end = 0usize;
    let entries = fpt.entries as usize;

    for (i, p) in fpt.partitions.iter().enumerate() {
        let name = p.name_str();
        let mut part_length = p.length as usize;
        // ME 6: last partition uses 0xffffffff as size.
        if variant == "ME" && version.0[0] == 6 && i == entries - 1 && p.length == 0xffff_ffff {
            part_length = me_len - p.start as usize;
        }
        let part_start = p.start as usize;
        let part_end = part_start + part_length;

        if p.flags & 0x7f == 2 {
            logln!(
                report.log,
                " {:<4} (NVRAM partition, no data): nothing to remove",
                name
            );
        } else if part_start == 0 || part_length == 0 || part_end > me_len {
            logln!(report.log, " {:<4} (no data here): nothing to remove", name);
        } else {
            let keep =
                whitelist.contains(&name) || (!blacklist.is_empty() && !blacklist.contains(&name));
            if keep {
                kept.extend_from_slice(&p.raw);
                kept_names.push(name.clone());
                if name != "FTPR" {
                    extra_part_end = extra_part_end.max(part_end);
                }
                logln!(
                    report.log,
                    " {:<4} (0x{:08x} - 0x{:08x}): NOT removed",
                    name,
                    part_start,
                    part_end
                );
            } else {
                me.fill_range(buf, part_start, part_end, 0xff)?;
                logln!(
                    report.log,
                    " {:<4} (0x{:08x} - 0x{:08x}): removed",
                    name,
                    part_start,
                    part_end
                );
            }
        }
    }

    logln!(report.log, "Removing partition entries in FPT...");
    me.write(buf, fpt_off + 0x20, &kept)?;
    me.write_u32(buf, fpt_off + 0x4, (kept.len() / 0x20) as u32)?;
    me.fill_range(
        buf,
        fpt_off + 0x20 + kept.len(),
        fpt_off + 0x20 + entries * 0x20,
        0xff,
    )?;

    // EFFS presence flag.
    let effs_default = (blacklist.is_empty() && !whitelist.iter().any(|w| w == "EFFS"))
        || blacklist.iter().any(|b| b == "EFFS");
    if effs_default {
        logln!(report.log, "Removing EFFS presence flag...");
        let flags = me.read_u32(buf, fpt_off + 0x14)?;
        me.write_u32(buf, fpt_off + 0x14, flags & !0x1)?;
    }

    // FPT checksum.
    let (hdr_start, hdr_len, cksum_idx) = if generation == Some(3) {
        (fpt_off, 0x20usize, 0x0busize)
    } else {
        (fpt_off.saturating_sub(0x10), 0x30usize, 0x1busize)
    };
    let mut header = me.read(buf, hdr_start, hdr_len)?.to_vec();
    header[cksum_idx] = 0;
    let sum: u32 = header.iter().map(|&b| b as u32).sum();
    let checksum = ((0x100 - (sum & 0xff)) & 0xff) as u8;
    logln!(report.log, "Correcting checksum (0x{:02x})...", checksum);
    me.write_u8(buf, fpt_off + 0xb, checksum)?;

    // FTPR module pass.
    let ph_offset = match kept_names.iter().position(|n| n == "FTPR") {
        Some(idx) => fpt_off + 0x20 + idx * 0x20,
        None => fpt_off + 0x20,
    };

    logln!(report.log, "Reading FTPR modules list...");
    let res = if generation == Some(3) {
        modules::check_and_remove_modules_gen3(
            me,
            buf,
            me_len,
            ftpr_offset,
            ftpr_length,
            MIN_FTPR_OFFSET,
            opts.relocate,
            opts.keep_modules,
            ph_offset,
        )?
    } else {
        modules::check_and_remove_modules(
            me,
            buf,
            me_len,
            ftpr_offset,
            ftpr_length,
            MIN_FTPR_OFFSET,
            opts.relocate,
            opts.keep_modules,
            ph_offset,
        )?
    };

    *ftpr_offset_out = res.ftpr_offset;

    Ok(res.end_addr.map(|e| e.max(extra_part_end)))
}
