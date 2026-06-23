//! Survey vendor lock / root-of-trust mechanisms in a flash image:
//! Boot Guard (FIT), BIOS Guard (AMI PFAT), Secure Boot key material
//! (best-effort GUID scan), and FLMSTR descriptor access.

use crate::descriptor::Descriptor;
use crate::fit::{EntryType, Fit};

/// Region names by descriptor index.
pub const REGIONS: &[&str] = &[
    "Descriptor",
    "BIOS",
    "ME",
    "GbE",
    "PDR",
    "DevExp1",
    "BIOS2",
    "uCodePatch",
    "EC",
    "DevExp2",
    "IE",
    "10GbE",
];

/// 16-byte EFI wire encoding of a GUID (first three fields little-endian,
/// trailing eight bytes as-is).
const fn guid(d1: u32, d2: u16, d3: u16, d4: [u8; 8]) -> [u8; 16] {
    let a = d1.to_le_bytes();
    let b = d2.to_le_bytes();
    let c = d3.to_le_bytes();
    [
        a[0], a[1], a[2], a[3], b[0], b[1], c[0], c[1], d4[0], d4[1], d4[2], d4[3], d4[4], d4[5],
        d4[6], d4[7],
    ]
}

struct SbKey {
    label: &'static str,
    guid: [u8; 16],
}

/// Vendor Secure Boot key-material sections. PK = keys provisioned; dbx = revocation list.
const SB_KEYS: &[SbKey] = &[
    SbKey { label: "AMI PK", guid: guid(0xCC0F8A3F, 0x3DEA, 0x4376, [0x96, 0x79, 0x54, 0x26, 0xBA, 0x0A, 0x90, 0x7E]) },
    SbKey { label: "AMI dbx", guid: guid(0x9D7A05E9, 0xF740, 0x44C3, [0x85, 0x8B, 0x75, 0x58, 0x6A, 0x8F, 0x9C, 0x8E]) },
    SbKey { label: "Dell PK", guid: guid(0x2C37326C, 0x3FC1, 0x4B03, [0x97, 0xBE, 0x20, 0x71, 0xCC, 0x81, 0x9B, 0x46]) },
    SbKey { label: "Dell dbx", guid: guid(0x83072A6C, 0x4399, 0x49FF, [0xAC, 0xFA, 0x34, 0xF0, 0x6C, 0x61, 0x8B, 0xC0]) },
    SbKey { label: "HP PK", guid: guid(0x3C8C6AC6, 0x2F87, 0x494C, [0xB8, 0x43, 0x41, 0x06, 0x07, 0xD3, 0xAD, 0x3D]) },
];

/// Read/write region bitmasks for one descriptor master.
#[derive(Debug, Clone)]
pub struct MasterAccess {
    pub name: &'static str,
    pub read: u16,
    pub write: u16,
}

/// Decoded FLMSTR access matrix.
#[derive(Debug, Clone)]
pub struct FlmstrReport {
    pub v2: bool,
    pub masters: Vec<MasterAccess>,
    /// ME has write access to the BIOS region (region 1); what `clean -d` removes.
    pub me_writes_bios: bool,
    /// Every master reads/writes every region: the wide-open descriptor
    /// coreboot/liberated boards ship (here `me_writes_bios` is intended).
    pub fully_unlocked: bool,
}

/// Locks determined for an image.
#[derive(Debug, Default, Clone)]
pub struct LockReport {
    pub boot_guard: bool,
    pub boot_guard_entries: Vec<String>,
    pub bios_guard_pfat: bool,
    pub secure_boot_keys: Vec<&'static str>,
    pub descriptor: Option<FlmstrReport>,
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.len() <= haystack.len() && haystack.windows(needle.len()).any(|w| w == needle)
}

impl LockReport {
    /// Scan an image for locks. `descriptor`/`generation` are optional so this
    /// works on BIOS-only images too.
    pub fn scan(buf: &[u8], descriptor: Option<&Descriptor>, generation: Option<u8>) -> Self {
        let mut r = LockReport::default();

        // Boot Guard (FIT)
        if let Ok(fit) = Fit::parse(buf) {
            for e in &fit.entries {
                if matches!(
                    e.entry_type,
                    EntryType::KeyManifest | EntryType::BootPolicyManifest
                ) {
                    r.boot_guard = true;
                    r.boot_guard_entries
                        .push(format!("{} @ {:#x}", e.entry_type.name(), e.address));
                }
            }
        }

        // BIOS Guard (AMI PFAT)
        r.bios_guard_pfat = contains(buf, b"_AMIPFAT");

        // Secure Boot key material
        r.secure_boot_keys = SB_KEYS
            .iter()
            .filter(|k| contains(buf, &k.guid))
            .map(|k| k.label)
            .collect();

        // Descriptor FLMSTR access
        if let Some(d) = descriptor {
            let v2 = generation.map(|g| g >= 3).unwrap_or(false);
            let rd = |o: usize| crate::bytes::u32_le(buf, o);
            let decode = |flmstr: u32| -> (u16, u16) {
                if v2 {
                    (((flmstr >> 8) & 0xfff) as u16, ((flmstr >> 20) & 0xfff) as u16)
                } else {
                    (((flmstr >> 16) & 0xff) as u16, ((flmstr >> 24) & 0xff) as u16)
                }
            };
            let names = ["Host/BIOS", "ME", "GbE"];
            let mut masters = Vec::new();
            for (i, name) in names.iter().enumerate() {
                let (read, write) = decode(rd(d.fmba + i * 4));
                masters.push(MasterAccess { name, read, write });
            }
            // ME master is index 1; BIOS region is bit 1.
            let me_writes_bios = masters[1].write & (1 << 1) != 0;
            let full = if v2 { 0x0fff } else { 0x00ff };
            let fully_unlocked = masters.iter().all(|m| m.read == full && m.write == full);
            r.descriptor = Some(FlmstrReport {
                v2,
                masters,
                me_writes_bios,
                fully_unlocked,
            });
        }

        r
    }

    /// True if any enforcement lock (Boot Guard / BIOS Guard / Secure Boot) is present.
    pub fn any_enforcement(&self) -> bool {
        self.boot_guard || self.bios_guard_pfat || !self.secure_boot_keys.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::descriptor::Descriptor;
    use crate::region::Region;

    #[test]
    fn flmstr_v2_flags_me_write_to_bios() {
        // FLMSTR base 0x100; FLMSTR2 (ME) write field is bits [31:20], so
        // region 1 (BIOS) -> bit 21.
        let mut buf = vec![0u8; 0x200];
        buf[0x104..0x108].copy_from_slice(&(1u32 << 21).to_le_bytes());
        let d = Descriptor {
            frba: 0x40,
            fmba: 0x100,
            fisba: 0,
            fmsba: 0,
            fpsba: 0,
            fd: Region::new(0, 0x1000),
            bios: Region::new(0, 0),
            me: Region::new(0, 0),
        };
        let r = LockReport::scan(&buf, Some(&d), Some(3));
        let flm = r.descriptor.expect("descriptor decoded");
        assert!(flm.v2);
        assert!(flm.me_writes_bios, "ME should be flagged as writing BIOS");
        assert!(flm.masters[1].write & (1 << 1) != 0);
    }
}
