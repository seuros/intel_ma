//! Firmware Interface Table (FIT) parsing. Intel FIT BIOS Spec rev 1.x.
//! FIT pointer sits at physical `4GiB - 0x40` (file offset `len - 0x40`),
//! masked by flash size since the flash is memory-mapped ending at 0xFFFF_FFFF.

use crate::bytes::{u16_le, u24_le, u32_le, u64_le};
use crate::error::{Error, Result};

const FIT_MAGIC: &[u8; 8] = b"_FIT_   ";
const FIT_POINTER_FROM_END: usize = 0x40;
const HEADER_SIZE: usize = 0x10;
const ENTRY_SIZE: usize = 0x10;

/// FIT entry type (low 7 bits of the type/checksum byte).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryType {
    Header,
    MicrocodeUpdate,
    StartupAcm,
    DiagnosticAcm,
    BiosStartupModule,
    TpmPolicy,
    BiosPolicy,
    TxtPolicy,
    KeyManifest,
    BootPolicyManifest,
    CseSecureBoot,
    FeaturePolicyDelivery,
    JmpDebugPolicy,
    UnusedEntry,
    Reserved(u8),
}

impl EntryType {
    fn from_u8(v: u8) -> Self {
        match v {
            0x00 => Self::Header,
            0x01 => Self::MicrocodeUpdate,
            0x02 => Self::StartupAcm,
            0x03 => Self::DiagnosticAcm,
            0x07 => Self::BiosStartupModule,
            0x08 => Self::TpmPolicy,
            0x09 => Self::BiosPolicy,
            0x0a => Self::TxtPolicy,
            0x0b => Self::KeyManifest,
            0x0c => Self::BootPolicyManifest,
            0x10 => Self::CseSecureBoot,
            0x2d => Self::FeaturePolicyDelivery,
            0x2f => Self::JmpDebugPolicy,
            0x7f => Self::UnusedEntry,
            other => Self::Reserved(other),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Header => "FIT Header",
            Self::MicrocodeUpdate => "Microcode Update",
            Self::StartupAcm => "Startup ACM",
            Self::DiagnosticAcm => "Diagnostic ACM",
            Self::BiosStartupModule => "BIOS Startup Module",
            Self::TpmPolicy => "TPM Policy Record",
            Self::BiosPolicy => "BIOS Policy Record",
            Self::TxtPolicy => "TXT Policy Record",
            Self::KeyManifest => "Boot Guard Key Manifest",
            Self::BootPolicyManifest => "Boot Guard Boot Policy",
            Self::CseSecureBoot => "CSE Secure Boot",
            Self::FeaturePolicyDelivery => "Feature Policy Delivery",
            Self::JmpDebugPolicy => "JMP $ Debug Policy",
            Self::UnusedEntry => "Unused Entry",
            Self::Reserved(_) => "Reserved",
        }
    }
}

/// One 16-byte FIT entry.
#[derive(Debug, Clone, Copy)]
pub struct FitEntry {
    pub address: u64,
    pub size: u32,
    pub version: u16,
    pub entry_type: EntryType,
    pub checksum_valid: bool,
    pub checksum: u8,
}

/// Parsed Firmware Interface Table.
#[derive(Debug, Clone)]
pub struct Fit {
    /// File offset of the FIT header.
    pub offset: usize,
    /// FIT format version (expected `0x0100`).
    pub version: u16,
    pub entries: Vec<FitEntry>,
}

/// Mask translating the memory-mapped FIT pointer to a file offset.
fn mapping_for(size: usize) -> usize {
    match size {
        0x80_0000 => 0x7f_ffff,   // 8 MiB
        0x100_0000 => 0xff_ffff,  // 16 MiB
        0x200_0000 => 0x1ff_ffff, // 32 MiB
        _ => 0xff_ffff,
    }
}

impl Fit {
    /// Locate and parse the FIT in a full firmware image.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < FIT_POINTER_FROM_END + 4 {
            return Err(Error::FitNotFound);
        }
        let ptr_pos = data.len() - FIT_POINTER_FROM_END;
        let fp = u32_le(data, ptr_pos);
        if fp == 0xffff_ffff || fp == 0 {
            return Err(Error::FitNotFound);
        }

        let offset = mapping_for(data.len()) & fp as usize;
        if !offset.is_multiple_of(0x10) || offset + HEADER_SIZE > data.len() {
            return Err(Error::FitInvalidPointer { offset });
        }
        if &data[offset..offset + 8] != FIT_MAGIC {
            return Err(Error::FitNotFound);
        }

        // Header's `entries` field is the total record count including itself.
        let total = u32_le(data, offset + 0x8) as usize;
        let version = u16_le(data, offset + 0xc);
        let count = total.saturating_sub(1);

        let body = offset + HEADER_SIZE;
        if body + count * ENTRY_SIZE > data.len() {
            return Err(Error::FitInvalidPointer { offset });
        }

        let mut entries = Vec::with_capacity(count);
        for i in 0..count {
            let e = &data[body + i * ENTRY_SIZE..body + (i + 1) * ENTRY_SIZE];
            let address = u64_le(e, 0);
            let size = u24_le(e, 8);
            let version = u16_le(e, 12);
            let type_byte = e[14];
            entries.push(FitEntry {
                address,
                size,
                version,
                entry_type: EntryType::from_u8(type_byte & 0x7f),
                checksum_valid: type_byte & 0x80 != 0,
                checksum: e[15],
            });
        }

        Ok(Fit {
            offset,
            version,
            entries,
        })
    }

    /// True if the FIT advertises Boot Guard (Key Manifest or Boot Policy).
    /// Flashing an unsigned image on such a board can brick it.
    pub fn has_boot_guard(&self) -> bool {
        self.entries.iter().any(|e| {
            matches!(
                e.entry_type,
                EntryType::KeyManifest | EntryType::BootPolicyManifest
            )
        })
    }

    pub fn microcode_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.entry_type == EntryType::MicrocodeUpdate)
            .count()
    }
}
