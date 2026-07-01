//! AMD PSP firmware parsing (inspector; PSP cannot be disabled). Ported from PSPTool (GPL-3).

use crate::bytes::u32_le;

/// FET signature (LE `0x55AA55AA`).
pub const FET_MAGIC: [u8; 4] = [0xAA, 0x55, 0xAA, 0x55];

const DIR_MAGICS: [&[u8; 4]; 6] = [b"$PSP", b"$PL2", b"$BHD", b"$BL2", b"2PSP", b"2BHD"];

/// One PSP/BIOS directory entry.
#[derive(Debug, Clone)]
pub struct Entry {
    pub type_id: u8,
    pub size: u32,
    pub location: u32,
}

impl Entry {
    /// Entry type name (PSP or BIOS table).
    pub fn name_for(&self, is_bios: bool) -> &'static str {
        if is_bios {
            bios_entry_name(self.type_id)
        } else {
            psp_entry_name(self.type_id)
        }
    }
}

/// A parsed `$PSP`/`$BHD` directory.
#[derive(Debug, Clone)]
pub struct Directory {
    pub magic: [u8; 4],
    pub offset: usize,
    pub count: u32,
    pub is_bios: bool,
    pub is_combo: bool,
    pub entries: Vec<Entry>,
}

impl Directory {
    pub fn magic_str(&self) -> String {
        String::from_utf8_lossy(&self.magic).into_owned()
    }
}

/// Parsed AMD firmware view.
#[derive(Debug, Clone)]
pub struct AmdFirmware {
    pub fet_offset: Option<usize>,
    pub rom_size: usize,
    pub directories: Vec<Directory>,
}

fn rom_size_for(len: usize) -> usize {
    for mb in [32usize, 16, 8] {
        if mb * 1024 * 1024 <= len {
            return mb * 1024 * 1024;
        }
    }
    len.next_power_of_two()
}

/// Fixed EFS offsets where AMD places the FET.
const FET_FIXED_OFFSETS: [usize; 7] = [
    0x20000, 0x820000, 0x920000, 0xc20000, 0xe20000, 0xf20000, 0xfa0000,
];

/// Locate the FET: try fixed offsets, else scan for `FF`/`00` padding followed by magic.
fn find_fet(buf: &[u8]) -> Option<usize> {
    for off in FET_FIXED_OFFSETS {
        if off + 4 <= buf.len() && buf[off..off + 4] == FET_MAGIC {
            return Some(off);
        }
    }
    let n = buf.len();
    let mut i = 0;
    while i + 8 <= n {
        let pre = &buf[i..i + 4];
        if (pre == [0xff; 4] || pre == [0x00; 4]) && buf[i + 4..i + 8] == FET_MAGIC {
            return Some(i + 4);
        }
        i += 1;
    }
    None
}

/// Translate a mapped ROM address into a file offset.
fn mask_addr(addr: u32, rom_size: usize) -> usize {
    if addr > 0xff00_0000 && rom_size > 16 * 1024 * 1024 {
        (addr & 0x00ff_ffff) as usize
    } else {
        (addr as usize) & (rom_size - 1)
    }
}

/// Validate and parse a directory at `offset` (rejects embedded false positives).
fn parse_directory(buf: &[u8], offset: usize, rom_size: usize) -> Option<Directory> {
    if offset + 0x10 > buf.len() {
        return None;
    }
    let magic: [u8; 4] = buf[offset..offset + 4].try_into().ok()?;
    if !DIR_MAGICS.contains(&&magic) {
        return None;
    }
    let is_combo = &magic == b"2PSP" || &magic == b"2BHD";
    let is_bios = &magic == b"$BHD" || &magic == b"$BL2" || &magic == b"2BHD";
    let count = u32_le(buf, offset + 8);
    if count == 0 || count > 256 {
        return None;
    }

    let mut entries = Vec::new();
    if !is_combo {
        let esize = if is_bios { 24 } else { 16 };
        let base = offset + 0x10;
        if base + count as usize * esize > buf.len() {
            return None;
        }
        for i in 0..count as usize {
            let e = base + i * esize;
            entries.push(Entry {
                type_id: buf[e],
                size: u32_le(buf, e + 4),
                location: mask_addr(u32_le(buf, e + 8), rom_size) as u32,
            });
        }
        // Real directories have >=1 entry inside the ROM with a plausible size.
        let sane = entries
            .iter()
            .filter(|e| (e.location as usize) < rom_size && (e.size as usize) <= rom_size)
            .count();
        if sane == 0 {
            return None;
        }
    }

    Some(Directory {
        magic,
        offset,
        count,
        is_bios,
        is_combo,
        entries,
    })
}

/// Parse AMD firmware in a full SPI image (scans for directory magics; FET
/// layout varies across Zen generations).
pub fn parse(buf: &[u8]) -> Option<AmdFirmware> {
    let fet_offset = find_fet(buf);
    let rom_size = rom_size_for(buf.len());

    let mut directories: Vec<Directory> = Vec::new();
    let n = buf.len();
    let mut i = 0;
    while i + 4 <= n {
        // Magics start with '$' or '2'; cheap pre-filter.
        if (buf[i] == b'$' || buf[i] == b'2')
            && let Some(dir) = parse_directory(buf, i, rom_size)
        {
            directories.push(dir);
        }
        i += 1;
    }

    if fet_offset.is_none() && directories.is_empty() {
        return None;
    }
    Some(AmdFirmware {
        fet_offset,
        rom_size,
        directories,
    })
}

/// Human-readable name for a PSP directory entry type.
pub fn psp_entry_name(t: u8) -> &'static str {
    match t {
        0x00 => "AMD_PUBLIC_KEY",
        0x01 => "PSP_FW_BOOT_LOADER",
        0x02 => "PSP_FW_TRUSTED_OS",
        0x03 => "PSP_FW_RECOVERY_BOOT_LOADER",
        0x04 => "PSP_NV_DATA",
        0x05 => "BIOS_PUBLIC_KEY",
        0x06 => "BIOS_RTM_FIRMWARE",
        0x07 => "BIOS_RTM_SIGNATURE",
        0x08 => "SMU_OFFCHIP_FW",
        0x09 => "SEC_DBG_PUBLIC_KEY",
        0x0a => "OEM_PSP_FW_PUBLIC_KEY",
        0x0b => "SOFT_FUSE_CHAIN",
        0x0c => "PSP_BOOT_TIME_TRUSTLETS",
        0x10 => "PSP_AGESA_RESUME_FW",
        0x12 => "SMU_OFF_CHIP_FW_2",
        0x13 => "DEBUG_UNLOCK",
        0x21 => "WRAPPED_IKEK",
        0x22 => "TOKEN_UNLOCK",
        0x24 => "SEC_GASKET",
        0x25 => "MP2_FW",
        0x28 => "DRIVER_ENTRIES",
        0x30..=0x37 => "ABL",
        0x38 => "SEV_DATA",
        0x39 => "SEV_CODE",
        0x40 => "PSP_FW_L2_PTR",
        0x44 => "FW_XHCI",
        0x48 => "PSP_FW_L2A_PTR",
        0x49 => "BIOS_L2AB_PTR",
        0x4a => "PSP_FW_L2B_PTR",
        0x4e => "PMU_PUBKEY",
        _ => "unknown",
    }
}

/// Human-readable name for a BIOS directory entry type.
pub fn bios_entry_name(t: u8) -> &'static str {
    match t {
        0x60 => "APCB",
        0x61 => "APOB",
        0x62 => "BIOS",
        0x63 => "APOB_NV_COPY",
        0x64 => "PMU_CODE",
        0x65 => "PMU_DATA",
        0x66 => "MICROCODE_PATCH",
        0x67 => "CORE_MCE_DATA",
        0x68 => "APCB_COPY",
        0x69 => "EARLY_VGA_IMAGE",
        0x70 => "APOB_NV",
        0x77 => "DDRPHY_PCU_FW",
        _ => "unknown",
    }
}
