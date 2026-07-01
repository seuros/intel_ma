//! Flash Partition Table (`$FPT`) parsing and FTPR location.

use crate::bytes::u32_le;
use crate::error::{Error, Result};
use crate::region::Region;

pub const FPT_HEADER_LEN: usize = 0x20;
pub const ENTRY_LEN: usize = 0x20;

/// One FPT partition entry (0x20 bytes).
#[derive(Debug, Clone)]
pub struct Partition {
    pub name: [u8; 4],
    pub start: u32,
    pub length: u32,
    pub flags: u32,
    pub raw: [u8; ENTRY_LEN],
}

impl Partition {
    /// Partition name as a printable string (NUL-trimmed, lossy on non-ascii).
    pub fn name_str(&self) -> String {
        let trimmed: Vec<u8> = self.name.iter().copied().take_while(|&b| b != 0).collect();
        match std::str::from_utf8(&trimmed) {
            Ok(s) => s.to_string(),
            Err(_) => "????".to_string(),
        }
    }

    pub fn end(&self) -> u64 {
        self.start as u64 + self.length as u64
    }
}

/// Parsed `$FPT` table.
#[derive(Debug, Clone)]
pub struct Fpt {
    /// Region-relative offset of the `$FPT` header.
    pub offset: usize,
    pub entries: u32,
    pub partitions: Vec<Partition>,
}

/// Scan the ME region for every `$FPT` signature.
/// Matches magic + entry count whose three high bytes are zero
/// (`\x24\x46\x50\x54.\x00\x00\x00`). Returns all matches; images can carry
/// primary + backup tables.
pub fn find_all_fpt(me_data: &[u8]) -> Vec<usize> {
    let mut matches = Vec::new();
    let n = me_data.len();
    if n < 8 {
        return matches;
    }
    let mut i = 0;
    while i + 8 <= n {
        if &me_data[i..i + 4] == b"$FPT"
            && me_data[i + 5] == 0
            && me_data[i + 6] == 0
            && me_data[i + 7] == 0
        {
            matches.push(i);
        }
        i += 1;
    }
    matches
}

/// Strict single-`$FPT` lookup, for destructive operations that must be sure.
pub fn find_fpt(me_data: &[u8]) -> Result<usize> {
    let matches = find_all_fpt(me_data);
    match matches.len() {
        0 => Err(Error::FptNotFound),
        1 => Ok(matches[0]),
        _ => Err(Error::MultipleFpt),
    }
}

/// Parse the `$FPT` table at `fpt_offset` (region-relative).
pub fn parse_fpt(me: &Region, buf: &[u8], fpt_offset: usize) -> Result<Fpt> {
    let entries = me.read_u32(buf, fpt_offset + 0x4)?;
    let table = me.read(buf, fpt_offset + 0x20, entries as usize * ENTRY_LEN)?;

    let mut partitions = Vec::with_capacity(entries as usize);
    for i in 0..entries as usize {
        let e = &table[i * ENTRY_LEN..(i + 1) * ENTRY_LEN];
        let mut raw = [0u8; ENTRY_LEN];
        raw.copy_from_slice(e);
        partitions.push(Partition {
            name: [e[0], e[1], e[2], e[3]],
            start: u32_le(e, 8),
            length: u32_le(e, 12),
            flags: u32_le(e, 0x1c),
            raw,
        });
    }

    Ok(Fpt {
        offset: fpt_offset,
        entries,
        partitions,
    })
}

/// Location of the FTPR/CODE partition within the ME region.
#[derive(Debug, Clone, Copy)]
pub struct Ftpr {
    pub offset: u32,
    pub length: u32,
    /// True when found as a `CODE` partition (generation 1).
    pub is_code: bool,
    /// True when located via IFWI `$CPD` scan (length unknown, set to 0).
    pub is_ifwi: bool,
}

/// Locate FTPR: via the FPT entry list, else scan for a `$CPD` directory
/// tagged `FTPR` (IFWI images).
pub fn find_ftpr(fpt: &Fpt, me_data: &[u8]) -> Result<Ftpr> {
    for p in &fpt.partitions {
        if &p.name == b"CODE" || &p.name == b"FTPR" {
            return Ok(Ftpr {
                offset: p.start,
                length: p.length,
                is_code: &p.name == b"CODE",
                is_ifwi: false,
            });
        }
    }

    // IFWI / modern CSME: "$CPD" + 8 bytes + "FTPR". Take the first of the
    // primary + backup copies.
    let n = me_data.len();
    let mut i = 0;
    while i + 16 <= n {
        if &me_data[i..i + 4] == b"$CPD" && &me_data[i + 12..i + 16] == b"FTPR" {
            return Ok(Ftpr {
                offset: i as u32,
                length: 0,
                is_code: false,
                is_ifwi: true,
            });
        }
        i += 1;
    }

    Err(Error::FtprNotFound)
}
