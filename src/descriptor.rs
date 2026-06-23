//! Intel Flash Descriptor (IFD) parsing and per-generation disable-ME strap bits.

use crate::region::Region;

/// IFD signature `0x0FF0A55A`, little-endian on disk: `5A A5 F0 0F`.
pub const FD_SIGNATURE: [u8; 4] = [0x5a, 0xa5, 0xf0, 0x0f];
/// `$FPT`.
pub const FPT_MAGIC: [u8; 4] = *b"$FPT";

/// Decode an FLREG register into `(start, end)` byte offsets; `end` is exclusive.
pub fn flreg_to_start_end(flreg: u32) -> (usize, usize) {
    let start = ((flreg & 0x7fff) << 12) as usize;
    let end = (((flreg >> 4) & 0x7fff000 | 0xfff) + 1) as usize;
    (start, end)
}

/// Encode `(start, end)` into an FLREG register value.
pub fn start_end_to_flreg(start: usize, end: usize) -> u32 {
    let start = start as u32;
    let end = end as u32;
    (start & 0x7fff000) >> 12 | ((end - 1) & 0x7fff000) << 4
}

/// Parsed descriptor layout. `fpsba` = soft-strap base (== `fisba` for gen 2+).
#[derive(Debug, Clone, Copy)]
pub struct Descriptor {
    pub frba: usize,
    pub fmba: usize,
    pub fisba: usize,
    pub fmsba: usize,
    pub fpsba: usize,
    pub fd: Region,
    pub bios: Region,
    pub me: Region,
}

impl Descriptor {
    /// Parse the descriptor; `sig_at_zero` = FD signature at offset 0 (gen 1) vs 0x10.
    pub fn parse(buf: &[u8], sig_at_zero: bool) -> Self {
        let base = if sig_at_zero { 0x4 } else { 0x14 };
        let rd = |o: usize| crate::bytes::u32_le(buf, o);

        let flmap0 = rd(base);
        let flmap1 = rd(base + 4);
        let flmap2 = rd(base + 8);

        let frba = (flmap0 >> 12 & 0xff0) as usize;
        let fmba = ((flmap1 & 0xff) << 4) as usize;
        let fisba = (flmap1 >> 12 & 0xff0) as usize;
        let fmsba = ((flmap2 & 0xff) << 4) as usize;
        let fpsba = fisba;

        let flreg0 = rd(frba);
        let flreg1 = rd(frba + 4);
        let flreg2 = rd(frba + 8);

        let (fd_s, fd_e) = flreg_to_start_end(flreg0);
        let (bios_s, bios_e) = flreg_to_start_end(flreg1);
        let (me_s, me_e) = flreg_to_start_end(flreg2);

        Self {
            frba,
            fmba,
            fisba,
            fmsba,
            fpsba,
            fd: Region::new(fd_s, fd_e),
            bios: Region::new(bios_s, bios_e),
            me: Region::new(me_s, me_e),
        }
    }
}

/// Location of the disable-ME strap for a generation. Gen 1 is special-cased (two straps, bit 0).
pub struct DisableBit {
    /// Strap dword offset relative to `fpsba`.
    pub strap_off: usize,
    /// Bit index within the strap dword.
    pub bit: u32,
    /// Human-readable strap name, for messages.
    pub name: &'static str,
}

/// Resolve the HAP/AltMeDisable strap for gen >= 2; `None` for gen 1.
pub fn disable_bit(generation: u8) -> Option<DisableBit> {
    Some(match generation {
        2 => DisableBit { strap_off: 0x28, bit: 7, name: "AltMeDisable bit in PCHSTRP10" },
        3 => DisableBit { strap_off: 0x00, bit: 16, name: "HAP bit in PCHSTRP0" },
        4 => DisableBit { strap_off: 0x70, bit: 16, name: "HAP bit in PCHSTRP28" },
        5 => DisableBit { strap_off: 0x80, bit: 16, name: "HAP bit in PCHSTRP32" },
        6 => DisableBit { strap_off: 0x7c, bit: 16, name: "HAP bit in PCHSTRP31" },
        7 => DisableBit { strap_off: 0xdc, bit: 16, name: "HAP bit in PCHSTRP55" },
        _ => DisableBit { strap_off: 0x00, bit: 16, name: "HAP bit in PCHSTRP0" },
    })
}
