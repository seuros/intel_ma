//! Intel GbE region: the LAN controller's NVM image (MAC, banks, controller ID).

use crate::bytes::u16_le;

/// Bytes covered by the NVM checksum (64 little-endian words).
const NVM_BYTES: usize = 0x80;
/// The 64 checksummed words sum (mod 2^16) to this on a valid bank.
const CHECKSUM_TARGET: u16 = 0xbaba;

/// One NVM bank (part) within the GbE region.
#[derive(Debug, Clone)]
pub struct Bank {
    pub mac: [u8; 6],
    pub checksum_valid: bool,
    /// LAN controller PCI Device ID (word 0x0d); vendor is implicitly Intel.
    pub device_id: u16,
    pub subsystem_vendor: u16,
    pub subsystem_device: u16,
}

impl Bank {
    fn read(region: &[u8], base: usize) -> Self {
        let word = |w: usize| u16_le(region, base + w * 2);
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&region[base..base + 6]);
        let sum = (0..NVM_BYTES / 2).map(|w| word(w) as u32).sum::<u32>() as u16;
        Bank {
            mac,
            checksum_valid: sum == CHECKSUM_TARGET,
            device_id: word(0x0d),
            subsystem_vendor: word(0x0c),
            subsystem_device: word(0x0b),
        }
    }

    pub fn mac_blank(&self) -> bool {
        self.mac == [0xff; 6]
    }

    /// Intel's placeholder MAC shipped in NVM update images.
    pub fn mac_default(&self) -> bool {
        self.mac == [0x88, 0x88, 0x88, 0x88, 0x87, 0x88]
    }

    pub fn controller(&self) -> Option<&'static str> {
        controller_name(self.device_id)
    }
}

/// Parsed GbE region: its banks and the active (checksum-valid) one.
#[derive(Debug, Clone)]
pub struct Gbe {
    pub size: usize,
    pub bank_size: usize,
    pub banks: Vec<Bank>,
    pub active: Option<usize>,
}

/// Parse a GbE region slice; `None` if too small to hold a bank.
pub fn parse(region: &[u8]) -> Option<Gbe> {
    if region.len() < NVM_BYTES {
        return None;
    }
    // Two banks split the region in half; a lone-bank region falls back to one.
    let bank_size = region.len() / 2;
    let bases: &[usize] = if bank_size >= NVM_BYTES {
        &[0, region.len() / 2]
    } else {
        &[0]
    };
    let banks: Vec<Bank> = bases.iter().map(|&b| Bank::read(region, b)).collect();
    let active = banks.iter().position(|b| b.checksum_valid);
    Some(Gbe {
        size: region.len(),
        bank_size,
        banks,
        active,
    })
}

/// Intel PCH-integrated LAN controller Device ID -> model name.
pub fn controller_name(device_id: u16) -> Option<&'static str> {
    Some(match device_id {
        0x10ea => "82577LM",
        0x10eb => "82577LC",
        0x10ef => "82578DM",
        0x10f0 => "82578DC",
        0x1502 => "82579LM",
        0x1503 => "82579V",
        0x153a => "I217-LM",
        0x153b => "I217-V",
        0x155a => "I218-LM",
        0x1559 => "I218-V",
        0x15a0 => "I218-LM (2)",
        0x15a1 => "I218-V (2)",
        0x15a2 => "I218-LM (3)",
        0x15a3 => "I218-V (3)",
        0x156f => "I219-LM",
        0x1570 => "I219-V",
        0x15b7 => "I219-LM (2)",
        0x15b8 => "I219-V (2)",
        0x15b9 => "I219-LM (3)",
        0x15d7 => "I219-LM (4)",
        0x15d8 => "I219-V (4)",
        0x15e3 => "I219-LM (5)",
        0x15d6 => "I219-V (5)",
        _ => return None,
    })
}
