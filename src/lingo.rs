//! lingo - the CLI's themed user-facing strings. Keep the real term in parentheses.

/// Top-level program description.
pub const ABOUT: &str =
    "Intel: Management Absent - take back the silicon a squatter stole from you";

pub const INFO_ABOUT: &str = "Survey the stolen property (descriptor, partitions, ME version)";
pub const CHECK_ABOUT: &str = "Check the squatter's forged papers (FTPR RSA signature, layout)";
pub const CLEAN_ABOUT: &str = "Take the house back (strip and neuter the ME)";
pub const FIT_ABOUT: &str =
    "Inspect the locks they installed (FIT: microcode, ACMs, vendor lock-in)";
pub const LOCKS_ABOUT: &str =
    "Inventory every lock on the house (Boot Guard, BIOS Guard, Secure Boot, descriptor)";
pub const AMD_ABOUT: &str =
    "Cross the street to the AMD house (PSP firmware: FET, directories, entries)";
pub const BIOS_ABOUT: &str =
    "Search the BIOS region (UEFI volumes, modules; decompresses EFI/Tiano sections)";
pub const GBE_ABOUT: &str =
    "Read the mailbox on the wall (GbE region: MAC, LAN controller, NVM banks)";
pub const MEI_ABOUT: &str =
    "Knock on the door of the live machine (probe the running ME over PCI/MEI - Linux only)";

pub const FULL_IMAGE: &str = "The whole house - full SPI dump (flash descriptor present)";
pub const ME_IMAGE: &str = "Just the room they barricaded - ME/TXE region image";
pub const ME_ALREADY_GONE: &str = "Squatter's already gone - ME region is disabled";

/// Render the ME firmware line as a squatter notice.
pub fn squatter_line(version: &str, generation: u8) -> String {
    format!(
        "Squatter found: Intel ME v{version} (generation {generation}) - moved in uninvited, forged the deed, never left"
    )
}

/// Boot Guard headline; `cmd_hint` adds a pointer to the `fit` subcommand.
///
/// Deliberately says CONFIGURED, not ENFORCED: all we can see from a flash
/// image is that the Key Manifest / Boot Policy are present. Real enforcement
/// is decided by the PCH fuses (FPFs), which are burned at the factory and are
/// not part of the SPI image - so a dump can never confirm it either way.
pub fn vendor_lock(cmd_hint: bool) -> String {
    let mut s = String::from(
        "🔒  BOOT GUARD CONFIGURED (Key Manifest + Boot Policy present)\n    The board is set up for Boot Guard, but whether it is ENFORCED lives in the\n    PCH fuses (FPFs) - burned at the factory, not in this image, unreadable from a\n    dump. On OEM hardware assume it is fused ON. If it is, flashing an unsigned or\n    modified BIOS may BRICK the board. A flash cannot turn this on or off.",
    );
    if cmd_hint {
        s.push_str("\n    Case the locks first:  intel_ma fit <image>");
    }
    s
}

pub const NO_VENDOR_LOCK: &str = "No Boot Guard manifests in the FIT - this image is not configured for it (fuse state still unknown)";

pub const DEED_VALID: &str = "Their forged deed is genuine Intel paper - FTPR RSA signature VALID";
pub const DEED_INVALID: &str = "Even the forgery is botched - FTPR RSA signature INVALID!!";

/// House reclaimed; `out` is where the new image was written.
pub fn house_reclaimed(out: &str) -> String {
    format!("House reclaimed. The silicon is yours again.  ->  {out}")
}
