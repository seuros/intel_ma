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
pub fn vendor_lock(cmd_hint: bool) -> String {
    let mut s = String::from(
        "🔒  THEY CHANGED THE LOCKS (Boot Guard)\n    \"This hardware is property of Intel Corporation, by the will of silicon.\"\n    The squatter nailed the doors shut: forcing your way in (flashing an unsigned image) may BRICK the board.",
    );
    if cmd_hint {
        s.push_str("\n    Case the locks first:  intel_ma fit <image>");
    }
    s
}

pub const NO_VENDOR_LOCK: &str = "Doors are open - Boot Guard not enforced (no lock in the FIT)";

pub const DEED_VALID: &str = "Their forged deed is genuine Intel paper - FTPR RSA signature VALID";
pub const DEED_INVALID: &str = "Even the forgery is botched - FTPR RSA signature INVALID!!";

/// House reclaimed; `out` is where the new image was written.
pub fn house_reclaimed(out: &str) -> String {
    format!("House reclaimed. The silicon is yours again.  ->  {out}")
}
