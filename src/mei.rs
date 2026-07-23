//! Live probe of the Management Engine on the *running* machine (Linux only).
//!
//! Never touches a firmware image; reads what the OS already exposes: the
//! HECI/MEI PCI function, the `/dev/mei0` node, and sysfs
//! `dev_state`/`fw_ver`/`fw_status`. All world-readable, no root or ioctl. On
//! macOS/FreeBSD [`probe`] returns [`Error::Unsupported`] and the build stays green.

use crate::error::Result;

/// An Intel HECI/MEI PCI function found on the bus.
#[derive(Debug, Clone)]
pub struct PciDevice {
    pub address: String,
    pub vendor: u16,
    pub device: u16,
    pub class: u32,
}

/// One firmware-version block as reported by the kernel (`platform:maj.min.hotfix.build`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FwVer {
    pub platform: u16,
    pub major: u16,
    pub minor: u16,
    pub hotfix: u16,
    pub build: u16,
}

impl FwVer {
    /// Human name for the ME family, keyed off the major version.
    pub fn family(&self) -> String {
        match self.major {
            11..=19 => format!("CSME {}", self.major),
            6..=10 => format!("ME {}", self.major),
            1..=5 => format!("ME/TXE {}", self.major),
            other => format!("ME (major {other})"),
        }
    }
}

impl std::fmt::Display for FwVer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}",
            self.major, self.minor, self.hotfix, self.build
        )
    }
}

/// Result of probing the running system.
#[derive(Debug, Default, Clone)]
pub struct MeiProbe {
    /// Intel HECI/MEI PCI functions on the bus.
    pub pci: Vec<PciDevice>,
    /// `/dev/mei0` exists (driver bound, engine reachable).
    pub dev_node: bool,
    /// sysfs `dev_state` (e.g. `ENABLED`, `DISABLED`, `INIT_CLIENTS`).
    pub dev_state: Option<String>,
    /// Parsed sysfs `fw_ver` blocks (code / recovery / FITC).
    pub fw_ver: Vec<FwVer>,
    /// sysfs `fw_status` HFSTS registers.
    pub fw_status: Vec<u32>,
}

/// Parse one `fw_ver` line, e.g. `0:16.0.15.1620`. Returns `None` on any garbage.
pub fn parse_fw_ver(line: &str) -> Option<FwVer> {
    let (platform, rest) = line.trim().split_once(':')?;
    let mut n = rest.split('.');
    let mut next = || n.next()?.parse::<u16>().ok();
    let ver = FwVer {
        platform: platform.parse().ok()?,
        major: next()?,
        minor: next()?,
        hotfix: next()?,
        build: next()?,
    };
    // Reject trailing junk (more than four dotted fields).
    if n.next().is_some() {
        return None;
    }
    Some(ver)
}

#[cfg(target_os = "linux")]
pub fn probe() -> Result<MeiProbe> {
    let mut p = MeiProbe {
        pci: scan_pci_heci(),
        dev_node: std::path::Path::new("/dev/mei0").exists(),
        ..Default::default()
    };

    let base = std::path::Path::new("/sys/class/mei/mei0");
    p.dev_state = read_trimmed(base.join("dev_state"));
    if let Some(text) = read_trimmed(base.join("fw_ver")) {
        p.fw_ver = text.lines().filter_map(parse_fw_ver).collect();
    }
    if let Some(text) = read_trimmed(base.join("fw_status")) {
        p.fw_status = text
            .lines()
            .filter_map(|l| u32::from_str_radix(l.trim(), 16).ok())
            .collect();
    }
    Ok(p)
}

#[cfg(not(target_os = "linux"))]
pub fn probe() -> Result<MeiProbe> {
    Err(crate::error::Error::Unsupported(
        "live ME probe reads Linux sysfs (/sys/class/mei) and /dev/mei - Linux only",
    ))
}

#[cfg(target_os = "linux")]
fn read_trimmed<P: AsRef<std::path::Path>>(path: P) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim_end().to_string())
        .filter(|s| !s.is_empty())
}

/// Walk `/sys/bus/pci/devices` for Intel communication controllers (class
/// 0x0780xx) - the HECI/MEI functions. Works even when no `mei` driver is bound.
#[cfg(target_os = "linux")]
fn scan_pci_heci() -> Vec<PciDevice> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir("/sys/bus/pci/devices") else {
        return out;
    };
    for e in entries.flatten() {
        let dir = e.path();
        let rd = |name: &str| read_trimmed(dir.join(name));
        let (Some(vendor), Some(device), Some(class)) = (rd("vendor"), rd("device"), rd("class"))
        else {
            continue;
        };
        let parse = |s: &str| u32::from_str_radix(s.trim_start_matches("0x"), 16).ok();
        let (Some(vendor), Some(device), Some(class)) =
            (parse(&vendor), parse(&device), parse(&class))
        else {
            continue;
        };
        // Intel (0x8086), communication controller / other (class 0x0780xx).
        if vendor == 0x8086 && (class >> 8) == 0x0780 {
            out.push(PciDevice {
                address: e.file_name().to_string_lossy().into_owned(),
                vendor: vendor as u16,
                device: device as u16,
                class,
            });
        }
    }
    out.sort_by(|a, b| a.address.cmp(&b.address));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fw_ver_parse_display_and_family() {
        let v = parse_fw_ver("0:16.0.15.1620").expect("valid");
        assert_eq!(
            v,
            FwVer {
                platform: 0,
                major: 16,
                minor: 0,
                hotfix: 15,
                build: 1620
            }
        );
        assert_eq!(v.to_string(), "16.0.15.1620");

        let family = |major| FwVer { major, ..v }.family();
        assert_eq!(family(16), "CSME 16");
        assert_eq!(family(9), "ME 9");
        assert_eq!(family(3), "ME/TXE 3");

        for junk in ["", "nope", "0:16.0.15", "0:16.0.15.1620.9"] {
            assert!(parse_fw_ver(junk).is_none(), "should reject {junk:?}");
        }
    }
}
