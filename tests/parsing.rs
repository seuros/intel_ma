//! Parsing/analysis tests on synthetic images.

use intel_ma::descriptor::{flreg_to_start_end, start_end_to_flreg};
use intel_ma::region::Region;

/// Build a minimal, well-formed ME-only image (no descriptor) with a single
/// FTPR partition carrying a `$MN2` manifest and a version field.
fn synthetic_me_image() -> Vec<u8> {
    let mut buf = vec![0u8; 0x1000];

    // $FPT header at 0x10 (after a 16-byte ROM_BYPASS vector).
    buf[0x10..0x14].copy_from_slice(b"$FPT");
    buf[0x14..0x18].copy_from_slice(&1u32.to_le_bytes()); // entry count

    // FTPR partition entry at 0x30.
    let e = 0x30;
    buf[e..e + 4].copy_from_slice(b"FTPR");
    buf[e + 0x8..e + 0xc].copy_from_slice(&0x100u32.to_le_bytes()); // offset
    buf[e + 0xc..e + 0x10].copy_from_slice(&0x80u32.to_le_bytes()); // length
    buf[e + 0x1c..e + 0x20].copy_from_slice(&0u32.to_le_bytes()); // flags

    // FTPR body at 0x100: $MN2 manifest tag at +0x1c, version at +0x24.
    let f = 0x100;
    buf[f + 0x1c..f + 0x20].copy_from_slice(b"$MN2");
    buf[f + 0x24..f + 0x26].copy_from_slice(&9u16.to_le_bytes()); // major = 9

    buf
}

#[test]
fn flreg_roundtrip() {
    for &(start, end) in &[
        (0x3000usize, 0x100000usize),
        (0x1000, 0x800000),
        (0, 0x1000),
    ] {
        let flreg = start_end_to_flreg(start, end);
        let (s, e) = flreg_to_start_end(flreg);
        assert_eq!(
            (s, e),
            (start, end),
            "flreg roundtrip for {start:#x}..{end:#x}"
        );
    }
}

#[test]
fn region_bounds_and_ops() {
    let mut buf = vec![0u8; 0x100];
    let r = Region::new(0x10, 0x40);

    assert_eq!(r.len(), 0x30);
    assert!(r.read(&buf, 0x30, 1).is_err()); // out of region
    r.write_u32(&mut buf, 0, 0xdead_beef).unwrap();
    assert_eq!(r.read_u32(&buf, 0).unwrap(), 0xdead_beef);

    r.fill_range(&mut buf, 0x4, 0x8, 0xff).unwrap();
    assert_eq!(&buf[0x14..0x18], &[0xff; 4]);

    // move_range relocates and fills the source with 0xff.
    r.write(&mut buf, 0x10, b"DATA").unwrap();
    r.move_range(&mut buf, 0x10, 4, 0x20, 0xff).unwrap();
    assert_eq!(r.read(&buf, 0x20, 4).unwrap(), b"DATA");
    assert_eq!(r.read(&buf, 0x10, 4).unwrap(), &[0xff; 4]);
}

#[test]
fn analyze_synthetic_me_image() {
    let buf = synthetic_me_image();
    let a = intel_ma::analyze(&buf).expect("analyze should succeed");

    assert!(!a.full_image);
    assert!(a.descriptor.is_none());
    assert_eq!(a.me, Region::new(0, 0x1000));
    assert_eq!(a.generation, Some(2));
    assert_eq!(a.variant, "ME"); // unknown key -> assumed ME (major >= 6)

    let v = a.version.expect("version parsed");
    assert_eq!(v.0[0], 9);

    let fpt = a.fpt.expect("fpt parsed");
    assert_eq!(fpt.entries, 1);
    assert_eq!(fpt.partitions[0].name_str(), "FTPR");

    let ftpr = a.ftpr.expect("ftpr found");
    assert_eq!(ftpr.offset, 0x100);
    assert_eq!(ftpr.length, 0x80);
    assert!(!ftpr.is_ifwi);
}

#[test]
fn fit_parse_and_boot_guard() {
    use intel_ma::fit::{EntryType, Fit};

    // 16 MiB image; FIT at 0x1000 with header + a microcode + a Key Manifest.
    let size = 0x100_0000usize;
    let mut buf = vec![0xffu8; size];
    let fit_off = 0x1000usize;

    // Header: magic, entries=3 (incl. header), version 0x0100.
    buf[fit_off..fit_off + 8].copy_from_slice(b"_FIT_   ");
    buf[fit_off + 8..fit_off + 0xc].copy_from_slice(&3u32.to_le_bytes());
    buf[fit_off + 0xc..fit_off + 0xe].copy_from_slice(&0x0100u16.to_le_bytes());

    // Entry 1: microcode (type 0x01), checksum-valid bit set.
    let e1 = fit_off + 0x10;
    buf[e1 + 14] = 0x80 | 0x01;
    // Entry 2: Boot Guard Key Manifest (type 0x0b).
    let e2 = fit_off + 0x20;
    buf[e2 + 14] = 0x0b;

    // FIT pointer at len-0x40, memory-mapped (mask 0xff_ffff for 16 MiB).
    let ptr = size - 0x40;
    buf[ptr..ptr + 4].copy_from_slice(&(fit_off as u32 | 0xff00_0000).to_le_bytes());

    let fit = Fit::parse(&buf).expect("FIT should parse");
    assert_eq!(fit.offset, fit_off);
    assert_eq!(fit.version, 0x0100);
    assert_eq!(fit.entries.len(), 2);
    assert_eq!(fit.entries[0].entry_type, EntryType::MicrocodeUpdate);
    assert!(fit.entries[0].checksum_valid);
    assert_eq!(fit.entries[1].entry_type, EntryType::KeyManifest);
    assert!(fit.has_boot_guard());
    assert_eq!(fit.microcode_count(), 1);
}

#[test]
fn locks_detects_boot_guard_bios_guard_secure_boot() {
    use intel_ma::locks::LockReport;
    let size = 0x100_0000usize;
    let mut buf = vec![0xffu8; size];

    // FIT with a Boot Guard Key Manifest entry.
    let fit_off = 0x1000usize;
    buf[fit_off..fit_off + 8].copy_from_slice(b"_FIT_   ");
    buf[fit_off + 8..fit_off + 0xc].copy_from_slice(&2u32.to_le_bytes());
    buf[fit_off + 0xc..fit_off + 0xe].copy_from_slice(&0x0100u16.to_le_bytes());
    buf[fit_off + 0x10 + 14] = 0x0b; // Key Manifest
    let ptr = size - 0x40;
    buf[ptr..ptr + 4].copy_from_slice(&(fit_off as u32 | 0xff00_0000).to_le_bytes());

    // BIOS Guard marker and an AMI PK GUID (EFI wire encoding).
    buf[0x5000..0x5008].copy_from_slice(b"_AMIPFAT");
    let ami_pk: [u8; 16] = [
        0x3f, 0x8a, 0x0f, 0xcc, 0xea, 0x3d, 0x76, 0x43, 0x96, 0x79, 0x54, 0x26, 0xba, 0x0a, 0x90,
        0x7e,
    ];
    buf[0x6000..0x6010].copy_from_slice(&ami_pk);

    let r = LockReport::scan(&buf, None, None);
    assert!(r.boot_guard);
    assert!(r.bios_guard_pfat);
    assert!(r.secure_boot_keys.contains(&"AMI PK"));
    assert!(r.any_enforcement());
    assert!(r.descriptor.is_none()); // no descriptor passed
}

#[test]
fn fit_rejects_no_pointer() {
    let buf = vec![0xffu8; 0x100_0000];
    assert!(intel_ma::fit::Fit::parse(&buf).is_err());
}

#[test]
fn analyze_tolerates_multiple_fpt() {
    // Two $FPT signatures: the real one (with FTPR) at 0x10, a decoy at 0x800.
    let mut buf = synthetic_me_image();
    let d = 0x800;
    buf[d..d + 4].copy_from_slice(b"$FPT");
    buf[d + 4..d + 8].copy_from_slice(&1u32.to_le_bytes()); // 1 entry, high bytes 0
    // decoy entry: a non-FTPR partition with no data
    buf[d + 0x20..d + 0x24].copy_from_slice(b"XXXX");

    let a = intel_ma::analyze(&buf).expect("analyze must not abort on multiple $FPT");
    assert_eq!(a.fpt_candidates.len(), 2);
    assert!(!a.warnings.is_empty());
    // The FTPR-bearing table (0x10) must win.
    assert_eq!(a.fpt.as_ref().unwrap().offset, 0x10);
    assert_eq!(a.ftpr.unwrap().offset, 0x100);
}

#[test]
fn clean_refuses_multiple_fpt() {
    let mut buf = synthetic_me_image();
    let d = 0x800;
    buf[d..d + 4].copy_from_slice(b"$FPT");
    buf[d + 4..d + 8].copy_from_slice(&1u32.to_le_bytes());

    let err = intel_ma::clean(&mut buf, &intel_ma::Options::default()).unwrap_err();
    assert!(matches!(err, intel_ma::Error::MultipleFpt));
}

#[test]
fn amd_parses_psp_directory() {
    use intel_ma::amd;
    let size = 0x80_0000usize; // 8 MiB
    let mut buf = vec![0u8; size];

    // FET magic at the fixed 0x20000 offset.
    buf[0x20000..0x20004].copy_from_slice(&amd::FET_MAGIC);

    // A $PSP directory at 0x40000: header (magic, checksum, count=2, info).
    let d = 0x40000usize;
    buf[d..d + 4].copy_from_slice(b"$PSP");
    buf[d + 8..d + 0xc].copy_from_slice(&2u32.to_le_bytes());
    // entry 0: PSP_FW_BOOT_LOADER
    buf[d + 0x10] = 0x01;
    buf[d + 0x14..d + 0x18].copy_from_slice(&0x1000u32.to_le_bytes());
    buf[d + 0x18..d + 0x1c].copy_from_slice(&0x50000u32.to_le_bytes());
    // entry 1: AMD_PUBLIC_KEY
    buf[d + 0x20] = 0x00;
    buf[d + 0x24..d + 0x28].copy_from_slice(&0x440u32.to_le_bytes());
    buf[d + 0x28..d + 0x2c].copy_from_slice(&0x60000u32.to_le_bytes());

    let fw = amd::parse(&buf).expect("AMD firmware should parse");
    assert_eq!(fw.fet_offset, Some(0x20000));
    let psp = fw
        .directories
        .iter()
        .find(|d| &d.magic == b"$PSP")
        .expect("$PSP directory found");
    assert_eq!(psp.entries.len(), 2);
    assert_eq!(psp.entries[0].name_for(false), "PSP_FW_BOOT_LOADER");
    assert_eq!(psp.entries[1].name_for(false), "AMD_PUBLIC_KEY");
}

#[test]
fn amd_absent_on_intel_image() {
    // The synthetic Intel ME image has no FET and no valid AMD directories.
    assert!(intel_ma::amd::parse(&synthetic_me_image()).is_none());
}

#[test]
fn analyze_rejects_garbage() {
    let buf = vec![0xa5u8; 0x1000];
    assert!(intel_ma::analyze(&buf).is_err());
}

#[test]
fn analyze_detects_full_image() {
    // Minimal full image: FD signature at 0x10, descriptor maps an empty ME
    // region (start >= end) so analysis short-circuits as "ME disabled".
    let mut buf = vec![0u8; 0x1000];
    buf[0x10..0x14].copy_from_slice(&[0x5a, 0xa5, 0xf0, 0x0f]);
    // flmap0 at 0x14: frba nibble. Put FRBA at 0x40.
    // frba = flmap0 >> 12 & 0xff0  => need (flmap0 >> 12 & 0xff0) == 0x40
    // 0x40 = flmap0 >> 12 & 0xff0  -> flmap0 = 0x40 << 12 = 0x40000
    buf[0x14..0x18].copy_from_slice(&0x0004_0000u32.to_le_bytes());
    // FLREG2 (ME) at frba+8 = 0x48: leave 0 -> start=0,end=0x1000? end=(0|0xfff)+1=0x1000.
    // Make ME empty: set so start>=end. flreg with start bits high, end low:
    // start=(flreg&0x7fff)<<12. Use flreg=0x00007fff -> start=0x7fff000, end=0x1000.
    buf[0x48..0x4c].copy_from_slice(&0x0000_7fffu32.to_le_bytes());

    let a = intel_ma::analyze(&buf).expect("full image analyze");
    assert!(a.full_image);
    assert!(a.me_disabled);
}

/// One 128-byte GbE NVM bank with word 0x3f fixed so the 64 words sum to 0xbaba.
fn gbe_bank(mac: [u8; 6], device_id: u16) -> [u8; 0x80] {
    let mut b = [0u8; 0x80];
    b[0..6].copy_from_slice(&mac);
    b[0x1a..0x1c].copy_from_slice(&device_id.to_le_bytes()); // word 0x0d
    let partial: u16 = (0..0x3f)
        .map(|w| u16::from_le_bytes([b[w * 2], b[w * 2 + 1]]))
        .fold(0u16, |a, w| a.wrapping_add(w));
    let fixup = 0xbabau16.wrapping_sub(partial);
    b[0x7e..0x80].copy_from_slice(&fixup.to_le_bytes());
    b
}

#[test]
fn gbe_parses_mac_controller_and_active_bank() {
    let mut region = vec![0u8; 0x2000];
    let mac = [0xc0, 0x3f, 0xd5, 0x64, 0x09, 0x82];
    region[0..0x80].copy_from_slice(&gbe_bank(mac, 0x1559));

    let gbe = intel_ma::gbe::parse(&region).expect("gbe parse");
    assert_eq!(gbe.banks.len(), 2);
    assert_eq!(gbe.active, Some(0));
    assert!(gbe.banks[0].checksum_valid);
    assert!(!gbe.banks[1].checksum_valid);
    assert_eq!(gbe.banks[0].mac, mac);
    assert_eq!(gbe.banks[0].device_id, 0x1559);
    assert_eq!(gbe.banks[0].controller(), Some("I218-V"));
}

#[test]
fn bios_scan_finds_option_rom() {
    let mut buf = vec![0u8; 0x400];
    buf[0] = 0x55;
    buf[1] = 0xaa;
    buf[2] = 2; // 2 * 512 = 1024 bytes
    buf[0x18..0x1a].copy_from_slice(&0x20u16.to_le_bytes());
    buf[0x20..0x24].copy_from_slice(b"PCIR");
    buf[0x24..0x26].copy_from_slice(&0x10deu16.to_le_bytes()); // NVIDIA
    buf[0x26..0x28].copy_from_slice(&0x0ffcu16.to_le_bytes());
    buf[0x2d..0x30].copy_from_slice(&[0x00, 0x00, 0x03]); // display class

    let img = intel_ma::bios::parse(&buf);
    assert_eq!(img.option_roms.len(), 1);
    let r = &img.option_roms[0];
    assert_eq!((r.vendor, r.device), (0x10de, 0x0ffc));
    assert_eq!(r.size, 1024);
    assert!(r.is_display());
    assert_eq!(r.vendor_name(), "NVIDIA");
    assert_eq!(r.data.len(), 1024);
    assert_eq!(&r.data[..2], &[0x55, 0xaa]);
    assert_eq!(r.file_stem(), "vgabios_nvidia_10de_0ffc");
}
