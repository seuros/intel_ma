//! UEFI BIOS-region walker: firmware volumes -> FFS files -> sections.

use crate::bytes::{u16_le, u32_le};
use efi_compress::{Compression, decompress};

const FV_SIG_OFFSET: usize = 0x28; // "_FVH" within the FV header
const MAX_DEPTH: usize = 16;

/// LZMA custom-decompress GUID EE4E5898-3914-4259-9D6E-DC7BD79403CF.
const LZMA_GUID: [u8; 16] = [
    0x98, 0x58, 0x4e, 0xee, 0x14, 0x39, 0x59, 0x42, 0x9d, 0x6e, 0xdc, 0x7b, 0xd7, 0x94, 0x03, 0xcf,
];

/// Tiano custom-decompress GUID A31280AD-481E-41B6-95E8-127F4C984779.
const TIANO_GUID: [u8; 16] = [
    0xad, 0x80, 0x12, 0xa3, 0x1e, 0x48, 0xb6, 0x41, 0x95, 0xe8, 0x12, 0x7f, 0x4c, 0x98, 0x47, 0x79,
];

#[derive(Debug, Clone)]
pub struct Volume {
    pub offset: usize,
    pub length: u64,
    pub files: usize,
}

/// BIOS vendor signature strings, checked against raw and decompressed content.
const VENDOR_MARKERS: &[(&[u8], &str)] = &[
    (b"InsydeH2O", "Insyde H2O"),
    (b"$IBIOSI$", "Insyde H2O"),
    (b"American Megatrends", "AMI Aptio"),
    (b"AMITSE", "AMI Aptio"),
    (b"_AMIPFAT", "AMI Aptio"),
    (b"Phoenix Technologies", "Phoenix"),
    (b"PhoenixTechnologies", "Phoenix"),
    (b"PhoenixTrust", "Phoenix"),
    (b"PhoenixImage", "Phoenix"),
    // coreboot distros (more specific than generic CBFS marker below).
    (b"Dasharo", "Dasharo (coreboot)"),
    (b"LARCHIVE", "coreboot (CBFS)"),
];

fn detect_vendor(data: &[u8]) -> Option<&'static str> {
    VENDOR_MARKERS.iter().find_map(|(needle, name)| {
        (needle.len() <= data.len() && data.windows(needle.len()).any(|w| w == *needle))
            .then_some(*name)
    })
}

/// Aggregate result of walking the BIOS region.
#[derive(Debug, Default, Clone)]
pub struct BiosImage {
    pub vendor: Option<&'static str>,
    pub volumes: Vec<Volume>,
    pub files: usize,
    /// PE32 / TE executable sections (drivers/applications).
    pub modules: usize,
    pub decompressed_sections: usize,
    pub decompressed_bytes: usize,
    pub lzma_sections: usize,
    /// UI-name strings (section type 0x15).
    pub names: Vec<String>,
}

struct Ctx<'a> {
    buf: &'a [u8],
    img: BiosImage,
}

fn u24(b: &[u8], o: usize) -> usize {
    (b[o] as usize) | ((b[o + 1] as usize) << 8) | ((b[o + 2] as usize) << 16)
}

/// Walk a firmware volume at absolute offset `fv`.
fn walk_volume(ctx: &mut Ctx, fv: usize) {
    let buf = ctx.buf;
    if fv + 0x38 > buf.len() {
        return;
    }
    let fv_len = u64::from_le_bytes(buf[fv + 0x20..fv + 0x28].try_into().unwrap());
    let hdr_len = u16_le(buf, fv + 0x30) as usize;
    let ext = u16_le(buf, fv + 0x34) as usize;
    if fv_len == 0 || fv as u64 + fv_len > buf.len() as u64 || hdr_len < 0x38 {
        return;
    }
    let end = fv + fv_len as usize;

    // File area starts after the (extended) header.
    let mut pos = if ext != 0 {
        let eh = fv + ext;
        if eh + 0x14 > buf.len() {
            fv + hdr_len
        } else {
            let eh_size = u32_le(buf, eh + 0x10) as usize;
            (eh + eh_size + 7) & !7
        }
    } else {
        fv + hdr_len
    };

    let mut file_count = 0;
    while pos + 0x18 <= end {
        let size = u24(buf, pos + 0x14);
        let ftype = buf[pos + 0x12];
        let attrs = buf[pos + 0x13];
        // 0xffffff/0 size = free space / end of files.
        if size == 0xffffff || size == 0 {
            break;
        }
        // attrs bit0 = large file: 64-bit ExtendedSize, data after 0x20 header.
        let (data_start, file_size) = if attrs & 0x01 != 0 {
            let esz = u64::from_le_bytes(buf[pos + 0x18..pos + 0x20].try_into().unwrap()) as usize;
            (pos + 0x20, esz)
        } else {
            (pos + 0x18, size)
        };
        if pos + file_size > end || file_size <= (data_start - pos) {
            break;
        }
        if ftype != 0xf0 {
            // ftype 0xf0 = padding file
            file_count += 1;
            ctx.img.files += 1;
            walk_sections(ctx, data_start, pos + file_size, 0);
        }
        pos = (pos + file_size + 7) & !7;
    }

    ctx.img.volumes.push(Volume {
        offset: fv,
        length: fv_len,
        files: file_count,
    });
}

/// Walk a run of sections in `buf[start..end]`.
fn walk_sections(ctx: &mut Ctx, start: usize, end: usize, depth: usize) {
    if depth > MAX_DEPTH {
        return;
    }
    let buf = ctx.buf;
    let mut pos = start;
    while pos + 4 <= end {
        let mut size = u24(buf, pos);
        let stype = buf[pos + 3];
        let mut content = pos + 4;
        if size == 0xffffff {
            if pos + 8 > end {
                break;
            }
            size = u32_le(buf, pos + 4) as usize;
            content = pos + 8;
        }
        if size < 4 || pos + size > end {
            break;
        }
        let sec_end = pos + size;

        match stype {
            0x01 => decompress_section(ctx, content, sec_end, depth),
            0x02 => guid_section(ctx, pos, content, sec_end, depth),
            0x10..=0x12 => ctx.img.modules += 1, // PE32 / PIC / TE
            0x15 => {
                if let Some(name) = utf16le(&buf[content..sec_end])
                    && !name.is_empty()
                {
                    ctx.img.names.push(name);
                }
            }
            // 0x17 = nested firmware volume image.
            0x17 => {
                walk_volume_slice(ctx, content, sec_end, depth);
            }
            _ => {}
        }

        pos = (sec_end + 3) & !3;
    }
}

/// `EFI_COMPRESSION_SECTION`: UncompressedLength (u32), CompressionType (u8), payload.
fn decompress_section(ctx: &mut Ctx, content: usize, sec_end: usize, depth: usize) {
    if content + 5 > sec_end {
        return;
    }
    let ctype = ctx.buf[content + 4];
    let payload = &ctx.buf[content + 5..sec_end];
    match ctype {
        0x00 => {
            // ctype 0x00 = stored uncompressed; payload is more sections.
            let (s, e) = (content + 5, sec_end);
            walk_sections(ctx, s, e, depth + 1);
        }
        _ => {
            let out = decompress(payload, Compression::EfiStandard)
                .or_else(|_| decompress(payload, Compression::Tiano));
            if let Ok(data) = out {
                record_decompressed(ctx, &data, depth);
            }
        }
    }
}

/// GUID-defined section: decompress LZMA/Tiano, else descend (CRC32-guarded).
fn guid_section(ctx: &mut Ctx, sec_start: usize, content: usize, sec_end: usize, depth: usize) {
    let buf = ctx.buf;
    if content + 0x14 > sec_end {
        return;
    }
    let guid: [u8; 16] = buf[content..content + 16].try_into().unwrap();
    let data_offset = u16_le(buf, content + 16) as usize;
    let inner = sec_start + data_offset;
    if inner >= sec_end {
        return;
    }

    if guid == LZMA_GUID {
        let payload = &buf[inner..sec_end];
        match decompress(payload, Compression::Lzma) {
            Ok(data) => record_decompressed(ctx, &data, depth),
            Err(_) => ctx.img.lzma_sections += 1,
        }
    } else if guid == TIANO_GUID {
        let payload = &buf[inner..sec_end];
        let out = decompress(payload, Compression::Tiano)
            .or_else(|_| decompress(payload, Compression::EfiStandard));
        if let Ok(data) = out {
            record_decompressed(ctx, &data, depth);
        }
    } else {
        // CRC32 guard or similar: inner data is plain sections.
        walk_sections(ctx, inner, sec_end, depth + 1);
    }
}

/// Record a decompressed payload and descend into its sections.
fn record_decompressed(ctx: &mut Ctx, data: &[u8], depth: usize) {
    ctx.img.decompressed_sections += 1;
    ctx.img.decompressed_bytes += data.len();
    walk_owned_sections(ctx, data, depth + 1);
}

/// Walk sections in an owned (decompressed) buffer.
fn walk_owned_sections(ctx: &mut Ctx, data: &[u8], depth: usize) {
    if ctx.img.vendor.is_none() {
        ctx.img.vendor = detect_vendor(data);
    }
    // Temporary Ctx over `data` so offsets stay local.
    let mut sub = Ctx {
        buf: data,
        img: std::mem::take(&mut ctx.img),
    };
    walk_sections(&mut sub, 0, data.len(), depth);
    ctx.img = sub.img;
}

/// Treat `buf[start..end]` as nested firmware volume(s).
fn walk_volume_slice(ctx: &mut Ctx, start: usize, end: usize, depth: usize) {
    if depth > MAX_DEPTH || start + FV_SIG_OFFSET + 4 > end {
        return;
    }
    if &ctx.buf[start + FV_SIG_OFFSET..start + FV_SIG_OFFSET + 4] == b"_FVH" {
        walk_volume(ctx, start);
    }
}

fn utf16le(b: &[u8]) -> Option<String> {
    let mut s = String::new();
    let mut i = 0;
    while i + 1 < b.len() {
        let c = u16::from_le_bytes([b[i], b[i + 1]]);
        if c == 0 {
            break;
        }
        s.push(char::from_u32(c as u32)?);
        i += 2;
    }
    Some(s)
}

/// Parse the BIOS region: find and walk every top-level firmware volume.
pub fn parse(buf: &[u8]) -> BiosImage {
    let mut ctx = Ctx {
        buf,
        img: BiosImage::default(),
    };
    // Top-level FVs found by "_FVH" signature at +0x28.
    let n = buf.len();
    let mut i = 0;
    while i + 4 <= n {
        if &buf[i..i + 4] == b"_FVH" && i >= FV_SIG_OFFSET {
            let fv = i - FV_SIG_OFFSET;
            // Skip volumes already covered by a parsed one.
            let covered = ctx
                .img
                .volumes
                .iter()
                .any(|v| fv >= v.offset && (fv as u64) < v.offset as u64 + v.length);
            if !covered {
                walk_volume(&mut ctx, fv);
            }
        }
        i += 1;
    }
    if ctx.img.vendor.is_none() {
        ctx.img.vendor = detect_vendor(buf);
    }
    ctx.img
}
