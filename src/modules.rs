//! FTPR module removal and partition relocation.
//!
//! Gen 2: `$MME` headers, optional Huffman via `LLUT` chunk table.
//! Gen 3: `$CPD` directory with per-module compression flags.
//! All offsets are ME-region-relative; `me_len` clamps every fill.

use crate::bytes::{u24_le, u32_le};
use crate::error::{Error, Result};
use crate::region::Region;

pub const MIN_FTPR_OFFSET: usize = 0x400;
pub const SPARED_BLOCKS: usize = 4;
const UNREMOVABLE: [&str; 2] = ["ROMP", "BUP"];
const UNREMOVABLE_GEN3: [&str; 4] = ["rbe", "kernel", "syslib", "bup"];

fn ascii_trim(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

/// `(start, end)` byte ranges of every Huffman chunk, derived from the LLUT.
fn get_chunks_offsets(llut: &[u8]) -> Vec<[u32; 2]> {
    let chunk_count = u32_le(llut, 0x4) as usize;
    let huffman_stream_end = u32_le(llut, 0x10).wrapping_add(u32_le(llut, 0x14));

    let mut nonzero = vec![huffman_stream_end];
    let mut offsets: Vec<[u32; 2]> = Vec::with_capacity(chunk_count);

    for i in 0..chunk_count {
        let chunk = &llut[0x40 + i * 4..0x44 + i * 4];
        let offset = if chunk[3] != 0x80 { u24_le(chunk, 0) } else { 0 };
        offsets.push([offset, 0]);
        if offset != 0 {
            nonzero.push(offset);
        }
    }

    nonzero.sort_unstable();

    for o in offsets.iter_mut() {
        if o[0] != 0 {
            // end = next sorted offset after this one
            let idx = nonzero.iter().position(|&v| v == o[0]).unwrap();
            o[1] = nonzero[idx + 1];
        }
    }

    offsets
}

/// Remove gen-2 modules; returns region-relative end of retained data.
fn remove_modules(
    me: &Region,
    buf: &mut [u8],
    mod_headers: &[&[u8]],
    ftpr_offset: usize,
    me_len: usize,
) -> Result<usize> {
    let mut unremovable_huff: Vec<[u32; 2]> = Vec::new();
    let mut chunks_offsets: Vec<[u32; 2]> = Vec::new();
    let mut base: u32 = 0;
    let mut chunk_size: u32 = 0;
    let mut end_addr: usize = 0;

    for mh in mod_headers {
        let name = ascii_trim(&mh[0x04..0x14]);
        let offset =
            u32_le(mh, 0x38) as usize + ftpr_offset;
        let size = u32_le(mh, 0x40) as usize;
        let flags = u32_le(mh, 0x50);
        let comp_type = (flags >> 4) & 7;

        match comp_type {
            0x00 | 0x02 => {
                if UNREMOVABLE.contains(&name.as_str()) {
                    end_addr = end_addr.max(offset + size);
                } else {
                    let end = (offset + size).min(me_len);
                    me.fill_range(buf, offset, end, 0xff)?;
                }
            }
            0x01 => {
                if chunks_offsets.is_empty() {
                    let tag = me.read(buf, offset, 4)?;
                    if tag != b"LLUT" {
                        return Err(Error::MissingLlut);
                    }
                    let head = me.read(buf, offset, 0x40)?.to_vec();
                    let chunk_count =
                        u32_le(&head, 0x4) as usize;
                    base = u32_le(&head, 0x8)
                        .wrapping_add(0x10000000);
                    chunk_size =
                        u32_le(&head, 0x30);
                    let mut llut = head;
                    llut.extend_from_slice(me.read(buf, offset + 0x40, chunk_count * 4)?);
                    chunks_offsets = get_chunks_offsets(&llut);
                }

                let module_base = u32_le(mh, 0x34);
                let module_size = u32_le(mh, 0x3c);
                let first = ((module_base - base) / chunk_size) as usize;
                let last = first + (module_size / chunk_size) as usize;

                if UNREMOVABLE.contains(&name.as_str()) {
                    for c in &chunks_offsets[first..=last.min(chunks_offsets.len() - 1)] {
                        if c[0] != 0 {
                            unremovable_huff.push(*c);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    if !chunks_offsets.is_empty() {
        for chunk in &chunks_offsets {
            let overlaps = unremovable_huff.iter().any(|u| {
                (u[0] <= chunk[0] && chunk[0] < u[1]) || (u[0] < chunk[1] && chunk[1] <= u[1])
            });
            if !overlaps && chunk[1] > chunk[0] {
                let end = (chunk[1] as usize).min(me_len);
                me.fill_range(buf, chunk[0] as usize, end, 0xff)?;
            }
        }
        if let Some(max) = unremovable_huff.iter().map(|c| c[1] as usize).max() {
            end_addr = end_addr.max(max);
        }
    }

    Ok(end_addr)
}

/// Relocate partition (FPT entry at `ph_offset`) to `new_offset`, fixing FPT and LLUT pointers; returns final offset.
pub fn relocate_partition(
    me: &Region,
    buf: &mut [u8],
    me_len: usize,
    ph_offset: usize,
    mut new_offset: usize,
    mod_headers: &[&[u8]],
) -> Result<usize> {
    let old_offset = me.read_u32(buf, ph_offset + 0x8)? as usize;
    let partition_size = me.read_u32(buf, ph_offset + 0xc)? as usize;

    let mut llut_start: usize = 0;
    for mh in mod_headers {
        let flags = u32_le(mh, 0x50);
        if (flags >> 4) & 7 == 0x01 {
            llut_start =
                u32_le(mh, 0x38) as usize + old_offset;
            break;
        }
    }

    let mut lut_start_corr: u16 = 0;
    if !mod_headers.is_empty() && llut_start != 0 {
        lut_start_corr = me.read_u16(buf, llut_start + 0x9)?;
        let min_new =
            lut_start_corr as i64 - llut_start as i64 - 0x40 + old_offset as i64;
        if min_new > new_offset as i64 {
            new_offset = min_new as usize;
        }
        new_offset = new_offset.div_ceil(0x20) * 0x20;
    }

    let offset_diff = new_offset as i64 - old_offset as i64;
    me.write_u32(buf, ph_offset + 0x8, new_offset as u32)?;

    if !mod_headers.is_empty()
        && llut_start != 0 {
            if me.read(buf, llut_start, 4)? == b"LLUT" {
                let lut_offset =
                    llut_start as i64 + offset_diff + 0x40 - lut_start_corr as i64;
                me.write_u32(buf, llut_start + 0x0c, lut_offset as u32)?;

                let old_huff = me.read_u32(buf, llut_start + 0x14)? as i64;
                me.write_u32(buf, llut_start + 0x14, (old_huff + offset_diff) as u32)?;

                let chunk_count = me.read_u32(buf, llut_start + 0x4)? as usize;
                let mut chunks = me.read(buf, llut_start + 0x40, chunk_count * 4)?.to_vec();
                let mut i = 0;
                while i < chunk_count * 4 {
                    if chunks[i + 3] != 0x80 {
                        let val = u24_le(&chunks[i..i + 3], 0) as i64 + offset_diff;
                        let le = (val as u32).to_le_bytes();
                        chunks[i..i + 3].copy_from_slice(&le[0..3]);
                    }
                    i += 4;
                }
                me.write(buf, llut_start + 0x40, &chunks)?;
            } else {
                return Err(Error::MissingLlutRelocate);
            }
        }

    let size = partition_size.min(me_len - old_offset);
    me.move_range(buf, old_offset, size, new_offset, 0xff)?;

    Ok(new_offset)
}

/// Module pass result. `end_addr == None`: header size undetermined, removal skipped.
pub struct ModuleResult {
    pub end_addr: Option<usize>,
    pub ftpr_offset: usize,
}

/// Generation 2 (`$MME`) module pass.
#[allow(clippy::too_many_arguments)]
pub fn check_and_remove_modules(
    me: &Region,
    buf: &mut [u8],
    me_len: usize,
    mut offset: usize,
    ftpr_length: usize,
    min_offset: usize,
    relocate: bool,
    keep_modules: bool,
    ph_offset: usize,
) -> Result<ModuleResult> {
    let num_modules = me.read_u32(buf, offset + 0x20)? as usize;
    let probe = me.read(buf, offset + 0x290, 0x84)?.to_vec();

    let mut mod_header_size = 0usize;
    if &probe[0x0..0x4] == b"$MME" {
        if &probe[0x60..0x64] == b"$MME" || num_modules == 1 {
            mod_header_size = 0x60;
        } else if &probe[0x80..0x84] == b"$MME" {
            mod_header_size = 0x80;
        }
    }

    if mod_header_size == 0 {
        return Ok(ModuleResult {
            end_addr: None,
            ftpr_offset: offset,
        });
    }

    let data = me
        .read(buf, offset + 0x290, mod_header_size * num_modules)?
        .to_vec();
    let mod_headers: Vec<&[u8]> = (0..num_modules)
        .map(|i| &data[i * mod_header_size..(i + 1) * mod_header_size])
        .collect();

    if !mod_headers.iter().all(|h| h.starts_with(b"$MME")) {
        // Fewer modules than expected; skip removal.
        return Ok(ModuleResult {
            end_addr: None,
            ftpr_offset: offset,
        });
    }

    let mut end_addr = if keep_modules {
        offset + ftpr_length
    } else {
        remove_modules(me, buf, &mod_headers, offset, me_len)?
    };

    if relocate {
        let new_offset = relocate_partition(me, buf, me_len, ph_offset, min_offset, &mod_headers)?;
        end_addr += new_offset - offset;
        offset = new_offset;
    }

    Ok(ModuleResult {
        end_addr: Some(end_addr),
        ftpr_offset: offset,
    })
}

/// Generation 3 (`$CPD`) module pass.
#[allow(clippy::too_many_arguments)]
pub fn check_and_remove_modules_gen3(
    me: &Region,
    buf: &mut [u8],
    me_len: usize,
    mut partition_offset: usize,
    partition_length: usize,
    min_offset: usize,
    relocate: bool,
    keep_modules: bool,
    ph_offset: usize,
) -> Result<ModuleResult> {
    let mut end_data: usize;

    if keep_modules {
        end_data = partition_offset + partition_length;
    } else {
        end_data = 0;
        let module_count = me.read_u32(buf, partition_offset + 0x4)? as usize;

        // (name, region-relative offset within partition, comp_type)
        let mut modules: Vec<(String, usize, u32)> = Vec::with_capacity(module_count + 1);
        modules.push(("end".to_string(), partition_length, 0));

        for i in 0..module_count {
            let data = me.read(buf, partition_offset + 0x10 + i * 0x18, 0x18)?;
            let name = ascii_trim(&data[0x0..0xc]);
            let offset_block = u32_le(data, 0xc);
            let off = (offset_block & 0x01ff_ffff) as usize;
            let comp_type = (offset_block & 0x0200_0000) >> 25;
            modules.push((name, off, comp_type));
        }

        modules.sort_by_key(|m| m.1);

        for i in 0..module_count {
            let name = &modules[i].0;
            let offset = partition_offset + modules[i].1;
            let end = partition_offset + modules[i + 1].1;

            let keep = name.ends_with(".man")
                || name.ends_with(".met")
                || UNREMOVABLE_GEN3.iter().any(|m| name.starts_with(m));
            let removed = if keep {
                false
            } else {
                me.fill_range(buf, offset, end.min(me_len), 0xff)?;
                true
            };

            if !removed {
                end_data = end_data.max(end);
            }
        }
    }

    if relocate {
        let new_offset = relocate_partition(me, buf, me_len, ph_offset, min_offset, &[])?;
        end_data += new_offset - partition_offset;
        partition_offset = new_offset;
    }

    Ok(ModuleResult {
        end_addr: Some(end_data),
        ftpr_offset: partition_offset,
    })
}
