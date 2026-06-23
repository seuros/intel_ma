//! A bounded `{start, end}` view into a flash image buffer. Methods take the
//! whole buffer so multiple regions can be edited without a long-lived `&mut`.

use crate::error::{Error, Result};

/// Block size for structural reads/writes (flash erase granularity).
pub const BLOCK: usize = 0x1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Region {
    pub start: usize,
    pub end: usize,
}

impl Region {
    pub fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    pub fn len(&self) -> usize {
        self.end - self.start
    }

    pub fn is_empty(&self) -> bool {
        self.end <= self.start
    }

    fn check(&self, off: usize, len: usize) -> Result<usize> {
        let abs = self.start + off;
        if abs + len <= self.end {
            Ok(abs)
        } else {
            Err(Error::OutOfRegion { offset: off, len })
        }
    }

    /// The whole region as a slice.
    pub fn all<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        &buf[self.start..self.end]
    }

    pub fn read<'a>(&self, buf: &'a [u8], off: usize, len: usize) -> Result<&'a [u8]> {
        let abs = self.check(off, len)?;
        Ok(&buf[abs..abs + len])
    }

    pub fn read_u32(&self, buf: &[u8], off: usize) -> Result<u32> {
        Ok(crate::bytes::u32_le(self.read(buf, off, 4)?, 0))
    }

    pub fn read_u16(&self, buf: &[u8], off: usize) -> Result<u16> {
        Ok(crate::bytes::u16_le(self.read(buf, off, 2)?, 0))
    }

    pub fn write(&self, buf: &mut [u8], off: usize, data: &[u8]) -> Result<()> {
        let abs = self.check(off, data.len())?;
        buf[abs..abs + data.len()].copy_from_slice(data);
        Ok(())
    }

    pub fn write_u32(&self, buf: &mut [u8], off: usize, val: u32) -> Result<()> {
        self.write(buf, off, &val.to_le_bytes())
    }

    pub fn write_u8(&self, buf: &mut [u8], off: usize, val: u8) -> Result<()> {
        self.write(buf, off, &[val])
    }

    /// Fill `[start, end)` (region-relative) with `fill`.
    pub fn fill_range(&self, buf: &mut [u8], start: usize, end: usize, fill: u8) -> Result<()> {
        if start >= end {
            return Ok(());
        }
        let abs = self.check(start, end - start)?;
        buf[abs..abs + (end - start)].fill(fill);
        Ok(())
    }

    pub fn fill_all(&self, buf: &mut [u8], fill: u8) -> Result<()> {
        self.fill_range(buf, 0, self.len(), fill)
    }

    /// Move `size` bytes `from`->`to` (region-relative), filling vacated source
    /// bytes with `fill`. Copied block by block; ranges may overlap.
    pub fn move_range(
        &self,
        buf: &mut [u8],
        from: usize,
        size: usize,
        to: usize,
        fill: u8,
    ) -> Result<()> {
        self.check(from, size)?;
        self.check(to, size)?;
        let mut i = 0;
        while i < size {
            let chunk = BLOCK.min(size - i);
            let src = self.start + from + i;
            let dst = self.start + to + i;
            let block: Vec<u8> = buf[src..src + chunk].to_vec();
            buf[src..src + chunk].fill(fill);
            buf[dst..dst + chunk].copy_from_slice(&block);
            i += chunk;
        }
        Ok(())
    }

    /// Copy `size` region-relative bytes out into a fresh buffer.
    pub fn extract(&self, buf: &[u8], size: usize) -> Result<Vec<u8>> {
        let abs = self.check(0, size)?;
        Ok(buf[abs..abs + size].to_vec())
    }
}
