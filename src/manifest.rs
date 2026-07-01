//! FTPR manifest: tag, version, public key, RSA signature.

use crate::bytes::{u16_le, u32_le};
use crate::error::{Error, Result};
use crate::region::Region;
use md5::{Digest as Md5Digest, Md5};
use num_bigint::BigUint;
use sha2::Sha256;

/// Firmware version, as four 16-bit fields (major.minor.hotfix.build).
#[derive(Debug, Clone, Copy)]
pub struct Version(pub [u16; 4]);

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}.{}", self.0[0], self.0[1], self.0[2], self.0[3])
    }
}

/// Validate the manifest tag at `offset` (region-relative).
/// Generation 1 uses `$MAN`; everything else uses `$MN2`.
pub fn check_mn2_tag(me: &Region, buf: &[u8], offset: usize, generation: Option<u8>) -> Result<()> {
    let tag = me.read(buf, offset + 0x1c, 4)?;
    let expected: &[u8; 4] = if generation == Some(1) {
        b"$MAN"
    } else {
        b"$MN2"
    };
    if tag == expected {
        Ok(())
    } else {
        let mut t = [0u8; 4];
        t.copy_from_slice(tag);
        Err(Error::BadManifestTag(t))
    }
}

/// Read the firmware version from the manifest at `man_offset` (region-relative).
pub fn read_version(me: &Region, buf: &[u8], man_offset: usize) -> Result<Version> {
    let b = me.read(buf, man_offset + 0x24, 8)?;
    Ok(Version([
        u16_le(b, 0),
        u16_le(b, 2),
        u16_le(b, 4),
        u16_le(b, 6),
    ]))
}

/// MD5 of the public key (0x104 bytes at `man_offset + 0x80`), as lowercase hex.
pub fn pubkey_md5(me: &Region, buf: &[u8], man_offset: usize) -> Result<String> {
    let key = me.read(buf, man_offset + 0x80, 0x104)?;
    let digest = Md5::digest(key);
    Ok(hex_lower(&digest))
}

/// Verify the RSA signature of a partition manifest at `offset` (region-relative).
///
/// 2048-bit modulus and signature are little-endian on disk (hence the reversal);
/// decrypted signature must end with SHA-256 over header + manifest body.
pub fn check_partition_signature(me: &Region, buf: &[u8], offset: usize) -> Result<bool> {
    let header = me.read(buf, offset, 0x80)?.to_vec();

    let mut modulus_bytes = me.read(buf, offset + 0x80, 0x100)?.to_vec();
    modulus_bytes.reverse();
    let modulus = BigUint::from_bytes_be(&modulus_bytes);

    let public_exponent = me.read_u32(buf, offset + 0x180)?;
    let exponent = BigUint::from(public_exponent);

    let mut sig_bytes = me.read(buf, offset + 0x184, 0x100)?.to_vec();
    sig_bytes.reverse();
    let signature = BigUint::from_bytes_be(&sig_bytes);

    let header_len = u32_le(&header, 0x4) as usize * 4;
    let manifest_len = u32_le(&header, 0x18) as usize * 4;

    if manifest_len < header_len {
        return Ok(false);
    }

    let mut sha = Sha256::new();
    sha.update(&header);
    let body = me.read(buf, offset + header_len, manifest_len - header_len)?;
    sha.update(body);
    let digest_hex = hex_lower(&sha.finalize());

    let decrypted = signature.modpow(&exponent, &modulus);
    let decrypted_hex = format!("{:x}", decrypted);

    Ok(decrypted_hex.ends_with(&digest_hex))
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}
