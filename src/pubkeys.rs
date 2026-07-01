//! Known Intel ME/TXE/SPS public-key MD5 fingerprints (from me_cleaner).

/// `(md5_hex, variant, versions)`.
pub const PUBKEYS: &[(&str, &str, &[&str])] = &[
    (
        "8431285d43b0f2a2f520d7cab3d34178",
        "ME",
        &["2.0.x.x", "2.1.x.x", "2.2.x.x"],
    ),
    (
        "4c00dd06c28119b5c1e5bb8eb6f30596",
        "ME",
        &["2.5.x.x", "2.6.x.x"],
    ),
    ("9c24077a7f7490967855e9c4c16c6b9e", "ME", &["3.x.x.x"]),
    ("bf41464be736f5520d80c67f6789020e", "ME", &["4.x.x.x"]),
    ("5c7169b7e7065323fb7b3b5657b4d57a", "ME", &["5.x.x.x"]),
    ("763e59ebe235e45a197a5b1a378dfa04", "ME", &["6.x.x.x"]),
    ("3a98c847d609c253e145bd36512629cb", "ME", &["6.0.50.x"]),
    (
        "0903fc25b0f6bed8c4ed724aca02124c",
        "ME",
        &["7.x.x.x", "8.x.x.x"],
    ),
    (
        "2011ae6df87c40fba09e3f20459b1ce0",
        "ME",
        &["9.0.x.x", "9.1.x.x"],
    ),
    (
        "e8427c5691cf8b56bc5cdd82746957ed",
        "ME",
        &["9.5.x.x", "10.x.x.x"],
    ),
    ("986a78e481f185f7d54e4af06eb413f6", "ME", &["11.x.x.x"]),
    ("3efc26920b4bee901b624771c742887b", "ME", &["12.x.x.x"]),
    ("8e4f834644da2bef03039d69d41ecf02", "ME", &["14.x.x.x"]),
    ("b29411f89bf20ed177d411c46e8ec185", "ME", &["15.x.x.x"]),
    ("5887caf9b677601ffb257cc98a13d2a9", "ME", &["16.x.x.x"]),
    ("bda0b6bb8ca0bf0cac55ac4c4d55e0f2", "TXE", &["1.x.x.x"]),
    ("b726a2ab9cd59d4e62fe2bead7cf6997", "TXE", &["1.x.x.x"]),
    ("0633d7f951a3e7968ae7460861be9cfb", "TXE", &["2.x.x.x"]),
    ("1d0a36e9f5881540d8e4b382c6612ed8", "TXE", &["3.x.x.x"]),
    ("be900fef868f770d266b1fc67e887e69", "SPS", &["2.x.x.x"]),
    ("4622e3f2cb212a89c90a4de3336d88d2", "SPS", &["3.x.x.x"]),
    ("31ef3d950eac99d18e187375c0764ca4", "SPS", &["4.x.x.x"]),
];

pub fn lookup(md5_hex: &str) -> Option<(&'static str, &'static [&'static str])> {
    PUBKEYS
        .iter()
        .find(|(k, _, _)| *k == md5_hex)
        .map(|(_, v, vers)| (*v, *vers))
}
