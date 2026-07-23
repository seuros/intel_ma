//! Error types for intel_ma.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("out of region: offset {offset:#x} (len {len:#x}) exceeds region bounds")]
    OutOfRegion { offset: usize, len: usize },

    #[error("unknown image: no $FPT or flash descriptor signature found")]
    UnknownImage,

    #[error("no FIT found in image")]
    FitNotFound,

    #[error("invalid FIT pointer (offset {offset:#x})")]
    FitInvalidPointer { offset: usize },

    #[error("$FPT not found in ME region")]
    FptNotFound,

    #[error("more than one $FPT found in ME region")]
    MultipleFpt,

    #[error("FTPR header not found; this image doesn't seem to be valid")]
    FtprNotFound,

    #[error("can't find the manifest of the FTPR partition")]
    FtprManifestNotFound,

    #[error("wrong FTPR manifest tag ({0:?}); this image may be corrupted")]
    BadManifestTag([u8; 4]),

    #[error("Huffman modules found, but LLUT is not present")]
    MissingLlut,

    #[error("Huffman modules present but no LLUT found during relocation")]
    MissingLlutRelocate,

    #[error("the FTPR partition signature is not valid; is the input ME/TXE image valid?")]
    InvalidSignature,

    #[error("operation {op} requires a full dump (descriptor + ME region)")]
    RequiresFullDump { op: &'static str },

    #[error("invalid option combination: {0}")]
    BadOptions(String),

    #[error("{0}")]
    Unsupported(&'static str),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
