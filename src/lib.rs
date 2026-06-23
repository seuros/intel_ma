//! intel_ma - Intel: Management Absent. Inspect and deblob ME/TXE/CSME, PSP, and vendor locks.

pub mod amd;
pub mod bios;
pub(crate) mod bytes;
pub mod cleaner;
pub mod descriptor;
pub mod error;
pub mod fit;
pub mod fpt;
pub mod locks;
pub mod manifest;
pub mod modules;
pub mod pubkeys;
pub mod region;

pub use cleaner::{Analysis, Options, Report, analyze, clean};
pub use error::{Error, Result};
