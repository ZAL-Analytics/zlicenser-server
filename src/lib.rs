#![warn(clippy::all, clippy::pedantic)]
#![deny(unsafe_op_in_unsafe_fn)]
// Pre-existing documentation debt; fix incrementally as code is touched .
#![allow(clippy::missing_errors_doc, clippy::must_use_candidate)]

pub mod core;
pub mod error;
pub mod issuance;
pub mod payment;
pub mod storage;

#[cfg(feature = "http-server")]
pub mod sessions;

#[cfg(feature = "http-server")]
pub mod http;

pub use error::Error;
pub type Result<T> = std::result::Result<T, Error>;

pub fn hello_world() -> &'static str {
    "hello from zlicenser-server"
}
