pub mod core;
pub mod error;
pub mod issuance;
pub mod payment;
pub mod storage;

#[cfg(feature = "http-server")]
pub mod http;

pub use error::Error;
pub type Result<T> = std::result::Result<T, Error>;

pub fn hello_world() -> &'static str {
    "hello from zlicenser-server"
}
