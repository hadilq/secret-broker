//! secret-broker: let an AI agent (or any process running as you) USE secrets
//! through allowlisted commands without ever being able to READ them.
//!
//! No panics in non-test code: see the `[lints.clippy]` table in Cargo.toml
//! (unwrap/expect/panic/indexing/slicing/arithmetic... are denied) and the
//! `clippy` flake check, which fails the build on any violation.

pub mod approve;
pub mod audit;
pub mod caller;
pub mod client;
pub mod config;
pub mod error;
pub mod gpgcache;
pub mod policy;
pub mod proto;
pub mod pin;
pub mod redact;
pub mod sandbox;
pub mod secmem;
pub mod server;
pub mod sops;
pub mod sys;

pub use error::{Error, Result};
