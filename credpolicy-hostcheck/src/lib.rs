//! Host-runnable tests for the E-OS credential policy.
//!
//! The parent package cannot be built on a developer host — `cargo test --lib` there fails on
//! `libredox`, which has no macOS target and nothing to do with this code. So this crate includes
//! the same source and nothing else.
//!
//! The `#[path]` module below is deliberately named `credpolicy`, at the crate root, because that
//! is exactly where `userutils` puts it. Every `crate::credpolicy::…` inside the policy therefore
//! means the same thing in both crates, and the tests exercise the file the image will build —
//! not a copy that drifted.
//!
//!   cargo test --manifest-path credpolicy-hostcheck/Cargo.toml
//!
//! Same shape, same reason, as `hostcheck/` in the `eos-users` fork.

#![forbid(unsafe_code)]

#[path = "../../src/credpolicy/mod.rs"]
pub mod credpolicy;
