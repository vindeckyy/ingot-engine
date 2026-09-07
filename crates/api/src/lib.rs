//! Docker Engine API–compatible data transfer objects.
//!
//! Field names intentionally mirror the Engine API JSON exactly (including
//! quirks like `ImageID`, `RepoDigests`, epoch `Created`) so that the real
//! `docker` CLI and other Docker API clients can talk to ingot.
#![allow(non_snake_case)]

pub mod container;
pub mod de;
pub mod image;
pub mod network;
pub mod system;
pub mod volume;

pub use container::*;
pub use image::*;
pub use network::*;
pub use system::*;
pub use volume::*;

/// API version we claim in `/_ping` (Docker 25.0-era).
pub const API_VERSION: &str = "1.44";
/// Oldest API version we accept from clients.
pub const MIN_API_VERSION: &str = "1.44";
/// Engine version string reported by /version.
pub const ENGINE_VERSION: &str = "0.1.0";
/// Request header carrying a one-time build-secret token (POST /secrets).
/// A header, not a query param, so the token never lands in access logs.
pub const BUILD_SECRET_TOKEN_HEADER: &str = "x-ingot-secret-token";
/// Git commit from release build or repository.
pub const GIT_COMMIT: &str = env!("INGOT_GIT_COMMIT");
/// Stable timestamp when the binary was built.
pub const BUILD_TIME: &str = env!("INGOT_BUILD_TIME");
