//! Docker Registry HTTP API v2 client: reference parsing, token auth,
//! manifest/index handling, verified blob streaming.

pub mod client;
pub mod reference;

pub use client::{daemon_platform, parse_platform, Descriptor, PlatformManifest, RegistryClient};
pub use reference::ImageRef;
