//! Docker Registry HTTP API v2 client: reference parsing, token auth,
//! manifest/index handling, verified blob streaming.

pub mod reference;
pub mod client;

pub use client::{RegistryClient, PlatformManifest, Descriptor};
pub use reference::ImageRef;
