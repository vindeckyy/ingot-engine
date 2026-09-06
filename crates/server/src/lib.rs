//! Ingot daemon: axum router + Unix-socket serving.

pub mod handlers;
pub mod router;
pub mod serve;
pub mod state;

pub use state::{DaemonConfig, DaemonState};
