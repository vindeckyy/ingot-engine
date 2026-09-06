//! Image content store: blobs, unpacked layers (diffIDs/chainIDs), image
//! records, tag index, and the pull pipeline.

pub mod unpack;
pub mod store;
pub mod pull;

pub use store::{ImageStore, ImageRecord};

use anyhow::Result;
use std::path::Path;

/// Unpack a gzip/none tar blob into a layer dir (used by the builder too).
pub fn unpack_layer_dir(blob_path: &Path, dest_dir: &Path, media_type: &str) -> Result<String> {
    unpack::unpack_layer(blob_path, dest_dir, media_type)
}
