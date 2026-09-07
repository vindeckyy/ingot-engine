//! Image content store: blobs, unpacked layers (diffIDs/chainIDs), image
//! records, tag index, and the pull pipeline.

pub mod fsck;
pub mod pull;
pub mod push;
pub mod store;
pub mod unpack;

pub use store::{ImageRecord, ImageStore};

use anyhow::Result;
use std::path::Path;

/// Unpack a gzip/none tar blob into a layer dir (used by the builder too).
pub fn unpack_layer_dir(blob_path: &Path, dest_dir: &Path, media_type: &str) -> Result<String> {
    unpack::unpack_layer(blob_path, dest_dir, media_type)
}

pub use unpack::unpack_entries;
