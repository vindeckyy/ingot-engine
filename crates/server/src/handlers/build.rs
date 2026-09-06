//! POST /build — classic builder: tar context upload + JSON progress stream.

use crate::state::SharedState;
use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use ingot_api::ProgressMessage;
use std::collections::HashMap;

#[derive(serde::Deserialize, Default)]
#[serde(default)]
pub struct BuildQuery {
    /// tag (repeatable via t=x&t=y)
    #[serde(rename = "t", deserialize_with = "ingot_api::de::string_vec", default)]
    t: Vec<String>,
    dockerfile: Option<String>,
    #[serde(deserialize_with = "ingot_api::de::flexible_bool", default)]
    q: Option<bool>,
    #[serde(deserialize_with = "ingot_api::de::flexible_bool", default)]
    nocache: Option<bool>,
    #[serde(deserialize_with = "ingot_api::de::flexible_bool", default)]
    rm: Option<bool>,
    #[serde(deserialize_with = "ingot_api::de::flexible_bool", default)]
    forcerm: Option<bool>,
    target: Option<String>,
    buildargs: Option<String>,
    #[serde(deserialize_with = "ingot_api::de::flexible_bool", default)]
    version: Option<bool>,
}

pub async fn build(
    State(state): State<SharedState>,
    Query(q): Query<BuildQuery>,
    body: axum::body::Bytes,
) -> Response {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<ProgressMessage>(64);
    let build_id = ingot_util::new_id()[..16].to_string();
    let context_dir = state.paths.build_contexts().join(&build_id);

    // Extract the uploaded tar context on a blocking thread.
    let ctx_dir = context_dir.clone();
    let bytes = body.clone();
    let extract = tokio::task::spawn_blocking(move || -> Result<String, anyhow::Error> {
        std::fs::create_dir_all(&ctx_dir)?;
        if bytes.starts_with(&[0x1f, 0x8b]) {
            let gz = flate2::read::GzDecoder::new(&bytes[..]);
            let mut archive = tar::Archive::new(gz);
            archive.unpack(&ctx_dir)?;
        } else {
            let mut archive = tar::Archive::new(&bytes[..]);
            archive.unpack(&ctx_dir)?;
        }
        Ok("ok".into())
    })
    .await;

    let dockerfile_name = q.dockerfile.clone().unwrap_or_else(|| "Dockerfile".into());
    let dockerfile_path = context_dir.join(&dockerfile_name);

    match extract {
        Ok(Ok(_)) if dockerfile_path.exists() => {}
        Ok(Ok(_)) => {
            return crate::handlers::not_found(format!(
                "Cannot locate specified Dockerfile: {dockerfile_name}"
            ))
        }
        Ok(Err(e)) => return crate::handlers::server_error(format!("unpack context: {e:#}")),
        Err(e) => return crate::handlers::server_error(format!("join: {e}")),
    }

    let dockerfile = match std::fs::read_to_string(&dockerfile_path) {
        Ok(d) => d,
        Err(e) => return crate::handlers::server_error(format!("read Dockerfile: {e}")),
    };

    // buildargs JSON: {"name":"value",...}
    let build_args: HashMap<String, String> = q
        .buildargs
        .as_deref()
        .and_then(|s| serde_json::from_str::<HashMap<String, String>>(s).ok())
        .unwrap_or_default();

    let opts = ingot_builder::BuildOptions {
        dockerfile,
        context_dir: context_dir.clone(),
        tags: q.t.clone(),
        target: q.target.clone(),
        build_args,
        nocache: q.nocache.unwrap_or(false),
    };
    let registry = state.registry.clone();
    let images = state.images.clone();
    let paths = state.paths.clone();
    tokio::spawn(async move {
        if let Err(e) =
            ingot_builder::build_image(images, registry, paths, opts, tx.clone()).await
        {
            let _ = tx.send(ProgressMessage::error(format!("{e:#}"))).await;
        }
        let _ = tokio::fs::remove_dir_all(context_dir).await;
    });

    let quiet = q.q.unwrap_or(false);
    let stream = futures::stream::unfold(rx, move |mut rx| async move {
        rx.recv().await.map(|msg| {
            let rendered = if quiet {
                // -q: only the final image id (stream lines)
                msg.stream.clone().unwrap_or_default()
            } else {
                let mut line = serde_json::to_string(&msg).unwrap_or_default();
                line.push('\n');
                line
            };
            (Ok::<_, std::io::Error>(axum::body::Bytes::from(rendered)), rx)
        })
    });
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from_stream(stream))
        .unwrap()
}
