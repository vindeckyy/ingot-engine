//! CLI command implementations.

use crate::client::ApiClient;
use crate::RunOpts;
use anyhow::{anyhow, Result};
use http_body_util::BodyExt;

pub fn not_ready(what: &str) -> Result<()> {
    println!("`ingot {what}` lands in an upcoming milestone — daemon must be at M2");
    Ok(())
}

pub async fn version(api: &ApiClient) -> Result<()> {
    println!("Client:");
    println!("  Version:   {}", env!("CARGO_PKG_VERSION"));
    println!("  OS/Arch:   {}/{}", std::env::consts::OS, std::env::consts::ARCH);
    println!();
    let v = api.get_json::<serde_json::Value>("/version").await?;
    println!("Server: {}", api.socket.display());
    println!("  Engine:");
    println!("  Version:   {}", v["Version"].as_str().unwrap_or("?"));
    println!(
        "  API ver:   {} (min {})",
        v["ApiVersion"].as_str().unwrap_or("?"),
        v["MinAPIVersion"].as_str().unwrap_or("?")
    );
    println!(
        "  OS/Arch:   {}/{}",
        v["Os"].as_str().unwrap_or("?"),
        v["Arch"].as_str().unwrap_or("?")
    );
    println!("  Kernel:    {}", v["KernelVersion"].as_str().unwrap_or("?"));
    Ok(())
}

pub async fn info(api: &ApiClient) -> Result<()> {
    let v = api.get_json::<serde_json::Value>("/info").await?;
    println!("Containers: {}", v["Containers"].as_i64().unwrap_or(0));
    println!(" Images:    {}", v["Images"].as_i64().unwrap_or(0));
    println!("Server Version: {}", v["ServerVersion"].as_str().unwrap_or("?"));
    println!("Storage Driver: {}", v["Driver"].as_str().unwrap_or("?"));
    println!("Cgroup Version: {}", v["CgroupVersion"].as_str().unwrap_or("?"));
    println!("Operating System: {}", v["OperatingSystem"].as_str().unwrap_or("?"));
    println!("Kernel Version: {}", v["KernelVersion"].as_str().unwrap_or("?"));
    println!("NCPU: {}", v["NCPU"].as_i64().unwrap_or(0));
    println!("MemTotal: {} MB", v["MemTotal"].as_i64().unwrap_or(0) / 1024 / 1024);
    Ok(())
}

fn human_created(epoch: i64) -> String {
    let created = chrono::DateTime::from_timestamp(epoch, 0).unwrap_or_default();
    let secs = (chrono::Utc::now() - created).num_seconds().max(0);
    if secs < 60 {
        format!("{secs} seconds ago")
    } else if secs < 3600 {
        format!("{} minutes ago", secs / 60)
    } else if secs < 86400 {
        format!("{} hours ago", secs / 3600)
    } else {
        format!("{} days ago", secs / 86400)
    }
}

fn human_size(bytes: i64) -> String {
    if bytes >= 1_000_000_000 {
        format!("{:.1}GB", bytes as f64 / 1e9)
    } else if bytes >= 1_000_000 {
        format!("{:.1}MB", bytes as f64 / 1e6)
    } else {
        format!("{:.1}KB", bytes as f64 / 1e3)
    }
}

pub async fn ps(api: &ApiClient, all: bool) -> Result<()> {
    let list: Vec<serde_json::Value> =
        api.get_json(&format!("/containers/json?all={}", if all { 1 } else { 0 })).await?;
    println!(
        "{:<14} {:<16} {:<24} {:<12} {:<16} {}",
        "CONTAINER ID", "IMAGE", "COMMAND", "CREATED", "STATUS", "NAMES"
    );
    for c in &list {
        println!(
            "{:<14} {:<16} {:<24} {:<12} {:<16} {}",
            c["Id"].as_str().unwrap_or("").chars().take(12).collect::<String>(),
            c["Image"].as_str().unwrap_or(""),
            truncate(c["Command"].as_str().unwrap_or(""), 22),
            human_created(c["Created"].as_i64().unwrap_or(0)),
            c["Status"].as_str().unwrap_or(""),
            c["Names"][0].as_str().unwrap_or("").trim_start_matches('/'),
        );
    }
    Ok(())
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n).collect::<String>())
    }
}

pub async fn images(api: &ApiClient) -> Result<()> {
    let list: Vec<serde_json::Value> = api.get_json("/images/json").await?;
    println!(
        "{:<20} {:<10} {:<16} {:<20} {}",
        "REPOSITORY", "TAG", "IMAGE ID", "CREATED", "SIZE"
    );
    for img in &list {
        let (repo, tag) = img["RepoTags"][0]
            .as_str()
            .map(|t| {
                t.split_once(':')
                    .map(|(a, b)| (a.to_string(), b.to_string()))
                    .unwrap_or((t.to_string(), "latest".into()))
            })
            .unwrap_or(("<none>".into(), "<none>".into()));
        println!(
            "{:<20} {:<10} {:<16} {:<20} {}",
            repo,
            tag,
            img["Id"].as_str().unwrap_or("").trim_start_matches("sha256:").chars().take(12).collect::<String>(),
            human_created(img["Created"].as_i64().unwrap_or(0)),
            human_size(img["Size"].as_i64().unwrap_or(0)),
        );
    }
    Ok(())
}

/// POST /images/create and print the docker-style progress stream.
pub async fn pull(api: &ApiClient, image: &str) -> Result<()> {
    let (repo, tag) = match image.split_once(':') {
        Some((r, t)) => (r, t),
        None => (image, "latest"),
    };
    let resp = api
        .request(
            "POST",
            &format!("/images/create?fromImage={repo}&tag={tag}"),
            None,
        )
        .await?;
    let mut had_error = false;
    crate::client::stream_lines(resp, |v| {
        if let Some(status) = v["status"].as_str() {
            let id = &v["id"];
            let progress = &v["progress"];
            if !id.is_null() {
                println!("{status} [{id}] {progress}");
            } else {
                println!("{status}");
            }
        } else if let Some(stream) = v["stream"].as_str() {
            print!("{stream}");
        } else if let Some(err) = v["error"].as_str() {
            eprintln!("{err}");
            had_error = true;
        }
    })
    .await?;
    if had_error {
        return Err(anyhow!("pull failed"));
    }
    Ok(())
}

/// create → start → (follow logs + wait) — docker run style.
pub async fn run(api: &ApiClient, opts: &RunOpts, image: &str, cmd: Vec<String>) -> Result<()> {
    let mut port_bindings = serde_json::Map::new();
    for p in &opts.publish {
        // host:container[/proto] or container[/proto]
        let (host_part, rest) = match p.split_once(':') {
            Some((h, r)) => (Some(h), r),
            None => (None, p.as_str()),
        };
        let (cport, proto) = rest.split_once('/').unwrap_or((rest, "tcp"));
        let key = format!("{cport}/{proto}");
        let binding = serde_json::json!({
            "HostIp": host_part.unwrap_or(""),
            "HostPort": host_part.unwrap_or(""),
        });
        port_bindings
            .entry(key)
            .or_insert_with(|| serde_json::Value::Array(vec![]))
            .as_array_mut()
            .unwrap()
            .push(binding);
    }
    let body = serde_json::json!({
        "Image": image,
        "Cmd": cmd,
        "Tty": opts.tty,
        "OpenStdin": opts.interactive,
        "Env": opts.env,
        "WorkingDir": opts.workdir.clone().unwrap_or_default(),
        "HostConfig": {
            "AutoRemove": opts.rm,
            "Binds": opts.volume,
            "NetworkMode": opts.network,
            "PortBindings": port_bindings,
        },
    });
    let q = match &opts.name {
        Some(n) => format!("?name={n}"),
        None => String::new(),
    };
    let created = api
        .request_json("POST", &format!("/containers/create{q}"), Some(serde_json::to_vec(&body)?))
        .await?;
    let id = created["Id"]
        .as_str()
        .ok_or_else(|| anyhow!("create failed"))?
        .to_string();

    if let Err(e) = api.request_raw("POST", &format!("/containers/{id}/start"), None).await {
        let _ = api.request_raw("DELETE", &format!("/containers/{id}?force=1"), None).await;
        return Err(e);
    }

    if opts.detach {
        println!("{id}");
        return Ok(());
    }

    // Follow the framed log stream concurrently; exit when the container does.
    let mut resp = api
        .request(
            "GET",
            &format!("/containers/{id}/logs?stdout=1&stderr=1&follow=1&tail=all"),
            None,
        )
        .await?;
    let multiplexed = !opts.tty;
    let printer = tokio::spawn(async move {
        use std::io::Write;
        let mut body = resp.into_body();
        let mut pending: Vec<u8> = Vec::new();
        loop {
            match body.frame().await {
                Some(Ok(frame)) => {
                    let data = frame.data_ref().map(|b| b.as_ref()).unwrap_or(&[]);
                    pending.extend_from_slice(data);
                }
                Some(Err(_)) | None => break,
            }
            while pending.len() >= 8 && multiplexed {
                let len = u32::from_be_bytes([pending[4], pending[5], pending[6], pending[7]]) as usize;
                if pending.len() < 8 + len {
                    break;
                }
                let (_, payload) = crate::demux(&pending[..8 + len]);
                let _ = std::io::stdout().write_all(payload);
                let _ = std::io::stdout().flush();
                pending.drain(..8 + len);
            }
            if !multiplexed && !pending.is_empty() {
                let _ = std::io::stdout().write_all(&pending);
                pending.clear();
            }
        }
    });

    let wait = api
        .request_json("POST", &format!("/containers/{id}/wait"), None)
        .await?;
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    printer.abort();
    std::process::exit(wait["StatusCode"].as_i64().unwrap_or(0) as i32);
}

pub async fn stop(api: &ApiClient, containers: &[String]) -> Result<()> {
    for c in containers {
        let _ = api.request_raw("POST", &format!("/containers/{c}/stop"), None).await?;
        println!("{c}");
    }
    Ok(())
}

pub async fn kill(api: &ApiClient, container: &str) -> Result<()> {
    api.request_raw("POST", &format!("/containers/{container}/kill"), None).await?;
    Ok(())
}

pub async fn rm(api: &ApiClient, force: bool, containers: &[String]) -> Result<()> {
    for c in containers {
        let suffix = if force { "?force=1" } else { "" };
        api.request_raw("DELETE", &format!("/containers/{c}{suffix}"), None).await?;
        println!("{c}");
    }
    Ok(())
}

pub async fn logs(
    api: &ApiClient,
    container: &str,
    follow: bool,
    tail: Option<String>,
) -> Result<()> {
    let f = if follow { 1 } else { 0 };
    let tail = tail.unwrap_or_else(|| "all".into());
    let mut resp = api
        .request(
            "GET",
            &format!("/containers/{container}/logs?stdout=1&stderr=1&follow={f}&tail={tail}"),
            None,
        )
        .await?;
    // Demultiplex the 8-byte framed stream (plain for tty containers).
    let mut body = Box::pin(resp.into_body());
    let mut pending: Vec<u8> = Vec::new();
    loop {
        match body.frame().await {
            Some(Ok(frame)) => {
                let data = frame.data_ref().map(|b| b.as_ref()).unwrap_or(&[]);
                pending.extend_from_slice(data);
            }
            Some(Err(e)) => return Err(e.into()),
            None => break,
        }
        // Parse as many complete frames as available.
        while pending.len() >= 8 {
            let len = u32::from_be_bytes([pending[4], pending[5], pending[6], pending[7]]) as usize;
            if pending.len() < 8 + len {
                break;
            }
            let (stream, payload) = crate::demux(&pending[..8 + len]);
            let _ = stream;
            use std::io::Write;
            std::io::stdout().write_all(payload)?;
            std::io::stdout().flush()?;
            pending.drain(..8 + len);
        }
        if !follow {
            // drain remainder without framing (tty case)
            if !pending.is_empty() {
                use std::io::Write;
                std::io::stdout().write_all(&pending)?;
                pending.clear();
            }
            break;
        }
    }
    Ok(())
}

pub async fn exec(api: &ApiClient, container: &str, cmd: Vec<String>) -> Result<()> {
    if cmd.is_empty() {
        return Err(anyhow!("no command specified"));
    }
    let created: serde_json::Value = api
        .post(
            &format!("/containers/{container}/exec"),
            Some(serde_json::json!({
                "AttachStdout": true,
                "AttachStderr": true,
                "Cmd": cmd,
            })),
        )
        .await?;
    let eid = created["Id"].as_str().ok_or_else(|| anyhow!("no exec id"))?.to_string();
    // Hijacked start would need raw duplex; for M2 use the logs-less variant:
    // start detached then report exit via inspect polling.
    api.post::<serde_json::Value>(
        &format!("/exec/{eid}/start"),
        Some(serde_json::json!({"Detach": false, "Tty": false})),
    )
    .await
    .or_else(|e| {
        // The hijacked response cannot be parsed as JSON — expected.
        Err(e)
    })
    .ok();
    // Poll exec inspect for exit code.
    loop {
        let insp = api.get_json::<serde_json::Value>(&format!("/exec/{eid}/json")).await?;
        let running = insp["Running"].as_bool().unwrap_or(false);
        if !running {
            let code = insp["ExitCode"].as_i64().unwrap_or(0);
            std::process::exit(code as i32);
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

/// Tar the build context (honouring .dockerignore) and stream /build.
pub async fn build(
    api: &ApiClient,
    tags: &[String],
    dockerfile: &str,
    no_cache: bool,
    quiet: bool,
    path: &str,
) -> Result<()> {
    use std::io::Write;
    let ctx = std::path::Path::new(path);
    if !ctx.is_dir() {
        return Err(anyhow!("build context {path:?} is not a directory"));
    }
    // .dockerignore → simple prefix/name filters.
    let ignores: Vec<String> = std::fs::read_to_string(ctx.join(".dockerignore"))
        .map(|f| f.lines().filter(|l| !l.trim().is_empty() && !l.starts_with('#')).map(|l| l.trim().trim_end_matches('/').to_string()).collect())
        .unwrap_or_default();

    let tmp = std::env::temp_dir().join(format!("ingot-ctx-{}.tar.gz", std::process::id()));
    let gz = flate2::write::GzEncoder::new(std::fs::File::create(&tmp)?, flate2::Compression::fast());
    let mut tar = tar::Builder::new(gz);
    for entry in walkdir::WalkDir::new(ctx).sort_by_file_name() {
        let entry = entry?;
        let rel = entry.path().strip_prefix(ctx)?;
        let rel_s = rel.to_string_lossy().to_string();
        if rel_s.is_empty() {
            continue;
        }
        if ignores.iter().any(|ig| rel_s == *ig || rel_s.starts_with(&format!("{ig}/"))) {
            continue;
        }
        if entry.file_type().is_dir() {
            if !rel_s.is_empty() {
                let mut h = tar::Header::new_gnu();
                tar.append_data(&mut h, &rel_s, std::io::empty())?;
            }
        } else {
            tar.append_path_with_name(entry.path(), rel)?;
        }
    }
    let gz = tar.into_inner()?;
    gz.finish()?;
    let body = std::fs::read(&tmp)?;
    let _ = std::fs::remove_file(&tmp);

    let mut query = String::new();
    for t in tags {
        query.push_str(&format!("&t={}", url_escape(t)));
    }
    query.push_str(&format!("&dockerfile={}", url_escape(dockerfile)));
    if no_cache {
        query.push_str("&nocache=1");
    }
    if quiet {
        query.push_str("&q=1");
    }
    let resp = api
        .request("POST", &format!("/build?{}", query.trim_start_matches('&')), Some(body))
        .await?;
    let mut final_image = String::new();
    crate::client::stream_lines(resp, |v| {
        if let Some(stream) = v["stream"].as_str() {
            print!("{stream}");
            let _ = std::io::stdout().flush();
            if stream.starts_with("Successfully tagged ") {
                let _ = &mut final_image;
            }
        } else if let Some(err) = v["error"].as_str() {
            eprintln!("{err}");
        }
    })
    .await?;
    Ok(())
}

fn url_escape(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b':' | b'/' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
