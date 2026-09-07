//! CLI command implementations.

use crate::client::ApiClient;
use crate::RunOpts;
use anyhow::{anyhow, Result};
use http_body_util::BodyExt;

pub async fn version(api: &ApiClient) -> Result<()> {
    println!("Client:");
    println!("  Version:   {}", env!("CARGO_PKG_VERSION"));
    println!(
        "  OS/Arch:   {}/{}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
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
    println!(
        "  Kernel:    {}",
        v["KernelVersion"].as_str().unwrap_or("?")
    );
    Ok(())
}

pub async fn info(api: &ApiClient) -> Result<()> {
    let v = api.get_json::<serde_json::Value>("/info").await?;
    println!("Containers: {}", v["Containers"].as_i64().unwrap_or(0));
    println!(" Images:    {}", v["Images"].as_i64().unwrap_or(0));
    println!(
        "Server Version: {}",
        v["ServerVersion"].as_str().unwrap_or("?")
    );
    println!("Storage Driver: {}", v["Driver"].as_str().unwrap_or("?"));
    println!(
        "Cgroup Version: {}",
        v["CgroupVersion"].as_str().unwrap_or("?")
    );
    println!(
        "Operating System: {}",
        v["OperatingSystem"].as_str().unwrap_or("?")
    );
    println!(
        "Kernel Version: {}",
        v["KernelVersion"].as_str().unwrap_or("?")
    );
    println!("NCPU: {}", v["NCPU"].as_i64().unwrap_or(0));
    println!(
        "MemTotal: {} MB",
        v["MemTotal"].as_i64().unwrap_or(0) / 1024 / 1024
    );
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

/// Output format for list commands. `table` is the human default;
/// `json` prints one raw object per line for scripting. Anything else —
/// including Go templates — is rejected with the accepted values named.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListFormat {
    Table,
    Json,
}

pub fn parse_list_format(s: Option<&str>) -> Result<Option<ListFormat>> {
    match s {
        None => Ok(None),
        Some("table") => Ok(Some(ListFormat::Table)),
        Some("json") => Ok(Some(ListFormat::Json)),
        Some(other) => Err(anyhow!(
            "unsupported --format {other:?} (expected \"table\" or \"json\"; Go templates are not supported)"
        )),
    }
}

pub async fn ps(
    api: &ApiClient,
    all: bool,
    quiet: bool,
    no_trunc: bool,
    filters: &[String],
    format: Option<&str>,
) -> Result<()> {
    let mut url = format!("/containers/json?all={}", if all { 1 } else { 0 });
    if !filters.is_empty() {
        let map: serde_json::Map<String, serde_json::Value> = filters
            .iter()
            .filter_map(|f| {
                let (k, v) = f.split_once('=')?;
                Some((
                    k.to_string(),
                    serde_json::Value::Array(vec![serde_json::json!(v)]),
                ))
            })
            .collect();
        url.push_str(&format!(
            "&filters={}",
            url_escape(&serde_json::to_string(&map)?)
        ));
    }
    let list: Vec<serde_json::Value> = api.get_json(&url).await?;
    let format = parse_list_format(format)?;
    if format == Some(ListFormat::Json) && !quiet {
        for c in &list {
            println!("{}", serde_json::to_string(c)?);
        }
        return Ok(());
    }
    if quiet {
        for c in &list {
            let id = c["Id"].as_str().unwrap_or("");
            println!(
                "{}",
                if no_trunc {
                    id
                } else {
                    &id[..12.min(id.len())]
                }
            );
        }
        return Ok(());
    }
    println!(
        "{:<14} {:<16} {:<24} {:<12} {:<16} NAMES",
        "CONTAINER ID", "IMAGE", "COMMAND", "CREATED", "STATUS"
    );
    for c in &list {
        let id = c["Id"].as_str().unwrap_or("");
        let id_str = if no_trunc {
            id.to_string()
        } else {
            id.chars().take(12).collect::<String>()
        };
        println!(
            "{:<14} {:<16} {:<24} {:<12} {:<16} {}",
            id_str,
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

pub async fn images(
    api: &ApiClient,
    quiet: bool,
    no_trunc: bool,
    filters: &[String],
    format: Option<&str>,
) -> Result<()> {
    let mut url = "/images/json".to_string();
    if !filters.is_empty() {
        let map: serde_json::Map<String, serde_json::Value> = filters
            .iter()
            .filter_map(|f| {
                let (k, v) = f.split_once('=')?;
                Some((
                    k.to_string(),
                    serde_json::Value::Array(vec![serde_json::json!(v)]),
                ))
            })
            .collect();
        url.push_str(&format!(
            "?filters={}",
            url_escape(&serde_json::to_string(&map)?)
        ));
    }
    let list: Vec<serde_json::Value> = api.get_json(&url).await?;
    let format = parse_list_format(format)?;
    if format == Some(ListFormat::Json) && !quiet {
        for img in &list {
            println!("{}", serde_json::to_string(img)?);
        }
        return Ok(());
    }
    if quiet {
        for img in &list {
            let id = img["Id"]
                .as_str()
                .unwrap_or("")
                .trim_start_matches("sha256:");
            println!(
                "{}",
                if no_trunc {
                    id
                } else {
                    &id[..12.min(id.len())]
                }
            );
        }
        return Ok(());
    }
    println!(
        "{:<20} {:<10} {:<16} {:<20} SIZE",
        "REPOSITORY", "TAG", "IMAGE ID", "CREATED"
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
        let id = img["Id"]
            .as_str()
            .unwrap_or("")
            .trim_start_matches("sha256:");
        let id_str = if no_trunc {
            id.to_string()
        } else {
            id.chars().take(12).collect::<String>()
        };
        println!(
            "{:<20} {:<10} {:<16} {:<20} {}",
            repo,
            tag,
            id_str,
            human_created(img["Created"].as_i64().unwrap_or(0)),
            human_size(img["Size"].as_i64().unwrap_or(0)),
        );
    }
    Ok(())
}

/// Store registry credentials locally (client-side, like `docker login`;
/// validated on the next authenticated pull).
pub async fn login(
    server: &str,
    username: Option<&str>,
    password: Option<&str>,
    password_stdin: bool,
) -> Result<()> {
    let username = match username {
        Some(u) => u.to_string(),
        None => {
            eprint!("Username: ");
            let _ = std::io::Write::flush(&mut std::io::stderr());
            let mut line = String::new();
            std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut line)?;
            line.trim_end_matches(['\r', '\n']).to_string()
        }
    };
    let password = if password_stdin {
        let mut all = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut all)?;
        all.trim_end_matches(['\r', '\n']).to_string()
    } else {
        match password {
            Some(p) => p.to_string(),
            None => crate::auth::read_password("Password: ")?,
        }
    };
    crate::auth::store(server, &username, &password)?;
    println!("Login Succeeded");
    Ok(())
}

/// Drop stored registry credentials.
pub async fn logout(server: &str) -> Result<()> {
    if crate::auth::remove(server)? {
        println!("Removing login credentials for {server}");
    } else {
        println!("Not logged in to {server}");
    }
    Ok(())
}

/// POST /images/create and print the docker-style progress stream.
pub async fn pull(api: &ApiClient, image: &str, platform: Option<&str>) -> Result<()> {
    let parsed = ingot_registry::ImageRef::parse(image)?;
    let repo_part = if parsed.registry_is_default() {
        parsed.repo.clone()
    } else {
        format!("{}/{}", parsed.registry, parsed.repo)
    };
    let tag_or_digest = if let Some(ref d) = parsed.digest {
        d.clone()
    } else {
        parsed.tag.unwrap_or_else(|| "latest".to_string())
    };
    let mut url = format!(
        "/images/create?fromImage={}&tag={}",
        url_escape(&repo_part),
        url_escape(&tag_or_digest)
    );
    if let Some(p) = platform {
        url.push_str("&platform=");
        url.push_str(p);
    }
    let mut headers: Vec<(&str, String)> = Vec::new();
    let auth_value;
    if let Some(a) = crate::auth::auth_header_for_image(image)? {
        auth_value = a;
        headers.push(("X-Registry-Auth", auth_value.clone()));
    }
    let header_refs: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let resp = api
        .request_with_headers("POST", &url, None, &header_refs)
        .await?;
    stream_progress(resp, "pull").await
}

/// POST /images/{name}/push and print the docker-style progress stream.
pub async fn push(api: &ApiClient, image: &str) -> Result<()> {
    let (name, tag) = push_path(image)?;
    let mut url = format!("/images/{name}/push");
    if let Some(t) = tag {
        url.push_str(&format!("?tag={}", url_escape(&t)));
    }
    let mut headers: Vec<(&str, String)> = Vec::new();
    let auth_value;
    if let Some(a) = crate::auth::auth_header_for_image(image)? {
        auth_value = a;
        headers.push(("X-Registry-Auth", auth_value.clone()));
    }
    let header_refs: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let resp = api
        .request_with_headers("POST", &url, None, &header_refs)
        .await?;
    stream_progress(resp, "push").await
}

/// Split a push reference into the URL path name (registry-qualified repo,
/// `/` encoded for the single-segment `{name}` route) and the tag query.
/// Digest-only references carry no tag: the daemon defaults those to
/// `latest`, the same default docker applies.
pub fn push_path(image: &str) -> Result<(String, Option<String>)> {
    let parsed = ingot_registry::ImageRef::parse(image)?;
    let repo = if parsed.registry_is_default() {
        parsed.repo.clone()
    } else {
        format!("{}/{}", parsed.registry, parsed.repo)
    };
    Ok((path_escape(&repo), parsed.tag.clone()))
}

/// Print a daemon progress stream (pull/push): `status` lines to stdout,
/// `stream` chunks inline, `error` lines to stderr. Any error line fails
/// the command once the stream ends.
async fn stream_progress(resp: hyper::Response<hyper::body::Incoming>, action: &str) -> Result<()> {
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
        return Err(anyhow!("{action} failed"));
    }
    Ok(())
}

/// create → start → (follow logs + wait) — docker run style.
pub async fn run(api: &ApiClient, opts: &RunOpts, image: &str, cmd: Vec<String>) -> Result<()> {
    let mut port_bindings = serde_json::Map::new();
    for p in &opts.publish {
        for m in crate::ports::parse_port_spec(p).map_err(|e| anyhow::anyhow!("{e}"))? {
            let binding = serde_json::json!({
                "HostIp": m.host_ip,
                "HostPort": m.host_port,
            });
            port_bindings
                .entry(m.container_key)
                .or_insert_with(|| serde_json::Value::Array(vec![]))
                .as_array_mut()
                .unwrap()
                .push(binding);
        }
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
            "Dns": opts.dns,
            "DnsSearch": opts.dns_search,
            "DnsOptions": opts.dns_opt,
        },
    });
    let q = match &opts.name {
        Some(n) => format!("?name={n}"),
        None => String::new(),
    };
    let created = api
        .request_json(
            "POST",
            &format!("/containers/create{q}"),
            Some(serde_json::to_vec(&body)?),
        )
        .await?;
    let id = created["Id"]
        .as_str()
        .ok_or_else(|| anyhow!("create failed"))?
        .to_string();

    if opts.detach {
        println!("{id}");
        return Ok(());
    }

    if opts.interactive {
        let attach_url = format!("/containers/{id}/attach?stream=1&stdin=1&stdout=1&stderr=1");
        let upgraded = api.upgrade_stream(&attach_url, None).await?;
        if let Err(e) = api
            .request_raw("POST", &format!("/containers/{id}/start"), None)
            .await
        {
            let _ = api
                .request_raw("DELETE", &format!("/containers/{id}?force=1"), None)
                .await;
            return Err(e);
        }
        crate::client::run_attached_stream(upgraded, opts.tty, true).await?;
        let wait = api
            .request_json("POST", &format!("/containers/{id}/wait"), None)
            .await?;
        let code = wait["StatusCode"].as_i64().unwrap_or(0);
        if code != 0 {
            std::process::exit(code as i32);
        }
        return Ok(());
    }

    if let Err(e) = api
        .request_raw("POST", &format!("/containers/{id}/start"), None)
        .await
    {
        let _ = api
            .request_raw("DELETE", &format!("/containers/{id}?force=1"), None)
            .await;
        return Err(e);
    }

    // Follow the framed log stream concurrently; exit when the container does.
    let resp = api
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
                let len =
                    u32::from_be_bytes([pending[4], pending[5], pending[6], pending[7]]) as usize;
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
    let code = wait["StatusCode"].as_i64().unwrap_or(0);
    if code != 0 {
        std::process::exit(code as i32);
    }
    Ok(())
}

pub async fn stop(api: &ApiClient, containers: &[String]) -> Result<()> {
    for c in containers {
        let _ = api
            .request_raw("POST", &format!("/containers/{c}/stop"), None)
            .await?;
        println!("{c}");
    }
    Ok(())
}

pub async fn kill(api: &ApiClient, container: &str) -> Result<()> {
    api.request_raw("POST", &format!("/containers/{container}/kill"), None)
        .await?;
    Ok(())
}

pub async fn rm(api: &ApiClient, force: bool, containers: &[String]) -> Result<()> {
    for c in containers {
        let suffix = if force { "?force=1" } else { "" };
        api.request_raw("DELETE", &format!("/containers/{c}{suffix}"), None)
            .await?;
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
    let resp = api
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

pub async fn exec(
    api: &ApiClient,
    container: &str,
    interactive: bool,
    tty: bool,
    cmd: Vec<String>,
) -> Result<()> {
    if cmd.is_empty() {
        return Err(anyhow!("no command specified"));
    }
    let created: serde_json::Value = api
        .post(
            &format!("/containers/{container}/exec"),
            Some(serde_json::json!({
                "AttachStdin": interactive,
                "AttachStdout": true,
                "AttachStderr": true,
                "Tty": tty,
                "Cmd": cmd,
            })),
        )
        .await?;
    let eid = created["Id"]
        .as_str()
        .ok_or_else(|| anyhow!("no exec id"))?
        .to_string();

    let start_body = serde_json::json!({
        "Detach": false,
        "Tty": tty,
    });
    let upgraded = api
        .upgrade_stream(
            &format!("/exec/{eid}/start"),
            Some(serde_json::to_vec(&start_body)?),
        )
        .await?;

    crate::client::run_attached_stream(upgraded, tty, interactive).await?;

    // Fetch exit code from inspect
    let insp = api
        .get_json::<serde_json::Value>(&format!("/exec/{eid}/json"))
        .await?;
    let code = insp["ExitCode"].as_i64().unwrap_or(0);
    if code != 0 {
        std::process::exit(code as i32);
    }
    Ok(())
}

/// Tar the build context (honouring .dockerignore) and stream /build.
/// Parse one `--secret id=name,src=path|env=VAR` spec into its id and
/// value. Values are read here, on the client, and travel to the daemon
/// once inside the POST /secrets body — never on a command line or URL.
pub fn parse_secret_spec(spec: &str) -> Result<(String, String)> {
    let mut id: Option<String> = None;
    let mut src: Option<String> = None;
    let mut env: Option<String> = None;
    for part in spec.split(',') {
        let (k, v) = part
            .split_once('=')
            .ok_or_else(|| anyhow!("bad --secret {spec:?} (want id=name,src=path|env=VAR)"))?;
        match k {
            "id" => id = Some(v.to_string()),
            "src" => src = Some(v.to_string()),
            "env" => env = Some(v.to_string()),
            _ => anyhow::bail!("bad --secret {spec:?} (unknown key {k:?})"),
        }
    }
    let id = id.ok_or_else(|| anyhow!("bad --secret {spec:?} (missing id=)"))?;
    if id.is_empty() {
        anyhow::bail!("bad --secret {spec:?} (empty id)");
    }
    let value = match (src, env) {
        (Some(p), None) => std::fs::read_to_string(&p)
            .map_err(|e| anyhow!("bad --secret {id:?}: cannot read {p:?}: {e}"))?,
        (None, Some(var)) => std::env::var(&var)
            .map_err(|_| anyhow!("bad --secret {id:?}: env {var:?} is not set"))?,
        _ => anyhow::bail!("bad --secret {id:?} (need exactly one of src=, env=)"),
    };
    Ok((id, value))
}

#[allow(clippy::too_many_arguments)]
pub async fn build(
    api: &ApiClient,
    tags: &[String],
    dockerfile: &str,
    no_cache: bool,
    no_cache_filter: &[String],
    secrets: &[(String, String)],
    quiet: bool,
    path: &str,
) -> Result<()> {
    use std::io::Write;
    let ctx = std::path::Path::new(path);
    if !ctx.is_dir() {
        return Err(anyhow!("build context {path:?} is not a directory"));
    }
    // .dockerignore → anchored/negated/glob semantics via the shared
    // matcher (last match wins on the full path, so a negation can
    // re-include files under an excluded directory). The Dockerfile being
    // sent and .dockerignore itself always ship, mirroring Docker.
    // Excluded subtrees are pruned entirely — except ancestors of the
    // always-sent files, and excluded directories while any negation
    // exists (something beneath may be re-included).
    let ignores = ingot_util::ignore::parse_ignore(
        &std::fs::read_to_string(ctx.join(".dockerignore")).unwrap_or_default(),
    );
    // Forward-slash form of the Dockerfile path, as sent to the daemon.
    let dockerfile_rel = dockerfile.replace('\\', "/");
    let always_send = [dockerfile_rel.as_str(), ".dockerignore"];
    let keep = |rel_s: &str| {
        always_send.iter().any(|k| {
            *k == rel_s
                || k.starts_with(&format!("{rel_s}/"))
                || rel_s.starts_with(&format!("{k}/"))
        })
    };

    let tmp = std::env::temp_dir().join(format!("ingot-ctx-{}.tar.gz", std::process::id()));
    let gz =
        flate2::write::GzEncoder::new(std::fs::File::create(&tmp)?, flate2::Compression::fast());
    let mut tar = tar::Builder::new(gz);
    let walker = walkdir::WalkDir::new(ctx)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|e| {
            let rel = match e.path().strip_prefix(ctx) {
                Ok(r) => r,
                Err(_) => return false,
            };
            let rel_s = rel.to_string_lossy().replace('\\', "/");
            if rel_s.is_empty() {
                return true; // root
            }
            if keep(&rel_s) {
                return true;
            }
            let excluded = ignores.is_excluded(&rel_s, e.file_type().is_dir());
            // Prune excluded subtrees, but still descend when a negation
            // may re-include something beneath this directory.
            !(excluded && (!e.file_type().is_dir() || !ignores.has_negations()))
        });
    for entry in walker {
        let entry = entry?;
        let rel = entry.path().strip_prefix(ctx)?;
        let rel_s = rel.to_string_lossy().replace('\\', "/");
        if rel_s.is_empty() {
            continue;
        }
        // Excluded files are skipped. Excluded directories reached here
        // were descended for a possible negation below: emit the entry
        // so re-included children have their parent in the archive.
        if !keep(&rel_s) && !entry.file_type().is_dir() && ignores.is_excluded(&rel_s, false) {
            continue;
        }
        if entry.file_type().is_dir() {
            if !rel_s.is_empty() {
                // Directory headers need a valid size + checksum or the
                // daemon's tar reader rejects the whole archive.
                let mut h = tar::Header::new_gnu();
                h.set_entry_type(tar::EntryType::Directory);
                h.set_size(0);
                h.set_mode(0o755);
                h.set_cksum();
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
    for f in no_cache_filter {
        query.push_str(&format!("&nocachefilter={}", url_escape(f)));
    }
    if quiet {
        query.push_str("&q=1");
    }
    // Stage secrets first, if any: values go in the POST body, and the
    // one-time token returns in a header on the build request (never a
    // URL, so it stays out of logs on both ends).
    let secret_token: Option<String> = if secrets.is_empty() {
        None
    } else {
        let values: std::collections::HashMap<&str, &str> = secrets
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let staged = api
            .request_raw("POST", "/secrets", Some(serde_json::to_vec(&values)?))
            .await?;
        Some(
            serde_json::from_slice::<serde_json::Value>(&staged)
                .ok()
                .and_then(|v| v.get("token")?.as_str().map(str::to_string))
                .ok_or_else(|| anyhow!("POST /secrets did not return a token"))?,
        )
    };
    let mut build_headers: Vec<(&str, &str)> = Vec::new();
    if let Some(token) = &secret_token {
        build_headers.push((ingot_api::BUILD_SECRET_TOKEN_HEADER, token.as_str()));
    }
    let resp = api
        .request_with_headers(
            "POST",
            &format!("/build?{}", query.trim_start_matches('&')),
            Some(body),
            &build_headers,
        )
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

// ---- image: rmi, tag ----

pub async fn rmi(api: &ApiClient, force: bool, images: &[String]) -> Result<()> {
    for image in images {
        let suffix = if force { "?force=1" } else { "" };
        let events: serde_json::Value = api
            .request_json("DELETE", &format!("/images/{image}{suffix}"), None)
            .await?;
        let events = events.as_array().cloned().unwrap_or_default();
        for ev in &events {
            if let Some(t) = ev["Untagged"].as_str() {
                if !t.is_empty() {
                    println!("Untagged: {t}");
                }
            }
            if let Some(d) = ev["Deleted"].as_str() {
                if !d.is_empty() {
                    println!("Deleted: {d}");
                }
            }
        }
    }
    Ok(())
}

pub async fn tag(api: &ApiClient, source: &str, target: &str) -> Result<()> {
    let parsed = ingot_registry::ImageRef::parse(target)?;
    let repo_part = if parsed.registry_is_default() {
        parsed.repo.clone()
    } else {
        format!("{}/{}", parsed.registry, parsed.repo)
    };
    let mut url = format!("/images/{source}/tag?repo={}", url_escape(&repo_part));
    if let Some(ref t) = parsed.tag {
        url.push_str(&format!("&tag={}", url_escape(t)));
    }
    api.request_raw("POST", &url, None).await?;
    Ok(())
}

// ---- cp ----

/// Split a `container:path` spec into (container, path). Returns None for
/// a plain local path. A leading `/` is a local absolute path, not a
/// container name.
fn split_cp_spec(spec: &str) -> Option<(&str, &str)> {
    let (c, p) = spec.split_once(':')?;
    if c.is_empty() || p.is_empty() {
        return None;
    }
    // Container names/ids are alphanumeric + `-_._`; a Windows drive letter
    // (`C:\foo`) would collide but we're Linux-only.
    if c.contains('/') || c.contains('\\') {
        return None;
    }
    Some((c, p))
}

pub async fn cp(api: &ApiClient, source: &str, dest: &str) -> Result<()> {
    use std::io::Write;
    let src_ctn = split_cp_spec(source);
    let dst_ctn = split_cp_spec(dest);
    if src_ctn.is_some() == dst_ctn.is_some() {
        return Err(anyhow!(
            "exactly one of SRC and DEST must be a container (form: container:path)"
        ));
    }
    if let Some((ctn, path)) = src_ctn {
        // Download tar from container, extract to local dest.
        let resp = api
            .request(
                "GET",
                &format!("/containers/{ctn}/archive?path={}", url_escape(path)),
                None,
            )
            .await?;
        let bytes = resp.into_body().collect().await?.to_bytes();
        let dest_path = std::path::Path::new(dest);
        // If dest is an existing directory, extract into it; otherwise
        // extract in place (docker creates the leaf).
        let into = if dest_path.is_dir() {
            dest_path
        } else {
            if let Some(parent) = dest_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            dest_path
        };
        let mut archive = tar::Archive::new(std::io::Cursor::new(bytes));
        archive.unpack(into)?;
        return Ok(());
    }
    // Upload local source to container.
    let (ctn, path) = dst_ctn.unwrap();
    let src_path = std::path::Path::new(source);
    if !src_path.exists() {
        return Err(anyhow!("no such local path: {source}"));
    }
    let tmp = std::env::temp_dir().join(format!("ingot-cp-{}.tar", std::process::id()));
    let file = std::fs::File::create(&tmp)?;
    let mut tar = tar::Builder::new(file);
    let base = src_path.file_name().unwrap_or_default();
    if src_path.is_dir() {
        tar.append_dir_all(base, src_path)?;
    } else {
        tar.append_path_with_name(src_path, base)?;
    }
    tar.finish()?;
    let body = std::fs::read(&tmp)?;
    let _ = std::fs::remove_file(&tmp);
    api.request_raw(
        "PUT",
        &format!("/containers/{ctn}/archive?path={}", url_escape(path)),
        Some(body),
    )
    .await?;
    let _ = std::io::stdout().flush();
    Ok(())
}

// ---- network ----

pub async fn network_ls(api: &ApiClient) -> Result<()> {
    let list: Vec<serde_json::Value> = api.get_json("/networks").await?;
    println!(
        "{:<20} {:<12} {:<18} {:<16}",
        "NETWORK ID", "NAME", "DRIVER", "SUBNET"
    );
    for n in &list {
        let id = n["Id"].as_str().unwrap_or("");
        let subnet = n["IPAM"]["Config"][0]["Subnet"].as_str().unwrap_or("");
        println!(
            "{:<20} {:<12} {:<18} {:<16}",
            &id[..12.min(id.len())],
            n["Name"].as_str().unwrap_or(""),
            n["Driver"].as_str().unwrap_or(""),
            subnet,
        );
    }
    Ok(())
}

pub async fn network_create(
    api: &ApiClient,
    name: &str,
    subnet: Option<&str>,
    gateway: Option<&str>,
    internal: bool,
    labels: &[String],
) -> Result<()> {
    let mut ipam = serde_json::json!({});
    if subnet.is_some() || gateway.is_some() {
        let mut cfg = serde_json::json!({});
        if let Some(s) = subnet {
            cfg["Subnet"] = serde_json::json!(s);
        }
        if let Some(g) = gateway {
            cfg["Gateway"] = serde_json::json!(g);
        }
        ipam = serde_json::json!({"Config": [cfg]});
    }
    let mut body = serde_json::json!({
        "Name": name,
        "Internal": internal,
        "IPAM": ipam,
    });
    if !labels.is_empty() {
        let map: serde_json::Map<String, serde_json::Value> = labels
            .iter()
            .filter_map(|l| {
                let (k, v) = l.split_once('=')?;
                Some((k.to_string(), serde_json::json!(v)))
            })
            .collect();
        body["Labels"] = serde_json::Value::Object(map);
    }
    let resp: serde_json::Value = api.post("/networks/create", Some(body)).await?;
    let id = resp["Id"].as_str().unwrap_or("");
    println!("{}", &id[..12.min(id.len())]);
    Ok(())
}

pub async fn network_rm(api: &ApiClient, networks: &[String]) -> Result<()> {
    for n in networks {
        api.request_raw("DELETE", &format!("/networks/{n}"), None)
            .await?;
        println!("{n}");
    }
    Ok(())
}

pub async fn network_inspect(api: &ApiClient, network: &str) -> Result<()> {
    let v: serde_json::Value = api.get_json(&format!("/networks/{network}")).await?;
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(())
}

pub async fn network_connect(
    api: &ApiClient,
    network: &str,
    container: &str,
    aliases: &[String],
) -> Result<()> {
    let mut body = serde_json::json!({"Container": container});
    if !aliases.is_empty() {
        body["EndpointConfig"] = serde_json::json!({"Aliases": aliases});
    }
    api.post::<serde_json::Value>(&format!("/networks/{network}/connect"), Some(body))
        .await
        .ok();
    Ok(())
}

pub async fn network_disconnect(
    api: &ApiClient,
    network: &str,
    container: &str,
    force: bool,
) -> Result<()> {
    let body = serde_json::json!({"Container": container, "Force": force});
    api.post::<serde_json::Value>(&format!("/networks/{network}/disconnect"), Some(body))
        .await
        .ok();
    Ok(())
}

pub async fn network_prune(api: &ApiClient) -> Result<()> {
    let v: serde_json::Value = api.post("/networks/prune", None).await?;
    let deleted = v["NetworksDeleted"]
        .as_array()
        .map(|a| a.len())
        .unwrap_or(0);
    println!("Deleted {} unused network(s)", deleted);
    Ok(())
}

// ---- volume ----

pub async fn volume_ls(api: &ApiClient) -> Result<()> {
    let v: serde_json::Value = api.get_json("/volumes").await?;
    println!(
        "{:<32} {:<12} {:<16}",
        "VOLUME NAME", "DRIVER", "MOUNTPOINT"
    );
    if let Some(vols) = v["Volumes"].as_array() {
        for vol in vols {
            println!(
                "{:<32} {:<12} {:<16}",
                vol["Name"].as_str().unwrap_or(""),
                vol["Driver"].as_str().unwrap_or(""),
                vol["Mountpoint"].as_str().unwrap_or(""),
            );
        }
    }
    Ok(())
}

pub async fn volume_create(api: &ApiClient, name: Option<&str>, labels: &[String]) -> Result<()> {
    let mut body = serde_json::json!({});
    if let Some(n) = name {
        body["Name"] = serde_json::json!(n);
    }
    if !labels.is_empty() {
        let map: serde_json::Map<String, serde_json::Value> = labels
            .iter()
            .filter_map(|l| {
                let (k, v) = l.split_once('=')?;
                Some((k.to_string(), serde_json::json!(v)))
            })
            .collect();
        body["Labels"] = serde_json::Value::Object(map);
    }
    let resp: serde_json::Value = api.post("/volumes/create", Some(body)).await?;
    println!("{}", resp["Name"].as_str().unwrap_or(""));
    Ok(())
}

pub async fn volume_rm(api: &ApiClient, volumes: &[String]) -> Result<()> {
    for v in volumes {
        api.request_raw("DELETE", &format!("/volumes/{v}"), None)
            .await?;
        println!("{v}");
    }
    Ok(())
}

pub async fn volume_inspect(api: &ApiClient, volume: &str) -> Result<()> {
    let v: serde_json::Value = api.get_json(&format!("/volumes/{volume}")).await?;
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(())
}

pub async fn volume_prune(api: &ApiClient) -> Result<()> {
    let v: serde_json::Value = api.post("/volumes/prune", None).await?;
    println!(
        "Deleted {} volume(s)",
        v["VolumesDeleted"].as_i64().unwrap_or(0)
    );
    Ok(())
}

// ---- system ----

pub async fn system_df(api: &ApiClient) -> Result<()> {
    let v: serde_json::Value = api.get_json("/system/df").await?;
    let images = v["Images"].as_array().map(|a| a.len()).unwrap_or(0);
    let layers_size = v["LayersSize"].as_i64().unwrap_or(0);
    let containers = v["Containers"].as_array().map(|a| a.len()).unwrap_or(0);
    let volumes = v["Volumes"].as_array().map(|a| a.len()).unwrap_or(0);
    let build_cache = v["BuildCache"].as_array().map(|a| a.len()).unwrap_or(0);
    println!("TYPE            TOTAL     ACTIVE    SIZE        RECLAIMABLE");
    println!(
        "Images          {:<9} {:<9} {:<11} 0B (0%)",
        images,
        0,
        human_size(layers_size)
    );
    println!(
        "Containers      {:<9} {:<9} 0B          0B (0%)",
        containers, 0
    );
    println!(
        "Local Volumes   {:<9} {:<9} 0B          0B (0%)",
        volumes, 0
    );
    println!(
        "Build Cache     {:<9} {:<9} 0B          0B (0%)",
        build_cache, 0
    );
    Ok(())
}

pub async fn system_prune(api: &ApiClient, force: bool) -> Result<()> {
    if !force {
        eprint!("This will remove all stopped containers, dangling images, unused networks and volumes. Continue? [y/N] ");
        let _ = std::io::Write::flush(&mut std::io::stderr());
        let mut line = String::new();
        std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut line)?;
        if !line.trim().eq_ignore_ascii_case("y") {
            return Ok(());
        }
    }
    let mut reclaimed: i64 = 0;
    let c: serde_json::Value = api.post("/containers/prune", None).await?;
    reclaimed += c["SpaceReclaimed"].as_i64().unwrap_or(0);
    let i: serde_json::Value = api.post("/images/prune", None).await?;
    reclaimed += i["SpaceReclaimed"].as_i64().unwrap_or(0);
    let v: serde_json::Value = api.post("/volumes/prune", None).await?;
    reclaimed += v["Reclaimable"].as_i64().unwrap_or(0);
    let n: serde_json::Value = api.post("/networks/prune", None).await?;
    let nets = n["NetworksDeleted"]
        .as_array()
        .map(|a| a.len())
        .unwrap_or(0);
    println!("Deleted {} network(s)", nets);
    println!("Total reclaimed space: {}", human_size(reclaimed));
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

/// Path-segment escaping for `/images/{name}/...` routes: like
/// `url_escape`, but `/` encodes too so a namespaced repo stays one
/// segment (axum percent-decodes it back before the handler sees it).
fn path_escape(s: &str) -> String {
    url_escape(s).replace('/', "%2F")
}

pub async fn doctor(api: &ApiClient, socket_path: &std::path::Path) -> Result<()> {
    println!("Checking Ingot system requirements and health...\n");
    let mut all_ok = true;

    // 1. Socket & daemon connection
    print!("  [..] Ingot daemon connection: ");
    if !socket_path.exists() {
        println!("FAIL (socket {} does not exist)", socket_path.display());
        all_ok = false;
    } else {
        match api.get_json::<serde_json::Value>("/version").await {
            Ok(v) => {
                let ver = v["Version"].as_str().unwrap_or("unknown");
                let api_ver = v["ApiVersion"].as_str().unwrap_or("unknown");
                println!("OK (version {ver}, API {api_ver})");
            }
            Err(e) => {
                println!("FAIL ({e})");
                all_ok = false;
            }
        }
    }

    // 2. cgroup v2
    print!("  [..] cgroup v2 support: ");
    let cgroups = std::fs::read_to_string("/sys/fs/cgroup/cgroup.controllers");
    match cgroups {
        Ok(controllers) if !controllers.trim().is_empty() => {
            println!("OK (controllers: {})", controllers.trim());
        }
        _ => {
            println!("FAIL (cgroup v2 controllers missing from /sys/fs/cgroup)");
            all_ok = false;
        }
    }

    // 3. overlayfs
    print!("  [..] overlayfs kernel module: ");
    let filesystems = std::fs::read_to_string("/proc/filesystems").unwrap_or_default();
    if filesystems.contains("overlay") {
        println!("OK");
    } else {
        println!("FAIL (overlay filesystem not supported by kernel)");
        all_ok = false;
    }

    // 4. ip binary
    print!("  [..] iproute2 (`ip`): ");
    match std::process::Command::new("ip").arg("-V").output() {
        Ok(out) if out.status.success() => {
            println!("OK ({})", String::from_utf8_lossy(&out.stdout).trim());
        }
        _ => {
            println!("FAIL (`ip` binary not found or failed)");
            all_ok = false;
        }
    }

    // 5. iptables binary
    print!("  [..] iptables: ");
    match std::process::Command::new("iptables").arg("-V").output() {
        Ok(out) if out.status.success() => {
            println!("OK ({})", String::from_utf8_lossy(&out.stdout).trim());
        }
        _ => {
            println!("FAIL (`iptables` binary not found or failed)");
            all_ok = false;
        }
    }

    // 6. data paths
    print!("  [..] data paths: ");
    let info = api.get_json::<serde_json::Value>("/info").await;
    match info {
        Ok(inf) => {
            let root_dir = inf["DockerRootDir"].as_str().unwrap_or("/var/lib/ingot");
            let p = std::path::Path::new(root_dir);
            if p.exists() {
                println!("OK ({})", root_dir);
            } else {
                println!("WARN (daemon root {} does not exist yet)", root_dir);
            }

            // 7. seccomp
            print!("  [..] seccomp profile: ");
            let sec_opts = inf["SecurityOptions"].as_array();
            let has_seccomp = sec_opts.is_some_and(|opts| {
                opts.iter()
                    .any(|o| o.as_str().is_some_and(|s| s.contains("seccomp")))
            });
            if has_seccomp {
                println!("OK (default profile active)");
            } else {
                println!("WARN (seccomp profile not reported)");
            }

            // 8. data-root schema marker (read-only; WARN, never FAIL:
            // doctor often runs without the daemon's file permissions).
            print!("  [..] data-root schema: ");
            let marker = std::path::Path::new(root_dir).join("schema-version");
            match std::fs::read_to_string(&marker) {
                Ok(raw) => match raw.trim().parse::<u32>() {
                    Ok(v) => println!("OK (version {v})"),
                    Err(_) => println!(
                        "WARN (unparsable marker {}; back up before touching it)",
                        marker.display()
                    ),
                },
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    println!("WARN (no schema marker yet; written on first daemon boot)")
                }
                Err(e) => println!("SKIP (cannot read {}: {e})", marker.display()),
            }
        }
        Err(_) => {
            println!("SKIP (daemon not reachable)");
        }
    }

    println!();
    if all_ok {
        println!("All critical preflight checks passed.");
        Ok(())
    } else {
        Err(anyhow!("One or more preflight checks failed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_path_splits_name_and_tag() {
        // Default registry drops the host; the repo keeps its slashes
        // encoded for the single-segment route.
        assert_eq!(
            push_path("busybox:1.36").unwrap(),
            ("library%2Fbusybox".to_string(), Some("1.36".to_string()))
        );
        assert_eq!(
            push_path("myuser/myapp").unwrap(),
            ("myuser%2Fmyapp".to_string(), Some("latest".to_string()))
        );
        // Custom registries stay qualified, ports intact.
        assert_eq!(
            push_path("127.0.0.1:5000/team/app:dev").unwrap(),
            (
                "127.0.0.1:5000%2Fteam%2Fapp".to_string(),
                Some("dev".to_string())
            )
        );
        // Digest-only references carry no tag for the query.
        let (name, tag) = push_path(
            "busybox@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        assert_eq!(name, "library%2Fbusybox");
        assert_eq!(tag, None);
        assert!(push_path("").is_err());
    }

    #[test]
    fn list_format_parsing() {
        assert_eq!(parse_list_format(None).unwrap(), None);
        assert_eq!(
            parse_list_format(Some("table")).unwrap(),
            Some(ListFormat::Table)
        );
        assert_eq!(
            parse_list_format(Some("json")).unwrap(),
            Some(ListFormat::Json)
        );
        // Go templates and anything else fail closed with guidance.
        let err = parse_list_format(Some("{{.ID}}")).unwrap_err().to_string();
        assert!(err.contains("table") && err.contains("json"), "{err}");
    }
}
