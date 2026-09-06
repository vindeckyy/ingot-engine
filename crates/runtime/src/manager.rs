//! Container lifecycle: create / start / stop / kill / wait / logs / remove.
//!
//! Start sequence (docker/runc equivalent):
//!   1. mount overlay rootfs (daemon ns)
//!   2. clone() with NEWNS|NEWPID|NEWUTS|NEWIPC|NEWNET — child waits on a
//!      readiness pipe before doing its mount/exec work
//!   3. parent: cgroup v2 setup, netns bind + veth setup, then signals 'g'
//!   4. child: mounts /dev /proc /sys, pivot_root, caps, execve
//!   5. parent: pump stdio → json-file log + attach subscribers; waitpid

use crate::cgroup::Cgroup;
use crate::child::ChildContext;
use crate::overlay;
use crate::record::{ContainerRecord, ContainerState, StateStatus};
use crate::stdio::{pump_pipe, StdioHub, STREAM_STDERR, STREAM_STDOUT};
use anyhow::{anyhow, Context, Result};
use ingot_api::{ContainerConfig, ContainerCreateBody, EventMessage, HostConfig};
use ingot_store::paths::DataPaths;
use ingot_store::EventBus;
use std::collections::{HashMap, HashSet};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};
use tokio::sync::broadcast;

pub struct ContainerHandle {
    pub record: Mutex<ContainerRecord>,
    pub state: Mutex<ContainerState>,
    pub stdio: Arc<StdioHub>,
    /// stdin receiver created at hub construction, taken by `start`.
    pub stdin_rx: Mutex<Option<tokio::sync::mpsc::Receiver<Vec<u8>>>>,
    pub manual_stop: AtomicBool,
    exit_tx: broadcast::Sender<i64>,
}

impl ContainerHandle {
    pub fn subscribe_exit(&self) -> broadcast::Receiver<i64> {
        self.exit_tx.subscribe()
    }

    pub fn is_running(&self) -> bool {
        self.state.lock().unwrap().status == StateStatus::Running
    }

    pub fn id(&self) -> String {
        self.record.lock().unwrap().id.clone()
    }
}

pub struct ContainerManager {
    pub paths: DataPaths,
    pub events: EventBus,
    pub images: Arc<ingot_image::ImageStore>,
    /// Attached network manager (set by ingotd once M3 boots).
    pub net: RwLock<Option<Arc<ingot_network::NetworkManager>>>,
    pub self_ref: RwLock<Option<Weak<ContainerManager>>>,
    live: RwLock<HashMap<String, Arc<ContainerHandle>>>,
    execs: RwLock<HashMap<String, Arc<crate::exec::ExecSession>>>,
}

impl ContainerManager {
    pub fn new(paths: DataPaths, events: EventBus, images: Arc<ingot_image::ImageStore>) -> Result<Self> {
        Ok(ContainerManager {
            paths,
            events,
            images,
            net: RwLock::new(None),
            self_ref: RwLock::new(None),
            live: RwLock::new(HashMap::new()),
            execs: RwLock::new(HashMap::new()),
        })
    }

    // ---------- create ----------

    pub async fn create(
        &self,
        image_name: &str,
        mut body: ContainerCreateBody,
        name: Option<String>,
    ) -> Result<Arc<ContainerHandle>> {
        let image_id = self.images.resolve(&body.Image).await?;
        let image = self
            .images
            .load(&image_id)
            .await?
            .ok_or_else(|| anyhow!("image vanished: {image_id}"))?;

        // Merge image config + request (docker semantics).
        body.Image = format!("sha256:{}", image.id);
        let user_cmd = if body.Cmd.is_empty() { None } else { Some(std::mem::take(&mut body.Cmd)) };
        let user_ep = body.Entrypoint.clone();
        let mut env = image.config.Env.clone();
        env.extend(std::mem::take(&mut body.Env));
        body.Env = env;
        if body.WorkingDir.is_empty() {
            body.WorkingDir = image.config.WorkingDir.clone();
        }
        if body.User.is_empty() {
            body.User = image.config.User.clone();
        }
        for (k, v) in &image.config.Labels {
            body.Labels.entry(k.clone()).or_insert_with(|| v.clone());
        }

        let id = ingot_util::new_id();
        let name = match name {
            Some(n) => {
                if self.name_taken(&n).await {
                    return Err(anyhow!(
                        "Conflict. The container name \"/{n}\" is already in use"
                    ));
                }
                n
            }
            None => loop {
                let candidate = ingot_util::name::random_name();
                if !self.name_taken(&candidate).await {
                    break candidate;
                }
            },
        };

        let hostname = if body.Hostname.is_empty() { id[..12].to_string() } else { body.Hostname.clone() };

        let mut config: ContainerConfig = body.clone().into_container_config();
        config.Hostname = hostname;
        config.Image = format!("sha256:{}", image.id);
        config.Entrypoint = user_ep;
        config.Cmd = user_cmd.unwrap_or_else(|| image.config.Cmd.clone());
        config.Env = body.Env.clone();

        let mounts = self.resolve_mounts(&body.HostConfig, &image, body.Volumes.as_ref(), &id).await?;

        let cmd_display = {
            let ep = config.Entrypoint.clone().unwrap_or_default();
            let cmd = config.Cmd.clone();
            let argv = if ep.is_empty() { cmd } else { [ep, cmd].concat() };
            format!("\"{}\"", argv.join(" "))
        };

        let record = ContainerRecord {
            id: id.clone(),
            name: name.clone(),
            created: ingot_util::now_rfc3339(),
            image_id: format!("sha256:{}", image.id),
            image_name: image_name.to_string(),
            config,
            hostconfig: body.HostConfig.clone(),
            cmd_display,
            endpoints: Vec::new(),
            mounts,
        };

        // Persist.
        let dir = self.paths.container(&id);
        std::fs::create_dir_all(dir.join("logs"))?;
        ingot_store::write_json_atomic(&self.paths.container_config(&id), &record)?;
        ingot_store::write_json_atomic(&self.paths.container_hostconfig(&id), &record.hostconfig)?;

        std::fs::write(self.paths.container_hostname(&id), format!("{}\n", record.config.Hostname))?;
        std::fs::write(self.paths.container_hosts(&id), default_hosts(&record, "", ""))?;
        std::fs::write(self.paths.container_resolv(&id), default_resolv())?;

        let state = ContainerState { status: StateStatus::Created, ..Default::default() };
        ingot_store::write_json_atomic(&self.paths.container_state(&id), &state)?;

        let (hub, stdin_rx) = StdioHub::new(self.paths.container_log(&id));
        let handle = Arc::new(ContainerHandle {
            record: Mutex::new(record),
            state: Mutex::new(state),
            stdio: Arc::new(hub),
            stdin_rx: Mutex::new(Some(stdin_rx)),
            manual_stop: AtomicBool::new(false),
            exit_tx: broadcast::channel(16).0,
        });
        self.live.write().unwrap().insert(id.clone(), handle.clone());

        self.events.publish(EventMessage::new(
            "container",
            "create",
            &id,
            container_attrs(&handle),
        ));
        Ok(handle)
    }

    async fn name_taken(&self, name: &str) -> bool {
        self.list_records().await.iter().any(|r| r.name == name)
    }

    async fn resolve_mounts(
        &self,
        hostconfig: &HostConfig,
        image: &ingot_image::ImageRecord,
        body_volumes: Option<&HashMap<String, serde_json::Value>>,
        _container_id: &str,
    ) -> Result<Vec<crate::record::MountRecord>> {
        let mut out = Vec::new();
        for bind in &hostconfig.Binds {
            let (spec, ro) = match bind.strip_suffix(":ro") {
                Some(s) => (s, true),
                None => (bind.as_str(), false),
            };
            if let Some((source, dest)) = spec.split_once(':') {
                if source.starts_with('/') || source.starts_with('.') {
                    out.push(crate::record::MountRecord {
                        typ: "bind".into(),
                        name: String::new(),
                        source: source.to_string(),
                        destination: dest.to_string(),
                        read_only: ro,
                    });
                } else {
                    // Named volume!
                    let dir = self.paths.volumes().join(source);
                    std::fs::create_dir_all(&dir)?;
                    let meta_path = dir.join("metadata.json");
                    if !meta_path.exists() {
                        let meta = serde_json::json!({
                            "name": source,
                            "created_at": ingot_util::now_rfc3339(),
                            "driver": "local",
                            "labels": {},
                            "options": {}
                        });
                        let _ = ingot_store::write_json_atomic(&meta_path, &meta);
                    }
                    out.push(crate::record::MountRecord {
                        typ: "volume".into(),
                        name: source.to_string(),
                        source: dir.to_string_lossy().to_string(),
                        destination: dest.to_string(),
                        read_only: ro,
                    });
                }
            } else {
                // Anonymous volume: e.g. "-v /data"
                let dest = spec;
                let n = ingot_util::new_id()[..32].to_string();
                let dir = self.paths.volumes().join(&n);
                std::fs::create_dir_all(&dir)?;
                let meta_path = dir.join("metadata.json");
                let meta = serde_json::json!({
                    "name": n,
                    "created_at": ingot_util::now_rfc3339(),
                    "driver": "local",
                    "labels": {},
                    "options": {}
                });
                let _ = ingot_store::write_json_atomic(&meta_path, &meta);
                out.push(crate::record::MountRecord {
                    typ: "volume".into(),
                    name: n,
                    source: dir.to_string_lossy().to_string(),
                    destination: dest.to_string(),
                    read_only: ro,
                });
            }
        }
        for m in &hostconfig.Mounts {
            let typ = if m.typ.is_empty() { "volume".to_string() } else { m.typ.clone() };
            if typ == "volume" {
                let name = if m.Source.is_empty() {
                    ingot_util::new_id()[..32].to_string()
                } else {
                    m.Source.clone()
                };
                let dir = self.paths.volumes().join(&name);
                std::fs::create_dir_all(&dir)?;
                let meta_path = dir.join("metadata.json");
                if !meta_path.exists() {
                    let meta = serde_json::json!({
                        "name": name,
                        "created_at": ingot_util::now_rfc3339(),
                        "driver": "local",
                        "labels": {},
                        "options": {}
                    });
                    let _ = ingot_store::write_json_atomic(&meta_path, &meta);
                }
                out.push(crate::record::MountRecord {
                    typ: "volume".into(),
                    name,
                    source: dir.to_string_lossy().to_string(),
                    destination: m.Target.clone(),
                    read_only: m.read_only,
                });
            } else {
                out.push(crate::record::MountRecord {
                    typ,
                    name: String::new(),
                    source: m.Source.clone(),
                    destination: m.Target.clone(),
                    read_only: m.read_only,
                });
            }
        }
        // Image VOLUME declarations → anonymous volumes (copy-on-first-mount).
        if let Some(vols) = &image.config.Volumes {
            for dest in vols.keys() {
                if !out.iter().any(|m| &m.destination == dest) {
                    let n = ingot_util::new_id()[..32].to_string();
                    let dir = self.paths.volumes().join(&n);
                    std::fs::create_dir_all(&dir)?;
                    let meta_path = dir.join("metadata.json");
                    let meta = serde_json::json!({
                        "name": n,
                        "created_at": ingot_util::now_rfc3339(),
                        "driver": "local",
                        "labels": {},
                        "options": {}
                    });
                    let _ = ingot_store::write_json_atomic(&meta_path, &meta);
                    out.push(crate::record::MountRecord {
                        typ: "volume".into(),
                        name: n,
                        source: dir.to_string_lossy().to_string(),
                        destination: dest.clone(),
                        read_only: false,
                    });
                }
            }
        }
        // Body Volumes declarations → anonymous volumes.
        if let Some(vols) = body_volumes {
            for dest in vols.keys() {
                if !out.iter().any(|m| &m.destination == dest) {
                    let n = ingot_util::new_id()[..32].to_string();
                    let dir = self.paths.volumes().join(&n);
                    std::fs::create_dir_all(&dir)?;
                    let meta_path = dir.join("metadata.json");
                    let meta = serde_json::json!({
                        "name": n,
                        "created_at": ingot_util::now_rfc3339(),
                        "driver": "local",
                        "labels": {},
                        "options": {}
                    });
                    let _ = ingot_store::write_json_atomic(&meta_path, &meta);
                    out.push(crate::record::MountRecord {
                        typ: "volume".into(),
                        name: n,
                        source: dir.to_string_lossy().to_string(),
                        destination: dest.clone(),
                        read_only: false,
                    });
                }
            }
        }
        Ok(out)
    }

    // ---------- start ----------

    pub fn start<'a>(&'a self, id_or_name: &'a str) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Arc<ContainerHandle>>> + Send + 'a>> {
        Box::pin(async move {
        let handle = self
            .get(id_or_name)
            .await?
            .ok_or_else(|| anyhow!("No such container: {id_or_name}"))?;
        {
            let st = handle.state.lock().unwrap();
            if st.status == StateStatus::Running {
                return Err(anyhow!("container is already started"));
            }
        }

        let record = handle.record.lock().unwrap().clone();
        let image_id = record.image_id.trim_start_matches("sha256:").to_string();
        let image = self
            .images
            .load(&image_id)
            .await?
            .ok_or_else(|| anyhow!("No such image: {image_id}"))?;

        overlay::mount_rootfs(&self.paths, &record.id, &image.diff_ids)
            .with_context(|| format!("prepare rootfs for {id_or_name}"))?;
        apply_mounts(&self.paths, &record).with_context(|| format!("apply mounts for {id_or_name}"))?;

        let (ready_tx, ready_rx) = std::os::unix::net::UnixStream::pair()?;

        // ---- stdio ----
        // REAL pipes (not socketpairs): container processes re-open
        // /proc/self/fd/N (nginx log symlinks), which only works for pipes.
        // Parent ends are pumped on blocking threads; child gets dup()s.
        let tty = record.config.Tty;
        let (child_in_fd, child_out_fd, child_err_fd, pumps, stdin_w) = if tty {
            let pty = openpty_pair()?;
            let master = to_tokio_stream(pty.master_fd)?;
            (
                pty.slave_fd,
                pty.slave_fd,
                -1,
                vec![(STREAM_STDOUT, Pump::Async(master))],
                None,
            )
        } else {
            let (in_r, in_w) = os_pipe_pair()?;
            let (out_r, out_w) = os_pipe_pair()?;
            let (err_r, err_w) = os_pipe_pair()?;
            (
                in_r,
                out_w,
                err_w,
                vec![
                    (
                        STREAM_STDOUT,
                        Pump::Blocking(unsafe { std::fs::File::from_raw_fd(out_r) }),
                    ),
                    (
                        STREAM_STDERR,
                        Pump::Blocking(unsafe { std::fs::File::from_raw_fd(err_r) }),
                    ),
                ],
                Some(in_w),
            )
        };

        let cap_add = record.hostconfig.CapAdd.clone();
        let cap_drop = record.hostconfig.CapDrop.clone();
        let (uid, gid, extra_gids) = parse_user_numeric(&record.config.User);

        let mut env: Vec<String> = record.config.Env.clone();
        if !env.iter().any(|e| e.starts_with("PATH=")) {
            env.push("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into());
        }
        if !env.iter().any(|e| e.starts_with("HOME=")) {
            env.push("HOME=/".into());
        }
        env.push(format!("HOSTNAME={}", record.config.Hostname));

        let argv = record.argv();
        if argv.is_empty() {
            return Err(anyhow!("No command specified"));
        }

        let network_mode = record.hostconfig.NetworkMode.clone();

        let ctx = ChildContext {
            ready_pipe_rd: ready_rx.as_raw_fd(),
            stdin_fd: child_in_fd,
            stdout_fd: child_out_fd,
            stderr_fd: child_err_fd,
            merged: cstring(self.paths.overlay_merged(&record.id).to_str().unwrap())?,
            hostname: cstring(&record.config.Hostname)?,
            resolv: cstring(self.paths.container_resolv(&record.id).to_str().unwrap())?,
            hosts: cstring(self.paths.container_hosts(&record.id).to_str().unwrap())?,
            hostname_file: cstring(self.paths.container_hostname(&record.id).to_str().unwrap())?,
            argv: argv.iter().map(|a| cstring(a)).collect::<Result<Vec<_>>>()?,
            envp: env.iter().map(|e| cstring(e)).collect::<Result<Vec<_>>>()?,
            workdir: cstring(if record.config.WorkingDir.is_empty() {
                "/"
            } else {
                &record.config.WorkingDir
            })?,
            user_raw: cstring(&record.config.User)?,
            uid,
            gid,
            extra_gids,
            cap_add,
            cap_drop,
            privileged: record.hostconfig.Privileged,
            no_new_privs: !record.hostconfig.Privileged,
            readonly_rootfs: record.hostconfig.ReadonlyRootfs,
            bring_lo_up: network_mode == "none" || self.net.read().unwrap().is_none(),
            has_netns: !matches!(network_mode.as_str(), "host" | ""),
            tty,
        };

        // ---- clone ----
        let clone_flags: i32 = libc::SIGCHLD as i32
            | libc::CLONE_NEWNS
            | libc::CLONE_NEWPID
            | libc::CLONE_NEWUTS
            | libc::CLONE_NEWIPC
            | if network_mode == "host" { 0 } else { libc::CLONE_NEWNET };

        let pid = {
            let ctx_ptr = ctx.into_raw() as *mut libc::c_void;
            let p = unsafe {
                const STACK: usize = 8 * 1024 * 1024;
                let mut stack = vec![0u8; STACK];
                let top = ((stack.as_mut_ptr() as usize) + STACK - 16) & !0xF;
                libc::clone(
                    child_trampoline_shim,
                    top as *mut libc::c_void,
                    clone_flags,
                    ctx_ptr,
                )
            };
            if p < 0 {
                unsafe { ChildContext::from_raw(ctx_ptr as *mut ChildContext) };
            }
            p
        };
        if pid < 0 {
            return Err(anyhow!("clone failed: {}", std::io::Error::last_os_error()));
        }
        drop(ready_rx);
        if child_in_fd >= 0 {
            unsafe { libc::close(child_in_fd) };
        }
        if child_out_fd >= 0 && child_out_fd != child_in_fd {
            unsafe { libc::close(child_out_fd) };
        }
        if child_err_fd >= 0 && child_err_fd != child_out_fd && child_err_fd != child_in_fd {
            unsafe { libc::close(child_err_fd) };
        }

        // ---- cgroup ----
        let cgroup = Cgroup::create(&record.id).ok();
        if let Some(cg) = &cgroup {
            let _ = cg.apply(
                record.hostconfig.Memory,
                record.hostconfig.NanoCpus,
                record.hostconfig.CpuShares,
                record.hostconfig.PidsLimit,
                &record.hostconfig.CpusetCpus,
            );
            let _ = cg.add_pid(pid as i64);
        }

        // ---- netns bind + network attach ----
        let netns_path = self.paths.netns_bind(&record.id);
        std::fs::create_dir_all(netns_path.parent().unwrap())?;
        let _ = std::fs::remove_file(&netns_path);
        let netns_src = format!("/proc/{pid}/ns/net");
        if std::path::Path::new(&netns_src).exists() {
            let _ = bind_mount(&netns_src, netns_path.to_str().unwrap());
        }
        let mntns_path = self.paths.container_mntns(&record.id);
        let _ = std::fs::remove_file(&mntns_path);
        let mntns_src = format!("/proc/{pid}/ns/mnt");
        if std::path::Path::new(&mntns_src).exists() {
            let _ = bind_mount(&mntns_src, mntns_path.to_str().unwrap());
        }

        let mut ip = String::new();
        let mut gw = String::new();
        let net_manager = self.net.read().unwrap().clone();
        if network_mode != "none" && network_mode != "host" && net_manager.is_some() {
            let req = ingot_network::AttachRequest {
                container_id: record.id.clone(),
                container_name: record.name.clone(),
                hostname: record.config.Hostname.clone(),
                network: if network_mode == "default" { "bridge".to_string() } else { network_mode.clone() },
                pid: pid as i64,
                netns_path: netns_path.to_string_lossy().to_string(),
                aliases: vec![record.name.clone()],
            };
            match net_manager.unwrap().attach(&req).await {
                Ok(ep) => {
                    ip = ep.ip.clone();
                    gw = ep.gateway.clone();
                    handle
                        .record
                        .lock()
                        .unwrap()
                        .endpoints
                        .push(crate::record::EndpointRecord {
                            network_id: ep.network_id.clone(),
                            network_name: ep.network_name.clone(),
                            ip: ep.ip.clone(),
                            gateway: ep.gateway.clone(),
                            mac: ep.mac.clone(),
                            aliases: ep.aliases.clone(),
                        });
                    let _ = ingot_store::write_json_atomic(
                        &self.paths.container_config(&record.id),
                        &*handle.record.lock().unwrap(),
                    );
                    // Publish declared ports (docker -p).
                    let net = self.net.read().unwrap().clone();
                    if let Some(net) = net {
                        for (k, bindings) in &record.hostconfig.PortBindings {
                            let (cport_str, proto) = match k.split_once('/') {
                                Some((p, t)) => (p, t),
                                None => (k.as_str(), "tcp"),
                            };
                            let Ok(cport) = cport_str.parse::<u16>() else { continue };
                            for b in bindings {
                                let host_port = match b.HostPort.parse::<u16>() {
                                    Ok(p) if p != 0 => p,
                                    _ => net.allocate_ephemeral_port().await,
                                };
                                let rule = ingot_network::PortRule {
                                    container_id: record.id.clone(),
                                    host_ip: b.HostIp.clone(),
                                    host_port,
                                    container_ip: ep.ip.clone(),
                                    container_port: cport,
                                    proto: proto.to_string(),
                                };
                                if let Err(e) = net.publish_port(rule).await {
                                    tracing::warn!("publish {} failed: {e}", k);
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    let _ = write_ready(&ready_tx, b'e');
                    reap_now(pid);
                    let _ = overlay::unmount_rootfs(&self.paths, &record.id);
                    return Err(anyhow!("network attach failed: {e:#}; container init aborted"));
                }
            }
        }
        // Otherwise: none/host (or no net manager yet) — the child brings lo
        // up itself via `bring_lo_up`.

        // hosts file now includes the allocated IP; resolv.conf points at
        // the embedded DNS on the gateway for user-defined networks.
        std::fs::write(
            self.paths.container_hosts(&record.id),
            default_hosts(&record, &ip, &gw),
        )?;
        if !ip.is_empty() && network_mode != "bridge" && network_mode != "default" {
            let mut resolv = String::new();
            for d in &record.hostconfig.Dns {
                resolv.push_str(&format!("nameserver {d}\n"));
            }
            if resolv.is_empty() {
                resolv = format!("nameserver {gw}\n");
            }
            std::fs::write(self.paths.container_resolv(&record.id), resolv)?;
        }

        // ---- stdio pumps ----
        for (tag, stream) in pumps {
            let hub = handle.stdio.clone();
            match stream {
                Pump::Blocking(file) => {
                    tokio::task::spawn_blocking(move || {
                        crate::stdio::pump_pipe_blocking(file, tag, (*hub).clone());
                    });
                }
                Pump::Async(stream) => {
                    tokio::spawn(crate::stdio::pump_pipe(stream, tag, (*hub).clone()));
                }
            }
        }
        if let (Some(rx), Some(writer)) = (handle.stdin_rx.lock().unwrap().take(), stdin_w) {
            let file = unsafe { std::fs::File::from_raw_fd(writer) };
            tokio::task::spawn_blocking(move || crate::stdio::pump_stdin_blocking(rx, file));
        }

        // ---- state: running ----
        {
            let mut st = handle.state.lock().unwrap();
            st.status = StateStatus::Running;
            st.pid = pid as i64;
            st.started_at = ingot_util::now_rfc3339();
            st.exit_code = 0;
        }
        self.persist_state(&handle).await;
        self.events.publish(EventMessage::new(
            "container",
            "start",
            &record.id,
            container_attrs(&handle),
        ));

        write_ready(&ready_tx, b'g')?;
        drop(ready_tx);

        handle.manual_stop.store(false, Ordering::SeqCst);

        // ---- healthcheck ----
        if let Some(hc) = &record.config.Healthcheck {
            if !hc.Test.is_empty() && hc.Test[0] != "NONE" {
                {
                    let mut st = handle.state.lock().unwrap();
                    st.health = Some(ingot_api::HealthState {
                        Status: "starting".into(),
                        FailingStreak: 0,
                        Log: Vec::new(),
                    });
                }
                self.persist_state(&handle).await;

                let probe_handle = handle.clone();
                let probe_paths = self.paths.clone();
                let probe_id = record.id.clone();
                let hc_clone = hc.clone();
                tokio::spawn(async move {
                    run_healthcheck_loop(probe_handle, probe_paths, probe_id, hc_clone).await;
                });
            }
        }

        // ---- reaper ----
        let mgr_handle = handle.clone();
        let paths = self.paths.clone();
        let events = self.events.clone();
        let live_id = record.id.clone();
        let cg = cgroup;
        let autoremove = record.hostconfig.AutoRemove;
        let restart_policy = record.hostconfig.RestartPolicy.clone();
        let self_ref = self.self_ref.read().unwrap().clone();
        tokio::task::spawn_blocking(move || {
            let mut status = 0;
            let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
            let exit_code: i64 = if rc == pid {
                if libc::WIFEXITED(status) {
                    libc::WEXITSTATUS(status) as i64
                } else if libc::WIFSIGNALED(status) {
                    (128 + libc::WTERMSIG(status)) as i64
                } else {
                    1
                }
            } else {
                -1
            };
            let mut should_restart = false;
            {
                let mut st = mgr_handle.state.lock().unwrap();
                st.status = StateStatus::Exited;
                st.exit_code = exit_code;
                st.finished_at = ingot_util::now_rfc3339();
                st.pid = 0;

                let manual_stop = mgr_handle.manual_stop.load(Ordering::SeqCst);
                if !manual_stop && !autoremove {
                    match restart_policy.Name.as_str() {
                        "always" => {
                            st.restart_count += 1;
                            should_restart = true;
                        }
                        "unless-stopped" => {
                            st.restart_count += 1;
                            should_restart = true;
                        }
                        "on-failure" => {
                            if exit_code != 0 {
                                if restart_policy.MaximumRetryCount <= 0 || st.restart_count < restart_policy.MaximumRetryCount {
                                    st.restart_count += 1;
                                    should_restart = true;
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            let _ = ingot_store::write_json_atomic(
                &paths.container_state(&live_id),
                &*mgr_handle.state.lock().unwrap(),
            );
            if let Some(cg) = cg {
                cg.remove();
            }
            let _ = overlay::unmount_rootfs(&paths, &live_id);
            tracing::debug!(container = %live_id, exit = exit_code, "reaper: publishing die");
            events.publish(EventMessage::new(
                "container",
                "die",
                &live_id,
                container_attrs(&mgr_handle),
            ));
            let _ = mgr_handle.exit_tx.send(exit_code);
            tracing::debug!(container = %live_id, "reaper: done");
            if autoremove {
                let paths = paths.clone();
                let live_id = live_id.clone();
                tokio::spawn(async move {
                    let _ = cleanup_container(&paths, &live_id);
                });
            } else if should_restart {
                if let Some(weak) = self_ref {
                    if let Some(mgr) = weak.upgrade() {
                        events.publish(EventMessage::new(
                            "container",
                            "restart",
                            &live_id,
                            container_attrs(&mgr_handle),
                        ));
                        tokio::spawn(restart_container(mgr, live_id));
                    }
                }
            }
        });

        Ok(handle)
        })
    }

    // ---------- stop / kill / pause ----------

    pub async fn stop(&self, id_or_name: &str, timeout: i64) -> Result<i64> {
        tracing::debug!(container = id_or_name, timeout, "stop: entered");
        let handle = self
            .get(id_or_name)
            .await?
            .ok_or_else(|| anyhow!("No such container: {id_or_name}"))?;
        handle.manual_stop.store(true, Ordering::SeqCst);
        let (pid, signal) = {
            let state = handle.state.lock().unwrap();
            if state.status != StateStatus::Running {
                return Ok(state.exit_code);
            }
            (state.pid as i32, handle.record.lock().unwrap().stop_signal())
        };
        // Subscribe BEFORE signalling: the process may exit immediately.
        let mut rx = handle.subscribe_exit();
        tracing::debug!(pid, "stop: sending signal");
        unsafe {
            libc::kill(pid, signal as libc::c_int);
        }
        match tokio::time::timeout(
            std::time::Duration::from_secs(timeout.max(0) as u64),
            rx.recv(),
        )
        .await
        {
            Ok(Ok(code)) => {
                tracing::debug!("stop: graceful exit {code}");
                return Ok(code);
            }
            Ok(Err(e)) => tracing::debug!("stop: recv error {e}"),
            Err(_) => tracing::debug!("stop: grace period expired"),
        }
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
        // Bounded final wait; report whatever state we reach.
        match tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv()).await {
            Ok(Ok(code)) => Ok(code),
            _ => Ok(handle.state.lock().unwrap().exit_code),
        }
    }

    pub async fn kill(&self, id_or_name: &str, signal: i32) -> Result<()> {
        let handle = self
            .get(id_or_name)
            .await?
            .ok_or_else(|| anyhow!("No such container: {id_or_name}"))?;
        handle.manual_stop.store(true, Ordering::SeqCst);
        let pid = {
            let st = handle.state.lock().unwrap();
            if st.status != StateStatus::Running {
                return Err(anyhow!("container is not running"));
            }
            st.pid as i32
        };
        let rc = unsafe { libc::kill(pid as i32, signal) };
        if rc != 0 {
            return Err(anyhow!("kill: {}", std::io::Error::last_os_error()));
        }
        Ok(())
    }

    pub async fn pause(&self, id_or_name: &str, on: bool) -> Result<()> {
        let handle = self
            .get(id_or_name)
            .await?
            .ok_or_else(|| anyhow!("No such container: {id_or_name}"))?;
        {
            let st = handle.state.lock().unwrap();
            if st.status != StateStatus::Running && st.status != StateStatus::Paused {
                return Err(anyhow!("container is not running"));
            }
        }
        let rid = handle.id();
        let cg = Cgroup::create(&rid)?;
        cg.freeze(on)?;
        let mut st = handle.state.lock().unwrap();
        st.status = if on { StateStatus::Paused } else { StateStatus::Running };
        Ok(())
    }

    // ---------- lookups ----------

    pub async fn get(&self, name_or_id: &str) -> Result<Option<Arc<ContainerHandle>>> {
        {
            let live = self.live.read().unwrap();
            if let Some(h) = live.get(name_or_id) {
                return Ok(Some(h.clone()));
            }
            for (id, h) in live.iter() {
                if id.starts_with(name_or_id) {
                    return Ok(Some(h.clone()));
                }
            }
        }
        let records = self.list_records().await;
        let record = records.into_iter().find(|r| {
            r.id == name_or_id
                || r.id.starts_with(name_or_id)
                || r.name == name_or_id
                || format!("/{}", r.name) == name_or_id
        });
        match record {
            Some(r) => {
                let state = ingot_store::read_json::<ContainerState>(&self.paths.container_state(&r.id))
                    .unwrap_or_default();
                let (hub, stdin_rx) = StdioHub::new(self.paths.container_log(&r.id));
                let handle = Arc::new(ContainerHandle {
                    record: Mutex::new(r),
                    state: Mutex::new(state),
                    stdio: Arc::new(hub),
                    stdin_rx: Mutex::new(Some(stdin_rx)),
                    manual_stop: AtomicBool::new(false),
                    exit_tx: broadcast::channel(16).0,
                });
                self.live
                    .write()
                    .unwrap()
                    .insert(handle.id(), handle.clone());
                Ok(Some(handle))
            }
            None => Ok(None),
        }
    }

    pub async fn list_records(&self) -> Vec<ContainerRecord> {
        let mut out = Vec::new();
        let Ok(mut rd) = std::fs::read_dir(self.paths.containers()) else {
            return out;
        };
        let mut seen = HashSet::new();
        for entry in rd.flatten() {
            let cfg = entry.path().join("config.json");
            if let Ok(data) = std::fs::read(&cfg) {
                if let Ok(r) = serde_json::from_slice::<ContainerRecord>(&data) {
                    if seen.insert(r.id.clone()) {
                        out.push(r);
                    }
                }
            }
        }
        out.sort_by(|a, b| b.created.cmp(&a.created));
        out
    }

    pub async fn persist_state(&self, handle: &ContainerHandle) {
        let id = handle.id();
        let st = handle.state.lock().unwrap().clone();
        let _ = ingot_store::write_json_atomic(&self.paths.container_state(&id), &st);
    }

    pub async fn remove(&self, id_or_name: &str, force: bool) -> Result<()> {
        let handle = self
            .get(id_or_name)
            .await?
            .ok_or_else(|| anyhow!("No such container: {id_or_name}"))?;
        let (rid, status) = {
            let r = handle.record.lock().unwrap();
            let s = handle.state.lock().unwrap();
            (r.id.clone(), s.status)
        };
        if status == StateStatus::Running {
            if !force {
                return Err(anyhow!(
                    "cannot remove container: container is running: stop the container before removing"
                ));
            }
            let _ = self.stop(&rid, 0).await;
        }
        // Network cleanup: unpublish ports, drop veths, release IPs.
        {
            let endpoints = handle.record.lock().unwrap().endpoints.clone();
            let net = self.net.read().unwrap().clone();
            if let Some(net) = net {
                net.unpublish_all(&rid).await;
                for ep in endpoints {
                    net.detach(&ep.network_id, &ep.ip, &rid).await;
                }
            }
        }
        cleanup_container(&self.paths, &rid)?;
        self.live.write().unwrap().remove(&rid);
        self.events.publish(EventMessage::new(
            "container",
            "destroy",
            &rid,
            HashMap::new(),
        ));
        Ok(())
    }

    // ---------- exec ----------

    pub fn register_exec(&self, session: Arc<crate::exec::ExecSession>) {
        self.execs.write().unwrap().insert(session.id.clone(), session);
    }

    pub fn exec_session(&self, id: &str) -> Option<Arc<crate::exec::ExecSession>> {
        self.execs.read().unwrap().get(id).cloned()
    }
}

async fn restart_container(mgr: Arc<ContainerManager>, id: String) {
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let _ = mgr.start(&id).await;
}

// ---------- free helpers ----------

extern "C" fn child_trampoline_shim(arg: *mut libc::c_void) -> i32 {
    crate::child::clone_entry(arg)
}

fn cstring(s: &str) -> Result<std::ffi::CString> {
    Ok(std::ffi::CString::new(s)?)
}

fn parse_user_numeric(user: &str) -> (u32, u32, Vec<u32>) {
    if user.is_empty() {
        return (u32::MAX, u32::MAX, vec![]); // let child resolve (root)
    }
    let (u, g) = user.split_once(':').unwrap_or((user, ""));
    match (u.parse::<u32>(), g.parse::<u32>()) {
        (Ok(uid), Ok(gid)) => (uid, gid, vec![]),
        _ => (u32::MAX, u32::MAX, vec![]), // names: resolved in-child
    }
}

fn default_hosts(record: &ContainerRecord, ip: &str, _gw: &str) -> String {
    let mut hosts = String::from("127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n");
    hosts.push_str("fe00::0\tip6-localnet\nff00::0\tip6-mcastprefix\nff02::1\tip6-allnodes\nff02::2\tip6-allrouters\n");
    if !ip.is_empty() {
        for e in &record.endpoints {
            for alias in &e.aliases {
                hosts.push_str(&format!("{}\t{}\n", e.ip, alias));
            }
        }
        hosts.push_str(&format!("{}\t{}\n", ip, record.config.Hostname));
    } else {
        hosts.push_str(&format!("127.0.0.1\t{}\n", record.config.Hostname));
    }
    for extra in &record.hostconfig.ExtraHosts {
        if let Some((host, ipaddr)) = extra.split_once(':') {
            hosts.push_str(&format!("{}\t{}\n", ipaddr, host));
        }
    }
    hosts
}

fn default_resolv() -> String {
    // Copy host resolv.conf minus loopback nameservers (docker behavior).
    match std::fs::read_to_string("/etc/resolv.conf") {
        Ok(content) => {
            let mut out = String::new();
            for line in content.lines() {
                let is_local = line.trim_start().starts_with("nameserver")
                    && line
                        .split_whitespace()
                        .nth(1)
                        .map(|ns| ns.starts_with("127."))
                        .unwrap_or(false);
                if !is_local {
                    out.push_str(line);
                    out.push('\n');
                }
            }
            if out.is_empty() {
                "nameserver 8.8.8.8\n".to_string()
            } else {
                out
            }
        }
        Err(_) => "nameserver 8.8.8.8\n".to_string(),
    }
}

/// Bind-mount volumes/binds/tmpfs into the merged rootfs (daemon side, before
/// the child clones — the child inherits the mounts).
fn apply_mounts(paths: &DataPaths, record: &ContainerRecord) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let merged = paths.overlay_merged(&record.id);
    for m in &record.mounts {
        let dest = merged.join(m.destination.trim_start_matches('/'));
        let dest_str = dest.as_os_str().as_bytes().to_vec();
        match m.typ.as_str() {
            "tmpfs" => {
                std::fs::create_dir_all(&dest)?;
                mount_fs_raw("tmpfs", &dest_str, "mode=1777")?;
            }
            "volume" | "bind" => {
                let src = std::path::Path::new(&m.source);
                if m.typ == "bind" {
                    if src.is_file() {
                        if let Some(parent) = dest.parent() {
                            let _ = std::fs::create_dir_all(parent);
                        }
                        if !dest.exists() {
                            let _ = std::fs::File::create(&dest);
                        }
                    } else {
                        if !src.exists() {
                            std::fs::create_dir_all(src)?;
                        }
                        std::fs::create_dir_all(&dest)?;
                    }
                } else {
                    // volume
                    if !src.exists() {
                        std::fs::create_dir_all(src)?;
                    }
                    let is_empty = match std::fs::read_dir(src) {
                        Ok(entries) => entries.filter_map(|e| e.ok()).all(|e| e.file_name() == "metadata.json"),
                        Err(_) => true,
                    };
                    if is_empty && dest.is_dir() {
                        let _ = copy_tree(&dest, src);
                    }
                    std::fs::create_dir_all(&dest)?;
                }
                let src_c = std::ffi::CString::new(src.as_os_str().as_bytes().to_vec())?;
                let dst_c = std::ffi::CString::new(dest_str.clone())?;
                let flags: libc::c_ulong = libc::MS_BIND | if m.read_only { libc::MS_RDONLY } else { 0 };
                let rc = unsafe {
                    libc::mount(src_c.as_ptr(), dst_c.as_ptr(), std::ptr::null(), flags, std::ptr::null())
                };
                if rc != 0 {
                    return Err(anyhow!(
                        "mount {} → {} failed: {}",
                        m.source,
                        m.destination,
                        std::io::Error::last_os_error()
                    ));
                }
                if m.read_only {
                    // Bind-remount to apply RDONLY.
                    let flags2: libc::c_ulong = libc::MS_BIND | libc::MS_RDONLY | libc::MS_REMOUNT;
                    unsafe {
                        libc::mount(
                            std::ptr::null(),
                            dst_c.as_ptr(),
                            std::ptr::null(),
                            flags2,
                            std::ptr::null(),
                        );
                    }
                }
            }
            other => anyhow::bail!("unknown mount type {other}"),
        }
    }
    Ok(())
}

fn copy_tree(src: &std::path::Path, dst: &std::path::Path) -> Result<()> {
    for entry in walkdir::WalkDir::new(src) {
        let entry = entry?;
        let rel = entry.path().strip_prefix(src)?;
        if rel.as_os_str().is_empty() {
            continue;
        }
        let target = dst.join(rel);
        if entry.file_type().is_dir() {
            std::fs::create_dir_all(&target)?;
        } else if entry.file_type().is_symlink() {
            if let Ok(link) = std::fs::read_link(entry.path()) {
                let _ = std::os::unix::fs::symlink(link, &target);
            }
        } else {
            if let Some(parent) = target.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::copy(entry.path(), &target);
        }
    }
    Ok(())
}

fn mount_fs_raw(fstype: &str, target: &[u8], data: &str) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let fs = std::ffi::CString::new(fstype)?;
    let tgt = std::ffi::CString::new(target.to_vec())?;
    let d = std::ffi::CString::new(data)?;
    let null = std::ffi::CString::new("")?;
    let rc = unsafe {
        libc::mount(
            null.as_ptr(),
            tgt.as_ptr(),
            fs.as_ptr(),
            0,
            d.as_ptr() as *const libc::c_void,
        )
    };
    if rc != 0 {
        return Err(anyhow!("mount {fstype}: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

fn bind_mount(src: &str, dst: &str) -> Result<()> {
    let s = std::ffi::CString::new(src)?;
    let d = std::ffi::CString::new(dst)?;
    let rc = unsafe {
        libc::mount(s.as_ptr(), d.as_ptr(), std::ptr::null(), libc::MS_BIND, std::ptr::null())
    };
    if rc != 0 {
        return Err(anyhow!("bind mount {src}→{dst}: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

/// Convert a raw fd (e.g. pty master) into a tokio stream.
fn to_tokio_stream(fd: i32) -> Result<tokio::net::UnixStream> {
    let std_stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
    std_stream.set_nonblocking(true)?;
    let t = tokio::net::UnixStream::from_std(std_stream)?;
    Ok(t)
}

enum Pump {
    Blocking(std::fs::File),
    Async(tokio::net::UnixStream),
}

/// Real os pipe (O_CLOEXEC): returns (read_fd, write_fd).
fn os_pipe_pair() -> Result<(i32, i32)> {
    let mut fds = [0i32; 2];
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if rc != 0 {
        return Err(anyhow!("pipe2: {}", std::io::Error::last_os_error()));
    }
    Ok((fds[0], fds[1]))
}

struct PtyPair {
    master_fd: i32,
    slave_fd: i32,
}

fn openpty_pair() -> Result<PtyPair> {
    let mut master: std::mem::MaybeUninit<i32> = std::mem::MaybeUninit::new(-1);
    let mut slave: std::mem::MaybeUninit<i32> = std::mem::MaybeUninit::new(-1);
    let rc = unsafe { libc::openpty(master.as_mut_ptr(), slave.as_mut_ptr(), std::ptr::null_mut(), std::ptr::null(), std::ptr::null_mut()) };
    if rc != 0 {
        return Err(anyhow!("openpty: {}", std::io::Error::last_os_error()));
    }
    Ok(PtyPair { master_fd: unsafe { master.assume_init() }, slave_fd: unsafe { slave.assume_init() } })
}

fn write_ready(stream: &std::os::unix::net::UnixStream, b: u8) -> Result<()> {
    use std::io::Write;
    let mut s = stream;
    s.write_all(&[b]).context("signal child readiness")
}

fn reap_now(pid: i32) {
    unsafe {
        libc::kill(pid as i32, libc::SIGKILL);
        let mut status = 0;
        libc::waitpid(pid, &mut status, 0);
    }
}

fn short(pid: &i64) -> String {
    pid.to_string()
}

fn container_attrs(handle: &ContainerHandle) -> HashMap<String, String> {
    let r = handle.record.lock().unwrap();
    let mut attrs = HashMap::new();
    attrs.insert("name".to_string(), r.name.clone());
    attrs.insert("image".to_string(), r.image_name.clone());
    attrs
}

/// Remove all traces of a container on disk + its mounts.
pub fn cleanup_container(paths: &DataPaths, id: &str) -> Result<()> {
    let _ = overlay::unmount_rootfs(paths, id);
    // Remove leftover binds: merged lives under overlay dir; umount2 detach on
    // merged handles nested binds lazily.
    let _ = ingot_util::remove_path(&paths.container(id));
    ingot_util::remove_path(&paths.overlay_container(id))?;
    ingot_util::remove_path(&paths.netns_bind(id))?;
    Ok(())
}

async fn run_healthcheck_loop(
    handle: Arc<ContainerHandle>,
    paths: DataPaths,
    container_id: String,
    hc: ingot_api::HealthConfig,
) {
    let mut cmd = Vec::new();
    if !hc.Test.is_empty() {
        if hc.Test[0] == "CMD-SHELL" {
            cmd.push("/bin/sh".to_string());
            cmd.push("-c".to_string());
            cmd.push(hc.Test[1..].join(" "));
        } else if hc.Test[0] == "CMD" {
            cmd.extend(hc.Test[1..].to_vec());
        } else {
            cmd.extend(hc.Test.clone());
        }
    }
    if cmd.is_empty() {
        return;
    }

    let interval = match hc.Interval {
        Some(i) if i > 1_000_000 => std::time::Duration::from_nanos(i as u64),
        Some(i) if i > 0 => std::time::Duration::from_secs(i as u64),
        _ => std::time::Duration::from_secs(30),
    };
    let timeout = match hc.Timeout {
        Some(t) if t > 1_000_000 => std::time::Duration::from_nanos(t as u64),
        Some(t) if t > 0 => std::time::Duration::from_secs(t as u64),
        _ => std::time::Duration::from_secs(30),
    };
    let retries = hc.Retries.unwrap_or(3);
    let start_period = match hc.StartPeriod {
        Some(sp) if sp > 1_000_000 => std::time::Duration::from_nanos(sp as u64),
        Some(sp) if sp > 0 => std::time::Duration::from_secs(sp as u64),
        _ => std::time::Duration::from_secs(0),
    };

    let start_instant = std::time::Instant::now();

    loop {
        tokio::time::sleep(interval).await;

        if !handle.is_running() {
            break;
        }

        let start_time = ingot_util::now_rfc3339();
        let log_dir = paths.container(&container_id).join("logs");
        let _ = std::fs::create_dir_all(&log_dir);
        let log_file = log_dir.join(format!("health_{}.log", ingot_util::new_id()[..8].to_string()));

        let session = Arc::new(crate::exec::ExecSession::new(
            container_id.clone(),
            cmd.clone(),
            false,
            false,
            "root".into(),
            "/".into(),
            vec![],
            log_file.clone(),
        ));

        let mut exit_rx = session.subscribe_exit();

        let exec_res = crate::exec::start_exec(session.clone(), handle.clone(), paths.clone());
        let (exit_code, output) = match exec_res {
            Ok(()) => {
                match tokio::time::timeout(timeout, exit_rx.recv()).await {
                    Ok(Ok(code)) => {
                        let out = std::fs::read_to_string(&log_file).unwrap_or_default();
                        let _ = std::fs::remove_file(&log_file);
                        (code, out)
                    }
                    _ => {
                        let st = session.state.lock().unwrap();
                        if st.pid > 0 {
                            unsafe { libc::kill(st.pid as i32, libc::SIGKILL); }
                        }
                        let _ = std::fs::remove_file(&log_file);
                        (-1, "health check exceeded timeout".to_string())
                    }
                }
            }
            Err(e) => (-1, format!("failed to start health check: {e}")),
        };

        let end_time = ingot_util::now_rfc3339();
        let entry = ingot_api::HealthLogEntry {
            Start: start_time,
            End: end_time,
            ExitCode: exit_code,
            Output: output,
        };

        if !handle.is_running() {
            break;
        }

        {
            let mut st = handle.state.lock().unwrap();
            if let Some(h) = st.health.as_mut() {
                h.Log.push(entry);
                if h.Log.len() > 5 {
                    h.Log.remove(0);
                }
                if exit_code == 0 {
                    h.FailingStreak = 0;
                    h.Status = "healthy".into();
                } else {
                    h.FailingStreak += 1;
                    let in_start_period = start_instant.elapsed() < start_period;
                    if !in_start_period && h.FailingStreak >= retries {
                        h.Status = "unhealthy".into();
                    }
                }
            }
        }
        let _ = ingot_store::write_json_atomic(
            &paths.container_state(&container_id),
            &*handle.state.lock().unwrap(),
        );
    }
}


