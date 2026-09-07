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
use crate::stdio::{StdioHub, STREAM_STDERR, STREAM_STDOUT};
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
    /// Immutable container id (no lock needed; previously cloned under
    /// record lock on every id() call).
    pub id: String,
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
        self.id.clone()
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
    create_reservations: Arc<std::sync::Mutex<HashSet<String>>>,
    lifecycle_locks: std::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

struct ReservationGuard {
    reservations: Arc<std::sync::Mutex<HashSet<String>>>,
    name: String,
}

impl Drop for ReservationGuard {
    fn drop(&mut self) {
        let mut set = self.reservations.lock().unwrap();
        set.remove(&self.name);
    }
}

impl ContainerManager {
    pub fn new(
        paths: DataPaths,
        events: EventBus,
        images: Arc<ingot_image::ImageStore>,
    ) -> Result<Self> {
        Ok(ContainerManager {
            paths,
            events,
            images,
            net: RwLock::new(None),
            self_ref: RwLock::new(None),
            live: RwLock::new(HashMap::new()),
            execs: RwLock::new(HashMap::new()),
            create_reservations: Arc::new(std::sync::Mutex::new(HashSet::new())),
            lifecycle_locks: std::sync::Mutex::new(HashMap::new()),
        })
    }

    pub fn lifecycle_lock(&self, id: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut map = self.lifecycle_locks.lock().unwrap();
        map.entry(id.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    // ---------- create ----------

    pub async fn create(
        &self,
        image_name: &str,
        mut body: ContainerCreateBody,
        name: Option<String>,
        platform: Option<String>,
    ) -> Result<Arc<ContainerHandle>, crate::error::CreateError> {
        use crate::error::{validate_create, CreateError};
        validate_create(&body, name.as_deref(), platform.as_deref())?;
        let image_id = self
            .images
            .resolve(&body.Image)
            .await
            .map_err(|e| map_image_error(&body.Image, e))?;
        let image = self
            .images
            .load(&image_id)
            .await?
            .ok_or_else(|| CreateError::NotFound(format!("No such image: {}", body.Image)))?;

        // Merge image config + request (docker semantics).
        body.Image = format!("sha256:{}", image.id);
        let user_cmd = if body.Cmd.is_empty() {
            None
        } else {
            Some(std::mem::take(&mut body.Cmd))
        };
        let user_ep = body.Entrypoint.clone();
        let mut env = image.config.Env.clone();
        env.extend(std::mem::take(&mut body.Env));
        body.Env = env;
        // Image-exposed ports merge into the request (docker semantics):
        // `-P` publishes image EXPOSEs, not just `--expose`. Request keys
        // win on conflict (identical shapes in practice).
        if let Some(image_exposed) = image.config.ExposedPorts.clone() {
            let into = body.ExposedPorts.get_or_insert_with(Default::default);
            for (k, v) in image_exposed {
                into.entry(k).or_insert(v);
            }
        }
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
                let mut res = self.create_reservations.lock().unwrap();
                if res.contains(&n) || self.name_taken(&n) {
                    return Err(crate::error::CreateError::Conflict(n));
                }
                res.insert(n.clone());
                n
            }
            None => loop {
                let candidate = ingot_util::name::random_name();
                let mut res = self.create_reservations.lock().unwrap();
                if !res.contains(&candidate) && !self.name_taken(&candidate) {
                    res.insert(candidate.clone());
                    break candidate;
                }
            },
        };
        let _res_guard = ReservationGuard {
            reservations: self.create_reservations.clone(),
            name: name.clone(),
        };

        let hostname = if body.Hostname.is_empty() {
            id[..12].to_string()
        } else {
            body.Hostname.clone()
        };

        let mut config: ContainerConfig = body.clone().into_container_config();
        config.Hostname = hostname;
        config.Image = format!("sha256:{}", image.id);
        config.Entrypoint = user_ep;
        config.Cmd = user_cmd.unwrap_or_else(|| image.config.Cmd.clone());
        config.Env = body.Env.clone();
        // Image-inherited stop behavior (Docker semantics): an explicit
        // create-time value wins; otherwise the image's STOPSIGNAL and
        // HEALTHCHECK apply instead of silently falling back to defaults.
        inherit_image_config(&mut config, &image.config);

        let (mounts, anon_vols) = self
            .resolve_mounts(&body.HostConfig, &image, body.Volumes.as_ref(), &id)
            .await?;

        let cmd_display = {
            let ep = config.Entrypoint.clone().unwrap_or_default();
            let cmd = config.Cmd.clone();
            let argv = if ep.is_empty() {
                cmd
            } else {
                [ep, cmd].concat()
            };
            format!("\"{}\"", argv.join(" "))
        };

        // Seed create-time network endpoints (Plan Phase 6.3): aliases,
        // static IPs, and extra networks from NetworkingConfig ride the
        // record and are wired at first start (primary/NetworkMode first,
        // the rest sorted for determinism).
        let mut endpoints: Vec<crate::record::EndpointRecord> = Vec::new();
        if let Some(nc) = body.NetworkingConfig.as_ref() {
            if !nc.EndpointsConfig.is_empty() {
                let mode = body.HostConfig.NetworkMode.clone();
                let mut rest: Vec<(&String, &ingot_api::EndpointSettings)> = nc
                    .EndpointsConfig
                    .iter()
                    .filter(|(k, _)| *k != &mode)
                    .collect();
                rest.sort_by(|a, b| a.0.cmp(b.0));
                let mut ordered: Vec<(String, ingot_api::EndpointSettings)> = Vec::new();
                if let Some(primary) = nc.EndpointsConfig.get(&mode) {
                    ordered.push((mode.clone(), primary.clone()));
                } else if !mode.is_empty() && mode != "none" && mode != "host" {
                    ordered.push((mode.clone(), Default::default()));
                }
                for (k, v) in rest {
                    ordered.push((k.clone(), v.clone()));
                }
                for (i, (net, settings)) in ordered.into_iter().enumerate() {
                    let mut aliases = settings.Aliases.clone();
                    if i == 0 && aliases.is_empty() {
                        aliases.push(name.clone());
                    }
                    let requested_ip = settings
                        .IPAMConfig
                        .as_ref()
                        .map(|c| c.IPv4Address.clone())
                        .filter(|s| !s.is_empty());
                    endpoints.push(crate::record::EndpointRecord {
                        network_id: String::new(),
                        network_name: net,
                        ip: String::new(),
                        gateway: String::new(),
                        mac: String::new(),
                        aliases,
                        requested_ip,
                    });
                }
            }
        }

        let record = ContainerRecord {
            id: id.clone(),
            name: name.clone(),
            created: ingot_util::now_rfc3339(),
            image_id: format!("sha256:{}", image.id),
            image_name: image_name.to_string(),
            config,
            hostconfig: body.HostConfig.clone(),
            cmd_display,
            endpoints,
            wired_once: false,
            mounts,
        };

        // Persist.
        let dir = self.paths.container(&id);
        let persist_res: Result<()> = (|| {
            std::fs::create_dir_all(dir.join("logs"))?;
            ingot_store::write_json_atomic(&self.paths.container_config(&id), &record)?;
            ingot_store::write_json_atomic(
                &self.paths.container_hostconfig(&id),
                &record.hostconfig,
            )?;

            std::fs::write(
                self.paths.container_hostname(&id),
                format!("{}\n", record.config.Hostname),
            )?;
            std::fs::write(
                self.paths.container_hosts(&id),
                default_hosts(&record, "", ""),
            )?;
            std::fs::write(self.paths.container_resolv(&id), build_resolv(&record, &[]))?;
            Ok(())
        })();

        let state = ContainerState {
            status: StateStatus::Created,
            ..Default::default()
        };

        if persist_res.is_ok() {
            if let Err(e) = ingot_store::write_json_atomic(&self.paths.container_state(&id), &state)
            {
                for v in &anon_vols {
                    let _ = ingot_util::remove_path(&self.paths.volumes().join(v));
                }
                let _ = ingot_util::remove_path(&dir);
                return Err(crate::error::CreateError::Internal(e));
            }
        } else if let Err(e) = persist_res {
            for v in &anon_vols {
                let _ = ingot_util::remove_path(&self.paths.volumes().join(v));
            }
            let _ = ingot_util::remove_path(&dir);
            return Err(crate::error::CreateError::Internal(e));
        }

        let rotation = crate::stdio::rotation_from_config(&record.hostconfig.LogConfig.config);
        let (hub, stdin_rx) = StdioHub::with_rotation(self.paths.container_log(&id), rotation);
        let handle = Arc::new(ContainerHandle {
            id: id.clone(),
            record: Mutex::new(record),
            state: Mutex::new(state),
            stdio: Arc::new(hub),
            stdin_rx: Mutex::new(Some(stdin_rx)),
            manual_stop: AtomicBool::new(false),
            exit_tx: broadcast::channel(16).0,
        });
        self.live
            .write()
            .unwrap()
            .insert(id.clone(), handle.clone());

        self.events.publish(EventMessage::new(
            "container",
            "create",
            &id,
            container_attrs(&handle),
        ));
        Ok(handle)
    }

    fn name_taken(&self, name: &str) -> bool {
        self.list_records_sync().iter().any(|r| r.name == name)
    }

    async fn resolve_mounts(
        &self,
        hostconfig: &HostConfig,
        image: &ingot_image::ImageRecord,
        body_volumes: Option<&HashMap<String, serde_json::Value>>,
        _container_id: &str,
    ) -> Result<(Vec<crate::record::MountRecord>, Vec<String>)> {
        let mut out = Vec::new();
        let mut anon_vols = Vec::new();
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
                        is_anonymous: false,
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
                        is_anonymous: false,
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
                anon_vols.push(n.clone());
                out.push(crate::record::MountRecord {
                    typ: "volume".into(),
                    name: n,
                    source: dir.to_string_lossy().to_string(),
                    destination: dest.to_string(),
                    read_only: ro,
                    is_anonymous: true,
                });
            }
        }
        for m in &hostconfig.Mounts {
            let typ = if m.typ.is_empty() {
                "volume".to_string()
            } else {
                m.typ.clone()
            };
            if typ == "volume" {
                let is_anon = m.Source.is_empty();
                let name = if is_anon {
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
                if is_anon {
                    anon_vols.push(name.clone());
                }
                out.push(crate::record::MountRecord {
                    typ: "volume".into(),
                    name,
                    source: dir.to_string_lossy().to_string(),
                    destination: m.Target.clone(),
                    read_only: m.read_only,
                    is_anonymous: is_anon,
                });
            } else {
                out.push(crate::record::MountRecord {
                    typ,
                    name: String::new(),
                    source: m.Source.clone(),
                    destination: m.Target.clone(),
                    read_only: m.read_only,
                    is_anonymous: false,
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
                    anon_vols.push(n.clone());
                    out.push(crate::record::MountRecord {
                        typ: "volume".into(),
                        name: n,
                        source: dir.to_string_lossy().to_string(),
                        destination: dest.clone(),
                        read_only: false,
                        is_anonymous: true,
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
                    anon_vols.push(n.clone());
                    out.push(crate::record::MountRecord {
                        typ: "volume".into(),
                        name: n,
                        source: dir.to_string_lossy().to_string(),
                        destination: dest.clone(),
                        read_only: false,
                        is_anonymous: true,
                    });
                }
            }
        }
        Ok((out, anon_vols))
    }

    // ---------- start ----------

    pub fn start<'a>(
        &'a self,
        id_or_name: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Arc<ContainerHandle>>> + Send + 'a>,
    > {
        Box::pin(async move {
            let handle = self
                .get(id_or_name)
                .await?
                .ok_or_else(|| anyhow!("No such container: {id_or_name}"))?;
            let record = handle.record.lock().unwrap().clone();
            let lock = self.lifecycle_lock(&record.id);
            let _lifecycle = lock.lock().await;
            {
                let st = handle.state.lock().unwrap();
                if st.status == StateStatus::Running {
                    return Err(anyhow!("container is already started"));
                }
            }

            let image_id = record.image_id.trim_start_matches("sha256:").to_string();
            let image = self
                .images
                .load(&image_id)
                .await?
                .ok_or_else(|| anyhow!("No such image: {image_id}"))?;

            overlay::mount_rootfs(&self.paths, &record.id, &image.diff_ids)
                .with_context(|| format!("prepare rootfs for {id_or_name}"))?;
            apply_mounts(&self.paths, &record)
                .with_context(|| format!("apply mounts for {id_or_name}"))?;

            let (ready_tx, ready_rx) = std::os::unix::net::UnixStream::pair()?;
            // Exec-notification pipe: the child writes one byte just before
            // execve so start() can wait for the process image (Phase 2).
            let (exec_rd, exec_wr) = crate::stdio::os_pipe_pair()?;

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
                let (in_r, in_w) = crate::stdio::os_pipe_pair()?;
                let (out_r, out_w) = crate::stdio::os_pipe_pair()?;
                let (err_r, err_w) = crate::stdio::os_pipe_pair()?;
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
            // Resource controls validated at create; re-parse defensively
            // (records predate validation or were written by hand).
            let ulimits = crate::error::parse_ulimits(&record.hostconfig)
                .map_err(|e| anyhow!("invalid ulimits: {e}"))?;
            let (uid, gid, extra_gids) = parse_user_numeric(&record.config.User);

            let mut env: Vec<String> = record.config.Env.clone();
            if !env.iter().any(|e| e.starts_with("PATH=")) {
                env.push(
                    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into(),
                );
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
                exec_pipe_wr: exec_wr,
                shm_size: record.hostconfig.ShmSize,
                tmpfs: record
                    .hostconfig
                    .Tmpfs
                    .iter()
                    .map(|(k, v)| Ok((cstring(k)?, cstring(v)?)))
                    .collect::<Result<Vec<_>>>()?,
                sysctls: record
                    .hostconfig
                    .Sysctls
                    .iter()
                    .map(|(k, v)| Ok((cstring(k)?, cstring(v)?)))
                    .collect::<Result<Vec<_>>>()?,
                ulimits: ulimits
                    .iter()
                    .map(|(n, s, h)| Ok((cstring(n)?, *s, *h)))
                    .collect::<Result<Vec<_>>>()?,
                stdin_fd: child_in_fd,
                stdout_fd: child_out_fd,
                stderr_fd: child_err_fd,
                merged: cstring(self.paths.overlay_merged(&record.id).to_str().unwrap())?,
                hostname: cstring(&record.config.Hostname)?,
                resolv: cstring(self.paths.container_resolv(&record.id).to_str().unwrap())?,
                hosts: cstring(self.paths.container_hosts(&record.id).to_str().unwrap())?,
                hostname_file: cstring(
                    self.paths.container_hostname(&record.id).to_str().unwrap(),
                )?,
                argv: argv
                    .iter()
                    .map(|a| cstring(a))
                    .collect::<Result<Vec<_>>>()?,
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
                seccomp: !record.hostconfig.Privileged
                    && !record
                        .hostconfig
                        .SecurityOpt
                        .iter()
                        .any(|s| s == "seccomp=unconfined" || s == "seccomp:unconfined"),
                readonly_rootfs: record.hostconfig.ReadonlyRootfs,
                bring_lo_up: network_mode == "none" || self.net.read().unwrap().is_none(),
                has_netns: !matches!(network_mode.as_str(), "host" | ""),
                tty,
            };

            // ---- clone ----
            // NEWCGROUP hides the host cgroup layout from /proc/self/cgroup
            // and /sys/fs/cgroup (docker parity: private cgroupns).
            let clone_flags: i32 = libc::SIGCHLD
                | libc::CLONE_NEWNS
                | libc::CLONE_NEWPID
                | libc::CLONE_NEWUTS
                | libc::CLONE_NEWIPC
                | libc::CLONE_NEWCGROUP
                | if network_mode == "host" {
                    0
                } else {
                    libc::CLONE_NEWNET
                };

            let pid = {
                let ctx_ptr = ctx.into_raw() as *mut libc::c_void;
                let p = crate::child::clone_with_stack(child_trampoline_shim, clone_flags, ctx_ptr);
                if p < 0 {
                    unsafe { ChildContext::from_raw(ctx_ptr as *mut ChildContext) };
                }
                p
            };
            if pid < 0 {
                return Err(anyhow!("clone failed: {}", std::io::Error::last_os_error()));
            }
            drop(ready_rx);
            // Close our copy of the exec-pipe write end: EOF then reliably
            // means the child is gone, and only the child's byte counts.
            unsafe { libc::close(exec_wr) };
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
            let cgroup = match Cgroup::create(&record.id) {
                Ok(cg) => {
                    let hc = &record.hostconfig;
                    let limits = crate::cgroup::CgroupLimits {
                        memory_bytes: hc.Memory,
                        memory_swap_bytes: hc.MemorySwap,
                        nano_cpus: hc.NanoCpus,
                        cpu_quota: hc.CpuQuota,
                        cpu_period: hc.CpuPeriod,
                        cpu_shares: hc.CpuShares,
                        pids_limit: hc.PidsLimit,
                        cpuset_cpus: hc.CpusetCpus.clone(),
                    };
                    if let Err(e) = cg.apply(&limits) {
                        let _ = write_ready(&ready_tx, b'e');
                        reap_now(pid);
                        cg.remove();
                        let _ = overlay::unmount_rootfs(&self.paths, &record.id);
                        return Err(anyhow!("failed to apply cgroup limits: {e:#}"));
                    }
                    if let Err(e) = cg.add_pid(pid as i64) {
                        let _ = write_ready(&ready_tx, b'e');
                        reap_now(pid);
                        cg.remove();
                        let _ = overlay::unmount_rootfs(&self.paths, &record.id);
                        return Err(anyhow!("failed to place pid in cgroup: {e:#}"));
                    }
                    cg
                }
                Err(e) => {
                    let _ = write_ready(&ready_tx, b'e');
                    reap_now(pid);
                    let _ = overlay::unmount_rootfs(&self.paths, &record.id);
                    return Err(anyhow!("failed to create cgroup: {e:#}"));
                }
            };

            // ---- netns bind + network attach ----
            let netns_path = self.paths.netns_bind(&record.id);
            if let Some(parent) = netns_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let _ = std::fs::remove_file(&netns_path);
            let netns_src = format!("/proc/{pid}/ns/net");
            if std::path::Path::new(&netns_src).exists() {
                std::fs::File::create(&netns_path)?;
                if let Err(e) = bind_mount(&netns_src, netns_path.to_str().unwrap()) {
                    let _ = write_ready(&ready_tx, b'e');
                    reap_now(pid);
                    let _ = std::fs::remove_file(&netns_path);
                    cgroup.remove();
                    let _ = overlay::unmount_rootfs(&self.paths, &record.id);
                    return Err(anyhow!("failed to bind netns: {e:#}"));
                }
            }
            let mntns_path = self.paths.container_mntns(&record.id);
            if let Some(parent) = mntns_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::remove_file(&mntns_path);
            let mntns_src = format!("/proc/{pid}/ns/mnt");
            if std::path::Path::new(&mntns_src).exists() {
                std::fs::File::create(&mntns_path)?;
                if let Err(e) = bind_mount(&mntns_src, mntns_path.to_str().unwrap()) {
                    let _ = write_ready(&ready_tx, b'e');
                    reap_now(pid);
                    let _ = unbind_mount(netns_path.to_str().unwrap());
                    let _ = std::fs::remove_file(&netns_path);
                    let _ = std::fs::remove_file(&mntns_path);
                    cgroup.remove();
                    let _ = overlay::unmount_rootfs(&self.paths, &record.id);
                    return Err(anyhow!("failed to bind mntns: {e:#}"));
                }
            }

            let mut ip = String::new();
            let mut gw = String::new();
            let net_manager = self.net.read().unwrap().clone();
            let net_manager = match net_manager {
                Some(nm) if network_mode != "none" && network_mode != "host" => Some(nm),
                _ => None,
            };
            if let Some(net_manager) = net_manager {
                // Seed the default entry for a never-started container
                // with no create-time endpoints.
                if !record.wired_once && handle.record.lock().unwrap().endpoints.is_empty() {
                    handle
                        .record
                        .lock()
                        .unwrap()
                        .endpoints
                        .push(crate::record::EndpointRecord {
                            network_id: String::new(),
                            network_name: if network_mode == "default" {
                                "bridge".to_string()
                            } else {
                                network_mode.clone()
                            },
                            ip: String::new(),
                            gateway: String::new(),
                            mac: String::new(),
                            aliases: vec![record.name.clone()],
                            requested_ip: None,
                        });
                }
                // Resolve every entry to its canonical (id, name): seeded
                // entries carry names, wired ones carry ids. Fail closed
                // before wiring anything — a deleted network aborts start
                // with no half-built dataplane to roll back. (Locks are
                // never held across the resolves.)
                let keys: Vec<(usize, String)> = handle
                    .record
                    .lock()
                    .unwrap()
                    .endpoints
                    .iter()
                    .enumerate()
                    .map(|(i, ep)| {
                        (
                            i,
                            if ep.network_id.is_empty() {
                                ep.network_name.clone()
                            } else {
                                ep.network_id.clone()
                            },
                        )
                    })
                    .collect();
                let mut resolve_failed: Option<String> = None;
                let mut resolved: Vec<(usize, String, String)> = Vec::new();
                for (i, key) in &keys {
                    match net_manager.resolve(key).await {
                        Ok(n) => resolved.push((*i, n.id.clone(), n.name.clone())),
                        Err(e) => {
                            resolve_failed = Some(format!("{e:#}"));
                            break;
                        }
                    }
                }
                if let Some(msg) = resolve_failed {
                    let _ = write_ready(&ready_tx, b'e');
                    reap_now(pid);
                    let _ = unbind_mount(mntns_path.to_str().unwrap());
                    let _ = std::fs::remove_file(&mntns_path);
                    let _ = unbind_mount(netns_path.to_str().unwrap());
                    let _ = std::fs::remove_file(&netns_path);
                    cgroup.remove();
                    let _ = overlay::unmount_rootfs(&self.paths, &record.id);
                    return Err(anyhow!(
                        "network attach failed: {msg}; container init aborted"
                    ));
                }
                {
                    let mut rec = handle.record.lock().unwrap();
                    for (i, nid, nname) in resolved {
                        if let Some(ep) = rec.endpoints.get_mut(i) {
                            ep.network_id = nid;
                            ep.network_name = nname;
                        }
                    }
                }
                // Heal duplicate endpoints on one network (same network
                // twice can never be wired — both veths would share a
                // name): keep the first, detach the rest so their leases
                // are released and the record is the truth again.
                // Duplicates are never live — no start since scoped naming
                // could wire two.
                let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
                let mut pruned: Vec<(String, String, Vec<String>)> = Vec::new();
                {
                    let mut rec = handle.record.lock().unwrap();
                    rec.endpoints.retain(|ep| {
                        if seen.insert(ep.network_id.clone()) {
                            true
                        } else {
                            pruned.push((ep.network_id.clone(), ep.ip.clone(), ep.aliases.clone()));
                            false
                        }
                    });
                }
                if !pruned.is_empty() {
                    for (nid, pip, paliases) in &pruned {
                        // A pruned twin of a kept (network, ip) still needs
                        // its lease: drop the record, keep the lease. A
                        // pruned entry that never wired holds no lease.
                        let kept = handle
                            .record
                            .lock()
                            .unwrap()
                            .endpoints
                            .iter()
                            .any(|ep| &ep.network_id == nid && &ep.ip == pip);
                        if kept || pip.is_empty() {
                            continue;
                        }
                        let mut keys = vec![record.name.clone(), record.config.Hostname.clone()];
                        keys.extend(paliases.clone());
                        net_manager.detach(nid, pip, &record.id, &keys).await;
                    }
                    let _ = ingot_store::write_json_batched(
                        &self.paths.container_config(&record.id),
                        &*handle.record.lock().unwrap(),
                    );
                    tracing::warn!(
                        "start: pruned {} duplicate endpoint(s) on {}",
                        pruned.len(),
                        &record.name,
                    );
                }
                // Wire each surviving entry in record order: empty ip
                // means attach (allocate, or reserve the create-time
                // request), set ip means rewire the held lease.
                let plans: Vec<usize> =
                    (0..handle.record.lock().unwrap().endpoints.len()).collect();
                // Networks wired by this start (for unwire rollback).
                let mut wired_nets: Vec<String> = Vec::new();
                for (if_index, pos) in plans.into_iter().enumerate() {
                    let Some((network, wired_ip, requested, aliases)) =
                        handle.record.lock().unwrap().endpoints.get(pos).map(|ep| {
                            (
                                ep.network_id.clone(),
                                ep.ip.clone(),
                                ep.requested_ip.clone(),
                                ep.aliases.clone(),
                            )
                        })
                    else {
                        continue;
                    };
                    // Empty ip wires fresh (allocating, or reserving the
                    // create-time request); a set ip re-wires the held
                    // lease.
                    let fresh = wired_ip.is_empty();
                    let want_ip = if fresh { requested } else { Some(wired_ip) };
                    let req = ingot_network::AttachRequest {
                        container_id: record.id.clone(),
                        container_name: record.name.clone(),
                        hostname: record.config.Hostname.clone(),
                        network: network.clone(),
                        pid: pid as i64,
                        netns_path: netns_path.to_string_lossy().to_string(),
                        aliases,
                        dns_search: record.hostconfig.DnsSearch.clone(),
                        requested_ip: want_ip.clone(),
                        if_index,
                    };
                    let res = match want_ip {
                        Some(want) if !fresh => match want.parse::<std::net::Ipv4Addr>() {
                            Ok(ipv4) => net_manager.rewire(&network, &req, ipv4).await,
                            Err(_) => {
                                Err(anyhow!("recorded endpoint address {want:?} is not IPv4"))
                            }
                        },
                        _ => net_manager.attach(&req).await,
                    };
                    match res {
                        Ok(ep) => {
                            // Primary endpoint (eth0) feeds the hosts file and
                            // port publishing below.
                            if if_index == 0 {
                                ip = ep.ip.clone();
                                gw = ep.gateway.clone();
                            }
                            wired_nets.push(ep.network_id.clone());
                            // Fill the entry in place so a failed later
                            // wire (or a crash) retries from the truth:
                            // filled entries hold leases, empty ones don't.
                            {
                                let mut rec = handle.record.lock().unwrap();
                                if let Some(entry) = rec.endpoints.get_mut(pos) {
                                    entry.network_id = ep.network_id.clone();
                                    entry.network_name = ep.network_name.clone();
                                    entry.ip = ep.ip.clone();
                                    entry.gateway = ep.gateway.clone();
                                    entry.mac.clone_from(&ep.mac);
                                }
                            }
                            let _ = ingot_store::write_json_batched(
                                &self.paths.container_config(&record.id),
                                &*handle.record.lock().unwrap(),
                            );
                            // Publish declared ports (docker -p/-P) on the
                            // primary endpoint only. A conflict aborts the
                            // start (naming the occupier); this start's
                            // wires and rules roll back with it.
                            if if_index == 0 {
                                let net = self.net.read().unwrap().clone();
                                if let Some(net) = net {
                                    if let Err(e) =
                                        self.publish_declared_ports(&net, &record, &ep.ip).await
                                    {
                                        for nid in &wired_nets {
                                            net_manager.unwire(nid, &record.id).await;
                                        }
                                        net.unpublish_all(&record.id).await;
                                        let _ = write_ready(&ready_tx, b'e');
                                        reap_now(pid);
                                        let _ = unbind_mount(mntns_path.to_str().unwrap());
                                        let _ = std::fs::remove_file(&mntns_path);
                                        let _ = unbind_mount(netns_path.to_str().unwrap());
                                        let _ = std::fs::remove_file(&netns_path);
                                        cgroup.remove();
                                        let _ = overlay::unmount_rootfs(&self.paths, &record.id);
                                        return Err(anyhow!(
                                            "port publish failed: {e:#}; container init aborted"
                                        ));
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            // Undo this start's wires without releasing their
                            // leases (still recorded): a retried start re-wires
                            // instead of colliding with stranded veths.
                            for nid in &wired_nets {
                                net_manager.unwire(nid, &record.id).await;
                            }
                            let _ = write_ready(&ready_tx, b'e');
                            reap_now(pid);
                            let _ = unbind_mount(mntns_path.to_str().unwrap());
                            let _ = std::fs::remove_file(&mntns_path);
                            let _ = unbind_mount(netns_path.to_str().unwrap());
                            let _ = std::fs::remove_file(&netns_path);
                            cgroup.remove();
                            let _ = overlay::unmount_rootfs(&self.paths, &record.id);
                            return Err(anyhow!(
                                "network attach failed: {e:#}; container init aborted"
                            ));
                        }
                    }
                }
            }
            // Networking is now decided (wired, rewired, deliberately
            // skipped for none/host, or left offline after an explicit
            // disconnect-to-zero): later starts must not fall back to the
            // default network and undo that decision.
            if !record.wired_once {
                handle.record.lock().unwrap().wired_once = true;
                let _ = ingot_store::write_json_atomic(
                    &self.paths.container_config(&record.id),
                    &*handle.record.lock().unwrap(),
                );
            }
            // Otherwise: none/host (or no net manager yet) — the child brings lo
            // up itself via `bring_lo_up`.

            // hosts file now includes the allocated IP; resolv.conf points at
            // the embedded DNS on the gateway for user-defined networks.
            std::fs::write(
                self.paths.container_hosts(&record.id),
                default_hosts(&record, &ip, &gw),
            )?;
            // Refresh resolv.conf from the wired endpoints: explicit --dns
            // wins, else the attached user-network gateways (embedded
            // DNS), else the host file. Always rewritten so a start after
            // a disconnect-to-zero leaves no stale gateway behind.
            {
                let rec = handle.record.lock().unwrap();
                let mut gateways: Vec<String> = Vec::new();
                for ep in &rec.endpoints {
                    if ep.network_name != "bridge"
                        && !ep.gateway.is_empty()
                        && !gateways.contains(&ep.gateway)
                    {
                        gateways.push(ep.gateway.clone());
                    }
                }
                let resolv = build_resolv(&rec, &gateways);
                std::fs::write(self.paths.container_resolv(&rec.id), resolv)?;
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

            // ---- wait for exec ----
            // The child writes one byte just before execve (it only gets
            // there after the 'g' above). Waiting here closes the start/top
            // race where `top` briefly shows the daemon's cmdline. EOF means
            // the child died pre-exec (the reaper records the real exit); a
            // timeout never fails the start, it just proceeds.
            {
                let ack = tokio::task::spawn_blocking(move || {
                    use std::io::Read;
                    let mut f = unsafe { std::fs::File::from_raw_fd(exec_rd) };
                    let mut b = [0u8; 1];
                    f.read_exact(&mut b).map(|_| b[0]).map_err(|e| e.kind())
                });
                match tokio::time::timeout(std::time::Duration::from_secs(10), ack).await {
                    Ok(Ok(Ok(b'x'))) => {}
                    Ok(Ok(Ok(_))) => {}
                    Ok(Ok(Err(_))) => {
                        tracing::debug!("start: child exited before exec");
                    }
                    _ => {
                        tracing::warn!("start: timed out waiting for exec ack");
                    }
                }
            }

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
                    let probe_events = self.events.clone();
                    tokio::spawn(async move {
                        run_healthcheck_loop(
                            probe_handle,
                            probe_paths,
                            probe_id,
                            hc_clone,
                            probe_events,
                        )
                        .await;
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
            let netmgr = self.net.read().unwrap().clone();
            tokio::task::spawn_blocking(move || {
                // OOM baseline (unit 2.5): a SIGKILL exit only counts as an
                // OOM kill if the cgroup counter moved while we ran.
                let oom_base = cg.oom_kills();
                let mut status = 0;
                let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
                let signaled = rc == pid && libc::WIFSIGNALED(status);
                let signo = if signaled { libc::WTERMSIG(status) } else { 0 };
                let exit_code: i64 = if rc == pid {
                    if libc::WIFEXITED(status) {
                        libc::WEXITSTATUS(status) as i64
                    } else if signaled {
                        (128 + signo) as i64
                    } else {
                        1
                    }
                } else {
                    -1
                };
                let oom_killed = signo == libc::SIGKILL && cg.oom_kills() > oom_base;
                let mut should_restart = false;
                {
                    let mut st = mgr_handle.state.lock().unwrap();
                    st.status = StateStatus::Exited;
                    st.exit_code = exit_code;
                    st.finished_at = ingot_util::now_rfc3339();
                    st.pid = 0;
                    st.oom_killed = oom_killed;
                    st.error = if oom_killed {
                        "container killed: out of memory (cgroup oom_kill)".to_string()
                    } else {
                        String::new()
                    };

                    // Healthy runs (≥10s) reset the backoff chain, matching
                    // docker behavior; crash loops keep counting up.
                    let healthy = run_duration_secs(&st.started_at, &st.finished_at) >= 10;
                    let bump = |st: &mut ContainerState| {
                        st.restart_count = if healthy { 1 } else { st.restart_count + 1 };
                    };
                    let manual_stop = mgr_handle.manual_stop.load(Ordering::SeqCst);
                    // Note: an `unhealthy` health status never triggers a
                    // restart by itself (docker semantics) — supervision
                    // reacts to exits only. Health-gated startup ordering
                    // lives in compose (Plan Phase 9).
                    if !manual_stop && !autoremove {
                        match restart_policy.Name.as_str() {
                            "always" => {
                                bump(&mut st);
                                should_restart = true;
                            }
                            "unless-stopped" => {
                                bump(&mut st);
                                should_restart = true;
                            }
                            "on-failure"
                                if exit_code != 0
                                    && (restart_policy.MaximumRetryCount <= 0
                                        || st.restart_count < restart_policy.MaximumRetryCount) =>
                            {
                                bump(&mut st);
                                should_restart = true;
                            }
                            _ => {}
                        }
                    }
                }
                let _ = ingot_store::write_json_atomic(
                    &paths.container_state(&live_id),
                    &*mgr_handle.state.lock().unwrap(),
                );
                cg.remove();
                let _ = overlay::unmount_rootfs(&paths, &live_id);
                tracing::debug!(container = %live_id, exit = exit_code, "reaper: publishing die");
                // Docker parity: the die event carries the exit code.
                let mut die_attrs = container_attrs(&mgr_handle);
                die_attrs.insert("exitCode".to_string(), exit_code.to_string());
                events.publish(EventMessage::new("container", "die", &live_id, die_attrs));
                let _ = mgr_handle.exit_tx.send(exit_code);
                tracing::debug!(container = %live_id, "reaper: done");
                if autoremove {
                    // Full teardown, mirroring remove(): unpublish ports,
                    // release IP leases, drop the record, forget the live
                    // handle, publish destroy. Filesystem-only cleanup
                    // here used to strand a lease + port rules + the live
                    // entry on every --rm run.
                    let (name, hostname, endpoints, mounts) = {
                        let rec = mgr_handle.record.lock().unwrap();
                        (
                            rec.name.clone(),
                            rec.config.Hostname.clone(),
                            rec.endpoints.clone(),
                            rec.mounts.clone(),
                        )
                    };
                    let netmgr = netmgr.clone();
                    let weak = self_ref.clone();
                    tokio::spawn(async move {
                        if let Some(net) = netmgr {
                            net.unpublish_all(&live_id).await;
                            for ep in &endpoints {
                                let mut keys = vec![name.clone(), hostname.clone()];
                                keys.extend(ep.aliases.clone());
                                net.detach(&ep.network_id, &ep.ip, &live_id, &keys).await;
                            }
                        }
                        for m in &mounts {
                            if m.is_anonymous && m.typ == "volume" && !m.name.is_empty() {
                                let dir = paths.volumes().join(&m.name);
                                let _ = ingot_util::remove_path(&dir);
                            }
                        }
                        let _ = cleanup_container(&paths, &live_id);
                        if let Some(weak) = weak {
                            if let Some(mgr) = weak.upgrade() {
                                mgr.live.write().unwrap().remove(&live_id);
                            }
                        }
                        events.publish(EventMessage::new(
                            "container",
                            "destroy",
                            &live_id,
                            HashMap::new(),
                        ));
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

    /// Stop with escalation. `timeout` precedence (Plan Phase 2, unit 2.2):
    /// per-request value → container StopTimeout → 10s daemon default.
    /// `signal` overrides the container's StopSignal for this stop only.
    pub async fn stop(
        &self,
        id_or_name: &str,
        timeout: Option<i64>,
        signal: Option<i32>,
    ) -> Result<i64> {
        let handle = self
            .get(id_or_name)
            .await?
            .ok_or_else(|| anyhow!("No such container: {id_or_name}"))?;
        let rid = handle.id();
        let lock = self.lifecycle_lock(&rid);
        let _lifecycle = lock.lock().await;
        self.stop_handle(&handle, timeout, signal).await
    }

    async fn stop_handle(
        &self,
        handle: &ContainerHandle,
        timeout: Option<i64>,
        signal: Option<i32>,
    ) -> Result<i64> {
        handle.manual_stop.store(true, Ordering::SeqCst);
        let (pid, signal, timeout) = {
            let state = handle.state.lock().unwrap();
            if state.status != StateStatus::Running {
                return Ok(state.exit_code);
            }
            let rec = handle.record.lock().unwrap();
            let timeout = timeout.or(rec.config.StopTimeout).unwrap_or(10).max(0) as u64;
            let signal = signal.unwrap_or_else(|| rec.stop_signal() as i32);
            (state.pid as i32, signal, timeout)
        };
        let id = handle.id();
        tracing::debug!(container = %id, timeout, "stop: entered");
        // Subscribe BEFORE signalling: the process may exit immediately.
        let mut rx = handle.subscribe_exit();
        tracing::debug!(pid, "stop: sending signal");
        let _ = send_signal(pid, signal);
        match tokio::time::timeout(std::time::Duration::from_secs(timeout), rx.recv()).await {
            Ok(Ok(code)) => {
                tracing::debug!("stop: graceful exit {code}");
                return Ok(code);
            }
            Ok(Err(e)) => tracing::debug!("stop: recv error {e}"),
            Err(_) => tracing::debug!("stop: grace period expired"),
        }
        let _ = send_signal(pid, libc::SIGKILL);
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
        let rid = handle.id();
        let lock = self.lifecycle_lock(&rid);
        let _lifecycle = lock.lock().await;
        handle.manual_stop.store(true, Ordering::SeqCst);
        let pid = {
            let st = handle.state.lock().unwrap();
            if st.status != StateStatus::Running {
                return Err(anyhow!("container is not running"));
            }
            st.pid as i32
        };
        send_signal(pid, signal)
    }

    pub async fn pause(&self, id_or_name: &str, on: bool) -> Result<()> {
        let handle = self
            .get(id_or_name)
            .await?
            .ok_or_else(|| anyhow!("No such container: {id_or_name}"))?;
        let rid = handle.id();
        let lock = self.lifecycle_lock(&rid);
        let _lifecycle = lock.lock().await;
        {
            // Strict state machine (Plan Phase 2, unit 2.6): pause only a
            // running container, unpause only a paused one.
            let st = handle.state.lock().unwrap();
            if on && st.status != StateStatus::Running {
                if st.status == StateStatus::Paused {
                    return Err(anyhow!("container is already paused"));
                }
                return Err(anyhow!("container is not running"));
            }
            if !on && st.status != StateStatus::Paused {
                return Err(anyhow!("container is not paused"));
            }
        }
        let cg = Cgroup::create(&rid)?;
        cg.freeze(on)?;
        {
            let mut st = handle.state.lock().unwrap();
            st.status = if on {
                StateStatus::Paused
            } else {
                StateStatus::Running
            };
        }
        self.persist_state(&handle).await;
        self.events.publish(EventMessage::new(
            "container",
            if on { "pause" } else { "unpause" },
            &rid,
            container_attrs(&handle),
        ));
        Ok(())
    }

    pub async fn restart(&self, id_or_name: &str, timeout: Option<i64>) -> Result<()> {
        let handle = self
            .get(id_or_name)
            .await?
            .ok_or_else(|| anyhow!("No such container: {id_or_name}"))?;
        let rid = handle.id();
        let lock = self.lifecycle_lock(&rid);
        let _lifecycle = lock.lock().await;
        if handle.is_running() {
            {
                let mut st = handle.state.lock().unwrap();
                st.status = StateStatus::Restarting;
            }
            self.persist_state(&handle).await;
            self.events.publish(EventMessage::new(
                "container",
                "restart",
                &rid,
                container_attrs(&handle),
            ));
            let (pid, signal, timeout_secs) = {
                let rec = handle.record.lock().unwrap();
                let t = timeout.or(rec.config.StopTimeout).unwrap_or(10).max(0) as u64;
                let s = rec.stop_signal() as i32;
                let st = handle.state.lock().unwrap();
                (st.pid as i32, s, t)
            };
            handle.manual_stop.store(true, Ordering::SeqCst);
            let mut rx = handle.subscribe_exit();
            let _ = send_signal(pid, signal);
            let stopped = matches!(
                tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), rx.recv()).await,
                Ok(Ok(_))
            );
            if !stopped {
                let _ = send_signal(pid, libc::SIGKILL);
                let _ = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv()).await;
            }
        }
        drop(_lifecycle);
        drop(lock);
        self.start(&rid).await?;
        Ok(())
    }

    // ---------- lookups ----------

    pub async fn get(&self, name_or_id: &str) -> Result<Option<Arc<ContainerHandle>>> {
        {
            let live = self.live.read().unwrap();
            if let Some(h) = live.get(name_or_id) {
                return Ok(Some(h.clone()));
            }
            // Name exact-match in live set before disk fallback (avoids
            // directory scan for running containers looked up by name).
            for h in live.values() {
                if let Ok(rec) = h.record.try_lock() {
                    if rec.name == name_or_id || format!("/{}", rec.name) == name_or_id {
                        return Ok(Some(h.clone()));
                    }
                }
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
                let state =
                    ingot_store::read_json::<ContainerState>(&self.paths.container_state(&r.id))
                        .unwrap_or_default();
                let rotation = crate::stdio::rotation_from_config(&r.hostconfig.LogConfig.config);
                let (hub, stdin_rx) =
                    StdioHub::with_rotation(self.paths.container_log(&r.id), rotation);
                let handle = Arc::new(ContainerHandle {
                    id: r.id.clone(),
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

    pub fn list_records_sync(&self) -> Vec<ContainerRecord> {
        let mut out = Vec::new();
        let Ok(rd) = std::fs::read_dir(self.paths.containers()) else {
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

    pub async fn list_records(&self) -> Vec<ContainerRecord> {
        self.list_records_sync()
    }

    pub async fn persist_state(&self, handle: &ContainerHandle) {
        let id = handle.id();
        let st = handle.state.lock().unwrap().clone();
        let _ = ingot_store::write_json_batched(&self.paths.container_state(&id), &st);
    }

    pub async fn remove(&self, id_or_name: &str, force: bool, remove_volumes: bool) -> Result<()> {
        let handle = self
            .get(id_or_name)
            .await?
            .ok_or_else(|| anyhow!("No such container: {id_or_name}"))?;
        let rid = handle.id();
        let lock = self.lifecycle_lock(&rid);
        let _lifecycle = lock.lock().await;
        let status = {
            let s = handle.state.lock().unwrap();
            s.status
        };
        if status == StateStatus::Running {
            if !force {
                return Err(anyhow!(
                    "cannot remove container: container is running: stop the container before removing"
                ));
            }
            let _ = self.stop_handle(&handle, Some(0), None).await;
        }
        // Network cleanup: unpublish ports, drop veths, release IPs,
        // deregister endpoint DNS names.
        {
            let (name, hostname, endpoints) = {
                let rec = handle.record.lock().unwrap();
                (
                    rec.name.clone(),
                    rec.config.Hostname.clone(),
                    rec.endpoints.clone(),
                )
            };
            let net = self.net.read().unwrap().clone();
            if let Some(net) = net {
                net.unpublish_all(&rid).await;
                for ep in endpoints {
                    let mut keys = vec![name.clone(), hostname.clone()];
                    keys.extend(ep.aliases.clone());
                    net.detach(&ep.network_id, &ep.ip, &rid, &keys).await;
                }
            }
        }
        if remove_volumes {
            let mounts = handle.record.lock().unwrap().mounts.clone();
            for m in &mounts {
                if m.is_anonymous && m.typ == "volume" && !m.name.is_empty() {
                    let dir = self.paths.volumes().join(&m.name);
                    let _ = ingot_util::remove_path(&dir);
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

    /// Publish a starting container's ports onto the primary endpoint:
    /// explicit `-p` bindings plus `-P` (PublishAllPorts) expansion over
    /// exposed ports (request and image exposes are merged at create).
    /// A conflict aborts with the occupying container named; the caller
    /// rolls back wires and rules.
    async fn publish_declared_ports(
        &self,
        net: &Arc<ingot_network::NetworkManager>,
        record: &ContainerRecord,
        container_ip: &str,
    ) -> Result<()> {
        // (container port, proto, host ip, host port), deterministic order.
        let mut specs: Vec<(u16, String, String, u16)> = Vec::new();
        let mut covered: HashSet<(u16, String)> = HashSet::new();
        let mut keys: Vec<&String> = record.hostconfig.PortBindings.keys().collect();
        keys.sort();
        for k in keys {
            let Some((cport, proto)) = split_port_key(k) else {
                continue; // validated at create; never fail a start here
            };
            for b in &record.hostconfig.PortBindings[k] {
                let host_port = match b.HostPort.parse::<u16>() {
                    Ok(p) if p != 0 => p,
                    _ => net.allocate_ephemeral_port(proto).await,
                };
                covered.insert((cport, proto.to_string()));
                specs.push((cport, proto.to_string(), b.HostIp.clone(), host_port));
            }
        }
        if record.hostconfig.PublishAllPorts {
            let mut exposed: Vec<&String> = record
                .config
                .ExposedPorts
                .as_ref()
                .map(|m| m.keys().collect())
                .unwrap_or_default();
            exposed.sort();
            for k in exposed {
                let Some((cport, proto)) = split_port_key(k) else {
                    continue; // image-provided oddity; never fail a start
                };
                if covered.contains(&(cport, proto.to_string())) {
                    continue;
                }
                let host_port = net.allocate_ephemeral_port(proto).await;
                specs.push((cport, proto.to_string(), String::new(), host_port));
            }
        }
        for (cport, proto, host_ip, host_port) in specs {
            let rule = ingot_network::PortRule {
                container_id: record.id.clone(),
                host_ip,
                host_port,
                container_ip: container_ip.to_string(),
                container_port: cport,
                proto,
            };
            if let Err(e) = net.publish_port(rule).await {
                if let Some(cf) = e.downcast_ref::<ingot_network::PortConflict>() {
                    if let Some(id) = &cf.occupier {
                        let name = match self.get(id).await {
                            Ok(Some(h)) => h.record.lock().unwrap().name.clone(),
                            _ => id[..12.min(id.len())].to_string(),
                        };
                        let ip = if cf.host_ip.is_empty() {
                            "0.0.0.0"
                        } else {
                            cf.host_ip.as_str()
                        };
                        anyhow::bail!(
                            "port {}:{}/{} is already allocated by container {name}",
                            ip,
                            cf.host_port,
                            cf.proto
                        );
                    }
                }
                return Err(e);
            }
        }
        Ok(())
    }

    // ---------- exec ----------

    pub fn register_exec(&self, session: Arc<crate::exec::ExecSession>) {
        self.execs
            .write()
            .unwrap()
            .insert(session.id.clone(), session);
    }

    pub fn exec_session(&self, id: &str) -> Option<Arc<crate::exec::ExecSession>> {
        self.execs.read().unwrap().get(id).cloned()
    }
}

/// Backoff for supervised restarts (Plan Phase 2, unit 2.3): 1s doubling
/// per consecutive failure, capped at 60s, so crash loops cannot hammer
/// the daemon.
pub fn restart_delay_secs(consecutive_failures: i64) -> u64 {
    let shift = consecutive_failures.clamp(1, 7) as u32 - 1;
    (1u64 << shift).min(60)
}

fn run_duration_secs(started_at: &str, finished_at: &str) -> i64 {
    let parse = |s: &str| {
        chrono::DateTime::parse_from_rfc3339(s)
            .map(|d| d.timestamp())
            .unwrap_or(0)
    };
    (parse(finished_at) - parse(started_at)).max(0)
}

async fn restart_container(mgr: Arc<ContainerManager>, id: String) {
    let delay = {
        let Some(h) = mgr.get(&id).await.unwrap_or(None) else {
            return;
        };
        let mut st = h.state.lock().unwrap();
        // A stop/remove issued while the reaper was deciding disarms the
        // restart (manual_stop is set first in stop()).
        if h.manual_stop.load(Ordering::SeqCst) {
            return;
        }
        st.status = StateStatus::Restarting;
        let delay = restart_delay_secs(st.restart_count);
        let _ = ingot_store::write_json_atomic(&mgr.paths.container_state(&id), &*st);
        delay
    };
    tracing::debug!(container = %id, delay, "supervisor: backing off");
    tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
    if let Some(h) = mgr.get(&id).await.unwrap_or(None) {
        if h.manual_stop.load(Ordering::SeqCst) {
            return;
        }
    }
    let _ = mgr.start(&id).await;
}

// ---------- free helpers ----------

extern "C" fn child_trampoline_shim(arg: *mut libc::c_void) -> i32 {
    crate::child::clone_entry(arg)
}

fn cstring(s: &str) -> Result<std::ffi::CString> {
    Ok(std::ffi::CString::new(s)?)
}

/// Numeric `--user` fast path: `uid:gid` or `uid:gid,gid2,...` with all
/// parts numeric. Anything else (bare ids, names) falls through to
/// in-container `/etc/passwd`+`/etc/group` resolution.
fn parse_user_numeric(user: &str) -> (u32, u32, Vec<u32>) {
    const MISS: (u32, u32, Vec<u32>) = (u32::MAX, u32::MAX, vec![]);
    if user.is_empty() {
        return MISS; // let child resolve (root)
    }
    let Some((u, groups)) = user.split_once(':') else {
        return MISS; // bare uid or name: resolved in-child
    };
    let Ok(uid) = u.parse::<u32>() else {
        return MISS;
    };
    let mut parts = groups.split(',');
    let Some(gid) = parts.next().and_then(|g| g.parse::<u32>().ok()) else {
        return MISS;
    };
    let mut extra = Vec::new();
    for g in parts {
        match g.parse::<u32>() {
            Ok(x) => extra.push(x),
            Err(_) => return MISS,
        }
    }
    (uid, gid, extra)
}

/// Split a `"port[/proto]"` key with the docker default proto. None when
/// malformed — start never fails on records that predate validation.
fn split_port_key(k: &str) -> Option<(u16, &str)> {
    let (port_str, proto) = match k.split_once('/') {
        Some((p, t)) => (p, t),
        None => (k, "tcp"),
    };
    if proto != "tcp" && proto != "udp" {
        return None;
    }
    port_str
        .parse::<u16>()
        .ok()
        .filter(|p| *p != 0)
        .map(|p| (p, proto))
}

fn default_hosts(record: &ContainerRecord, ip: &str, _gw: &str) -> String {
    let mut hosts =
        String::from("127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n");
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

/// Build a container resolv.conf (Plan Phase 6.5): explicit `--dns`
/// servers win everywhere (even on the default bridge, docker parity);
/// otherwise the attached user-network gateways (embedded DNS); otherwise
/// the host file minus loopback entries. Search domains and resolver
/// options (validated at create) always render when set, after any host
/// lines so ours take precedence.
fn build_resolv(record: &ContainerRecord, user_gateways: &[String]) -> String {
    let mut out = String::new();
    if !record.hostconfig.Dns.is_empty() {
        for d in &record.hostconfig.Dns {
            out.push_str("nameserver ");
            out.push_str(d);
            out.push('\n');
        }
    } else if !user_gateways.is_empty() {
        for gw in user_gateways {
            out.push_str("nameserver ");
            out.push_str(gw);
            out.push('\n');
        }
    } else {
        out.push_str(&default_resolv());
    }
    if !record.hostconfig.DnsSearch.is_empty() {
        out.push_str("search ");
        out.push_str(&record.hostconfig.DnsSearch.join(" "));
        out.push('\n');
    }
    if !record.hostconfig.DnsOptions.is_empty() {
        out.push_str("options ");
        out.push_str(&record.hostconfig.DnsOptions.join(" "));
        out.push('\n');
    }
    out
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
                        .map(|ns| ns.starts_with("127.") || ns == "::1")
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
        match m.typ.as_str() {
            "tmpfs" => {
                let dest_res = ingot_util::ensure_dir_in_root(
                    &merged,
                    std::path::Path::new(&m.destination),
                    0o755,
                )?;
                let dest_str = dest_res.proc_path().as_os_str().as_bytes().to_vec();
                mount_fs_raw("tmpfs", &dest_str, "mode=1777")?;
            }
            "volume" | "bind" => {
                let src = std::path::Path::new(&m.source);
                let dest_res = if m.typ == "bind" {
                    if src.is_file() {
                        ingot_util::ensure_file_in_root(
                            &merged,
                            std::path::Path::new(&m.destination),
                            0o644,
                        )?
                    } else {
                        if !src.exists() {
                            std::fs::create_dir_all(src)?;
                        }
                        ingot_util::ensure_dir_in_root(
                            &merged,
                            std::path::Path::new(&m.destination),
                            0o755,
                        )?
                    }
                } else {
                    // volume
                    if !src.exists() {
                        std::fs::create_dir_all(src)?;
                    }
                    let res = ingot_util::ensure_dir_in_root(
                        &merged,
                        std::path::Path::new(&m.destination),
                        0o755,
                    )?;
                    let is_empty = match std::fs::read_dir(src) {
                        Ok(entries) => entries
                            .filter_map(|e| e.ok())
                            .all(|e| e.file_name() == "metadata.json"),
                        Err(_) => true,
                    };
                    if is_empty && res.is_dir() {
                        let _ = copy_tree(res.proc_path(), src);
                    }
                    res
                };
                let src_c = std::ffi::CString::new(src.as_os_str().as_bytes().to_vec())?;
                let dst_c =
                    std::ffi::CString::new(dest_res.proc_path().as_os_str().as_bytes().to_vec())?;
                let flags: libc::c_ulong =
                    libc::MS_BIND | if m.read_only { libc::MS_RDONLY } else { 0 };
                let rc = unsafe {
                    libc::mount(
                        src_c.as_ptr(),
                        dst_c.as_ptr(),
                        std::ptr::null(),
                        flags,
                        std::ptr::null(),
                    )
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
                    let rc2 = unsafe {
                        libc::mount(
                            std::ptr::null(),
                            dst_c.as_ptr(),
                            std::ptr::null(),
                            flags2,
                            std::ptr::null(),
                        )
                    };
                    if rc2 != 0 {
                        return Err(anyhow!(
                            "remount ro {} failed: {}",
                            m.destination,
                            std::io::Error::last_os_error()
                        ));
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
        return Err(anyhow!(
            "mount {fstype}: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn bind_mount(src: &str, dst: &str) -> Result<()> {
    let s = std::ffi::CString::new(src)?;
    let d = std::ffi::CString::new(dst)?;
    let rc = unsafe {
        libc::mount(
            s.as_ptr(),
            d.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        return Err(anyhow!(
            "bind mount {src}→{dst}: {}",
            std::io::Error::last_os_error()
        ));
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

struct PtyPair {
    master_fd: i32,
    slave_fd: i32,
}

fn openpty_pair() -> Result<PtyPair> {
    let mut master: std::mem::MaybeUninit<i32> = std::mem::MaybeUninit::new(-1);
    let mut slave: std::mem::MaybeUninit<i32> = std::mem::MaybeUninit::new(-1);
    let rc = unsafe {
        libc::openpty(
            master.as_mut_ptr(),
            slave.as_mut_ptr(),
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null_mut(),
        )
    };
    if rc != 0 {
        return Err(anyhow!("openpty: {}", std::io::Error::last_os_error()));
    }
    Ok(PtyPair {
        master_fd: unsafe { master.assume_init() },
        slave_fd: unsafe { slave.assume_init() },
    })
}

fn write_ready(stream: &std::os::unix::net::UnixStream, b: u8) -> Result<()> {
    use std::io::Write;
    let mut s = stream;
    s.write_all(&[b]).context("signal child readiness")
}

fn reap_now(pid: i32) {
    unsafe {
        libc::kill(pid, libc::SIGKILL);
        let mut status = 0;
        libc::waitpid(pid, &mut status, 0);
    }
}

/// Image lookup failures are 404s when the image simply does not exist;
/// anything else (store corruption, IO) stays a 500.
fn map_image_error(image: &str, e: anyhow::Error) -> crate::error::CreateError {
    let msg = format!("{e:#}");
    if msg.contains("No such image") {
        crate::error::CreateError::NotFound(format!("No such image: {image}"))
    } else {
        crate::error::CreateError::Internal(e)
    }
}

fn container_attrs(handle: &ContainerHandle) -> HashMap<String, String> {
    let r = handle.record.lock().unwrap();
    let mut attrs = HashMap::new();
    attrs.insert("name".to_string(), r.name.clone());
    attrs.insert("image".to_string(), r.image_name.clone());
    attrs
}

/// Remove all traces of a container on disk + its mounts.
/// Idempotency contract (Plan Phase 2, unit 2.7): safe to call any number
/// of times, on live, dead, or already-removed containers; missing paths
/// are skipped, busy mounts are detached lazily.
pub fn cleanup_container(paths: &DataPaths, id: &str) -> Result<()> {
    cleanup_runtime_state(paths, id)?;
    // Remove leftover binds: merged lives under overlay dir; umount2 detach on
    // merged handles nested binds lazily.
    let _ = ingot_util::remove_path(&paths.container(id));
    Ok(())
}

/// Release runtime-only state (mounts, overlay workdirs, netns binds) while
/// keeping the container record (config + state) on disk. Used at boot
/// reconcile so crashed-while-running containers survive as Exited —
/// docker keeps them across daemon restarts instead of vanishing them.
pub fn cleanup_runtime_state(paths: &DataPaths, id: &str) -> Result<()> {
    let _ = overlay::unmount_rootfs(paths, id);
    ingot_util::remove_path(&paths.overlay_container(id))?;
    let _ = unbind_mount(&paths.container_mntns(id).to_string_lossy());
    let _ = ingot_util::remove_path(&paths.container_mntns(id));
    let _ = unbind_mount(&paths.netns_bind(id).to_string_lossy());
    ingot_util::remove_path(&paths.netns_bind(id))?;
    Ok(())
}

async fn run_healthcheck_loop(
    handle: Arc<ContainerHandle>,
    paths: DataPaths,
    container_id: String,
    hc: ingot_api::HealthConfig,
    events: EventBus,
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

    // Docker API durations are nanoseconds, always (Plan Phase 2, unit 2.4):
    // a missing/zero value means the documented default, never "seconds".
    let nanos_or = |v: Option<i64>, default: std::time::Duration| match v {
        Some(n) if n > 0 => std::time::Duration::from_nanos(n as u64),
        _ => default,
    };
    let interval = nanos_or(hc.Interval, std::time::Duration::from_secs(30));
    let timeout = nanos_or(hc.Timeout, std::time::Duration::from_secs(30));
    let retries = hc.Retries.unwrap_or(3).max(1);
    let start_period = nanos_or(hc.StartPeriod, std::time::Duration::from_secs(0));
    let start_interval = nanos_or(hc.StartInterval, interval);

    let start_instant = std::time::Instant::now();

    loop {
        // Faster probing while the container is still starting.
        let in_start_period = start_instant.elapsed() < start_period;
        let tick = if in_start_period {
            start_interval
        } else {
            interval
        };
        tokio::time::sleep(tick).await;

        if !handle.is_running() {
            break;
        }

        let start_time = ingot_util::now_rfc3339();
        let log_dir = paths.container(&container_id).join("logs");
        let _ = std::fs::create_dir_all(&log_dir);
        let log_file = log_dir.join(format!("health_{}.log", &ingot_util::new_id()[..8]));

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
            Ok(()) => match tokio::time::timeout(timeout, exit_rx.recv()).await {
                Ok(Ok(code)) => {
                    let out = std::fs::read_to_string(&log_file).unwrap_or_default();
                    let _ = std::fs::remove_file(&log_file);
                    (code, out)
                }
                _ => {
                    let st = session.state.lock().unwrap();
                    if st.pid > 0 {
                        unsafe {
                            libc::kill(st.pid as i32, libc::SIGKILL);
                        }
                    }
                    let _ = std::fs::remove_file(&log_file);
                    (-1, "health check exceeded timeout".to_string())
                }
            },
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

        // Docker parity: health transitions emit `health_status` events.
        let transition = {
            let mut st = handle.state.lock().unwrap();
            let mut transition = None;
            if let Some(h) = st.health.as_mut() {
                h.Log.push(entry);
                if h.Log.len() > 5 {
                    h.Log.remove(0);
                }
                if exit_code == 0 {
                    h.FailingStreak = 0;
                    if h.Status != "healthy" {
                        h.Status = "healthy".into();
                        transition = Some("healthy");
                    }
                } else {
                    h.FailingStreak += 1;
                    let in_start_period = start_instant.elapsed() < start_period;
                    if !in_start_period && h.FailingStreak >= retries && h.Status != "unhealthy" {
                        h.Status = "unhealthy".into();
                        transition = Some("unhealthy");
                    }
                }
            }
            transition
        };
        if let Some(status) = transition {
            let mut attrs = container_attrs(&handle);
            attrs.insert("healthStatus".to_string(), status.to_string());
            events.publish(EventMessage::new(
                "container",
                "health_status",
                &container_id,
                attrs,
            ));
        }
        let _ = ingot_store::write_json_atomic(
            &paths.container_state(&container_id),
            &*handle.state.lock().unwrap(),
        );
    }
}

/// Fill create-time gaps from the image: an explicitly set StopSignal or
/// Healthcheck wins, otherwise the image's STOPSIGNAL/HEALTHCHECK applies.
fn inherit_image_config(config: &mut ContainerConfig, image: &ContainerConfig) {
    if config.StopSignal.is_empty() {
        config.StopSignal = image.StopSignal.clone();
    }
    if config.Healthcheck.is_none() {
        config.Healthcheck = image.Healthcheck.clone();
    }
}

fn send_signal(pid: i32, sig: i32) -> Result<()> {
    if pid <= 0 {
        return Ok(());
    }
    // Try pidfd first to avoid race conditions with recycled PIDs
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) as i32 };
    if pidfd >= 0 {
        let ret = unsafe {
            let r = libc::syscall(
                libc::SYS_pidfd_send_signal,
                pidfd,
                sig,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            );
            libc::close(pidfd);
            r
        };
        if ret == 0 {
            return Ok(());
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ESRCH) {
            return Ok(());
        }
        return Err(anyhow!("pidfd_send_signal({pid}, {sig}): {err}"));
    }

    // Fallback to kill(pid, sig)
    let ret = unsafe { libc::kill(pid, sig) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ESRCH) {
            return Ok(());
        }
        return Err(anyhow!("kill({pid}, {sig}): {err}"));
    }
    Ok(())
}

fn unbind_mount(path: &str) -> Result<()> {
    let p = std::path::Path::new(path);
    if p.exists() {
        let _ = nix::mount::umount2(p, nix::mount::MntFlags::MNT_DETACH);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_config_inheritance_prefers_explicit() {
        let image = ContainerConfig {
            StopSignal: "SIGINT".to_string(),
            ..Default::default()
        };
        let mut config = ContainerConfig::default();
        inherit_image_config(&mut config, &image);
        assert_eq!(config.StopSignal, "SIGINT");
        assert!(config.Healthcheck.is_none());
        // Explicit values survive.
        let mut config = ContainerConfig {
            StopSignal: "SIGQUIT".to_string(),
            ..Default::default()
        };
        inherit_image_config(&mut config, &image);
        assert_eq!(config.StopSignal, "SIGQUIT");
    }

    #[test]
    fn restart_backoff_doubles_and_caps() {
        assert_eq!(restart_delay_secs(0), 1);
        assert_eq!(restart_delay_secs(1), 1);
        assert_eq!(restart_delay_secs(2), 2);
        assert_eq!(restart_delay_secs(3), 4);
        assert_eq!(restart_delay_secs(6), 32);
        assert_eq!(restart_delay_secs(7), 60);
        assert_eq!(restart_delay_secs(100), 60);
        assert_eq!(restart_delay_secs(-5), 1);
    }

    #[test]
    fn resolv_explicit_dns_wins_over_gateways() {
        let mut rec = ContainerRecord::default();
        rec.hostconfig.Dns = vec!["8.8.8.8".into()];
        let out = build_resolv(&rec, &["10.89.0.1".into()]);
        assert!(out.contains("nameserver 8.8.8.8\n"));
        assert!(!out.contains("10.89.0.1"));
    }

    #[test]
    fn resolv_gateways_then_search_and_options() {
        let mut rec = ContainerRecord::default();
        rec.hostconfig.DnsSearch = vec!["svc".into(), "local".into()];
        rec.hostconfig.DnsOptions = vec!["ndots:2".into()];
        let out = build_resolv(&rec, &["10.89.0.1".into(), "10.90.0.1".into()]);
        let names: Vec<&str> = out
            .lines()
            .filter(|l| l.starts_with("nameserver"))
            .collect();
        assert_eq!(names, vec!["nameserver 10.89.0.1", "nameserver 10.90.0.1"]);
        assert!(out.contains("search svc local\n"));
        assert!(out.contains("options ndots:2\n"));
    }

    #[test]
    fn resolv_no_gateways_falls_back_to_host_file() {
        let rec = ContainerRecord::default();
        assert_eq!(build_resolv(&rec, &[]), default_resolv());
    }

    #[test]
    fn numeric_user_multi_gid_splits() {
        assert_eq!(parse_user_numeric("1000:100,200"), (1000, 100, vec![200]));
        assert_eq!(parse_user_numeric("0:0"), (0, 0, vec![]));
    }

    #[test]
    fn numeric_user_non_numeric_misses_to_child() {
        let miss = (u32::MAX, u32::MAX, vec![]);
        assert_eq!(parse_user_numeric(""), miss);
        assert_eq!(parse_user_numeric("1000"), miss);
        assert_eq!(parse_user_numeric("nobody:nogroup"), miss);
        assert_eq!(parse_user_numeric("1000:abc"), miss);
        assert_eq!(parse_user_numeric("1000:100,abc"), miss);
    }

    #[test]
    fn run_duration_parses_rfc3339() {
        assert_eq!(
            run_duration_secs("2026-01-01T00:00:00Z", "2026-01-01T00:00:42Z"),
            42
        );
        assert_eq!(run_duration_secs("garbage", "also-garbage"), 0);
        assert_eq!(
            run_duration_secs("2026-01-01T00:01:00Z", "2026-01-01T00:00:00Z"),
            0
        );
    }
}
