//! cgroup v2 management — plain cgroupfs writes, no delegation required
//! (the daemon runs as root).

use anyhow::{anyhow, Result};
use std::path::{Path, PathBuf};

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const SLICE: &str = "ingot.slice";

pub struct Cgroup {
    dir: PathBuf,
}

/// Validated resource limits for one container (see
/// `validate_hostconfig`: negatives are rejected at create, so every
/// field here is either 0/empty (unset) or a meaningful value).
#[derive(Debug, Clone, Default)]
pub struct CgroupLimits {
    pub memory_bytes: i64,
    pub memory_swap_bytes: i64,
    pub nano_cpus: i64,
    pub cpu_quota: i64,
    pub cpu_period: i64,
    pub cpu_shares: i64,
    pub pids_limit: i64,
    pub cpuset_cpus: String,
}

impl Cgroup {
    /// Create `/sys/fs/cgroup/ingot.slice/<id>` and enable the controllers we
    /// use on the root and slice levels. Failing to enable a controller is
    /// non-fatal (kernel may not expose it); failing to mkdir is fatal.
    ///
    /// Controller enablement is boot-once: the first call programs
    /// `cgroup.subtree_control` on root+slice, later calls only mkdir the
    /// leaf. Use [`Cgroup::ensure_controllers`] at daemon boot to warm it.
    pub fn create(id: &str) -> Result<Cgroup> {
        let root = Path::new(CGROUP_ROOT);
        ensure_controllers_cached(root);
        let slice = root.join(SLICE);
        std::fs::create_dir_all(&slice)?;
        ensure_controllers_cached(&slice);
        let dir = slice.join(id);
        std::fs::create_dir_all(&dir)?;
        Ok(Cgroup { dir })
    }

    /// Boot-time warmup: enable controllers once so per-start `create`
    /// never pays the `cgroup.controllers` read + `subtree_control` write.
    pub fn ensure_controllers() {
        let root = Path::new(CGROUP_ROOT);
        let _ = enable_controllers(root);
        let slice = root.join(SLICE);
        if std::fs::create_dir_all(&slice).is_ok() {
            let _ = enable_controllers(&slice);
            mark_controllers_cached(root);
            mark_controllers_cached(&slice);
        }
    }

    pub fn apply(&self, lim: &CgroupLimits) -> Result<()> {
        if lim.memory_bytes > 0 {
            write(&self.dir, "memory.max", &lim.memory_bytes.to_string())?;
            write(
                &self.dir,
                "memory.swap.max",
                &swap_max_value(lim.memory_bytes, lim.memory_swap_bytes),
            )?;
        } else if lim.memory_swap_bytes > 0 {
            // Swap cap without a memory cap: still enforced.
            write(
                &self.dir,
                "memory.swap.max",
                &lim.memory_swap_bytes.to_string(),
            )?;
        }
        if let Some(val) = cpu_max_value(lim.nano_cpus, lim.cpu_quota, lim.cpu_period) {
            write(&self.dir, "cpu.max", &val)?;
        } else if lim.cpu_shares > 0 {
            let weight = shares_to_weight(lim.cpu_shares);
            write(&self.dir, "cpu.weight", &weight.to_string())?;
        }
        if lim.pids_limit > 0 {
            write(&self.dir, "pids.max", &lim.pids_limit.to_string())?;
        }
        if !lim.cpuset_cpus.is_empty() {
            write(&self.dir, "cpuset.cpus", &lim.cpuset_cpus)?;
        }
        Ok(())
    }

    pub fn add_pid(&self, pid: i64) -> Result<()> {
        write(&self.dir, "cgroup.procs", &pid.to_string())
    }

    /// cgroup v2 freezer: "1" freezes, "0" thaws.
    pub fn freeze(&self, on: bool) -> Result<()> {
        write(&self.dir, "cgroup.freeze", if on { "1" } else { "0" })
    }

    pub fn kill_all(&self) -> Result<()> {
        write(&self.dir, "cgroup.kill", "1")
    }

    pub fn current_pids(&self) -> Vec<i64> {
        std::fs::read_to_string(self.dir.join("cgroup.procs"))
            .map(|s| s.lines().filter_map(|l| l.parse().ok()).collect())
            .unwrap_or_default()
    }

    pub fn remove(&self) {
        // Tolerate failure (processes may still be draining).
        let _ = std::fs::remove_dir(&self.dir);
    }

    pub fn memory_usage(&self) -> u64 {
        parse_first_u64(&self.dir.join("memory.current"))
    }

    pub fn memory_max(&self) -> u64 {
        parse_first_u64(&self.dir.join("memory.max"))
    }

    pub fn cpu_stat(&self) -> (u64, u64) {
        // (usage_usec, nr_periods..) — we return usage_usec only for stats v1
        let data = std::fs::read_to_string(self.dir.join("cpu.stat")).unwrap_or_default();
        let mut usage = 0u64;
        for line in data.lines() {
            if let Some(v) = line.strip_prefix("usage_usec ") {
                usage = v.trim().parse().unwrap_or(0);
            }
        }
        (usage, 0)
    }

    pub fn pids_current(&self) -> u64 {
        parse_first_u64(&self.dir.join("pids.current"))
    }

    /// Cumulative OOM kills for this cgroup (Plan Phase 2, unit 2.5).
    /// Read at container start as a baseline and again at exit: a SIGKILL
    /// exit with an incremented counter is a real OOM kill, while a manual
    /// `kill -9` or stop-escalation leaves the counter flat.
    pub fn oom_kills(&self) -> u64 {
        std::fs::read_to_string(self.dir.join("memory.events"))
            .ok()
            .and_then(|s| parse_oom_kills(&s))
            .unwrap_or(0)
    }

    pub fn exists(&self) -> bool {
        self.dir.exists()
    }
}

fn parse_first_u64(p: &Path) -> u64 {
    std::fs::read_to_string(p)
        .ok()
        .and_then(|s| s.lines().next().and_then(|l| l.trim().parse().ok()))
        .unwrap_or(0)
}

fn parse_oom_kills(events: &str) -> Option<u64> {
    events.lines().find_map(|l| {
        l.strip_prefix("oom_kill ")
            .and_then(|v| v.trim().parse().ok())
    })
}

fn enable_controllers(dir: &Path) -> Result<()> {
    let available = std::fs::read_to_string(dir.join("cgroup.controllers"))
        .map_err(|e| anyhow!("read cgroup.controllers: {e}"))?;
    let mut want = String::with_capacity(32);
    for c in ["cpu", "memory", "pids", "cpuset", "io"] {
        if available.split_whitespace().any(|x| x == c) {
            want.push_str(&format!("+{c} "));
        }
    }
    if !want.is_empty() {
        let _ = write(dir, "cgroup.subtree_control", want.trim());
    }
    Ok(())
}

static CONTROLLERS_DONE: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> =
    std::sync::OnceLock::new();

fn controllers_done() -> &'static std::sync::Mutex<std::collections::HashSet<String>> {
    CONTROLLERS_DONE.get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()))
}

fn ensure_controllers_cached(dir: &Path) {
    let key = dir.to_string_lossy().to_string();
    {
        let guard = controllers_done().lock().unwrap();
        if guard.contains(&key) {
            return;
        }
    }
    if enable_controllers(dir).is_ok() {
        controllers_done().lock().unwrap().insert(key);
    }
}

fn mark_controllers_cached(dir: &Path) {
    controllers_done()
        .lock()
        .unwrap()
        .insert(dir.to_string_lossy().to_string());
}

fn write(dir: &Path, file: &str, val: &str) -> Result<()> {
    std::fs::write(dir.join(file), val).map_err(|e| anyhow!("write {file}={val}: {e}"))
}

/// `cpu.max` value from the docker inputs. `NanoCpus` (from `--cpus`)
/// wins when set; otherwise an explicit `--cpu-quota`/`--cpu-period`
/// pair is honored; otherwise `None` (no `cpu.max` write, so a
/// `CpuShares` weight can apply instead).
fn cpu_max_value(nano_cpus: i64, cpu_quota: i64, cpu_period: i64) -> Option<String> {
    if nano_cpus > 0 {
        // nano_cpus → "max $quota $period" (period 100ms)
        let quota = nano_cpus / 100_000; // per 100ms
        let val = if quota >= 100_000_000 {
            "max 100000".to_string()
        } else {
            format!("{quota} 100000")
        };
        return Some(val);
    }
    if cpu_quota > 0 {
        let period = if cpu_period > 0 { cpu_period } else { 100_000 };
        return Some(format!("{cpu_quota} {period}"));
    }
    None
}

/// `memory.swap.max` value: -1 (unlimited) → "max"; positive →
/// the cap; 0/negative → the memory limit (daemon default).
fn swap_max_value(memory_bytes: i64, memory_swap_bytes: i64) -> String {
    if memory_swap_bytes == -1 {
        "max".to_string()
    } else if memory_swap_bytes > 0 {
        memory_swap_bytes.to_string()
    } else {
        memory_bytes.to_string()
    }
}

/// docker --cpu-shares 1024..262144 → cgroup v2 weight 1..10000.
fn shares_to_weight(shares: i64) -> i64 {
    if shares <= 0 {
        return 100;
    }
    // Approximate the docker/libcontainer conversion.
    let clamped = shares.clamp(2, 262144);
    1 + ((clamped - 2) * 9999) / 262142
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shares_conversion() {
        assert_eq!(shares_to_weight(0), 100);
        assert!(shares_to_weight(1024) > 1 && shares_to_weight(1024) < 300);
        assert!(shares_to_weight(262144) <= 10000);
    }

    #[test]
    fn cpu_max_prefers_nano_then_quota() {
        assert_eq!(
            cpu_max_value(200_000_000, 0, 0).as_deref(),
            Some("2000 100000")
        );
        assert_eq!(
            cpu_max_value(0, 50000, 100000).as_deref(),
            Some("50000 100000")
        );
        // Zero period means the kernel default (100ms).
        assert_eq!(cpu_max_value(0, 25000, 0).as_deref(), Some("25000 100000"));
        assert_eq!(cpu_max_value(0, 0, 0), None);
    }

    #[test]
    fn swap_max_follows_docker_semantics() {
        assert_eq!(swap_max_value(100, 0), "100");
        assert_eq!(swap_max_value(100, 200), "200");
        assert_eq!(swap_max_value(100, -1), "max");
    }

    #[test]
    fn oom_kill_parsing() {
        let sample = "low 0\nhigh 0\nmax 0\noom 3\noom_kill 2\noom_group_kill 0\n";
        assert_eq!(parse_oom_kills(sample), Some(2));
        assert_eq!(parse_oom_kills("low 0\nhigh 0\n"), None);
        assert_eq!(parse_oom_kills(""), None);
    }
}
