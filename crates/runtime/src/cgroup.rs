//! cgroup v2 management — plain cgroupfs writes, no delegation required
//! (the daemon runs as root).

use anyhow::{anyhow, Result};
use std::path::{Path, PathBuf};

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const SLICE: &str = "ingot.slice";

pub struct Cgroup {
    dir: PathBuf,
}

impl Cgroup {
    /// Create `/sys/fs/cgroup/ingot.slice/<id>` and enable the controllers we
    /// use on the root and slice levels. Failing to enable a controller is
    /// non-fatal (kernel may not expose it); failing to mkdir is fatal.
    pub fn create(id: &str) -> Result<Cgroup> {
        let root = Path::new(CGROUP_ROOT);
        enable_controllers(root)?;
        let slice = root.join(SLICE);
        std::fs::create_dir_all(&slice)?;
        enable_controllers(&slice)?;
        let dir = slice.join(id);
        std::fs::create_dir_all(&dir)?;
        Ok(Cgroup { dir })
    }

    pub fn apply(
        &self,
        memory_bytes: i64,
        nano_cpus: i64,
        cpu_shares: i64,
        pids_limit: i64,
        cpuset_cpus: &str,
    ) -> Result<()> {
        if memory_bytes > 0 {
            write(&self.dir, "memory.max", &memory_bytes.to_string())?;
            write(&self.dir, "memory.swap.max", &memory_bytes.to_string())?;
        }
        if nano_cpus > 0 {
            // nano_cpus → "max $quota $period" (period 100ms)
            let quota = nano_cpus / 100_000; // per 100ms
            let val = if quota >= 100_000_000 { "max 100000".to_string() } else { format!("{quota} 100000") };
            write(&self.dir, "cpu.max", &val)?;
        } else if cpu_shares > 0 {
            let weight = shares_to_weight(cpu_shares);
            write(&self.dir, "cpu.weight", &weight.to_string())?;
        }
        if pids_limit > 0 {
            write(&self.dir, "pids.max", &pids_limit.to_string())?;
        }
        if !cpuset_cpus.is_empty() {
            write(&self.dir, "cpuset.cpus", cpuset_cpus)?;
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

fn enable_controllers(dir: &Path) -> Result<()> {
    let available = std::fs::read_to_string(dir.join("cgroup.controllers"))
        .map_err(|e| anyhow!("read cgroup.controllers: {e}"))?;
    let mut want = String::new();
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

fn write(dir: &Path, file: &str, val: &str) -> Result<()> {
    std::fs::write(dir.join(file), val)
        .map_err(|e| anyhow!("write {file}={val}: {e}"))
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
}
