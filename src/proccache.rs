use std::collections::HashMap;
use crate::config;
use crate::cpuset::CpuSet;
use crate::process;

/// 线程条目，对应 /proc/[pid]/task/[tid]
pub struct TaskEntry {
    pub pid: i32,
    pub cpus: CpuSet,
    pub cpuset_dir: String,
    pub is_thread_rule: bool,
}

/// 双模式共用进程缓存：eBPF 事件驱动增量维护，proc 模式触发全量重建
pub struct ProcCache {
    pub pkgs: HashMap<i32, (String, bool)>,
    pub tasks: HashMap<i32, TaskEntry>,
}

impl ProcCache {
    pub fn new() -> Self {
        Self { pkgs: HashMap::new(), tasks: HashMap::new() }
    }

    pub fn clear(&mut self) {
        self.pkgs.clear();
        self.tasks.clear();
    }

    /// 删除 tid，若该 pid 下无线程则清理 pkgs[pid]
    pub fn task_del(&mut self, tid: i32) {
        let pid = self.tasks.remove(&tid).map(|t| t.pid);
        if let Some(pid) = pid {
            self.pkgs_purge(pid);
        }
    }

    fn pkgs_purge(&mut self, pid: i32) {
        if !self.tasks.values().any(|t| t.pid == pid) {
            self.pkgs.remove(&pid);
        }
    }

    /// eBPF 专用：pkgs 缓存命中优先，否则 comm_to_pkg 匹配后缓存
    pub fn pkg_lookup_comm(&mut self, pid: i32, comm: &str, cfg: &config::AppConfig) -> Option<(String, bool)> {
        if let Some((pkg, htr)) = self.pkgs.get(&pid).cloned() {
            return Some((pkg, htr));
        }
        let pkg = crate::bpf::comm_to_pkg(comm, cfg)?;
        let has_thread_rules = cfg.pkg_has_thread_rules(&pkg);
        self.pkgs.insert(pid, (pkg.clone(), has_thread_rules));
        Some((pkg, has_thread_rules))
    }

    /// 计算并应用线程亲和性，trust_comm=false 时忽略 comm 走 fallback（FORK 继承场景）
    /// 新结果走 fallback 时保护已有线程规则绑定，防止临时改名降级
    pub fn task_apply<F>(&mut self, tid: i32, pid: i32, pkg: &str, comm: &str,
        has_thread_rules: bool, cfg: &config::AppConfig, trust_comm: bool, apply_fn: F) -> bool
    where F: FnOnce(i32, &CpuSet, &str) -> bool
    {
        let thread_name = if has_thread_rules && trust_comm { comm } else { "" };
        let Some(result) = crate::rule_match::thread_affinity(pkg, thread_name, cfg, &cfg.topo) else {
            return false;
        };

        // fallback 结果不覆盖已有线程规则绑定
        if !result.is_thread_rule {
            if let Some(old) = self.tasks.get(&tid) {
                if old.is_thread_rule {
                    return true;
                }
            }
        }

        self.tasks.remove(&tid);
        let dead = apply_fn(tid, &result.cpus, &result.cpuset_dir);
        if dead {
            return false;
        }

        self.tasks.insert(tid, TaskEntry {
            pid,
            cpus: result.cpus,
            cpuset_dir: result.cpuset_dir,
            is_thread_rule: result.is_thread_rule,
        });
        true
    }

    /// 遍历 tasks 应用亲和性，返回 dead_tids
    pub fn affinity_sync(&mut self, topo: &crate::cpuset::CpuTopology) -> Vec<i32> {
        let dead_tids: Vec<i32> = self.tasks.iter().filter_map(|(tid, e)| {
            if process::affinity_set(*tid, &e.cpus, &e.cpuset_dir, topo) { Some(*tid) } else { None }
        }).collect();
        for tid in &dead_tids {
            self.task_del(*tid);
        }
        dead_tids
    }
}
