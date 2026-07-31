use std::collections::HashSet;
use std::io::Write;

const MIN_USER_PID: i32 = 1000;
use std::fs;
use crate::cpuset::CpuSet;
use crate::config::{Rule, fnmatch};

static CPUSET_OK: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// 记录已报告失败的 (tid, cpus)，同一组合只报一次
static FAILED_ONCE: std::sync::LazyLock<std::sync::Mutex<std::collections::HashSet<(i32, String)>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashSet::new()));

/// 初始化 cpuset 目录
pub fn init_cpuset() {
    if !std::path::Path::new("/dev/cpuset").exists() { return; }
    let _ = fs::create_dir_all("/dev/cpuset/AppOpt");
    let present = std::fs::read_to_string("/sys/devices/system/cpu/present").unwrap_or_default();
    let _ = fs::write("/dev/cpuset/AppOpt/cpus", present.trim().as_bytes());
    if let Ok(mems) = fs::read_to_string("/dev/cpuset/mems") {
        let _ = fs::write("/dev/cpuset/AppOpt/mems", mems.trim().as_bytes());
    }
    CPUSET_OK.store(true, std::sync::atomic::Ordering::Release);
}

#[allow(dead_code)]
fn ensure_cpuset(cpus: &str) {
    if !CPUSET_OK.load(std::sync::atomic::Ordering::Acquire) { return; }
    let dir = format!("/dev/cpuset/AppOpt/{}", cpus.replace(',', "."));
    let _ = fs::create_dir_all(&dir);
    let _ = fs::write(format!("{}/cpus", &dir), cpus.as_bytes());
    if let Ok(mems) = fs::read_to_string("/dev/cpuset/mems") {
        let _ = fs::write(format!("{}/mems", &dir), mems.trim().as_bytes());
    }
}

#[allow(dead_code)]
fn cpuset_add(tid: i32, cpus: &str) {
    if !CPUSET_OK.load(std::sync::atomic::Ordering::Acquire) { return; }
    let dir = format!("/dev/cpuset/AppOpt/{}", cpus.replace(',', "."));
    let tasks = format!("{}/tasks", dir);
    if let Err(e) = fs::write(&tasks, format!("{}\n", tid).as_bytes()) {
        // ESRCH (os error 3) = 线程已退出, 静默跳过
        if e.raw_os_error() != Some(3) {
            crate::info!("cpuset_add tid={} cpus={} 写入失败 ({})", tid, cpus, e);
        }
    }
}

#[allow(dead_code)]
pub fn scan(rules: &[Rule], set: &HashSet<String>, wild: &[String]) -> Vec<(i32, String, Vec<(i32, String, CpuSet)>)> {
    let mut result = Vec::new();
    let mut buf = [0u8; 8192];
    let fd = unsafe { libc::open("/proc\0".as_ptr() as *const _, libc::O_RDONLY | libc::O_DIRECTORY) };
    if fd < 0 { return result; }
    let r = loop {
        let n = unsafe { libc::syscall(libc::SYS_getdents64, fd, buf.as_mut_ptr() as *mut i8, buf.len()) };
        if n <= 0 { break n; }
        let mut off = 0usize;
        while off < n as usize {
            let rec = u16::from_ne_bytes([buf[off+16], buf[off+17]]) as usize;
            let ino = u64::from_ne_bytes(buf[off..off+8].try_into().unwrap_or([0u8;8]));
            if rec < 19 || ino == 0 { off += rec; continue; }
            let name_end = buf[off+19..off+rec].iter().position(|&b| b == 0).unwrap_or(rec-20);
            let name = std::str::from_utf8(&buf[off+19..off+19+name_end]).unwrap_or("");
            off += rec;
            let pid: i32 = match name.parse() { Ok(p) => p, Err(_) => continue };
            if pid < MIN_USER_PID { continue; }
            if let Some(entry) = scan_one_pid(pid, rules, set, wild) { result.push(entry); }
        }
    };
    unsafe { libc::close(fd); }
    if r < 0 { result.clear(); }
    result
}

fn pkg_matches(pat: &str, name: &str) -> bool {
    fnmatch(pat, name) || {
        name.len() > pat.len() && name.as_bytes().get(pat.len()) == Some(&b':') && name.starts_with(pat)
    }
}

/// 扫描单个 PID，返回 (pid, pkg, Vec<(tid, comm, cpus)>) 其中 cpus 为 CpuSet
#[allow(dead_code)]
pub fn scan_one_pid(pid: i32, rules: &[Rule], set: &HashSet<String>, wild: &[String])
    -> Option<(i32, String, Vec<(i32, String, CpuSet)>)>
{
    if pid < MIN_USER_PID { return None; }
    let cl = fs::read_to_string(format!("/proc/{}/cmdline", pid)).ok()?;
    let pkg = cl.split('\0').next().unwrap_or("").trim_end_matches('\0').to_string();
    if pkg.is_empty() { return None; }
    let base_pkg = pkg.split(':').next().unwrap_or(&pkg);
    let pass = set.contains(&pkg) || set.contains(base_pkg)
        || wild.iter().any(|w| fnmatch(w, &pkg))
        || wild.iter().any(|w| pkg_matches(w, &pkg));
    if !pass { return None; }

    let mut th = Vec::new();
    if let Ok(tk) = fs::read_dir(format!("/proc/{}/task", pid)) {
        for t in tk.flatten() {
            let tid: i32 = t.file_name().to_string_lossy().parse().unwrap_or(0);
            let comm = fs::read_to_string(t.path().join("comm")).unwrap_or_default().trim().to_string();
            let mut best = CpuSet::new(); let mut bp = -1i32;
            for r in rules {
                if !pkg_matches(&r.pkg, &pkg) { continue; }
                if r.thread.is_empty() { if 200 > bp { best = CpuSet::from_range(&r.cpus); bp = 200; } }
                else if fnmatch(&r.thread, &comm) && r.prio > bp { best = CpuSet::from_range(&r.cpus); bp = r.prio; }
            }
            th.push((tid, comm, best));
        }
    }
    if th.is_empty() { return None; }
    Some((pid, pkg, th))
}

/// 扫描未配置的用户应用
pub fn scan_unknown(set: &HashSet<String>, wild: &[String]) -> Vec<(i32, String, Vec<(i32, String)>)> {
    let mut result = Vec::new();
    let dir = match fs::read_dir("/proc") { Ok(d) => d, Err(_) => return result };
    for entry in dir.flatten() {
        let pid: i32 = match entry.file_name().to_string_lossy().parse() { Ok(p) => p, Err(_) => continue };
        if pid < MIN_USER_PID { continue; }
        let cl = match fs::read_to_string(entry.path().join("cmdline")) { Ok(c) => c, Err(_) => continue };
        let pkg = cl.split('\0').next().unwrap_or("").trim_end_matches('\0').to_string();
        if pkg.is_empty() || pkg.contains('/') || !pkg.contains('.') { continue; }
        if set.contains(&pkg) || wild.iter().any(|w| fnmatch(w, &pkg)) { continue; }
        if let Ok(st) = fs::read_to_string(entry.path().join("status")) {
            let mut is_user = false;
            for line in st.lines() {
                if line.starts_with("Uid:") {
                    if let Some(u) = line.split_whitespace().nth(1) {
                        if let Ok(uid) = u.parse::<u32>() { is_user = uid >= 10000; }
                    }
                    break;
                }
            }
            if !is_user { continue; }
        } else { continue; }
        let mut th = Vec::new();
        if let Ok(tk) = fs::read_dir(entry.path().join("task")) {
            for t in tk.flatten() {
                let tid: i32 = t.file_name().to_string_lossy().parse().unwrap_or(0);
                let comm = fs::read_to_string(t.path().join("comm")).unwrap_or_default().trim().to_string();
                th.push((tid, comm));
            }
        }
        if th.is_empty() { continue; }
        result.push((pid, pkg, th));
    }
    result
}

/// 应用绑核：sched_getaffinity 短路 → sched_setaffinity → cpuset 写入
/// 返回 (进程数, 总线程数, 新增绑定数)
#[allow(dead_code)]
pub fn apply(procs: &[(i32, String, Vec<(i32, String, CpuSet)>)],
    bound_set: &mut HashSet<(i32, String)>) -> (usize, usize, usize) {
    let mut seen_cpus = HashSet::<String>::new();
    let mut n = 0usize;
    let mut new_set = HashSet::<(i32, String)>::new();
    for (_, _, th) in procs {
        for (tid, _, cpus) in th {
            if cpus.is_zero() { continue; }
            let cpus_str = cpus.to_range();
            let key = (*tid, cpus_str.clone());

            // sched_getaffinity 短路：已绑且 cpuset 已写则跳过
            let already_bound = CpuSet::get_affinity(*tid).map(|curr| curr == *cpus).unwrap_or(false);
            if already_bound {
                new_set.insert(key);
                continue;
            }
            if bound_set.contains(&key) { continue; }
            n += 1;

            if seen_cpus.insert(cpus_str.clone()) { ensure_cpuset(&cpus_str); }
            // 先写 cpuset（cgroup 限制 CPU 范围），再设亲和性
            cpuset_add(*tid, &cpus_str);
            if let Err(e) = cpus.set_affinity(*tid) {
                // ESRCH (os error 3) = 线程已退出, 静默跳过
                if e.raw_os_error() != Some(3) {
                    let mut seen = FAILED_ONCE.lock().unwrap_or_else(|p| p.into_inner());
        if seen.insert((*tid, cpus_str.clone())) {
            crate::info!("绑核失败 tid={} cpus={} ({}) (可能被系统 cpuset 管控限制)", tid, cpus_str, e);
        }
                }
            }
            new_set.insert(key);
        }
    }
    for k in new_set { bound_set.insert(k); }
    let total: usize = procs.iter().map(|(_, _, th)| th.len()).sum();
    if n > 0 { info!("已绑核 {} 进程 {} 线程 (+{} 新)", procs.len(), total, n); }
    (procs.len(), total, n)
}

/// 对单线程应用亲和性（参考项目逻辑）：getaffinity 短路 → 写 cpuset tasks → setaffinity
/// cpuset_dir 为空时写 BASE_CPUSET（允许全部 present CPU），保证大核可绑
/// 返回 true 表示 ESRCH 线程已退出
pub fn affinity_set(tid: i32, cpus: &CpuSet, cpuset_dir: &str, topo: &crate::cpuset::CpuTopology) -> bool {
    // sched_getaffinity 短路：已符合目标零开销返回
    if let Some(curr) = CpuSet::get_affinity(tid) {
        if curr == *cpus { return false; }
    }

    if topo.cpuset_enabled {
        let tid_str = format!("{}\n", tid);
        let tasks_path = if cpuset_dir.is_empty() {
            format!("{}/tasks", crate::common::base_cpuset())
        } else {
            format!("{}/{}/tasks", crate::common::base_cpuset(), cpuset_dir)
        };
        let _ = fs::OpenOptions::new()
            .append(true)
            .open(&tasks_path)
            .and_then(|mut f| f.write_all(tid_str.as_bytes()));
    }

    if let Err(e) = cpus.set_affinity(tid) {
        if e.raw_os_error() == Some(3) { return true; }  // ESRCH: 线程已退出
        let mut seen = FAILED_ONCE.lock().unwrap_or_else(|p| p.into_inner());
        if seen.insert((tid, cpus.to_range_string())) {
            crate::info!("绑核失败 tid={} cpus={} ({})", tid, cpus.to_range_string(), e);
        }
    }
    false
}

/// 读 /proc/{pid}/cmdline 取包名
pub fn read_cmdline(pid: i32) -> Option<String> {
    let cl = fs::read_to_string(format!("/proc/{}/cmdline", pid)).ok()?;
    let pkg = cl.split('\0').next().unwrap_or("").trim_end_matches('\0').to_string();
    if pkg.is_empty() { None } else { Some(pkg) }
}

/// 读 /proc/{pid}/task 全部 tid
pub fn task_tids(pid: i32) -> Option<Vec<i32>> {
    let dir = fs::read_dir(format!("/proc/{}/task", pid)).ok()?;
    Some(dir.flatten().filter_map(|t| t.file_name().to_string_lossy().parse().ok()).collect())
}

/// 读线程 comm
pub fn tid_comm(tid: i32) -> Option<String> {
    let comm = fs::read_to_string(format!("/proc/{}/comm", tid)).ok()?;
    let s = comm.trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}
