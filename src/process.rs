use std::{collections::HashSet, fs, mem};
use crate::config::{self, Rule, fnmatch};

static CPUSET_OK: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// 初始化 cpuset 目录
pub fn init_cpuset() {
    if !std::path::Path::new("/dev/cpuset").exists() { return; }
    let _ = fs::create_dir_all("/dev/cpuset/AppOpt");
    // 写入所有可用 CPU 到根 cpuset
    let present = std::fs::read_to_string("/sys/devices/system/cpu/present").unwrap_or_default();
    let _ = fs::write("/dev/cpuset/AppOpt/cpus", present.trim().as_bytes());
    if let Ok(mems) = fs::read_to_string("/dev/cpuset/mems") {
        let _ = fs::write("/dev/cpuset/AppOpt/mems", mems.trim().as_bytes());
    }
    CPUSET_OK.store(true, std::sync::atomic::Ordering::Release);
}

/// 确保 CPU range 对应的 cpuset 目录存在
fn ensure_cpuset(cpus: &str) {
    if !CPUSET_OK.load(std::sync::atomic::Ordering::Acquire) { return; }
    let dir = format!("/dev/cpuset/AppOpt/{}", cpus.replace(',', "."));
    let _ = fs::create_dir_all(&dir);
    let _ = fs::write(format!("{}/cpus", &dir), cpus.as_bytes());
    if let Ok(mems) = fs::read_to_string("/dev/cpuset/mems") {
        let _ = fs::write(format!("{}/mems", &dir), mems.trim().as_bytes());
    }
}

/// 写 TID 到 cpuset tasks
fn cpuset_add(tid: i32, cpus: &str) {
    if !CPUSET_OK.load(std::sync::atomic::Ordering::Acquire) { return; }
    let dir = format!("/dev/cpuset/AppOpt/{}", cpus.replace(',', "."));
    let _ = fs::write(format!("{}/tasks", dir), format!("{}\n", tid).as_bytes());
}

pub fn scan(rules: &[Rule], set: &HashSet<String>, wild: &[String]) -> Vec<(i32, String, Vec<(i32, String, String)>)> {
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
            if pid < 1000 { continue; }
            if let Some(entry) = scan_one_pid(pid, rules, set, wild) { result.push(entry); }
        }
    };
    unsafe { libc::close(fd); }
    if r < 0 { result.clear(); }
    result
}

/// 扫描单个 PID，返回匹配的进程数据
pub fn scan_one_pid(pid: i32, rules: &[Rule], set: &HashSet<String>, wild: &[String])
    -> Option<(i32, String, Vec<(i32, String, String)>)>
{
    if pid < 1000 { return None; }
    let cl = fs::read_to_string(format!("/proc/{}/cmdline", pid)).ok()?;
    let pkg = cl.split('\0').next().unwrap_or("").trim_end_matches('\0').to_string();
    if pkg.is_empty() { return None; }
    if !set.contains(&pkg) && !wild.iter().any(|w| fnmatch(w, &pkg)) { return None; }
    let mut th = Vec::new();
    if let Ok(tk) = fs::read_dir(format!("/proc/{}/task", pid)) {
        for t in tk.flatten() {
            let tid: i32 = t.file_name().to_string_lossy().parse().unwrap_or(0);
            let comm = fs::read_to_string(t.path().join("comm")).unwrap_or_default().trim().to_string();
            let mut best = String::new(); let mut bp = -1i32;
            for r in rules {
                let pm = r.pkg == pkg || (r.thread.is_empty() && fnmatch(&r.pkg, &pkg));
                if !pm { continue; }
                if r.thread.is_empty() { if 200 > bp { best = r.cpus.clone(); bp = 200; } }
                else if fnmatch(&r.thread, &comm) && r.prio > bp { best = r.cpus.clone(); bp = r.prio; }
            }
            th.push((tid, comm, best));
        }
    }
    if th.is_empty() { return None; }
    Some((pid, pkg, th))
}

/// 扫描未配置的用户应用，用于自动分配
pub fn scan_unknown(set: &HashSet<String>, wild: &[String]) -> Vec<(i32, String, Vec<(i32, String)>)> {
    let mut result = Vec::new();
    let dir = match fs::read_dir("/proc") { Ok(d) => d, Err(_) => return result };
    for entry in dir.flatten() {
        let pid: i32 = match entry.file_name().to_string_lossy().parse() { Ok(p) => p, Err(_) => continue };
        if pid < 1000 { continue; }
        // 先读 cmdline（轻量），粗筛：包名必须含 '.' 且不含 '/'
        let cl = match fs::read_to_string(entry.path().join("cmdline")) { Ok(c) => c, Err(_) => continue };
        let pkg = cl.split('\0').next().unwrap_or("").trim_end_matches('\0').to_string();
        if pkg.is_empty() || pkg.contains('/') || !pkg.contains('.') { continue; }
        // 已收录的跳过
        if set.contains(&pkg) || wild.iter().any(|w| fnmatch(w, &pkg)) { continue; }
        // 再读 status 验证 UID >= 10000（确认是用户应用）
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

/// 解析 CPU range 字符串（如 "0-3,4,6-7"）并设置 cpu_set_t
pub fn parse_cpus_to_set(cpus: &str, set: &mut libc::cpu_set_t) {
    for part in cpus.split(',') {
        let part = part.trim();
        if part.is_empty() { continue; }
        if let Some((s, e)) = part.split_once('-') {
            let start: usize = s.parse().unwrap_or(0);
            let end: usize = e.parse().unwrap_or(start);
            for cpu in start..=end { unsafe { libc::CPU_SET(cpu, set); } }
        } else if let Ok(cpu) = part.parse::<usize>() {
            unsafe { libc::CPU_SET(cpu, set); }
        }
    }
}

/// 应用绑核 (增量模式: 跳过已绑线程)
/// 返回 (绑定的进程数, 总线程数, 新增绑定数)
pub fn apply(procs: &[(i32, String, Vec<(i32, String, String)>)],
    bound_set: &mut std::collections::HashSet<(i32, String)>) -> (usize, usize, usize) {
    let mut seen_cpus = std::collections::HashSet::<String>::new();
    let mut n = 0usize;
    let mut new_set = std::collections::HashSet::new();
    for (_, _, th) in procs {
        for (tid, _, cpus) in th {
            if cpus.is_empty() { continue; }
            let key = (*tid, cpus.clone());
            if bound_set.contains(&key) { continue; }  // 已绑, 跳过
            n += 1;

            // 确保 cpuset 目录存在 (仅首次)
            if seen_cpus.insert(cpus.clone()) { ensure_cpuset(cpus); }

            // sched_setaffinity
            let mut set: libc::cpu_set_t = unsafe { mem::zeroed() };
            unsafe { libc::CPU_ZERO(&mut set); }
            parse_cpus_to_set(cpus, &mut set);
            unsafe {
                libc::sched_setaffinity(*tid, mem::size_of::<libc::cpu_set_t>(), &set);
                // ESRCH: 线程已退出, 直接跳过
            }

            cpuset_add(*tid, cpus);
            new_set.insert(key);
        }
    }
    for k in new_set { bound_set.insert(k); }
    let total: usize = procs.iter().map(|(_, _, th)| th.len()).sum();
    (procs.len(), total, n)
}
