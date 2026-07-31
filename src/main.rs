use std::{
    env, fs, io::Write,
    path::Path,
    sync::mpsc,
    time::{Duration, Instant},
};

#[macro_use]
mod log;
mod config;
mod cpu;
mod process;
mod bpf;
mod cpuset;
mod proccache;
mod common;
mod rule_match;

use config::*;
use cpuset::CpuSet;

/// 热加载配置：重新解析线程配置、合并缓存
fn hot_reload(config_path: &str, cfg: &mut AppConfig) -> bool {
    if let Some(new_cfg) = AppConfig::load(config_path, &cfg.topo) {
        *cfg = new_cfg;
        cache::merge(&mut cfg.pkg_set, &mut cfg.rules);
        info!("配置已热加载, 共 {} 条规则", cfg.rules.len());
        true
    } else {
        info!("配置文件解析失败, 保持旧配置");
        false
    }
}

/// comm[16] 截断 NUL 转 String
fn comm_str(comm: &[u8; 16]) -> String {
    let end = comm.iter().position(|&b| b == 0).unwrap_or(16);
    std::str::from_utf8(&comm[..end]).unwrap_or("").trim().to_string()
}

/// eBPF 模式: 应用亲和性并写 APPLIED_MAP，返回 true 表示 tid 已退出
fn event_affinity_apply(tid: i32, cpus: &CpuSet, cpuset_dir: &str, cfg: &AppConfig, bpf_state: &mut bpf::BpfCtx) -> bool {
    let dead = process::affinity_set(tid, cpus, cpuset_dir, &cfg.topo);
    if !dead {
        bpf::applied_set(bpf_state, tid, cpus.bits[0]);
    }
    dead
}

/// eBPF 模式: 统一事件处理 (pkg 反查 → task_apply)
fn event_apply(pc: &mut proccache::ProcCache, bpf_state: &mut bpf::BpfCtx,
    tid: i32, pid: i32, comm: &str, cfg: &AppConfig, trust_comm: bool) -> bool {
    let Some((pkg, has_thread_rules)) = pc.pkg_lookup_comm(pid, comm, cfg) else {
        return false;
    };
    pc.task_apply(tid, pid, &pkg, comm, has_thread_rules, cfg, trust_comm,
        |t, c, dir| event_affinity_apply(t, c, dir, cfg, bpf_state));
    true
}

/// eBPF 模式: 事件派发
fn event_dispatch(event: &bpf::EbpfProcEvent, cfg: &AppConfig,
    pc: &mut proccache::ProcCache, bpf_state: &mut bpf::BpfCtx) {
    let tid = event.tid;
    let pid = event.pid;
    let comm = comm_str(&event.comm);

    match event.event_type {
        bpf::EVENT_EXIT => {
            if tid == pid { pc.pkgs.remove(&pid); }
            pc.task_del(tid);
            bpf::applied_del(bpf_state, tid);
        }
        bpf::EVENT_EXEC => {
            pc.pkgs.remove(&pid);
            if !event_apply(pc, bpf_state, tid, pid, &comm, cfg, true) {
                pc.task_del(tid);
                bpf::applied_del(bpf_state, tid);
            }
        }
        bpf::EVENT_FORK => {
            // FORK 子线程继承父 comm 不可信，主线程 tid==pid comm 为自身
            event_apply(pc, bpf_state, tid, pid, &comm, cfg, tid == pid);
        }
        bpf::EVENT_RENAME => {
            event_apply(pc, bpf_state, tid, pid, &comm, cfg, true);
        }
        _ => {}
    }
}

/// eBPF 模式: 全量扫描 /proc (仅启动或配置更新时调用, 日常零 /proc 读)
fn full_scan(cfg: &AppConfig, pc: &mut proccache::ProcCache, bpf_state: &mut bpf::BpfCtx) {
    pc.clear();
    bpf::applied_clear(bpf_state);

    let proc_dir = match fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return,
    };

    let targets: Vec<(i32, String, bool)> = proc_dir.flatten().filter_map(|entry| {
        let pid = entry.file_name().to_string_lossy().parse::<i32>().ok()?;
        let pkg = process::read_cmdline(pid).or_else(|| process::tid_comm(pid))?;
        // 包名匹配 (含 :suffix)
        let base_pkg = pkg.split(':').next().unwrap_or(&pkg);
        let interested = cfg.pkg_set.contains(&pkg) || cfg.pkg_set.contains(base_pkg)
            || cfg.wild.iter().any(|w| fnmatch(w, &pkg));
        if !interested { return None; }
        let htr = cfg.pkg_has_thread_rules(&pkg);
        Some((pid, pkg, htr))
    }).collect();

    for (pid, pkg, htr) in targets {
        let Some(tids) = process::task_tids(pid) else { continue };
        for tid in tids {
            let t_name = if htr { process::tid_comm(tid).unwrap_or_default() } else { String::new() };
            pc.task_apply(tid, pid, &pkg, &t_name, htr, cfg, true,
                |t, c, dir| event_affinity_apply(t, c, dir, cfg, bpf_state));
        }
        pc.pkgs.insert(pid, (pkg, htr));
    }
}

/// proc 模式增量同步状态（仿参考项目 ProcScanState）
struct ProcState {
    cache: proccache::ProcCache,
    last_proc_count: i32,
    scan_all_proc: bool,
    tracked_pids: std::collections::HashSet<i32>,
    last_proc_total: i32,
    force_affinity: bool,
}

impl ProcState {
    fn new() -> Self {
        Self {
            cache: proccache::ProcCache::new(),
            last_proc_count: 0,
            scan_all_proc: true,
            tracked_pids: std::collections::HashSet::new(),
            last_proc_total: 0,
            force_affinity: false,
        }
    }
}

/// 轻量增量同步：sysinfo 进程数变化或已跟踪 pid 消失才全量重建缓存
/// 返回 true 表示发生了全量重扫
fn proc_cache_sync(state: &mut ProcState, cfg: &AppConfig) -> bool {
    let mut need_reload = state.scan_all_proc;

    let mut info: libc::sysinfo = unsafe { std::mem::zeroed() };
    if unsafe { libc::sysinfo(&mut info) } != 0 {
        need_reload = true;
    } else {
        let cur = info.procs as i32;
        if cur > state.last_proc_count + 11 {
            need_reload = true;
        } else if cur > state.last_proc_count {
            state.force_affinity = true;
        }
        state.last_proc_count = cur;
    }

    if !need_reload {
        for &pid in state.tracked_pids.iter() {
            if unsafe { libc::kill(pid, 0) } != 0 {
                need_reload = true;
                break;
            }
        }
    }

    if !need_reload { return false; }

    // 全量重建缓存（只填充不绑核，绑核由 affinity_sync 统一做）
    state.cache.clear();
    let mut new_tracked: std::collections::HashSet<i32> = std::collections::HashSet::new();
    let mut current_total = 0i32;
    let mut scanned = 0usize;

    if let Ok(dir) = fs::read_dir("/proc") {
        for entry in dir.flatten() {
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else { continue };
            current_total += 1;
            if !state.scan_all_proc && !state.tracked_pids.contains(&pid) { continue; }

            let Some(pkg) = process::read_cmdline(pid).or_else(|| process::tid_comm(pid)) else { continue };
            let base_pkg = pkg.split(':').next().unwrap_or(&pkg);
            let interested = cfg.pkg_set.contains(&pkg) || cfg.pkg_set.contains(base_pkg)
                || cfg.wild.iter().any(|w| fnmatch(w, &pkg));
            if !interested { continue; }
            let htr = cfg.pkg_has_thread_rules(&pkg);
            let Some(tids) = process::task_tids(pid) else { continue };

            let mut any = false;
            for tid in tids {
                let tn = if htr { process::tid_comm(tid).unwrap_or_default() } else { String::new() };
                if state.cache.task_apply(tid, pid, &pkg, &tn, htr, cfg, true, |_, _, _| false) {
                    any = true;
                }
            }
            if any {
                state.cache.pkgs.insert(pid, (pkg, htr));
                new_tracked.insert(pid);
                scanned += 1;
            }
        }
    }

    state.scan_all_proc = current_total > state.last_proc_total;
    state.last_proc_total = current_total;
    state.tracked_pids = new_tracked;
    state.force_affinity = true;
    info!("proc: 缓存重建 ({} 进程)", scanned);
    true
}

fn main() {
    // 进程锁
    std::panic::set_hook(Box::new(|info| {
        let msg = info.payload().downcast_ref::<&str>().copied()
            .or_else(|| info.payload().downcast_ref::<String>().map(|s| s.as_str()))
            .unwrap_or("?");
        let loc = info.location().map(|l| format!("{}:{}", l.file(), l.line())).unwrap_or_default();
        let _ = fs::OpenOptions::new().create(true).append(true).open(log::PATH)
            .map(|mut f| write!(f, "[PANIC] {} at {}\n", msg, loc));
    }));

    let _ = fs::create_dir_all("/sdcard/Android/Aether");
    fs::write(log::PATH, "").ok();

    let args: Vec<String> = env::args().collect();
    let mut config_path = "/sdcard/Android/Aether/threads.json".to_string();
    let mut interval = 2u64;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-c" => { i += 1; if i < args.len() { config_path = args[i].clone(); } }
            "-s" => { i += 1; if i < args.len() { interval = args[i].parse().unwrap_or(2); } }
            _ => {}
        }
        i += 1;
    }
    if interval < 1 { interval = 1; }

    info!("CPU: {} cpuset={}", cpu::present(), Path::new("/dev/cpuset").exists());

    // CPU 拓扑 + BASE_CPUSET（绑核前必须初始化）
    crate::common::set_base_cpuset("AppOpt");
    let topo = crate::cpuset::init_cpu_topo();

    let mut cfg = match AppConfig::load(&config_path, &topo) {
        Some(c) => c,
        None => { error!("配置加载失败"); return; }
    };
    info!("已加载 {} 条规则", cfg.rules.len());

    cache::merge(&mut cfg.pkg_set, &mut cfg.rules);
    info!("共 {} 条规则 (含缓存)", cfg.rules.len());

    let (big, mid, little, topo) = cpu::detect();
    info!("拓扑: {} (大核={} 中核={} 小核={})", topo, big, if mid.is_empty() { "无" } else { &mid }, little);

    process::init_cpuset();

    // 自身限定在小核运行
    if !little.is_empty() && little != "0" {
        let self_pid = std::process::id() as i32;
        let set = CpuSet::from_range(&little);
        let r = unsafe { libc::sched_setaffinity(self_pid, std::mem::size_of::<libc::cpu_set_t>(), &set as *const CpuSet as *const libc::cpu_set_t) };
        if r != 0 { info!("自身绑核跳过 (errno={})", r); }
    }

    // eBPF 初始化
    let mut bpf_state = bpf::probe(cfg.ebpf);
    // 白名单容量须与 ebpf/src/main.rs MAP_CAPACITY 一致 (8192): 668 包 × 前后缀 ≈ 1336 键
    let mut comm_capacity = 8192u32;
    let mut need_full_scan = true;
    let mut affinity_deadline = Instant::now();

    // proc 模式状态
    let mut proc_state = ProcState::new();
    let mut cache_scan = 0i32;

    // 启动时自动分配 (两模式共用)
    let unknown = process::scan_unknown(&cfg.pkg_set, &cfg.wild);
    let mut saved = false;
    for (_, pkg, th) in &unknown {
        if config::cache::is_blacklisted(pkg) { continue; }
        info!("新应用: {} ({} 线程)", pkg, th.len());
        cache::save(pkg, &unknown, &big, &mid, &little);
        saved = true;
    }
    if saved {
        cache::merge(&mut cfg.pkg_set, &mut cfg.rules);
        info!("自动分配完成: {} 个", unknown.len());
    }

    info!("启动 (模式: {})", if bpf_state.ok { "eBPF 事件驱动" } else { "proc 轮询" });

    // inotify 配置文件监听
    let mut inotify_fd = init_inotify(&config_path);

    loop {
        // 配置热加载检测 (每轮)
        let mut config_changed = false;
        if let Some(ev) = read_inotify(inotify_fd) {
            if ev == 1 || ev == 2 {
                config_changed = hot_reload(&config_path, &mut cfg);
                if ev == 2 { rewatch_inotify(&config_path, &mut inotify_fd); }
            }
        }
        if inotify_fd < 0 {
            if let Ok(mt) = fs::metadata(&config_path).and_then(|m| m.modified()) {
                if mt > cfg.mtime {
                    config_changed = hot_reload(&config_path, &mut cfg);
                }
            }
        }

        if bpf_state.ok {
            // ===== eBPF 事件驱动模式 =====
            if config_changed || need_full_scan {
                // 同步白名单（容量编译期固定, 不足时不重建, 降级为部分匹配）
                if bpf::comm_map_init(&mut bpf_state, &cfg.pkg_set, &mut comm_capacity) {
                    info!("eBPF: 白名单容量不足, 部分包名无法即时发现 (需 {} 键)", cfg.pkg_set.len() * 2);
                }
                full_scan(&cfg, &mut proc_state.cache, &mut bpf_state);
                need_full_scan = false;
                info!("eBPF: 全量扫描完成 ({} 进程)", proc_state.cache.pkgs.len());
            }

            // 收事件 (阻塞 1s, 事件驱动日常零 /proc 读)
            match bpf_state.event_rx.recv_timeout(Duration::from_secs(1)) {
                Ok(event) => {
                    event_dispatch(&event, &cfg, &mut proc_state.cache, &mut bpf_state);
                    while let Ok(e) = bpf_state.event_rx.try_recv() {
                        event_dispatch(&e, &cfg, &mut proc_state.cache, &mut bpf_state);
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    info!("eBPF: 事件通道断开, 回退 /proc 轮询");
                    bpf_state = bpf::BpfCtx::empty();
                    need_full_scan = true;
                }
            }

            // 定期纠正亲和性 (每 3*interval 秒)
            if affinity_deadline.elapsed() >= Duration::from_secs(3 * interval) {
                let dead_tids = proc_state.cache.affinity_sync(&cfg.topo);
                for tid in dead_tids {
                    bpf::applied_del(&mut bpf_state, tid);
                }
                affinity_deadline = Instant::now();
            }
        } else {
            // ===== proc 轮询模式 (增量维护, 仿参考项目) =====
            if config_changed {
                proc_state.scan_all_proc = true;
            }

            let reloaded = proc_cache_sync(&mut proc_state, &cfg);
            let _ = reloaded;

            // 定期纠正亲和性 (每 3*interval 秒 或 进程数变化时)
            if proc_state.force_affinity || affinity_deadline.elapsed() >= Duration::from_secs(3 * interval) {
                let _dead = proc_state.cache.affinity_sync(&cfg.topo);
                proc_state.force_affinity = false;
                affinity_deadline = Instant::now();
            }

            // 未知应用自动分配 (每 30 轮)
            cache_scan += 1;
            if cache_scan >= 30 {
                cache_scan = 0;
                let u = process::scan_unknown(&cfg.pkg_set, &cfg.wild);
                let mut found = false;
                for (_, pkg, th) in &u {
                    if config::cache::is_blacklisted(pkg) { continue; }
                    info!("新应用: {} ({} 线程)", pkg, th.len());
                    cache::save(pkg, &u, &big, &mid, &little);
                    found = true;
                }
                if found {
                    cache::merge(&mut cfg.pkg_set, &mut cfg.rules);
                    info!("缓存已更新");
                }
            }

            std::thread::sleep(Duration::from_secs(interval));
        }
    }
}

fn init_inotify(path: &str) -> i32 {
    let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
    if fd < 0 { return -1; }
    let cpath = match std::ffi::CString::new(path) {
        Ok(c) => c,
        Err(_) => { unsafe { libc::close(fd); } return -1; }
    };
    let wd = unsafe {
        libc::inotify_add_watch(fd, cpath.as_ptr(),
            libc::IN_CLOSE_WRITE | libc::IN_DELETE_SELF | libc::IN_MOVE_SELF)
    };
    if wd < 0 { unsafe { libc::close(fd); } return -1; }
    info!("inotify: 监听配置文件变更 (fd={})", fd);
    fd
}

fn read_inotify(fd: i32) -> Option<u8> {
    if fd < 0 { return None; }
    let mut buf = [0u8; 1024];
    let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    if n <= 0 { return None; }
    let hdr = std::mem::size_of::<libc::inotify_event>();
    let mut off = 0usize;
    let mut reload = false;
    let mut rewatch = false;
    while off + hdr <= n as usize {
        let ev = unsafe { &*(buf.as_ptr().add(off) as *const libc::inotify_event) };
        if ev.mask & libc::IN_CLOSE_WRITE != 0 { reload = true; }
        if ev.mask & (libc::IN_DELETE_SELF | libc::IN_MOVE_SELF) != 0 { reload = true; rewatch = true; }
        off += hdr + ev.len as usize;
    }
    if reload { Some(if rewatch { 2 } else { 1 }) } else { None }
}

fn rewatch_inotify(path: &str, fd: &mut i32) {
    if *fd < 0 { return; }
    let cpath = match std::ffi::CString::new(path) {
        Ok(c) => c, Err(_) => return,
    };
    let wd = unsafe {
        libc::inotify_add_watch(*fd, cpath.as_ptr(),
            libc::IN_CLOSE_WRITE | libc::IN_DELETE_SELF | libc::IN_MOVE_SELF)
    };
    if wd < 0 {
        unsafe { libc::close(*fd); }
        *fd = -1;
        info!("inotify: 注册失败, 回退 mtime 轮询");
    } else {
        info!("inotify: 重新注册成功");
    }
}
