use std::{
    env, fs, io::Write, mem,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, SystemTime},
    collections::HashSet,
};

#[macro_use]
mod log;
mod config;
mod cpu;
mod process;
mod bpf;

use log::*;
use config::*;
use cpu::*;
use process::*;

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

    let mut cfg = match AppConfig::load(&config_path) {
        Some(c) => c,
        None => { error!("配置加载失败"); return; }
    };
    info!("已加载 {} 条规则", cfg.rules.len());

    // 合并缓存
    let all_w = &cfg.wild;
    cache::merge(&mut cfg.pkg_set, &mut cfg.rules);
    info!("共 {} 条规则 (含缓存)", cfg.rules.len());

    let (big, mid, little, topo) = cpu::detect();
    info!("拓扑: {} (大核={} 中核={} 小核={})", topo, big, if mid.is_empty() { "无" } else { &mid }, little);

    // 初始化 cpuset
    process::init_cpuset();

    // 自身限定在小核运行
    if !little.is_empty() && little != "0" {
        let self_pid = std::process::id() as i32;
        let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        unsafe { libc::CPU_ZERO(&mut set); }
        for part in little.split(',') {
            let part = part.trim();
            if part.is_empty() { continue; }
            if let Some((s, e)) = part.split_once('-') {
                let start: usize = s.parse().unwrap_or(0);
                let end: usize = e.parse().unwrap_or(start);
                for cpu in start..=end { unsafe { libc::CPU_SET(cpu, &mut set); } }
            } else if let Ok(cpu) = part.parse::<usize>() {
                unsafe { libc::CPU_SET(cpu, &mut set); }
            }
        }
        let r = unsafe { libc::sched_setaffinity(self_pid, std::mem::size_of::<libc::cpu_set_t>(), &set) };
        if r != 0 { info!("自身绑核跳过 (errno={})", std::io::Error::last_os_error().raw_os_error().unwrap_or(0)); }
    }

    // eBPF
    let bpf = bpf::probe(cfg.ebpf);
    if bpf.ok {
        info!("eBPF: 可用");
        if bpf.prog2_fd >= 0 { info!("eBPF: 内核绑核已就绪 (prog2_fd={})", bpf.prog2_fd); }
        bpf::sync_rules(&bpf, &cfg.rules);
    }

    let _ = fs::create_dir_all("/sdcard/Android/Aether");

    // 启动时自动分配
    let unknown = process::scan_unknown(&cfg.pkg_set, all_w);
    for (pid, pkg, th) in &unknown {
        info!("新应用: {} ({} 线程)", pkg, th.len());
        cache::save(pkg, &unknown, &big, &mid, &little);
    }
    if !unknown.is_empty() {
        cache::merge(&mut cfg.pkg_set, &mut cfg.rules);
        info!("自动分配完成: {} 个", unknown.len());
    }

    let mut cache = process::scan(&cfg.rules, &cfg.pkg_set, all_w);
    let mut cnt = 1i32;
    let mut cache_scan = 0i32;
    let rf = AtomicBool::new(false);
    let mut bound_set = std::collections::HashSet::<(i32, String)>::new();
    let mut bind_cycle = 0i32;
    let efd = unsafe { libc::epoll_create1(0) };
    if efd >= 0 && bpf.ok {
        let mut ev = libc::epoll_event { events: libc::EPOLLIN as u32, u64: 0 };
        unsafe { libc::epoll_ctl(efd, libc::EPOLL_CTL_ADD, bpf.ring_fd, &mut ev); }
        info!("eBPF: epoll 等待中 (即时响应)");
    }
    info!("启动");

    loop {
        // eBPF 事件驱动 (epoll 即时唤醒)
        if bpf.ok {
            for pid in bpf::poll_new_pids(&bpf) {
                if let Some(entry) = process::scan_one_pid(pid, &cfg.rules, &cfg.pkg_set, all_w) {
                    if let Some(pos) = cache.iter().position(|(p, _, _)| *p == pid) {
                        cache[pos] = entry;
                    } else {
                        cache.push(entry);
                    }
                    cnt = 0;  // 新进程立即触发绑核
                }
            }
        }

        // 定期扫描新应用
        cache_scan += 1;
        if cache_scan >= 30 {
            cache_scan = 0;
            let u = process::scan_unknown(&cfg.pkg_set, all_w);
            for (pid, pkg, th) in &u {
                info!("新应用: {} ({} 线程)", pkg, th.len());
                cache::save(pkg, &u, &big, &mid, &little);
            }
            if !u.is_empty() {
                cache::merge(&mut cfg.pkg_set, &mut cfg.rules);
                info!("缓存已更新");
            }
        }

        cnt -= 1;
        if cnt < 1 {
            process::apply(&cache, &rf, &mut bound_set);
            bind_cycle += 1;
            if bind_cycle >= 30 {
                bind_cycle = 0;
                bound_set.clear();  // 全量重绑
            }
            if rf.load(Ordering::Acquire) {
                cache = process::scan(&cfg.rules, &cfg.pkg_set, all_w);
                rf.store(false, Ordering::Release);
            }
            cnt = 1;
        }

        std::thread::sleep(Duration::from_secs(interval));
        // epoll 等待 ringbuf 事件 (即时响应, 0% CPU)
        if efd >= 0 {
            let mut _evs: [libc::epoll_event; 1] = [libc::epoll_event { events: 0, u64: 0 }];
            unsafe { libc::epoll_wait(efd, _evs.as_mut_ptr(), 1, (interval * 1000) as i32); }
        } else {
            std::thread::sleep(Duration::from_secs(interval));
        }
    }
}
