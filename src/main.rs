use std::{
    env, fs, io::Write,
    path::Path,
    time::Duration,
};

#[macro_use]
mod log;
mod config;
mod cpu;
mod process;
mod bpf;
#[cfg(target_os = "android")]
mod bpf_prog;

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
        process::parse_cpus_to_set(&little, &mut set);
        let r = unsafe { libc::sched_setaffinity(self_pid, std::mem::size_of::<libc::cpu_set_t>(), &set) };
        if r != 0 { info!("自身绑核跳过 (errno={})", r); }
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
    let unknown = process::scan_unknown(&cfg.pkg_set, &cfg.wild);
    for (_, pkg, th) in &unknown {
        info!("新应用: {} ({} 线程)", pkg, th.len());
        cache::save(pkg, &unknown, &big, &mid, &little);
    }
    if !unknown.is_empty() {
        cache::merge(&mut cfg.pkg_set, &mut cfg.rules);
        info!("自动分配完成: {} 个", unknown.len());
    }

    let mut cache = process::scan(&cfg.rules, &cfg.pkg_set, &cfg.wild);
    let mut cnt = 1i32;
    let mut cache_scan = 0i32;
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
                if let Some(entry) = process::scan_one_pid(pid, &cfg.rules, &cfg.pkg_set, &cfg.wild) {
                    if let Some(pos) = cache.iter().position(|(p, _, _)| *p == pid) {
                        cache[pos] = entry;
                    } else {
                        cache.push(entry);
                    }
                    cnt = 0;  // 新进程立即触发绑核
                }
            }
        }

        // 定期扫描新应用 + 检查配置热加载
        cache_scan += 1;
        if cache_scan >= 30 {
            cache_scan = 0;
            // 配置热加载: 检查 mtime 是否变化
            if let Ok(mt) = fs::metadata(&config_path).and_then(|m| m.modified()) {
                if mt > cfg.mtime {
                    info!("检测到配置变更, 热加载...");
                    if let Some(new_cfg) = AppConfig::load(&config_path) {
                        cfg = new_cfg;
                        let _ = process::scan(&cfg.rules, &cfg.pkg_set, &cfg.wild); // 预热
                        if bpf.ok { bpf::sync_rules(&bpf, &cfg.rules); }
                        cache::merge(&mut cfg.pkg_set, &mut cfg.rules);
                        bound_set.clear();
                        info!("配置已热加载, 共 {} 条规则", cfg.rules.len());
                    } else {
                        info!("配置文件解析失败, 保持旧配置");
                    }
                }
            }
            let u = process::scan_unknown(&cfg.pkg_set, &cfg.wild);
            for (_, pkg, th) in &u {
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
            let (np, nt, nb) = process::apply(&cache, &mut bound_set);
            if nb > 0 {
                info!("已绑核 {} 进程 {} 线程 (+{} 新)", np, nt, nb);
            }
            bind_cycle += 1;
            if bind_cycle >= 30 {
                bind_cycle = 0;
                bound_set.clear();  // 全量重绑
            }
            cnt = 1;
        }

        // 第一原则：不空转。保底 sleep + epoll 提前唤醒，总等待 ≈ interval。
        std::thread::sleep(Duration::from_millis(interval * 500)); // 至少等一半
        if efd >= 0 && bpf.ok {
            let mut evs: [libc::epoll_event; 1] = [libc::epoll_event { events: 0, u64: 0 }];
            unsafe { libc::epoll_wait(efd, evs.as_mut_ptr(), 1, (interval * 500) as i32); } // 最多再等一半
        }
    }
}
