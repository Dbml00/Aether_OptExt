use aya::Ebpf;
use aya::EbpfLoader;
use aya::maps::{Array, HashMap as BpfHashMap, RingBuf};
use aya::programs::TracePoint;
use std::convert::TryInto;
use std::convert::TryFrom;
use std::os::unix::io::AsRawFd;
use std::sync::mpsc;
use std::thread;
use crate::config;

pub const EVENT_FORK: u32 = 1;
pub const EVENT_EXEC: u32 = 2;
pub const EVENT_RENAME: u32 = 3;
pub const EVENT_EXIT: u32 = 4;

/// eBPF 进程事件，布局与内核态 ProcEvent 一致
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EbpfProcEvent {
    pub pid: i32,
    pub tid: i32,
    pub comm: [u8; 16],
    pub event_type: u32,
}

/// 用户态注入内核的 tracepoint 字段偏移，布局需与内核态 TracepointOffsets 一致
#[repr(C)]
#[derive(Clone, Copy)]
struct EbpfOffsets {
    fork_child_pid: u32,
    fork_child_comm: u32,
    rename_newcomm: u32,
}

// SAFETY: 全部为 u32 POD 字段
unsafe impl aya::Pod for EbpfOffsets {}

pub struct BpfCtx {
    pub ok: bool,
    pub event_rx: mpsc::Receiver<EbpfProcEvent>,
    pub bpf: Option<Ebpf>,
    wakeup_fd: i32,
    reader_thread: Option<thread::JoinHandle<()>>,
}

impl BpfCtx {
    pub fn empty() -> Self {
        let (_tx, rx) = mpsc::channel();
        BpfCtx { ok: false, event_rx: rx, bpf: None, wakeup_fd: -1, reader_thread: None }
    }
}

impl Drop for BpfCtx {
    fn drop(&mut self) {
        // 写 eventfd 唤醒 reader 线程的 epoll_wait 后 join 等待退出
        if self.wakeup_fd >= 0 {
            let val: u64 = 1;
            unsafe {
                libc::write(self.wakeup_fd, &val as *const u64 as *const _, 8);
            }
        }
        if let Some(handle) = self.reader_thread.take() {
            let _ = handle.join();
        }
        if self.wakeup_fd >= 0 {
            unsafe { libc::close(self.wakeup_fd); }
        }
    }
}

#[cfg(not(target_os = "android"))]
pub fn probe(_enable: bool) -> BpfCtx {
    BpfCtx::empty()
}

#[cfg(target_os = "android")]
pub fn probe(enable: bool) -> BpfCtx {
    if !enable { return BpfCtx::empty(); }

    let elf_data = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/ebpf_target.o"));
    crate::info!("eBPF: 尝试加载 {} bytes", elf_data.len());

    let mut bpf = match EbpfLoader::new().load(&elf_data[..]) {
        Ok(b) => b,
        Err(e) => { crate::info!("eBPF: EbpfLoader::load 失败 ({:?})", e); return BpfCtx::empty(); }
    };

    // tracepoint 偏移注入（必须先于 attach，避免首批事件读到空 map）
    if !offsets_inject(&mut bpf) {
        crate::info!("eBPF: tracepoint 偏移注入失败, 回退 /proc 轮询");
        return BpfCtx::empty();
    }

    // attach 4 个 tracepoint
    let attach = |bpf: &mut Ebpf, name: &str, category: &str, required: bool| -> bool {
        let prog = match bpf.program_mut(name) {
            Some(p) => p,
            None => {
                if required { crate::info!("eBPF: 程序 '{}' 不存在", name); }
                return false;
            }
        };
        let tp_prog: &mut TracePoint = match prog.try_into() {
            Ok(t) => t,
            Err(e) => {
                if required { crate::info!("eBPF: 程序 '{}' try_into 失败 ({:?})", name, e); }
                return false;
            }
        };
        if let Err(e) = tp_prog.load() {
            if required { crate::info!("eBPF: 程序 '{}' BPF_PROG_LOAD 失败 ({:?})", name, e); }
            return false;
        }
        if let Err(e) = tp_prog.attach(category, name) {
            if required { crate::info!("eBPF: 程序 '{}' attach {}/{} 失败 ({:?})", name, category, name, e); }
            return false;
        }
        if required { crate::info!("eBPF: 程序 '{}' 挂载成功", name); }
        true
    };

    let fork_ok = attach(&mut bpf, "sched_process_fork", "sched", true);
    let exec_ok = attach(&mut bpf, "sched_process_exec", "sched", true);
    let exit_ok = attach(&mut bpf, "sched_process_exit", "sched", true);
    attach(&mut bpf, "task_rename", "task", false); // rename 可选

    if !(fork_ok && exec_ok && exit_ok) {
        crate::info!("eBPF: 必要 tracepoint 挂载失败, 回退 /proc 轮询");
        return BpfCtx::empty();
    }

    // 创建事件通道 + reader 线程
    let (tx, rx) = mpsc::channel::<EbpfProcEvent>();
    let wakeup_fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    if wakeup_fd < 0 {
        crate::info!("eBPF: eventfd 创建失败");
        return BpfCtx::empty();
    }

    let ring_buf = match bpf.take_map("EVENTS") {
        Some(map) => match RingBuf::try_from(map) {
            Ok(rb) => rb,
            Err(e) => { crate::info!("eBPF: EVENTS RingBuf 失败 ({:?})", e); return BpfCtx::empty(); }
        },
        None => { crate::info!("eBPF: take_map(EVENTS) 失败"); return BpfCtx::empty(); }
    };

    let reader = thread::spawn(move || ebpf_reader(ring_buf, tx, wakeup_fd));

    crate::info!("eBPF: 就绪 (exec={} fork={} exit={})", exec_ok, fork_ok, exit_ok);
    BpfCtx { ok: true, event_rx: rx, bpf: Some(bpf), wakeup_fd, reader_thread: Some(reader) }
}

/// RingBuf 读取线程：epoll 阻塞等待事件，wakeup_fd 用于 Drop 唤醒退出
fn ebpf_reader(mut ring_buf: RingBuf<aya::maps::MapData>, tx: mpsc::Sender<EbpfProcEvent>, wakeup_fd: i32) {
    let epfd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    if epfd < 0 { return; }

    let ring_fd = ring_buf.as_raw_fd();
    let mut ring_ev: libc::epoll_event = unsafe { std::mem::zeroed() };
    ring_ev.events = libc::EPOLLIN as u32;
    ring_ev.u64 = 0;
    if unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, ring_fd, &mut ring_ev) } < 0 {
        unsafe { libc::close(epfd); }
        return;
    }

    let mut wake_ev: libc::epoll_event = unsafe { std::mem::zeroed() };
    wake_ev.events = libc::EPOLLIN as u32;
    wake_ev.u64 = 1;
    if unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, wakeup_fd, &mut wake_ev) } < 0 {
        unsafe { libc::close(epfd); }
        return;
    }

    let mut events: [libc::epoll_event; 2] = unsafe { std::mem::zeroed() };
    loop {
        let n = unsafe { libc::epoll_wait(epfd, events.as_mut_ptr(), 2, -1) };
        if n <= 0 {
            if n < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break;
        }
        // wakeup 事件优先退出
        let mut wakeup = false;
        for i in 0..n as usize {
            if events[i].u64 == 1 { wakeup = true; break; }
        }
        if wakeup { break; }

        while let Some(item) = ring_buf.next() {
            let bytes: &[u8] = &item;
            if bytes.len() >= std::mem::size_of::<EbpfProcEvent>() {
                let event: EbpfProcEvent =
                    unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const EbpfProcEvent) };
                if tx.send(event).is_err() {
                    unsafe { libc::close(epfd); }
                    return;
                }
            }
        }
    }
    unsafe { libc::close(epfd); }
}

/// 检测 tracefs 根路径
fn tracefs_root() -> Option<&'static str> {
    if std::path::Path::new("/sys/kernel/tracing").exists() {
        return Some("/sys/kernel/tracing");
    }
    if std::path::Path::new("/sys/kernel/debug/tracing").exists() {
        return Some("/sys/kernel/debug/tracing");
    }
    None
}

/// 解析 tracepoint format 文件提取字段偏移
fn tracepoint_parse(root: &str, category: &str, name: &str) -> Option<std::collections::HashMap<String, u32>> {
    let path = format!("{}/events/{}/{}/format", root, category, name);
    let content = std::fs::read_to_string(&path).ok()?;
    let mut offsets = std::collections::HashMap::new();
    for line in content.lines() {
        let Some(rest) = line.trim().strip_prefix("field:") else { continue };
        let parts: Vec<&str> = rest.split(';').map(|s| s.trim()).collect();
        if parts.len() < 2 { continue; }
        let field_name = parts[0].split_whitespace().last().unwrap_or("")
            .split('[').next().unwrap_or("");
        if field_name.is_empty() { continue; }
        for part in &parts[1..] {
            if let Some(off_str) = part.strip_prefix("offset:") {
                if let Ok(off) = off_str.trim().parse::<u32>() {
                    offsets.insert(field_name.to_string(), off);
                    break;
                }
            }
        }
    }
    Some(offsets)
}

/// 解析本机 format 文件并注入 OFFSETS_MAP 索引 0
fn offsets_inject(bpf: &mut Ebpf) -> bool {
    let Some(root) = tracefs_root() else {
        crate::info!("eBPF: tracefs 不可用");
        return false;
    };

    let offsets = (|| {
        let fork_fields = tracepoint_parse(root, "sched", "sched_process_fork")?;
        let rename_fields = tracepoint_parse(root, "task", "task_rename")?;
        Some(EbpfOffsets {
            fork_child_pid: *fork_fields.get("child_pid")?,
            fork_child_comm: *fork_fields.get("child_comm")?,
            rename_newcomm: *rename_fields.get("newcomm")?,
        })
    })();
    let Some(offsets) = offsets else {
        crate::info!("eBPF: tracepoint format 解析失败 [{}]", root);
        return false;
    };

    let Some(map) = bpf.map_mut("OFFSETS_MAP") else {
        crate::info!("eBPF: 未找到 OFFSETS_MAP");
        return false;
    };
    let Ok(mut offsets_map) = Array::<_, EbpfOffsets>::try_from(map) else {
        crate::info!("eBPF: OFFSETS_MAP 类型转换失败");
        return false;
    };
    if offsets_map.set(0, &offsets, 0).is_err() {
        crate::info!("eBPF: OFFSETS_MAP 注入失败");
        return false;
    }

    crate::info!("eBPF: 偏移注入 [{}] fork[child_pid={}, child_comm={}] rename[newcomm={}]",
        root, offsets.fork_child_pid, offsets.fork_child_comm, offsets.rename_newcomm);
    true
}

/// 构建白名单键：每个包名生成前 8 字节与末 8 字节键
pub fn comm_keys_build<'a, I: IntoIterator<Item = &'a String>>(pkgs: I) -> Vec<[u8; 8]> {
    let mut entries: Vec<[u8; 8]> = Vec::new();
    for pkg in pkgs {
        let bytes = pkg.as_bytes();
        if bytes.is_empty() { continue; }
        let mut prefix_key = [0u8; 8];
        let prefix_len = bytes.len().min(8);
        prefix_key[..prefix_len].copy_from_slice(&bytes[..prefix_len]);
        entries.push(prefix_key);
        if bytes.len() > 8 {
            let mut suffix_key = [0u8; 8];
            let start = bytes.len() - 8;
            suffix_key.copy_from_slice(&bytes[start..]);
            entries.push(suffix_key);
        }
    }
    entries.sort();
    entries.dedup();
    entries
}

/// 同步白名单到 BPF map，返回 true 表示容量不足需重载
pub fn comm_map_init(ctx: &mut BpfCtx, pkgs: &std::collections::HashSet<String>, comm_capacity: &mut u32) -> bool {
    let bpf = match &mut ctx.bpf { Some(b) => b, None => return false };
    let entries = comm_keys_build(pkgs.iter());

    if entries.len() > *comm_capacity as usize {
        crate::info!("eBPF: 白名单容量不足 (需 {} > 现 {})", entries.len(), comm_capacity);
        return true;
    }

    let Some(map) = bpf.map_mut("TARGET_COMM_MAP") else {
        crate::info!("eBPF: 未找到 TARGET_COMM_MAP");
        return false;
    };
    let Ok(mut target_map) = BpfHashMap::<_, [u8; 8], u32>::try_from(map) else {
        crate::info!("eBPF: TARGET_COMM_MAP 类型转换失败");
        return false;
    };

    let old_keys: Vec<[u8; 8]> = target_map.keys().filter_map(|r| r.ok()).collect();
    for key in &old_keys {
        let _ = target_map.remove(key);
    }

    let mut count = 0;
    for key in &entries {
        if target_map.insert(key, 1, 0).is_ok() { count += 1; }
    }

    crate::info!("eBPF: 白名单已配置, {} 个包名 > {} 条匹配规则", pkgs.len(), count);
    false
}

/// 写入 APPLIED_MAP tid → CPU mask
pub fn applied_set(ctx: &mut BpfCtx, tid: i32, cpus_bits0: u64) {
    let bpf = match &mut ctx.bpf { Some(b) => b, None => return };
    let Some(map) = bpf.map_mut("APPLIED_MAP") else { return };
    let Ok(mut applied) = BpfHashMap::<_, u32, u64>::try_from(map) else { return };
    let _ = applied.insert(&(tid as u32), cpus_bits0, 0);
}

/// 从 APPLIED_MAP 删除 tid
pub fn applied_del(ctx: &mut BpfCtx, tid: i32) {
    let bpf = match &mut ctx.bpf { Some(b) => b, None => return };
    let Some(map) = bpf.map_mut("APPLIED_MAP") else { return };
    let Ok(mut applied) = BpfHashMap::<_, u32, u64>::try_from(map) else { return };
    let _ = applied.remove(&(tid as u32));
}

/// 清空 APPLIED_MAP
pub fn applied_clear(ctx: &mut BpfCtx) {
    let bpf = match &mut ctx.bpf { Some(b) => b, None => return };
    let Some(map) = bpf.map_mut("APPLIED_MAP") else { return };
    let Ok(mut m) = BpfHashMap::<_, u32, u64>::try_from(map) else { return };
    let keys: Vec<u32> = m.keys().filter_map(|r| r.ok()).collect();
    for k in &keys {
        let _ = m.remove(k);
    }
}

/// 从 comm 16 字节反查包名（与 BPF 双键逻辑一致：精确优先，其次前缀/后缀）
pub fn comm_to_pkg(comm: &str, cfg: &config::AppConfig) -> Option<String> {
    if cfg.pkg_set.contains(comm) {
        return Some(comm.to_string());
    }
    if comm.len() >= 15 {
        for pkg in &cfg.pkg_set {
            if pkg.starts_with(comm) { return Some(pkg.clone()); }
        }
        for pkg in &cfg.pkg_set {
            if pkg.ends_with(comm) { return Some(pkg.clone()); }
        }
    }
    None
}
