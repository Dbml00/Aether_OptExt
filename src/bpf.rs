use std::mem;
use crate::config;

pub struct BpfCtx {
    pub ok: bool,
    pub ring_fd: i32,
    pub prog_fd: i32,   // ringbuf 程序 (exec+fork)
    pub prog2_fd: i32,  // 内核绑核程序 (仅 exec)
    pub pe_fd: i32,     // exec ringbuf
    pub pe_fd2: i32,    // fork ringbuf
    pub pe_fd3: i32,    // exec 内核绑核
    pub rule_map_fd: i32,
}

impl Drop for BpfCtx {
    fn drop(&mut self) {
        for fd in [self.pe_fd3, self.pe_fd2, self.pe_fd, self.prog2_fd, self.prog_fd, self.rule_map_fd, self.ring_fd] {
            if fd >= 0 { unsafe { let _ = libc::close(fd); } }
        }
    }
}

pub fn probe(enable: bool) -> BpfCtx {
    if !enable { return BpfCtx { ok: false, ring_fd: -1, prog_fd: -1, prog2_fd: -1, pe_fd: -1, pe_fd2: -1, pe_fd3: -1, rule_map_fd: -1 }; }

    #[repr(C, packed)]
    struct M { mt: u32, ks: u32, vs: u32, me: u32, mf: u32, pad: [u32;6] }
    #[repr(C, packed)]
    struct P { pt: u32, ic: u32, ins: u64, lic: u64, ll: u32, ls: u32, lb: u64, kv: u32, pad: u32 }

    unsafe {
        // === RINGBUF map (type=27) ===
        let ma = M { mt: 27, ks: 0, vs: 0, me: 4096, mf: 0, pad: [0;6] };
        let rfd = libc::syscall(280, 0, &ma as *const _, mem::size_of::<M>()) as i32;
        if rfd < 0 { return bpf_fail(); }

        // === 规则 HASH map (type=1, key=16byte comm, value=8byte cpumask) ===
        let rm = M { mt: 1, ks: 16, vs: 8, me: 1024, mf: 0, pad: [0;6] };
        let rufd = libc::syscall(280, 0, &rm as *const _, mem::size_of::<M>()) as i32;
        if rufd < 0 { libc::close(rfd); return bpf_fail(); }

        // === 程序1: ringbuf 输出 (12 insns, 输出 tgid) ===
        let mut ins1: [u64; 12] = [
            0x00000000000016bf,  // 0: r6=r1
            0x0000000e00000085,  // 1: call 14 (get_pid_tgid)
            0x0000002000000077,  // 2: r0>>=32 (tgid)
            0x00000000fffc0a63,  // 3: *(u32*)(r10-4)=r0
            0x0000000000001118,  // 4: lddw r1, ring_fd
            0x0000000000000000,  // 5: 2nd half
            0x000000000000a2bf,  // 6: r2=r10
            0xfffffffc00000207,  // 7: r2+=-4
            0x00000004000003b7,  // 8: r3=4
            0x00000000000004b7,  // 9: r4=0
            0x0000008200000085,  // 10: call 130
            0x0000000000000095,  // 11: exit
        ];
        ins1[4] = 0x18u64 | (1u64 << 8) | (1u64 << 12) | ((rfd as u64 & 0xFFFFFFFF) << 32);

        let lic: [u8; 4] = [71, 80, 76, 0];
        let mut vlog = [0u8; 4096];
        let pa1 = P { pt: 5, ic: 12, ins: &ins1 as *const _ as u64, lic: lic.as_ptr() as u64, ll: 1, ls: 4096, lb: &mut vlog as *mut _ as u64, kv: 0, pad: 0 };
        let pfd = libc::syscall(280, 5, &pa1 as *const _, mem::size_of::<P>()) as i32;
        if pfd < 0 { libc::close(rfd); libc::close(rufd); return bpf_fail(); }

        // === 程序2: exec 内核绑核 (C 编译, 25 insns) ===
        let mut ins2: [u64; 25] = [
            0x00000000000001b7,  // r0=0
            0x00000000fff81a7b,  // *(u64*)(r10-8)=0
            0x00000000fff01a7b,  // *(u64*)(r10-16)=0
            0x000000000000a6bf,  // r6=r10
            0xfffffff000000607,  // r6+=-16
            0x00000000000061bf,  // r1=r6
            0x00000010000002b7,  // r2=16
            0x0000001000000085,  // call 16 (get_comm)
            0x0000000000000118,  // lddw r1, rule_map_fd
            0x0000000000000000,  // 2nd half
            0x00000000000062bf,  // r2=r6
            0x0000000100000085,  // call 1 (map_lookup)
            0x00000000000a0015,  // if r0==0 goto 22
            0x0000000000000179,  // r1=*(u64*)(r0+0)
            0x00000000ffe81a7b,  // *(u64*)(r10-24)=r1
            0x0000000000070115,  // if r0!=0 goto 7
            0x0000002300000085,  // call 35 (get_task)
            0x0000000000050015,  // if r0==0 goto 23
            0x000000000000a3bf,  // r3=r10
            0xffffffe800000307,  // r3+=-24
            0x00000000000001bf,  // r1=r0
            0x00000008000002b7,  // r2=8
            0x000000d700000085,  // call 215 (setaffinity)
            0x00000000000000b7,  // r0=0
            0x0000000000000095,  // exit
        ];
        ins2[8] = 0x18u64 | (1u64 << 8) | (1u64 << 12) | ((rufd as u64 & 0xFFFFFFFF) << 32);

        let pa2 = P { pt: 7, ic: 25, ins: &ins2 as *const _ as u64, lic: lic.as_ptr() as u64, ll: 1, ls: 4096, lb: &mut vlog as *mut _ as u64, kv: 0, pad: 0 };
        let mut p2fd = libc::syscall(280, 5, &pa2 as *const _, mem::size_of::<P>()) as i32;
        // PERF_EVENT(7) 不行则降级到 TRACEPOINT(5)
        if p2fd < 0 {
            let pa2b = P { pt: 5, ic: 25, ins: &ins2 as *const _ as u64, lic: lic.as_ptr() as u64, ll: 1, ls: 4096, lb: &mut vlog as *mut _ as u64, kv: 0, pad: 0 };
            p2fd = libc::syscall(280, 5, &pa2b as *const _, mem::size_of::<P>()) as i32;
        }
        if p2fd < 0 {
            info!("eBPF: helper 215 不可用, 回退 ringbuf");
            libc::close(pfd); libc::close(rfd); libc::close(rufd);
            return BpfCtx { ok: true, ring_fd: rfd, prog_fd: pfd, prog2_fd: -1, pe_fd: -1, pe_fd2: -1, pe_fd3: -1, rule_map_fd: rufd };
        }

        // === 挂载 tracepoint ===
        let attach = |tp_name: &str, prog_fd: i32| -> i32 {
            let id_path = format!("/sys/kernel/tracing/events/sched/{}/id", tp_name);
            let id = match std::fs::read_to_string(&id_path) { Ok(s) => s.trim().parse::<u64>().unwrap_or(0), Err(_) => 0 };
            if id == 0 { return -1; }
            let mut attr: [u64; 16] = [0u64; 16];
            attr[0] = 2 | (64u64 << 32);
            attr[1] = id;
            let fd = libc::syscall(241, &attr as *const _, -1i32, 0, -1i32, 0i32) as i32;
            if fd < 0 { return -1; }
            if libc::ioctl(fd, 0x40042408, prog_fd) < 0 { libc::close(fd); return -1; }
            libc::ioctl(fd, 0x2400, 0);
            fd
        };

        let pe1 = attach("sched_process_exec", pfd);
        let pe2 = attach("sched_process_fork", pfd);
        let pe3 = attach("sched_process_exec", p2fd);  // 内核绑核程序只挂 exec

        info!("eBPF: ok (ringbuf={} rule_map={})", rfd, rufd);
        BpfCtx { ok: true, ring_fd: rfd, prog_fd: pfd, prog2_fd: p2fd, pe_fd: pe1, pe_fd2: pe2, pe_fd3: pe3, rule_map_fd: rufd }
    }
}

fn bpf_fail() -> BpfCtx {
    BpfCtx { ok: false, ring_fd: -1, prog_fd: -1, prog2_fd: -1, pe_fd: -1, pe_fd2: -1, pe_fd3: -1, rule_map_fd: -1 }
}

/// 写入一条规则到 BPF HASH map
pub fn set_rule(ctx: &BpfCtx, comm: &[u8; 16], cpumask: u64) -> bool {
    if !ctx.ok || ctx.rule_map_fd < 0 { return false; }
    let key = *comm;
    let val = cpumask;
    #[repr(C, packed)]
    struct E { mfd: u32, k: u64, v: u64, op: u64 }
    let e = E { mfd: ctx.rule_map_fd as u32, k: &key as *const _ as u64, v: &val as *const _ as u64, op: 0 };
    unsafe { libc::syscall(280, 2, &e as *const _, mem::size_of::<E>()) };
    true
}

/// 从 config::Rule 同步所有线程规则到 BPF map
pub fn sync_rules(ctx: &BpfCtx, rules: &[config::Rule]) {
    if !ctx.ok || ctx.rule_map_fd < 0 { return; }
    let mut n = 0usize;
    for r in rules {
        if r.thread.is_empty() { continue; } // 进程级规则不走内核
        let mut comm = [0u8; 16];
        let bytes = r.thread.as_bytes();
        let len = bytes.len().min(15);
        comm[..len].copy_from_slice(&bytes[..len]);
        // 解析 cpus 字符串为 u64 bitmask
        let mut mask = 0u64;
        for part in r.cpus.split(',') {
            let part = part.trim();
            if part.is_empty() { continue; }
            if let Some((a, b)) = part.split_once('-') {
                let s: usize = a.parse().unwrap_or(0);
                let e: usize = b.parse().unwrap_or(s);
                for cpu in s..=e.min(63) { mask |= 1u64 << cpu; }
            } else if let Ok(cpu) = part.parse::<usize>() {
                if cpu < 64 { mask |= 1u64 << cpu; }
            }
        }
        if set_rule(ctx, &comm, mask) {
            n += 1;
        }
    }
    info!("eBPF: 同步 {} 条规则到内核", n);
}

/// 从 ringbuf 读取新 PID (非阻塞)
pub fn poll_new_pids(ctx: &BpfCtx) -> Vec<i32> {
    let mut pids = Vec::new();
    if !ctx.ok { return pids; }
    let mut buf = [0u8; 4096];
    loop {
        let n = unsafe { libc::read(ctx.ring_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n <= 0 { break; }
        let mut off = 0usize;
        while off + 8 <= n as usize {
            let hdr = u64::from_ne_bytes(buf[off..off+8].try_into().unwrap_or([0;8]));
            let len = (hdr >> 48) as usize;
            if len < 8 || off + len > n as usize { off += 8; continue; }
            if len >= 12 {
                let pid = i32::from_ne_bytes(buf[off+8..off+12].try_into().unwrap_or([0;4]));
                if pid > 0 { pids.push(pid); }
            }
            off += (len + 7) & !7;
        }
    }
    pids
}
