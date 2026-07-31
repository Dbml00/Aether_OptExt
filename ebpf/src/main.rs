#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::bpf_get_current_comm, helpers::bpf_get_current_pid_tgid,
    macros::{map, tracepoint},
    maps::{Array, HashMap, LruHashMap, RingBuf},
    programs::TracePointContext,
};

const EVENT_FORK: u32 = 1;
const EVENT_EXEC: u32 = 2;
const EVENT_RENAME: u32 = 3;
const EVENT_EXIT: u32 = 4;

/// 4 类 tracepoint 字段布局：fork 读 child_pid/child_comm，rename 读 newcomm
/// 用户态解析 format 文件注入的字段偏移，因内核版本设备而异禁止硬编码
#[repr(C)]
#[derive(Clone, Copy)]
struct TracepointOffsets {
    fork_child_pid: u32,
    fork_child_comm: u32,
    rename_newcomm: u32,
}

/// 进程事件，布局需与用户态 EbpfProcEvent 一致
#[repr(C)]
struct ProcEvent {
    pid: i32,
    tid: i32,
    comm: [u8; 16],
    event_type: u32,
}

const MAP_CAPACITY: u32 = 16 << 9;  // 8192 条白名单键（~4096 包×前后缀），覆盖全部规则包名
const APPLIED_CAPACITY: u32 = 8192;

/// 白名单键为包名前 8 字节或末 8 字节
#[map]
static TARGET_COMM_MAP: HashMap<[u8; 8], u32> = HashMap::with_max_entries(MAP_CAPACITY, 0);

/// 已应用亲和性表 tid 到 CPU mask，LruHashMap 配合 ESRCH 兜底
#[map]
static APPLIED_MAP: LruHashMap<u32, u64> = LruHashMap::with_max_entries(APPLIED_CAPACITY, 0);

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// 用户态注入的 tracepoint 字段偏移单条 Array 索引 0
#[map]
static OFFSETS_MAP: Array<TracepointOffsets> = Array::with_max_entries(1, 0);

/// 读取偏移，fork_child_pid 为 0 视为未注入返回 None
#[inline(always)]
fn offsets_load() -> Option<TracepointOffsets> {
    OFFSETS_MAP.get(0).and_then(|o| {
        if o.fork_child_pid != 0 {
            Some(*o)
        } else {
            None
        }
    })
}

#[inline(always)]
fn applied_lookup(key: u32) -> bool {
    unsafe { APPLIED_MAP.get(&key) }.is_some()
}

/// 在 comm 16 字节上以 8 字节窗口滑动匹配白名单
#[inline(always)]
fn whitelist_matched(comm: &[u8; 16]) -> bool {
    for pos in 0..=8usize {
        let key: [u8; 8] = comm[pos..pos + 8].try_into().unwrap_or([0u8; 8]);
        if unsafe { TARGET_COMM_MAP.get(&key) }.is_some() {
            return true;
        }
    }
    false
}

#[inline(always)]
fn submit_event(event: ProcEvent) {
    if let Some(mut entry) = EVENTS.reserve(0) {
        entry.write(event);
        entry.submit(0);
    }
}

/// 解析 fork 字段，统一用 parent_tgid 作为 pid 确保 clone 共享 TGID，tid 为 child_pid
#[inline(always)]
fn fork_parse(ctx: &TracePointContext, offsets: &TracepointOffsets) -> (i32, i32, [u8; 16]) {
    let pid_tgid = bpf_get_current_pid_tgid();
    let parent_tgid = (pid_tgid >> 32) as u32;
    let child_pid = unsafe { ctx.read_at::<i32>(offsets.fork_child_pid as usize).unwrap_or(0) };
    let child_comm =
        unsafe { ctx.read_at::<[u8; 16]>(offsets.fork_child_comm as usize).unwrap_or([0u8; 16]) };
    (parent_tgid as i32, child_pid, child_comm)
}

#[tracepoint(name = "sched_process_fork", category = "sched")]
fn sched_process_fork(ctx: TracePointContext) -> u32 {
    let Some(offsets) = offsets_load() else {
        return 0;
    };
    let pid_tgid = bpf_get_current_pid_tgid();
    let parent_tid = (pid_tgid & 0xFFFFFFFF) as u32;

    let (pid, tid, comm) = fork_parse(&ctx, &offsets);

    // 父线程已管理 或 comm 命中白名单才上报
    let is_tracked = applied_lookup(parent_tid);
    if !is_tracked && !whitelist_matched(&comm) {
        return 0;
    }

    if is_tracked {
        let _ = APPLIED_MAP.insert(&(tid as u32), &0, 0);
    }

    submit_event(ProcEvent {
        pid,
        tid,
        comm,
        event_type: EVENT_FORK,
    });
    0
}

#[tracepoint(name = "sched_process_exec", category = "sched")]
fn sched_process_exec(ctx: TracePointContext) -> u32 {
    let _ = ctx;
    let pid_tgid = bpf_get_current_pid_tgid();
    let tid = (pid_tgid & 0xFFFFFFFF) as u32;
    let tgid = (pid_tgid >> 32) as u32;
    let comm: [u8; 16] = bpf_get_current_comm().unwrap_or_default();

    if !whitelist_matched(&comm) {
        return 0;
    }

    submit_event(ProcEvent {
        pid: tgid as i32,
        tid: tid as i32,
        comm,
        event_type: EVENT_EXEC,
    });
    0
}

/// 捕获线程改名，已管理线程直接放行否则白名单匹配
#[tracepoint(name = "task_rename", category = "task")]
fn task_rename(ctx: TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tid = (pid_tgid & 0xFFFFFFFF) as u32;
    if tid == 0 {
        return 0;
    }
    let tgid = (pid_tgid >> 32) as u32;

    let tracked = applied_lookup(tid);

    let Some(offsets) = offsets_load() else {
        return 0;
    };
    let new_comm =
        unsafe { ctx.read_at::<[u8; 16]>(offsets.rename_newcomm as usize).unwrap_or([0u8; 16]) };

    if !tracked && !whitelist_matched(&new_comm) {
        return 0;
    }

    submit_event(ProcEvent {
        pid: tgid as i32,
        tid: tid as i32,
        comm: new_comm,
        event_type: EVENT_RENAME,
    });
    0
}

/// 捕获线程退出，已管理线程清理 APPLIED_MAP
#[tracepoint(name = "sched_process_exit", category = "sched")]
fn sched_process_exit(_ctx: TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tid = (pid_tgid & 0xFFFFFFFF) as u32;
    let tgid = (pid_tgid >> 32) as u32;

    if !applied_lookup(tid) {
        return 0;
    }

    let _ = APPLIED_MAP.remove(&tid);

    submit_event(ProcEvent {
        pid: tgid as i32,
        tid: tid as i32,
        comm: [0u8; 16],
        event_type: EVENT_EXIT,
    });
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
