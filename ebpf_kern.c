// BPF 内核绑核程序 — 无 libbpf 依赖
// 编译: clang -target bpf -O2 -c ebpf_kern.c -o ebpf_kern.o

typedef unsigned int u32;
typedef unsigned long long u64;

#define SEC(name) __attribute__((section(name), used))

// 直接声明 BPF helper（无 libbpf 时用）
static u64 (*bpf_get_current_comm)(void *buf, u32 size) = (void *)16;
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static void *(*bpf_get_current_task)(void) = (void *)35;
static long (*bpf_sched_setaffinity)(void *task, u64 size, void *cpuset) = (void *)215;

struct {
    u32 type;
    u32 key_size;
    u32 value_size;
    u32 max_entries;
    u32 map_flags;
    u32 pad[6];
} rule_map __attribute__((section(".maps"))) = {
    .type = 1,        // BPF_MAP_TYPE_HASH
    .key_size = 16,   // comm[16]
    .value_size = 8,  // cpumask u64
    .max_entries = 1024,
};

SEC("tp/sched/sched_process_exec")
int on_exec(void *ctx) {
    char comm[16] = {};
    u64 *mask, cpumask = 0;
    void *task;

    bpf_get_current_comm(comm, sizeof(comm));
    mask = bpf_map_lookup_elem(&rule_map, comm);
    if (!mask) return 0;

    cpumask = *mask;
    if (!cpumask) return 0;

    task = bpf_get_current_task();
    if (!task) return 0;

    bpf_sched_setaffinity(task, sizeof(cpumask), &cpumask);
    return 0;
}

char _license[] SEC("license") = "GPL";
