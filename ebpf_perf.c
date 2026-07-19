
typedef unsigned int u32;
typedef unsigned long long u64;
#define SEC(n) __attribute__((section(n),used))
static u64 (*bpf_get_current_comm)(void *buf, u32 s) = (void*)16;
static void*(*bpf_map_lookup_elem)(void *m, const void *k) = (void*)1;
static void*(*bpf_get_current_task)(void) = (void*)35;
static long (*bpf_sched_setaffinity)(void *t, u64 s, void *c) = (void*)215;
struct {u32 t,ks,vs,me,mf,pad[6];} rm SEC(".maps") = {.t=1,.ks=16,.vs=8,.me=1024};
SEC("perf_event")
int f(void *ctx) {
    char c[16]={}; u64 *m,ms=0; void *t;
    bpf_get_current_comm(c,sizeof(c));
    m=bpf_map_lookup_elem(&rm,c); if(!m)return 0;
    ms=*m; if(!ms)return 0;
    t=bpf_get_current_task(); if(!t)return 0;
    bpf_sched_setaffinity(t,sizeof(ms),&ms); return 0;
}
char _l[] SEC("license") = "GPL";
