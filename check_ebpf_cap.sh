#!/system/bin/sh
# Aether OptExt — 内核 eBPF 能力检测

echo "================================"
echo " eBPF 能力检测"
echo "================================"
echo ""

# 1. 内核版本
KV=$(uname -r)
echo "内核版本: $KV"
echo "$KV" | grep -qE '^6\.' && echo "  → 内核 >= 6.0 (eBPF 特性齐全) ✓" || echo "  → 内核 < 6.0 (基础 eBPF 仍可用)"
echo ""

# 2. 内核配置
CFG=$(zcat /proc/config.gz 2>/dev/null)
[ -z "$CFG" ] && CFG=$(cat /proc/config 2>/dev/null)
for c in CONFIG_BPF_SYSCALL CONFIG_BPF_JIT CONFIG_HAVE_EBPF_JIT CONFIG_DEBUG_INFO_BTF CONFIG_BPF_EVENTS; do
    echo "$CFG" | grep -q "^${c}=y" && echo "  ✓ $c" || echo "  ✗ $c 未启用"
done
echo ""

# 3. BTF
if [ -f /sys/kernel/btf/vmlinux ]; then
    echo "  ✓ BTF vmlinux ($(ls -lh /sys/kernel/btf/vmlinux | awk '{print $5}'))"
else
    echo "  ✗ BTF 不可用"
fi
echo ""

# 4. tracepoint
for tp in sched_process_exec sched_process_fork sched_process_exit; do
    if [ -d "/sys/kernel/tracing/events/sched/$tp" ]; then
        echo "  ✓ $tp (id=$(cat /sys/kernel/tracing/events/sched/$tp/id))"
    else
        echo "  ✗ $tp 缺失"
    fi
done
echo ""

# 5. 当前是否在用 eBPF
pgrep "aether-optext" >/dev/null && echo "  ✓ aether-optext 运行中" || echo "  ✗ 守护进程未运行"
echo ""

echo "================================"
echo " A 方案 (ringbuf): 已实现 ✓"
[ -f /sys/kernel/btf/vmlinux ] && echo " B 方案 (内核侧): 可行 ✓" || echo " B 方案: 条件不足"
echo "================================"
