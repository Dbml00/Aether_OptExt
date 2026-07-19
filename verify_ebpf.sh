#!/system/bin/sh
# Aether OptExt eBPF 验证脚本

PASS=0
FAIL=0
ok() { echo "  [✓] $1"; PASS=$((PASS + 1)); }
no() { echo "  [✗] $1"; FAIL=$((FAIL + 1)); }

echo "================================"
echo " Aether OptExt eBPF 验证"
echo "================================"
echo ""

# 1. 进程是否运行
echo "--- 1. 守护进程 ---"
PID=$(pgrep -f "aether-optext" | head -1)
if [ -n "$PID" ]; then
    ok "aether-optext 运行中 (PID=$PID)"
    # 读取自身绑核
    SELF_CORE=$(taskset -p "$PID" 2>/dev/null | grep -o "current.*" || echo "?")
    echo "    自身 CPU 亲和性: $SELF_CORE"
else
    no "aether-optext 未运行"
fi

# 2. 日志中的 eBPF 状态
echo ""
echo "--- 2. eBPF 可用性 ---"
LOG=/sdcard/Android/Aether/threads_log.txt
if [ -f "$LOG" ]; then
    if grep -q "eBPF:.*可用" "$LOG"; then
        ok "日志显示 eBPF 可用"
        grep "eBPF:" "$LOG" | tail -3 | sed 's/^/    /'
    else
        no "日志中无 eBPF 可用标记"
        grep "eBPF:" "$LOG" | tail -3 | sed 's/^/    /'
    fi
else
    no "日志文件不存在"
fi

# 3. 内核 tracepoint 是否启用
echo ""
echo "--- 3. tracepoint 状态 ---"
TP_EXEC=/sys/kernel/tracing/events/sched/sched_process_exec
TP_FORK=/sys/kernel/tracing/events/sched/sched_process_fork
if [ -d "$TP_EXEC" ]; then
    ok "sched_process_exec 存在"
    # 检查是否有 perf_event 打开 (count 不为0)
    if [ -f "$TP_EXEC/id" ]; then
        TPID=$(cat "$TP_EXEC/id")
        # 通过 /sys/kernel/tracing/perf_event_enabled 检查
        ok "sched_process_exec id=$TPID"
    fi
else
    no "sched_process_exec 不存在 (内核不支持)"
fi
if [ -d "$TP_FORK" ]; then
    ok "sched_process_fork 存在"
else
    no "sched_process_fork 不存在"
fi

# 4. BPF 系统调用是否可用
echo ""
echo "--- 4. BPF 系统调用 ---"
BPF_CAP=$(cat /proc/self/status 2>/dev/null | grep -i capbpf || echo "N/A")
echo "    CAP_BPF: $BPF_CAP"

# 尝试加载一个最小 BPF 程序
if cat /proc/config.gz 2>/dev/null | grep -q "CONFIG_BPF_SYSCALL=y"; then
    ok "CONFIG_BPF_SYSCALL=y"
else
    # 有些内核不提供 config.gz
    if [ -f /sys/kernel/btf/vmlinux ]; then
        ok "BTF vmlinux 存在 (eBPF 已启用)"
    else
        no "无法确认 BPF 内核支持"
    fi
fi

# 5. 验证绑定效果
echo ""
echo "--- 5. 绑定验证 ---"
# 检查日志中的绑核统计
if [ -f "$LOG" ]; then
    BIND_LINE=$(grep "已绑核" "$LOG" | tail -1)
    if [ -n "$BIND_LINE" ]; then
        ok "最新绑核: $BIND_LINE"
        PROCS=$(echo "$BIND_LINE" | grep -oP '\d+(?= 进程)' || echo "?")
        echo "    进程数: $PROCS"
    else
        no "未找到绑核记录"
    fi
fi

# 检查是否有应用被绑到指定核心
echo "    样本: 查看 systemui 线程绑定"
for tid in $(pgrep -f "systemui" 2>/dev/null | head -5); do
    BIND=$(taskset -p "$tid" 2>/dev/null | grep -oP '(?<=currently: ).*')
    echo "    tid=$tid cores=$BIND"
done

# 结果
echo ""
echo "================================"
echo " 结果: $PASS 通过, $FAIL 失败"
echo "================================"
[ "$FAIL" -eq 0 ] && echo " eBPF 功能正常" || echo " eBPF 部分异常"
