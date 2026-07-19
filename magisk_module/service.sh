#!/system/bin/sh
MODDIR=${0%/*}
CONFIG="/sdcard/Android/Aether/threads.json"

wait_until_login() {
    while [ "$(getprop sys.boot_completed)" != "1" ]; do
        sleep 2.5s
    done
    local test_file="/sdcard/Android/.PERMISSION_TEST_AETHER"
    true >"$test_file"
    while [ ! -f "$test_file" ]; do
        sleep 0.25s
        true >"$test_file"
    done
    rm "$test_file"
}

wait_until_login
rm -f /sdcard/Android/Aether/threads_log.txt 2>/dev/null
pkill "aether-optext" 2>/dev/null
sleep 1

if [ -f "$MODDIR/aether-optext" ]; then
    echo "[Aether] 启动进程..."
    "$MODDIR/aether-optext" -c "$CONFIG" -s 2 &
    echo "[Aether] PID $!"
else
    echo "[Aether] 二进制不存在: $MODDIR/aether-optext"
fi
