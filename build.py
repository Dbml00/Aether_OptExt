#!/usr/bin/env python3
import os, sys, shutil, subprocess, zipfile
from datetime import datetime
from pathlib import Path

VERSION = "1.0.0"
SCRIPT_DIR = Path(__file__).resolve().parent
OUT_DIR = SCRIPT_DIR / "out"
MODULE_DIR = SCRIPT_DIR / "magisk_module"
MODULE_ZIP = OUT_DIR / f"Aether-OptExt_{datetime.now():%Y%m%d_%H%M%S}.zip"
TARGET = "aarch64-linux-android"

def info(m): print(f"[INFO] {m}")
def warn(m): print(f"[WARN] {m}")
def die(m): print(f"[ERROR] {m}"); sys.exit(1)

def gen_ebpf_bytecode():
    """编译 eBPF C 源码 → 生成 Rust 字节码"""
    clang = find_bpf_clang()
    if not clang: info("eBPF: 无 BPF target clang, 跳过"); return
    
    c_file = SCRIPT_DIR / "ebpf_kern.c"
    o_file = SCRIPT_DIR / "ebpf_target.o"
    if not c_file.exists(): info("eBPF: ebpf_kern.c 不存在, 跳过"); return
    
    r = subprocess.run([str(clang), "-target", "bpf", "-O2", "-c", str(c_file), "-o", str(o_file)],
                       capture_output=True, text=True)
    if r.returncode != 0: die(f"eBPF 编译失败: {r.stderr[:200]}")
    
    # 从 .o 提取字节码
    import struct
    with open(o_file, 'rb') as f: data = f.read()
    shoff = struct.unpack_from('<Q', data, 40)[0]
    shnum = struct.unpack_from('<H', data, 60)[0]
    shstrndx = struct.unpack_from('<H', data, 62)[0]
    shstr_off = struct.unpack_from('<Q', data, shoff + shstrndx*64 + 24)[0]
    
    progs = {}  # name → [insns]
    for i in range(shnum):
        off = shoff + i*64
        n_off = struct.unpack_from('<I', data, off)[0]
        n_end = data.find(b'\x00', shstr_off + n_off)
        name = data[shstr_off+n_off:n_end].decode() if n_end > shstr_off else ''
        if not name or name.startswith('.') or name == 'license': continue
        size = struct.unpack_from('<Q', data, off+32)[0]
        doff = struct.unpack_from('<Q', data, off+24)[0]
        if size == 0: continue
        insns = []
        for j in range(0, size, 8):
            insns.append(f"0x{struct.unpack_from('<Q', data, doff+j)[0]:016x}")
        progs[name] = insns
        info(f"eBPF 程序: {name} ({len(insns)} insns)")
    
    if not progs: info("eBPF: 未找到程序段"); return
    
    # 提取重定位信息
    relocs = {}
    for i in range(shnum):
        off = shoff + i*64
        n_off = struct.unpack_from('<I', data, off)[0]
        n_end = data.find(b'\x00', shstr_off + n_off)
        name = data[shstr_off+n_off:n_end].decode() if n_end > shstr_off else ''
        if not name.startswith('.rel'): continue
        target = name[4:]  # .relXXX → XXX
        size = struct.unpack_from('<Q', data, off+32)[0]
        doff = struct.unpack_from('<Q', data, off+24)[0]
        relocs[target] = []
        for j in range(0, size, 16):
            insn_off = struct.unpack_from('<Q', data, doff + j)[0]
            relocs[target].append(insn_off // 8)
            _ = struct.unpack_from('<Q', data, doff + j + 8)[0]  # info
        info(f"eBPF 重定位: {target} → insn[{relocs[target][0]}]")
    
    # 生成 Rust 文件
    out = "// 自动生成, 由 build.py 创建\n// 不要手动修改\n\n"
    for name, insns in progs.items():
        var = name.replace('/', '_').replace('.', '_').upper()
        out += f"pub const {var}: [u64; {len(insns)}] = [\n"
        for insn in insns:
            out += f"    {insn},\n"
        out += "];\n"
        r = relocs.get(name, [])
        if r:
            out += f"pub const {var}_MAP_FD_INSN: usize = {r[0]};\n"
        out += "\n"
    
    (SCRIPT_DIR / "src" / "bpf_prog.rs").write_text(out, encoding="utf-8")
    info(f"eBPF: 已生成 src/bpf_prog.rs ({len(progs)} 个程序)")

def find_bpf_clang():
    ndk_dir = find_ndk_inner()
    if not ndk_dir: return None
    for tag in ["windows-x86_64", "linux-x86_64", "darwin-x86_64"]:
        tc = ndk_dir / "toolchains/llvm/prebuilt" / tag
        if not tc.exists(): continue
        for name in ["clang.exe", "clang"]:
            clang = tc / "bin" / name
            if clang.exists():
                try:
                    r = subprocess.run([str(clang), "-target", "bpf", "-O2", "-c", "-x", "c", "-", "-o", os.devnull],
                                       input="int x=0;", capture_output=True, text=True, timeout=5)
                    if r.returncode == 0: return clang
                except: pass
    return None

def find_ndk_inner():
    for base in [os.environ.get(k) for k in ["ANDROID_NDK_HOME", "ANDROID_HOME", "ANDROID_SDK_ROOT"]] + \
                [str(Path.home() / "Android/Sdk"), "C:/Users/shenz/AppData/Local/Android/Sdk"]:
        if not base: continue
        base = Path(base)
        ndk_dir = base if (base / "toolchains/llvm/prebuilt").exists() else next(iter(sorted(base.glob("ndk/*"), reverse=True)), None)
        if not ndk_dir: continue
        return ndk_dir
    return None

def find_ndk():
    """找 NDK 目录用于 Rust 交叉编译。返回 (ndk_dir, host_tag, linker) 或 (None, None, None)"""
    # 环境变量优先
    for var in ["ANDROID_NDK_HOME", "ANDROID_HOME", "ANDROID_SDK_ROOT"]:
        base = os.environ.get(var)
        if not base: continue
        base = Path(base)
        ndk_dir = base if (base / "toolchains/llvm/prebuilt").exists() else \
                  next(iter(sorted(base.glob("ndk/*"), reverse=True)), None)
        if not ndk_dir: ndk_dir = next(iter(sorted(base.glob("ndk-bundle/*"), reverse=True)), None)
        if not ndk_dir: continue
        for tag in ["windows-x86_64", "linux-x86_64", "darwin-x86_64", "darwin-aarch64"]:
            tc = ndk_dir / "toolchains/llvm/prebuilt" / tag
            if not tc.exists(): continue
            linker = tc / "bin" / "aarch64-linux-android21-clang"
            if sys.platform == "win32": linker = linker.with_suffix(".cmd")
            if linker.exists(): info(f"NDK: {ndk_dir}"); return ndk_dir, tag, linker
    # 常见路径兜底
    for base_str in [str(Path.home() / "Android/Sdk"), str(Path.home() / "AppData/Local/Android/Sdk"),
                     "C:/Users/shenz/AppData/Local/Android/Sdk"]:
        base = Path(base_str)
        if not base.exists(): continue
        ndk_dir = next(iter(sorted(base.glob("ndk/*"), reverse=True)), None)
        if not ndk_dir: ndk_dir = next(iter(sorted(base.glob("ndk-bundle/*"), reverse=True)), None)
        if not ndk_dir: continue
        for tag in ["windows-x86_64", "linux-x86_64", "darwin-x86_64", "darwin-aarch64"]:
            tc = ndk_dir / "toolchains/llvm/prebuilt" / tag
            if not tc.exists(): continue
            linker = tc / "bin" / "aarch64-linux-android21-clang"
            if sys.platform == "win32": linker = linker.with_suffix(".cmd")
            if linker.exists(): info(f"NDK: {ndk_dir}"); return ndk_dir, tag, linker
    warn("无 NDK"); return None, None, None

def build(ndk_info):
    info("编译...")
    os.chdir(SCRIPT_DIR)
    env = os.environ.copy()
    if ndk_info:
        ndk_dir, host_tag, linker = ndk_info
        tc = ndk_dir / "toolchains/llvm/prebuilt" / host_tag
        env["CC_aarch64_linux_android"] = str(linker)
        env["AR_aarch64_linux_android"] = str(tc / "bin/llvm-ar")
        cargo_dir = SCRIPT_DIR / ".cargo"
        cargo_dir.mkdir(exist_ok=True)
        (cargo_dir / "config.toml").write_text(f"[target.{TARGET}]\nlinker = \"{str(linker).replace(chr(92), chr(47))}\"\n")
    if subprocess.run(["cargo", "build", "--target", TARGET, "--release"], env=env).returncode != 0:
        die("编译失败")

def fix_line_ending(path):
    with open(path, 'rb') as f: d = f.read()
    if b'\r\n' not in d: return False
    with open(path, 'wb') as f: f.write(d.replace(b'\r\n', b'\n'))
    return True

def package():
    info("打包...")
    binary = SCRIPT_DIR / "target" / TARGET / "release" / "aether-optext"
    if not binary.exists(): binary = SCRIPT_DIR / "target" / "release" / "aether-optext"
    if not binary.exists(): die("编译产物未找到")
    OUT_DIR.mkdir(exist_ok=True)
    MODULE_ZIP.unlink(missing_ok=True)
    shutil.copy2(binary, MODULE_DIR / "aether-optext")
    os.chmod(MODULE_DIR / "aether-optext", 0o755)

    # 更新版本号
    now = datetime.now()
    ver = now.strftime("%m%d-ReleasePreview")
    vc = int(now.strftime("%y%m%d"))
    prop = MODULE_DIR / "module.prop"
    prop.write_text(
        f"id=aether-optext\nname=Aether OptExt\nversion={ver}\nversionCode={vc}\nauthor=NetizenNemo\n"
        "description=Aether OptExt - Android CPU affinity optimizer\n"
    )

    for f in MODULE_DIR.glob("**/*"):
        if f.suffix in (".sh", ".prop", ".json", ".md") or f.name == "updater-script":
            if fix_line_ending(f): info(f"换行符: {f.name}")
    with zipfile.ZipFile(MODULE_ZIP, "w", zipfile.ZIP_STORED) as z:
        for root, dirs, files in os.walk(MODULE_DIR):
            for f in files:
                full = Path(root) / f; rel = str(full.relative_to(MODULE_DIR)).replace("\\", "/")
                if rel.startswith(".") or "/." in rel: continue
                z.write(binary if rel == "aether-optext" else full, rel)

def main():
    gen_ebpf_bytecode()
    ndk_info = find_ndk()
    build(ndk_info)
    package()
    info(f"完成: {MODULE_ZIP.name} ({MODULE_ZIP.stat().st_size/1024:.0f}KB)")

if __name__ == "__main__":
    main()
