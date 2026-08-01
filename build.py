import os
from pathlib import Path
import shutil
from datetime import datetime
import subprocess

SCRIPT_DIR = Path(__file__).parent.resolve()
OUTPUT_DIR = SCRIPT_DIR / "out"
BUILD_LOG = OUTPUT_DIR / "build.log"

def log_to_file(message):
    with open(BUILD_LOG, "a") as f:
        f.write(message + "\n")
    print(message)

def gen_ebpf_bytecode():
    # Fix for generic Linux environment (non-WSL)
    # The original script assumed a Windows path format (e.g., C:\...)
    as_posix = SCRIPT_DIR.as_posix()
    if ':' in as_posix:
        # Handling WSL paths (original logic)
        drive = as_posix.split(':', 1)[0].lower()
        wsl_path = "/mnt/" + drive + SCRIPT_DIR.as_posix().split(':', 1)[1]
    else:
        # Handling standard Linux paths
        wsl_path = SCRIPT_DIR.as_posix()
    
    log_to_file(f"Current WSL-compatible path: {wsl_path}")
    
    os.chdir(SCRIPT_DIR / "ebpf")
    
    # Check if we need to modify build commands if clang-14 isn't available
    # For GitHub ubuntu-latest, clang-14 is available.
    cmd = ["make", "LLVM_STRIP=/usr/lib/llvm-14/bin/llvm-strip", "wsl_path=" + wsl_path]
    
    log_to_file(f"Executing command: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    log_to_file(f"STDOUT:\n{result.stdout}")
    if result.stderr:
        log_to_file(f"STDERR:\n{result.stderr}")
        
    if result.returncode != 0:
        raise Exception(f"Failed to generate eBPF bytecode. See {BUILD_LOG}")

def build_rust_src():
    os.chdir(SCRIPT_DIR)
    
    cmd = ["cargo", "build", "--target", "aarch64-linux-android", "--release"]
    
    log_to_file(f"Executing command: {' '.join(cmd)}")
    # Pass environment variables correctly, especially ANDROID_NDK_HOME set by the workflow
    result = subprocess.run(cmd, capture_output=True, text=True, env=os.environ.copy())
    
    log_to_file(f"STDOUT:\n{result.stdout}")
    if result.stderr:
        log_to_file(f"STDERR:\n{result.stderr}")

    if result.returncode != 0:
        raise Exception(f"Failed to build Rust source. See {BUILD_LOG}")

def package_magisk_module():
    if not OUTPUT_DIR.exists():
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        
    time_stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_zip = OUTPUT_DIR / f"Aether-OptExt_{time_stamp}.zip"
    
    log_to_file(f"Packaging Magisk module to: {output_zip}")
    
    magisk_module_src = SCRIPT_DIR / "magisk_module"
    
    # Copy compiled binaries to correct locations within the magisk_module directory
    rust_bin = SCRIPT_DIR / "target/aarch64-linux-android/release/aether-opt"
    shutil.copy(rust_bin, magisk_module_src / "bin/aether-opt")
    
    # Assuming ebpf files are generated and need to be packaged
    # Modify as per the actual file outputs and structure required
    # shutil.copy(SCRIPT_DIR / "ebpf/ebpf_kern.o", magisk_module_src / "bin/ebpf_kern.o")

    # Create the zip file
    shutil.make_archive(str(output_zip).replace('.zip', ''), 'zip', root_dir=magisk_module_src)

def main():
    if OUTPUT_DIR.exists():
        shutil.rmtree(OUTPUT_DIR)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    with open(BUILD_LOG, "w") as f:
        f.write(f"Build started at {datetime.now()}\n\n")

    try:
        log_to_file("1. Generating eBPF bytecode...")
        gen_ebpf_bytecode()
        
        log_to_file("\n2. Building Rust source...")
        build_rust_src()
        
        log_to_file("\n3. Packaging Magisk module...")
        package_magisk_module()
        
        log_to_file("\nBuild completed successfully!")
        
    except Exception as e:
        log_to_file(f"\nBuild failed: {str(e)}")
        exit(1)

if __name__ == "__main__":
    main()
