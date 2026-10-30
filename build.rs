use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=ebpf/rudp_ebpf.c");

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let out_file = out_dir.join("rudp_ebpf.o");

    if let Ok(prebuilt) = env::var("RUDP_PREBUILT_EBPF") {
        std::fs::copy(&prebuilt, &out_file).expect("failed to copy prebuilt eBPF object");
        return;
    }

    let clang = env::var("CLANG").unwrap_or_else(|_| "clang".to_string());
    let status = Command::new(&clang)
        .args([
            "-target",
            "bpf",
            "-mcpu=v3",
            "-O2",
            "-g",
            "-Wall",
            "-Werror",
            "-c",
            "ebpf/rudp_ebpf.c",
            "-o",
        ])
        .arg(&out_file)
        .status()
        .expect("failed to execute clang to compile ebpf/rudp_ebpf.c");

    if !status.success() {
        panic!("clang failed to compile ebpf/rudp_ebpf.c");
    }
}
