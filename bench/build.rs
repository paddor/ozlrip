use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
};

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .expect("bench crate lives below workspace root");
    let openzl = env::var_os("OZLRIP_OPENZL_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace_root.join("tmp/openzl-upstream"));

    assert!(
        openzl.join("Makefile").exists(),
        "OpenZL checkout missing at {}; set OZLRIP_OPENZL_DIR",
        openzl.display()
    );
    build_openzl_lib(&openzl);

    cc::Build::new()
        .file("openzl_bench_shim.c")
        .include(openzl.join("include"))
        .include(openzl.join("src"))
        .include(openzl.join("deps/zstd/lib"))
        .include(openzl.join("deps/lz4/lib"))
        .flag_if_supported("-Wno-unused-parameter")
        .flag_if_supported("-Wno-unused-function")
        .compile("ozlrip_openzl_bench_shim");

    println!("cargo:rustc-link-search=native={}", openzl.display());
    println!(
        "cargo:rustc-link-search=native={}",
        openzl.join("deps/zstd/lib").display()
    );
    println!(
        "cargo:rustc-link-search=native={}",
        openzl.join("deps/lz4/lib").display()
    );
    println!("cargo:rustc-link-lib=static=openzl");
    println!("cargo:rustc-link-lib=static=zstd");
    println!("cargo:rustc-link-lib=static=lz4");
    if cfg!(target_os = "linux") {
        println!("cargo:rustc-link-lib=pthread");
        println!("cargo:rustc-link-lib=m");
    }

    println!("cargo:rerun-if-env-changed=OZLRIP_OPENZL_DIR");
    println!("cargo:rerun-if-changed=openzl_bench_shim.c");
}

fn build_openzl_lib(openzl: &Path) {
    if openzl.join("libopenzl.a").exists() {
        return;
    }
    let status = Command::new("make")
        .arg("BUILD_TYPE=OPT")
        .arg("libopenzl.a")
        .current_dir(openzl)
        .status()
        .expect("run OpenZL make");
    assert!(status.success(), "OpenZL libopenzl.a build failed");
}
