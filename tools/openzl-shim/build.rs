//! Builds upstream OpenZL (`libopenzl.a`) and the C shim.
//!
//! `OZLRIP_OPENZL_DIR` selects the OpenZL checkout (default
//! `tmp/openzl-upstream` in the ozlrip repo). `OZLRIP_OPENZL_MOREFLAGS` adds C
//! flags, e.g. `-march=native`; use a separate checkout per flag set because
//! `libopenzl.a` is only built when missing.

use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
};

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir
        .ancestors()
        .nth(2)
        .expect("openzl-shim lives at tools/openzl-shim");
    let openzl = env::var_os("OZLRIP_OPENZL_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| repo_root.join("tmp/openzl-upstream"));

    assert!(
        openzl.join("Makefile").exists(),
        "OpenZL checkout missing at {}; set OZLRIP_OPENZL_DIR",
        openzl.display()
    );
    let moreflags = env::var("OZLRIP_OPENZL_MOREFLAGS").unwrap_or_default();
    build_openzl_lib(&openzl, &moreflags);

    let mut shim = cc::Build::new();
    for flag in moreflags.split_whitespace() {
        shim.flag(flag);
    }
    shim.file("openzl_shim.c")
        .include(openzl.join("include"))
        .include(openzl.join("src"))
        .include(openzl.join("deps/zstd/lib"))
        .include(openzl.join("deps/lz4/lib"))
        .flag_if_supported("-Wno-unused-parameter")
        .flag_if_supported("-Wno-unused-function")
        .compile("ozlrip_openzl_shim");

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

    println!("cargo:rustc-env=OZLRIP_OPENZL_MOREFLAGS={moreflags}");
    println!("cargo:rerun-if-env-changed=OZLRIP_OPENZL_DIR");
    println!("cargo:rerun-if-env-changed=OZLRIP_OPENZL_MOREFLAGS");
    println!("cargo:rerun-if-changed=openzl_shim.c");
}

fn build_openzl_lib(openzl: &Path, moreflags: &str) {
    if openzl.join("libopenzl.a").exists() {
        return;
    }
    let status = Command::new("make")
        .arg("BUILD_TYPE=OPT")
        .arg(format!("MOREFLAGS={moreflags}"))
        .arg("libopenzl.a")
        .current_dir(openzl)
        .status()
        .expect("run OpenZL make");
    assert!(status.success(), "OpenZL libopenzl.a build failed");
}
