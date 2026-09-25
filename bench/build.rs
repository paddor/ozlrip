//! Records the rustflags the bench was built with, so result rows can say
//! whether they come from a portable or a native build.

use std::env;

fn main() {
    let rustflags = env::var("CARGO_ENCODED_RUSTFLAGS")
        .unwrap_or_default()
        .replace('\x1f', " ");
    println!("cargo:rustc-env=OZLRIP_BENCH_RUSTFLAGS={rustflags}");
    println!("cargo:rerun-if-env-changed=CARGO_ENCODED_RUSTFLAGS");
}
