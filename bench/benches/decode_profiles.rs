use std::{
    env,
    fs,
    hint::black_box,
    io::Write,
    os::raw::c_void,
    path::PathBuf,
    process::Command,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use rust_openzl_sys as sys;

const DEFAULT_TARGET_MS: u64 = 100;
const ROUNDS: usize = 7;
const WARMUP: usize = 3;
#[cfg(feature = "no-checksum")]
const OZLRIP_IMPL: &str = "ozlrip-no-checksum";
#[cfg(not(feature = "no-checksum"))]
const OZLRIP_IMPL: &str = "ozlrip";
#[cfg(feature = "no-checksum")]
const OPENZL_C_IMPL: &str = "openzl-c-ffi-no-checksum";
#[cfg(not(feature = "no-checksum"))]
const OPENZL_C_IMPL: &str = "openzl-c-ffi";

fn main() {
    let target = Duration::from_millis(
        env::var("OZLRIP_BENCH_TARGET_MS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(DEFAULT_TARGET_MS),
    );
    let cases = generated_cases();
    let impl_filter = env::var("OZLRIP_BENCH_IMPL").ok();
    let case_filter = env::var("OZLRIP_BENCH_CASE").ok();
    let mut results = Vec::new();

    for case in &cases {
        if case_filter.as_deref().is_some_and(|filter| filter != case.name) {
            continue;
        }
        let mut ozlrip_mbps = None;
        if impl_filter
            .as_deref()
            .is_none_or(|filter| filter == OZLRIP_IMPL)
        {
            let ozlrip = bench_ozlrip(case, target);
            ozlrip_mbps = Some(ozlrip.decode_mbps);
            print_result(&ozlrip, None);
            results.push(ozlrip);
        }

        if impl_filter
            .as_deref()
            .is_none_or(|filter| filter == OPENZL_C_IMPL)
        {
            let c = bench_openzl_c_ffi(case, target);
            let relative = ozlrip_mbps.map(|base| base / c.decode_mbps);
            print_result(&c, relative);
            results.push(c);
        }
    }

    write_cache(&results);
}

fn generated_cases() -> Vec<BenchCase> {
    let mut cases = Vec::new();
    for (name, input) in [
        ("serial-random-4k", high_entropy_bytes(4 * 1024)),
        ("serial-random-1m", high_entropy_bytes(1024 * 1024)),
        ("serial-repeated-4k", repeated_bytes(4 * 1024)),
        ("serial-sequential-1m", sequential_bytes(1024 * 1024)),
    ] {
        let frame = rust_openzl::compress_serial(&input).expect("openzl-c-ffi compress_serial");
        assert_eq!(
            decode_ozlrip_with_bench_limits(&frame).expect("ozlrip decode generated frame"),
            input
        );
        assert_eq!(
            rust_openzl::decompress_serial(&frame).expect("openzl-c-ffi decompress_serial"),
            input
        );
        cases.push(BenchCase {
            name,
            profile: "serial",
            input_size: input.len(),
            frame,
        });
    }
    cases
}

fn high_entropy_bytes(len: usize) -> Vec<u8> {
    let mut state = 0x243f_6a88_85a3_08d3u64;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.push((state >> 32) as u8);
    }
    out
}

fn repeated_bytes(len: usize) -> Vec<u8> {
    b"openzl-rust-decode-benchmark\n"
        .iter()
        .copied()
        .cycle()
        .take(len)
        .collect()
}

fn sequential_bytes(len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| u8::try_from(index & 0xff).expect("masked to byte"))
        .collect()
}

fn bench_ozlrip(case: &BenchCase, target: Duration) -> BenchResult {
    let mut decoder = ozlrip::Decoder::new(bench_limits());
    let mut dst = Vec::new();
    let decode_ns = bench_loop(target, || {
        dst.clear();
        decoder
            .decode_into(black_box(&case.frame), black_box(&mut dst))
            .expect("ozlrip decode failed");
        black_box(&dst);
    });
    BenchResult::new(OZLRIP_IMPL, case, decode_ns)
}

fn decode_ozlrip_with_bench_limits(frame: &[u8]) -> Result<Vec<u8>, ozlrip::Error> {
    let mut output = Vec::new();
    ozlrip::decode_into(frame, &mut output, bench_limits())?;
    Ok(output)
}

fn bench_limits() -> ozlrip::Limits {
    ozlrip::Limits {
        max_expansion_ratio: usize::MAX,
        ..ozlrip::Limits::default()
    }
}

fn bench_openzl_c_ffi(case: &BenchCase, target: Duration) -> BenchResult {
    let mut decoder = OpenZlCDecoder::new(case.input_size);
    let decode_ns = bench_loop(target, || {
        decoder.decode(black_box(&case.frame));
        black_box(&decoder.dst);
    });
    BenchResult::new(OPENZL_C_IMPL, case, decode_ns)
}

struct OpenZlCDecoder {
    dctx: *mut sys::ZL_DCtx,
    dst: Vec<u8>,
}

impl OpenZlCDecoder {
    fn new(output_size: usize) -> Self {
        let dctx = unsafe { sys::ZL_DCtx_create() };
        assert!(!dctx.is_null(), "ZL_DCtx_create returned null");
        #[cfg(feature = "no-checksum")]
        {
            set_dparam(dctx, sys::ZL_DParam::ZL_DParam_stickyParameters, 1);
            set_dparam(
                dctx,
                sys::ZL_DParam::ZL_DParam_checkCompressedChecksum,
                sys::ZL_TernaryParam::ZL_TernaryParam_disable as i32,
            );
            set_dparam(
                dctx,
                sys::ZL_DParam::ZL_DParam_checkContentChecksum,
                sys::ZL_TernaryParam::ZL_TernaryParam_disable as i32,
            );
        }
        Self {
            dctx,
            dst: vec![0; output_size],
        }
    }

    fn decode(&mut self, frame: &[u8]) {
        let report = unsafe {
            sys::ZL_DCtx_decompress(
                self.dctx,
                self.dst.as_mut_ptr().cast::<c_void>(),
                self.dst.len(),
                frame.as_ptr().cast::<c_void>(),
                frame.len(),
            )
        };
        assert!(!sys::report_is_error(report), "openzl-c-ffi decode failed");
        assert_eq!(sys::report_value(report), self.dst.len());
    }
}

impl Drop for OpenZlCDecoder {
    fn drop(&mut self) {
        unsafe { sys::ZL_DCtx_free(self.dctx) };
    }
}

#[cfg(feature = "no-checksum")]
fn set_dparam(dctx: *mut sys::ZL_DCtx, param: sys::ZL_DParam, value: i32) {
    let report = unsafe { sys::ZL_DCtx_setParameter(dctx, param, value) };
    assert!(!sys::report_is_error(report), "ZL_DCtx_setParameter failed");
}

fn bench_loop<F: FnMut()>(target: Duration, mut f: F) -> f64 {
    for _ in 0..WARMUP {
        f();
    }

    let mut best = f64::MAX;
    for _ in 0..ROUNDS {
        let started = Instant::now();
        let mut iters = 0u64;
        while started.elapsed() < target {
            black_box(&mut f)();
            iters += 1;
        }
        let elapsed = started.elapsed();
        let ns_per_op = elapsed.as_nanos() as f64 / iters as f64;
        best = best.min(ns_per_op);
    }
    best
}

#[derive(Clone)]
struct BenchCase {
    name: &'static str,
    profile: &'static str,
    input_size: usize,
    frame: Vec<u8>,
}

struct BenchResult {
    impl_name: &'static str,
    input_name: &'static str,
    profile: &'static str,
    input_size: usize,
    frame_size: usize,
    decode_ns: f64,
    decode_mbps: f64,
    frame_ratio: f64,
    timestamp_unix: u64,
    git_rev: String,
}

impl BenchResult {
    fn new(impl_name: &'static str, case: &BenchCase, decode_ns: f64) -> Self {
        let decode_mbps = case.input_size as f64 / decode_ns * 1_000.0;
        let frame_ratio = case.frame.len() as f64 / case.input_size as f64;
        Self {
            impl_name,
            input_name: case.name,
            profile: case.profile,
            input_size: case.input_size,
            frame_size: case.frame.len(),
            decode_ns,
            decode_mbps,
            frame_ratio,
            timestamp_unix: timestamp_unix(),
            git_rev: git_rev(),
        }
    }

    fn to_json(&self) -> String {
        format!(
            concat!(
                r#"{{"impl": "{}", "input": "{}", "profile": "{}", "#,
                r#""input_size": {}, "frame_size": {}, "#,
                r#""frame_ratio": {:.4}, "decode_ns": {:.1}, "decode_mbps": {:.1}, "#,
                r#""timestamp_unix": {}, "git_rev": "{}"}}"#
            ),
            self.impl_name,
            self.input_name,
            self.profile,
            self.input_size,
            self.frame_size,
            self.frame_ratio,
            self.decode_ns,
            self.decode_mbps,
            self.timestamp_unix,
            self.git_rev,
        )
    }
}

fn print_result(result: &BenchResult, relative_to_c: Option<f64>) {
    if let Some(relative) = relative_to_c {
        println!(
            "{:<20} {:<25} {:>9.1} MB/s {:>10.1} ns/decode frame={} ratio={:.3} {}/{}={relative:.2}x",
            result.input_name,
            result.impl_name,
            result.decode_mbps,
            result.decode_ns,
            result.frame_size,
            result.frame_ratio,
            OZLRIP_IMPL,
            OPENZL_C_IMPL
        );
    } else {
        println!(
            "{:<20} {:<25} {:>9.1} MB/s {:>10.1} ns/decode frame={} ratio={:.3}",
            result.input_name,
            result.impl_name,
            result.decode_mbps,
            result.decode_ns,
            result.frame_size,
            result.frame_ratio
        );
    }
}

fn write_cache(results: &[BenchResult]) {
    for result in results {
        let path = cache_dir().join(format!("{}.jsonl", result.impl_name.replace(' ', "_")));
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .expect("open benchmark cache");
        writeln!(file, "{}", result.to_json()).expect("write benchmark cache");
        eprintln!("appended 1 result to {}", path.display());
    }
}

fn cache_dir() -> PathBuf {
    let dir = PathBuf::from(env::var_os("HOME").unwrap_or_else(|| ".".into()))
        .join(".cache")
        .join("ozlrip")
        .join(env::consts::ARCH);
    fs::create_dir_all(&dir).expect("create benchmark cache dir");
    dir
}

fn timestamp_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_secs()
}

fn git_rev() -> String {
    let output = Command::new("git").args(["rev-parse", "HEAD"]).output();
    match output {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).trim().to_owned()
        }
        _ => "unknown".to_owned(),
    }
}
