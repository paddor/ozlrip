use std::{
    env, fs,
    hint::black_box,
    io::Write,
    mem::size_of,
    os::raw::{c_char, c_int, c_void},
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

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
    let impl_filter = env::var("OZLRIP_BENCH_IMPL").ok();
    let case_filter = env::var("OZLRIP_BENCH_CASE").ok();
    let cases = generated_cases(case_filter.as_deref());
    let mut results = Vec::new();

    for case in &cases {
        if case_filter
            .as_deref()
            .is_some_and(|filter| filter != case.name)
        {
            continue;
        }
        let mut ozlrip_mbps = None;
        if impl_filter
            .as_deref()
            .is_none_or(|filter| filter == OZLRIP_IMPL)
        {
            let ozlrip = bench_ozlrip(case, target);
            ozlrip_mbps = Some(ozlrip.decoded_mbps);
            print_result(&ozlrip, None);
            results.push(ozlrip);
        }

        let reference_impl = case.reference.impl_name();
        if impl_filter
            .as_deref()
            .is_none_or(|filter| filter == reference_impl)
        {
            let reference = bench_reference_decoder(case, target);
            let relative = ozlrip_mbps.map(|base| (OZLRIP_IMPL, base / reference.decoded_mbps));
            print_result(&reference, relative);
            results.push(reference);
        }
    }

    write_cache(&results);
}

fn generated_cases(case_filter: Option<&str>) -> Vec<BenchCase> {
    let mut cases = Vec::new();
    if let Some(zli) = zli_path() {
        cases.extend(serial_generated_cases(&zli, case_filter));
        cases.extend(zli_generated_cases(&zli, case_filter));
    } else {
        eprintln!("skipping benchmark cases: set OZLRIP_ZLI or build tmp/openzl-upstream/zli");
    }
    cases
}

fn serial_generated_cases(zli: &Path, case_filter: Option<&str>) -> Vec<BenchCase> {
    let mut cases = Vec::new();
    macro_rules! push_case {
        ($name:literal, $extra_args:expr, $input:expr) => {
            if case_filter.is_none_or(|filter| filter == $name) {
                let spec = ZliBenchSpec {
                    name: $name,
                    profile: "serial",
                    profile_arg: None,
                    extra_args: $extra_args,
                    input: $input,
                };
                cases.push(generated_case_from_zli(zli, &spec, ReferenceDecoder::Ffi));
            }
        };
    }
    push_case!("serial-random-4k", &[], high_entropy_bytes(4 * 1024));
    push_case!("serial-random-1m", &[], high_entropy_bytes(1024 * 1024));
    push_case!("serial-repeated-4k", &[], repeated_bytes(4 * 1024));
    push_case!("serial-sequential-1m", &[], sequential_bytes(1024 * 1024));
    push_case!(
        "serial-sequential-16m",
        &["--chunk-size", "4M"],
        sequential_bytes(16 * 1024 * 1024)
    );
    cases
}

fn zli_generated_cases(zli: &Path, case_filter: Option<&str>) -> Vec<BenchCase> {
    let mut cases = Vec::new();
    macro_rules! push_case {
        ($name:literal, $profile:literal, $profile_arg:expr, $extra_args:expr, $input:expr) => {
            if case_filter.is_none_or(|filter| filter == $name) {
                let spec = ZliBenchSpec {
                    name: $name,
                    profile: $profile,
                    profile_arg: $profile_arg,
                    extra_args: $extra_args,
                    input: $input,
                };
                cases.push(generated_case_from_zli(zli, &spec, ReferenceDecoder::Ffi));
            }
        };
    }
    push_case!(
        "u8-rle-16m",
        "u8",
        None,
        &["--chunk-size", "4M", "--no-store-on-expansion"],
        u8_runs(16 * 1024 * 1024)
    );
    push_case!(
        "le-u32-delta-16m",
        "le-u32",
        None,
        &["--chunk-size", "4M", "--no-store-on-expansion"],
        le_u32_delta_bytes(4 * 1024 * 1024)
    );
    push_case!(
        "era5-le-i32-sample",
        "le-i32",
        None,
        &["--no-store-on-expansion"],
        read_upstream_sample("examples/getting_started/sample_inputs/era5_ints.bin")
    );
    push_case!(
        "le-u64-timeseries-32m",
        "le-u64",
        None,
        &["--chunk-size", "4M", "--no-store-on-expansion"],
        le_u64_timeseries_bytes(4 * 1024 * 1024)
    );
    push_case!(
        "csv-timeseries-3m",
        "csv",
        None,
        &["--chunk-size", "1M"],
        csv_timeseries(120_000)
    );
    push_case!(
        "csv-timeseries-30m",
        "csv",
        None,
        &["--chunk-size", "4M"],
        csv_timeseries(1_000_000)
    );
    push_case!(
        "csv-pums-sample",
        "csv",
        None,
        &[],
        read_upstream_sample("examples/getting_started/sample_inputs/csv_samples/0001.csv")
    );
    push_case!(
        "tbl-supplier-pipe",
        "csv",
        Some("|".to_owned()),
        &[],
        read_upstream_sample("cli/tests/sample_files/tbl/supplier_trunc.tbl")
    );
    push_case!(
        "sao-fixed-5m",
        "sao",
        None,
        &["--no-store-on-expansion"],
        sao_synthetic_records(200_000)
    );
    push_case!(
        "sao-fixed-28m",
        "sao",
        None,
        &["--chunk-size", "4M", "--no-store-on-expansion"],
        sao_synthetic_records(1_000_000)
    );
    push_case!(
        "sddl2-sao-silesia-28m",
        "sddl2",
        Some(
            workspace_root()
                .join("tmp/openzl-upstream/examples/sddl2/sao_silesia.sddl")
                .display()
                .to_string()
        ),
        &["--chunk-size", "4M", "--no-store-on-expansion"],
        sao_synthetic_records(1_000_000)
    );
    push_case!(
        "parquet-canonical-sample",
        "parquet",
        None,
        &["--chunk-size", "1M"],
        parquet_canonical_sample()
    );
    push_case!(
        "parquet-nested-sample",
        "parquet",
        None,
        &["--chunk-size", "1M"],
        parquet_nested_sample()
    );
    push_case!(
        "lorem-serial-sample",
        "serial",
        None,
        &[],
        read_upstream_sample("examples/getting_started/sample_inputs/lorem_ipsum.txt")
    );
    push_case!(
        "u16-zigzag-sample",
        "le-u16",
        None,
        &["--no-store-on-expansion"],
        read_upstream_sample("cli/tests/sample_files/u16/zigzag_1000.bin")
    );
    cases
}

fn generated_case_from_zli(
    zli: &Path,
    spec: &ZliBenchSpec,
    reference: ReferenceDecoder,
) -> BenchCase {
    let frame = compress_with_zli(zli, spec);
    assert_eq!(
        decode_ozlrip_with_bench_limits(&frame).expect("ozlrip decode generated frame"),
        spec.input
    );
    assert_eq!(
        decode_openzl_c_with_bench_limits(&frame, spec.input.len()),
        spec.input
    );
    BenchCase {
        name: spec.name,
        profile: spec.profile,
        input_size: spec.input.len(),
        frame,
        reference,
    }
}

struct ZliBenchSpec {
    name: &'static str,
    profile: &'static str,
    profile_arg: Option<String>,
    extra_args: &'static [&'static str],
    input: Vec<u8>,
}

fn compress_with_zli(zli: &Path, spec: &ZliBenchSpec) -> Vec<u8> {
    let dir = workspace_root().join("tmp").join("ozlrip-bench-inputs");
    fs::create_dir_all(&dir).expect("create benchmark input dir");
    let frame_path = dir.join(format!("{}.zl", spec.name));
    let meta_path = dir.join(format!("{}.zl.meta", spec.name));
    let signature = zli_cache_signature(spec);

    if let Ok(frame) = fs::read(&frame_path)
        && fs::read_to_string(&meta_path).is_ok_and(|cached| cached == signature)
        && decode_ozlrip_with_bench_limits(&frame).is_ok_and(|decoded| decoded == spec.input)
        && decode_openzl_c_with_bench_limits(&frame, spec.input.len()) == spec.input
    {
        return frame;
    }

    let input_path = dir.join(format!("{}.input", spec.name));
    fs::write(&input_path, &spec.input).expect("write benchmark input");

    let mut command = Command::new(zli);
    command
        .arg("compress")
        .arg(&input_path)
        .arg("--profile")
        .arg(spec.profile);
    if let Some(profile_arg) = &spec.profile_arg {
        command.arg("--profile-arg").arg(profile_arg);
    }
    command
        .args(spec.extra_args)
        .arg("-o")
        .arg(&frame_path)
        .arg("-f");
    let output = command.output().expect("run zli compress");
    if !output.status.success() {
        panic!(
            "zli compress failed for {}: stdout={} stderr={}",
            spec.name,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let frame = fs::read(frame_path).expect("read generated zli frame");
    fs::write(meta_path, signature).expect("write generated zli metadata");
    frame
}

fn zli_cache_signature(spec: &ZliBenchSpec) -> String {
    format!(
        "v2\nname={}\nprofile={}\nprofile_arg={}\nextra_args={}\ninput_len={}\ninput_hash={:016x}\n",
        spec.name,
        spec.profile,
        spec.profile_arg.as_deref().unwrap_or(""),
        spec.extra_args.join("\x1f"),
        spec.input.len(),
        fnv1a64(&spec.input)
    )
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn zli_path() -> Option<PathBuf> {
    if let Some(path) = env::var_os("OZLRIP_ZLI").map(PathBuf::from)
        && path.exists()
    {
        return Some(path);
    }
    let path = workspace_root().join("tmp/openzl-upstream/zli");
    path.exists().then_some(path)
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("bench crate lives below workspace root")
        .to_path_buf()
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

fn u8_runs(len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    for index in 0..len {
        out.push(u8::try_from((index / 257) & 0xff).expect("masked to byte"));
    }
    out
}

fn le_u32_delta_bytes(values: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(values * size_of::<u32>());
    for index in 0..values {
        let value = 1_000_000u32.wrapping_add(u32::try_from(index).unwrap() * 3);
        out.extend_from_slice(&value.to_le_bytes());
    }
    out
}

fn le_u64_timeseries_bytes(values: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(values * size_of::<u64>());
    for index in 0..values {
        let trend = u64::try_from(index).unwrap() * 1_000;
        let jitter = u64::try_from(index % 17).unwrap() * 13;
        out.extend_from_slice(&(1_700_000_000_000u64 + trend + jitter).to_le_bytes());
    }
    out
}

fn csv_timeseries(rows: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(rows * 32);
    out.extend_from_slice(b"timestamp,sensor,value,status\n");
    for row in 0..rows {
        let timestamp = 1_700_000_000u64 + u64::try_from(row).unwrap() * 60;
        let sensor = row % 64;
        let value = (row.wrapping_mul(17) + sensor * 13) % 100_000;
        let status = match row % 11 {
            0 => "warm",
            1 => "cold",
            2 => "idle",
            _ => "ok",
        };
        writeln!(out, "{timestamp},s{sensor:02},{value}.{sensor:02},{status}")
            .expect("write csv row");
    }
    out
}

fn sao_synthetic_records(records: usize) -> Vec<u8> {
    let mut out = (0..28).map(|byte| byte as u8).collect::<Vec<u8>>();
    out.reserve(records * 28);
    for index in 0..records {
        let index_f64 = index as f64;
        let index_i16 = i16::try_from(index % 32_000).unwrap();
        out.extend_from_slice(&(0.1f64 + index_f64 * 0.0001).to_le_bytes());
        out.extend_from_slice(&(-0.2f64 - index_f64 * 0.0001).to_le_bytes());
        out.extend_from_slice(b"G2");
        out.extend_from_slice(&(100i16 + index_i16).to_le_bytes());
        out.extend_from_slice(&(0.01f32 * f32::from(index_i16 % 1024)).to_le_bytes());
        out.extend_from_slice(&(-0.02f32 * f32::from(index_i16 % 1024)).to_le_bytes());
    }
    out
}

fn parquet_canonical_sample() -> Vec<u8> {
    read_upstream_sample("cli/tests/sample_files/parquet/simple.parquet")
}

fn parquet_nested_sample() -> Vec<u8> {
    read_upstream_sample("cli/tests/sample_files/parquet/nested.parquet")
}

fn read_upstream_sample(relative_path: &str) -> Vec<u8> {
    fs::read(
        workspace_root()
            .join("tmp")
            .join("openzl-upstream")
            .join(relative_path),
    )
    .expect("read upstream sample")
}

fn bench_ozlrip(case: &BenchCase, target: Duration) -> BenchResult {
    let mut decoder = ozlrip::Decoder::with_options(ozlrip::Options {
        limits: bench_limits(),
    });
    let mut dst = Vec::new();
    let stats = bench_loop(target, || {
        dst.clear();
        decoder
            .decode_into(black_box(&case.frame), black_box(&mut dst))
            .expect("ozlrip decode failed");
        black_box(&dst);
    });
    BenchResult::new(OZLRIP_IMPL, case, stats)
}

fn decode_ozlrip_with_bench_limits(frame: &[u8]) -> Result<Vec<u8>, ozlrip::Error> {
    let mut output = Vec::new();
    ozlrip::decode_into_with_options(frame, &mut output, ozlrip::Options { limits: bench_limits() })?;
    Ok(output)
}

fn bench_limits() -> ozlrip::Limits {
    ozlrip::Limits {
        max_expansion_ratio: 1_000_000,
        ..ozlrip::Limits::strict()
    }
}

fn bench_reference_decoder(case: &BenchCase, target: Duration) -> BenchResult {
    match &case.reference {
        ReferenceDecoder::Ffi => bench_openzl_c_ffi(case, target),
    }
}

fn bench_openzl_c_ffi(case: &BenchCase, target: Duration) -> BenchResult {
    let mut decoder = OpenZlCDecoder::new(case.input_size);
    decoder.decode(&case.frame);
    assert_eq!(decoder.dst.len(), case.input_size);
    let stats = bench_loop(target, || {
        decoder.decode(black_box(&case.frame));
        black_box(&decoder.dst);
    });
    BenchResult::new(OPENZL_C_IMPL, case, stats)
}

fn decode_openzl_c_with_bench_limits(frame: &[u8], output_size: usize) -> Vec<u8> {
    let mut decoder = OpenZlCDecoder::new(output_size);
    decoder.decode(frame);
    std::mem::take(&mut decoder.dst)
}

struct OpenZlCDecoder {
    dctx: *mut OpenZlDCtx,
    dst: Vec<u8>,
}

impl OpenZlCDecoder {
    fn new(output_size: usize) -> Self {
        let dctx = unsafe { ozlrip_bench_openzl_dctx_create() };
        assert!(!dctx.is_null(), "ZL_DCtx_create returned null");
        configure_openzl_dctx(dctx);
        Self {
            dctx,
            dst: vec![0; output_size],
        }
    }

    fn decode(&mut self, frame: &[u8]) {
        let mut written = 0usize;
        let code = unsafe {
            ozlrip_bench_openzl_decompress_serial(
                self.dctx,
                self.dst.as_mut_ptr().cast::<c_void>(),
                self.dst.len(),
                frame.as_ptr().cast::<c_void>(),
                frame.len(),
                &mut written,
            )
        };
        assert_openzl_success(code, "openzl-c-ffi decode failed");
        assert_eq!(written, self.dst.len());
    }
}

impl Drop for OpenZlCDecoder {
    fn drop(&mut self) {
        unsafe { ozlrip_bench_openzl_dctx_free(self.dctx) };
    }
}

fn configure_openzl_dctx(dctx: *mut OpenZlDCtx) {
    #[cfg(feature = "no-checksum")]
    {
        let code = unsafe { ozlrip_bench_openzl_dctx_disable_checksums(dctx) };
        assert_openzl_success(code, "ZL_DCtx checksum parameter setup failed");
    }
    #[cfg(not(feature = "no-checksum"))]
    let _ = dctx;
}

fn assert_openzl_success(code: c_int, message: &str) {
    if code != 0 {
        panic!(
            "{message}: {}",
            openzl_cstr(unsafe { ozlrip_bench_openzl_last_error() })
        );
    }
}

fn openzl_cstr(ptr: *const c_char) -> String {
    if ptr.is_null() {
        return "<null>".to_owned();
    }
    unsafe { std::ffi::CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned()
}

fn bench_loop<F: FnMut()>(target: Duration, mut f: F) -> BenchStats {
    for _ in 0..WARMUP {
        f();
    }

    let mut rounds = Vec::with_capacity(ROUNDS);
    for _ in 0..ROUNDS {
        let started = Instant::now();
        let mut iters = 0u64;
        while started.elapsed() < target {
            black_box(&mut f)();
            iters += 1;
        }
        let elapsed = started.elapsed();
        let ns_per_op = elapsed.as_nanos() as f64 / iters as f64;
        rounds.push(ns_per_op);
    }
    rounds.sort_by(f64::total_cmp);
    BenchStats {
        median_ns: rounds[ROUNDS / 2],
        best_ns: rounds[0],
    }
}

struct BenchStats {
    median_ns: f64,
    best_ns: f64,
}

#[derive(Clone)]
struct BenchCase {
    name: &'static str,
    profile: &'static str,
    input_size: usize,
    frame: Vec<u8>,
    reference: ReferenceDecoder,
}

#[derive(Clone)]
enum ReferenceDecoder {
    Ffi,
}

impl ReferenceDecoder {
    fn impl_name(&self) -> &'static str {
        match self {
            Self::Ffi => OPENZL_C_IMPL,
        }
    }
}

enum OpenZlDCtx {}

unsafe extern "C" {
    fn ozlrip_bench_openzl_dctx_create() -> *mut OpenZlDCtx;
    fn ozlrip_bench_openzl_dctx_free(dctx: *mut OpenZlDCtx);
    fn ozlrip_bench_openzl_last_error() -> *const c_char;
    #[cfg(feature = "no-checksum")]
    fn ozlrip_bench_openzl_dctx_disable_checksums(dctx: *mut OpenZlDCtx) -> c_int;
    fn ozlrip_bench_openzl_decompress_serial(
        dctx: *mut OpenZlDCtx,
        dst: *mut c_void,
        dst_capacity: usize,
        src: *const c_void,
        src_size: usize,
        written: *mut usize,
    ) -> c_int;
}

struct BenchResult {
    impl_name: &'static str,
    input_name: &'static str,
    profile: &'static str,
    input_size: usize,
    frame_size: usize,
    median_decode_ns: f64,
    best_decode_ns: f64,
    decoded_mbps: f64,
    frame_mbps: f64,
    frame_ratio: f64,
    timestamp_unix: u64,
    git_rev: String,
    git_dirty: bool,
}

impl BenchResult {
    fn new(impl_name: &'static str, case: &BenchCase, stats: BenchStats) -> Self {
        let decoded_mbps = case.input_size as f64 / stats.median_ns * 1_000.0;
        let frame_mbps = case.frame.len() as f64 / stats.median_ns * 1_000.0;
        let frame_ratio = case.frame.len() as f64 / case.input_size as f64;
        Self {
            impl_name,
            input_name: case.name,
            profile: case.profile,
            input_size: case.input_size,
            frame_size: case.frame.len(),
            median_decode_ns: stats.median_ns,
            best_decode_ns: stats.best_ns,
            decoded_mbps,
            frame_mbps,
            frame_ratio,
            timestamp_unix: timestamp_unix(),
            git_rev: git_rev(),
            git_dirty: git_dirty(),
        }
    }

    fn to_json(&self) -> String {
        format!(
            concat!(
                r#"{{"impl": "{}", "input": "{}", "profile": "{}", "#,
                r#""input_size": {}, "frame_size": {}, "#,
                r#""frame_ratio": {:.4}, "median_decode_ns": {:.1}, "best_decode_ns": {:.1}, "#,
                r#""decoded_mbps": {:.1}, "frame_mbps": {:.1}, "#,
                r#""timestamp_unix": {}, "git_rev": "{}", "git_dirty": {}}}"#
            ),
            self.impl_name,
            self.input_name,
            self.profile,
            self.input_size,
            self.frame_size,
            self.frame_ratio,
            self.median_decode_ns,
            self.best_decode_ns,
            self.decoded_mbps,
            self.frame_mbps,
            self.timestamp_unix,
            self.git_rev,
            self.git_dirty,
        )
    }
}

fn print_result(result: &BenchResult, relative_to_reference: Option<(&str, f64)>) {
    if let Some((base_impl, relative)) = relative_to_reference {
        println!(
            "{:<20} {:<25} decoded={:>9.1} MB/s frame={:>9.1} MB/s {:>10.1} ns/decode frame={} ratio={:.4} {}/{}={relative:.2}x",
            result.input_name,
            result.impl_name,
            result.decoded_mbps,
            result.frame_mbps,
            result.median_decode_ns,
            result.frame_size,
            result.frame_ratio,
            base_impl,
            result.impl_name
        );
    } else {
        println!(
            "{:<20} {:<25} decoded={:>9.1} MB/s frame={:>9.1} MB/s {:>10.1} ns/decode frame={} ratio={:.4}",
            result.input_name,
            result.impl_name,
            result.decoded_mbps,
            result.frame_mbps,
            result.median_decode_ns,
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

fn git_dirty() -> bool {
    let output = Command::new("git")
        .args(["status", "--porcelain", "--untracked-files=no"])
        .output();
    match output {
        Ok(output) if output.status.success() => !output.stdout.is_empty(),
        _ => true,
    }
}
