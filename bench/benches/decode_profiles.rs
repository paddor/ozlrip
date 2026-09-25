use std::{
    env, fs,
    hint::black_box,
    io::Write,
    mem::size_of,
    path::{Path, PathBuf},
    process::{Command, Stdio},
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
    if env::var_os("OZLRIP_BENCH_CHILD").is_some() {
        child_main();
    } else {
        parent_main();
    }
}

fn target_duration() -> Duration {
    Duration::from_millis(
        env::var("OZLRIP_BENCH_TARGET_MS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(DEFAULT_TARGET_MS),
    )
}

/// Generates and verifies all frames, then measures each case and impl in
/// its own child process so glibc heap state from one case cannot leak into
/// the next measurement.
fn parent_main() {
    let impl_filter = env::var("OZLRIP_BENCH_IMPL").ok();
    let case_filter = env::var("OZLRIP_BENCH_CASE").ok();
    let Some(zli) = zli_path() else {
        eprintln!("skipping benchmark cases: set OZLRIP_ZLI or build tmp/openzl-upstream/zli");
        return;
    };
    let zli_rev = zli_rev(&zli);
    let cases = generated_cases(&zli, &zli_rev, case_filter.as_deref());
    let exe = env::current_exe().expect("benchmark executable path");

    for case in &cases {
        let mut ozlrip_ns = None;
        for impl_name in [OZLRIP_IMPL, case.reference.impl_name()] {
            if impl_filter
                .as_deref()
                .is_some_and(|filter| filter != impl_name)
            {
                continue;
            }
            let median_ns = run_child(&exe, &case.name, impl_name, &zli_rev);
            if impl_name == OZLRIP_IMPL {
                ozlrip_ns = Some(median_ns);
            } else if let Some(ozlrip_ns) = ozlrip_ns {
                println!(
                    "{:<20} {OZLRIP_IMPL}/{impl_name}={:.2}x",
                    case.name,
                    median_ns / ozlrip_ns
                );
            }
        }
    }
}

fn run_child(exe: &Path, case: &str, impl_name: &str, zli_rev: &str) -> f64 {
    let output = Command::new(exe)
        .args(env::args_os().skip(1))
        .env("OZLRIP_BENCH_CHILD", "1")
        .env("OZLRIP_BENCH_CASE", case)
        .env("OZLRIP_BENCH_IMPL", impl_name)
        .env("OZLRIP_BENCH_ZLI_REV", zli_rev)
        .stderr(Stdio::inherit())
        .output()
        .expect("run benchmark child");
    let mut median_ns = None;
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        if let Some(row) = line.strip_prefix("@@row\t") {
            let (_, ns) = row.split_once('\t').expect("benchmark child row");
            median_ns = Some(ns.parse::<f64>().expect("benchmark child median"));
        } else {
            println!("{line}");
        }
    }
    if !output.status.success() {
        eprintln!("benchmark child failed: case={case} impl={impl_name}");
        std::process::exit(output.status.code().unwrap_or(1));
    }
    median_ns.expect("benchmark child did not report a result")
}

fn child_main() {
    let name = env::var("OZLRIP_BENCH_CASE").expect("benchmark child needs OZLRIP_BENCH_CASE");
    let impl_name = env::var("OZLRIP_BENCH_IMPL").expect("benchmark child needs OZLRIP_BENCH_IMPL");
    let zli_rev = env::var("OZLRIP_BENCH_ZLI_REV").unwrap_or_else(|_| "unknown".to_owned());
    let case = load_cached_case(&name);
    let target = target_duration();
    let result = if impl_name == OZLRIP_IMPL {
        bench_ozlrip(&case, target, &zli_rev)
    } else if impl_name == case.reference.impl_name() {
        bench_reference_decoder(&case, target, &zli_rev)
    } else {
        panic!("unknown benchmark impl {impl_name}");
    };
    print_result(&result);
    write_cache(&result);
    println!("@@row\t{}\t{}", result.impl_name, result.median_decode_ns);
}

fn load_cached_case(name: &str) -> BenchCase {
    let dir = bench_input_dir();
    let frame = fs::read(dir.join(format!("{name}.zl"))).expect("read cached benchmark frame");
    let meta = fs::read_to_string(dir.join(format!("{name}.zl.meta")))
        .expect("read cached benchmark metadata");
    let field = |key: &str| {
        meta.lines()
            .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
            .unwrap_or_else(|| panic!("benchmark metadata for {name} has no {key}"))
            .to_owned()
    };
    BenchCase {
        name: name.to_owned(),
        profile: field("profile"),
        input_size: field("input_len").parse().expect("benchmark input length"),
        frame,
        reference: ReferenceDecoder::Ffi,
    }
}

fn generated_cases(zli: &Path, zli_rev: &str, case_filter: Option<&str>) -> Vec<BenchCase> {
    let mut cases = serial_generated_cases(zli, zli_rev, case_filter);
    cases.extend(zli_generated_cases(zli, zli_rev, case_filter));
    cases
}

fn serial_generated_cases(zli: &Path, zli_rev: &str, case_filter: Option<&str>) -> Vec<BenchCase> {
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
                cases.push(generated_case_from_zli(
                    zli,
                    zli_rev,
                    &spec,
                    ReferenceDecoder::Ffi,
                ));
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

fn zli_generated_cases(zli: &Path, zli_rev: &str, case_filter: Option<&str>) -> Vec<BenchCase> {
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
                cases.push(generated_case_from_zli(
                    zli,
                    zli_rev,
                    &spec,
                    ReferenceDecoder::Ffi,
                ));
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
    zli_rev: &str,
    spec: &ZliBenchSpec,
    reference: ReferenceDecoder,
) -> BenchCase {
    let frame = compress_with_zli(zli, zli_rev, spec);
    assert_eq!(
        decode_ozlrip_with_bench_limits(&frame).expect("ozlrip decode generated frame"),
        spec.input
    );
    assert_eq!(
        decode_openzl_c_with_bench_limits(&frame, spec.input.len()),
        spec.input
    );
    BenchCase {
        name: spec.name.to_owned(),
        profile: spec.profile.to_owned(),
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

fn compress_with_zli(zli: &Path, zli_rev: &str, spec: &ZliBenchSpec) -> Vec<u8> {
    let dir = bench_input_dir();
    fs::create_dir_all(&dir).expect("create benchmark input dir");
    let frame_path = dir.join(format!("{}.zl", spec.name));
    let meta_path = dir.join(format!("{}.zl.meta", spec.name));
    let signature = zli_cache_signature(zli_rev, spec);

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

fn zli_cache_signature(zli_rev: &str, spec: &ZliBenchSpec) -> String {
    format!(
        "v3\nzli_rev={zli_rev}\nname={}\nprofile={}\nprofile_arg={}\nextra_args={}\ninput_len={}\ninput_hash={:016x}\n",
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

fn bench_input_dir() -> PathBuf {
    workspace_root().join("tmp").join("ozlrip-bench-inputs")
}

/// Returns the git revision of the OpenZL checkout that contains `zli`, so
/// cached frames are regenerated when upstream changes.
fn zli_rev(zli: &Path) -> String {
    let zli = fs::canonicalize(zli).unwrap_or_else(|_| zli.to_path_buf());
    let Some(repo) = zli.ancestors().find(|path| path.join(".git").exists()) else {
        return "unknown".to_owned();
    };
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["rev-parse", "HEAD"])
        .output();
    match output {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).trim().to_owned()
        }
        _ => "unknown".to_owned(),
    }
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

fn bench_ozlrip(case: &BenchCase, target: Duration, zli_rev: &str) -> BenchResult {
    let mut options = ozlrip::Options {
        limits: bench_limits(),
        ..ozlrip::Options::default()
    };
    if !plan_cache_enabled() {
        options.plan_cache_max_frame_bytes = 0;
    }
    let mut decoder = ozlrip::Decoder::with_options(options);
    let mut dst = Vec::new();
    let stats = bench_loop(target, || {
        dst.clear();
        decoder
            .decode_into(black_box(&case.frame), black_box(&mut dst))
            .expect("ozlrip decode failed");
        black_box(&dst);
    });
    BenchResult::new(OZLRIP_IMPL, case, stats, zli_rev)
}

fn plan_cache_enabled() -> bool {
    env::var("OZLRIP_BENCH_PLAN_CACHE").map_or(true, |value| value != "0")
}

fn decode_ozlrip_with_bench_limits(frame: &[u8]) -> Result<Vec<u8>, ozlrip::Error> {
    let mut output = Vec::new();
    ozlrip::decode_into_with_options(
        frame,
        &mut output,
        ozlrip::Options {
            limits: bench_limits(),
            ..ozlrip::Options::default()
        },
    )?;
    Ok(output)
}

fn bench_limits() -> ozlrip::Limits {
    ozlrip::Limits {
        max_expansion_ratio: 1_000_000,
        ..ozlrip::Limits::strict()
    }
}

fn bench_reference_decoder(case: &BenchCase, target: Duration, zli_rev: &str) -> BenchResult {
    match &case.reference {
        ReferenceDecoder::Ffi => bench_openzl_c_ffi(case, target, zli_rev),
    }
}

fn bench_openzl_c_ffi(case: &BenchCase, target: Duration, zli_rev: &str) -> BenchResult {
    let mut decoder = OpenZlCDecoder::new(case.input_size);
    decoder.decode(&case.frame);
    assert_eq!(decoder.dst.len(), case.input_size);
    let stats = bench_loop(target, || {
        decoder.decode(black_box(&case.frame));
        black_box(&decoder.dst);
    });
    BenchResult::new(OPENZL_C_IMPL, case, stats, zli_rev)
}

fn decode_openzl_c_with_bench_limits(frame: &[u8], output_size: usize) -> Vec<u8> {
    let mut decoder = OpenZlCDecoder::new(output_size);
    decoder.decode(frame);
    std::mem::take(&mut decoder.dst)
}

struct OpenZlCDecoder {
    decompressor: openzl_shim::Decompressor,
    dst: Vec<u8>,
}

impl OpenZlCDecoder {
    fn new(output_size: usize) -> Self {
        let mut decompressor = openzl_shim::Decompressor::new();
        if cfg!(feature = "no-checksum") {
            decompressor
                .disable_checksums()
                .expect("ZL_DCtx checksum parameter setup failed");
        }
        Self {
            decompressor,
            dst: vec![0; output_size],
        }
    }

    fn decode(&mut self, frame: &[u8]) {
        let written = self
            .decompressor
            .decompress_serial(frame, &mut self.dst)
            .expect("openzl-c-ffi decode failed");
        assert_eq!(written, self.dst.len());
    }
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
    name: String,
    profile: String,
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

struct BenchResult {
    impl_name: &'static str,
    input_name: String,
    profile: String,
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
    build: &'static str,
    rustflags: &'static str,
    openzl_moreflags: &'static str,
    zli_rev: String,
    plan_cache: bool,
    codec_versions: String,
}

impl BenchResult {
    fn new(impl_name: &'static str, case: &BenchCase, stats: BenchStats, zli_rev: &str) -> Self {
        let decoded_mbps = case.input_size as f64 / stats.median_ns * 1_000.0;
        let frame_mbps = case.frame.len() as f64 / stats.median_ns * 1_000.0;
        let frame_ratio = case.frame.len() as f64 / case.input_size as f64;
        let rustflags = env!("OZLRIP_BENCH_RUSTFLAGS");
        Self {
            impl_name,
            input_name: case.name.clone(),
            profile: case.profile.clone(),
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
            build: if rustflags.contains("target-cpu=native") {
                "native"
            } else {
                "portable"
            },
            rustflags,
            openzl_moreflags: openzl_shim::OPENZL_MOREFLAGS,
            zli_rev: zli_rev.to_owned(),
            plan_cache: plan_cache_enabled(),
            codec_versions: codec_versions(),
        }
    }

    fn to_json(&self) -> String {
        format!(
            concat!(
                r#"{{"impl": "{}", "input": "{}", "profile": "{}", "#,
                r#""input_size": {}, "frame_size": {}, "#,
                r#""frame_ratio": {:.4}, "median_decode_ns": {:.1}, "best_decode_ns": {:.1}, "#,
                r#""decoded_mbps": {:.1}, "frame_mbps": {:.1}, "#,
                r#""timestamp_unix": {}, "git_rev": "{}", "git_dirty": {}, "#,
                r#""build": "{}", "rustflags": "{}", "openzl_moreflags": "{}", "#,
                r#""zli_rev": "{}", "plan_cache": {}, "codec_versions": "{}"}}"#
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
            self.build,
            json_escape(self.rustflags),
            json_escape(self.openzl_moreflags),
            self.zli_rev,
            self.plan_cache,
            json_escape(&self.codec_versions),
        )
    }
}

fn json_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Reads the resolved codec crate versions from the bench lockfile.
fn codec_versions() -> String {
    const CRATES: [&str; 5] = [
        "zrip-decode",
        "zrip-core",
        "lz4rip-decode",
        "fearless_simd",
        "xxhash-rust",
    ];
    let lock =
        fs::read_to_string(workspace_root().join("bench").join("Cargo.lock")).unwrap_or_default();
    let mut versions = Vec::new();
    let mut name = None;
    for line in lock.lines() {
        if let Some(value) = line.strip_prefix("name = ") {
            name = Some(value.trim_matches('"').to_owned());
        } else if let Some(value) = line.strip_prefix("version = ")
            && let Some(name) = name.take()
            && CRATES.contains(&name.as_str())
        {
            versions.push(format!("{name} {}", value.trim_matches('"')));
        }
    }
    versions.sort();
    versions.join(", ")
}

fn print_result(result: &BenchResult) {
    println!(
        "{:<20} {:<25} decoded={:>9.1} MB/s frame={:>9.1} MB/s {:>10.1} ns/decode frame={} ratio={:.4} build={}",
        result.input_name,
        result.impl_name,
        result.decoded_mbps,
        result.frame_mbps,
        result.median_decode_ns,
        result.frame_size,
        result.frame_ratio,
        result.build,
    );
}

fn write_cache(result: &BenchResult) {
    let path = cache_dir().join(format!("{}.jsonl", result.impl_name.replace(' ', "_")));
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .expect("open benchmark cache");
    writeln!(file, "{}", result.to_json()).expect("write benchmark cache");
}

fn cache_dir() -> PathBuf {
    let dir = env::var_os("OZLRIP_BENCH_CACHE_DIR").map_or_else(
        || {
            PathBuf::from(env::var_os("HOME").unwrap_or_else(|| ".".into()))
                .join(".cache")
                .join("ozlrip")
                .join(env::consts::ARCH)
        },
        PathBuf::from,
    );
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
