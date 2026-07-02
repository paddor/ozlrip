use std::{
    env,
    fs,
    hint::black_box,
    io::Write,
    path::PathBuf,
    process::Command,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const DEFAULT_TARGET_MS: u64 = 100;
const ROUNDS: usize = 7;
const WARMUP: usize = 3;

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
            .is_none_or(|filter| filter == "ozlrip")
        {
            let ozlrip = bench_ozlrip(case, target);
            ozlrip_mbps = Some(ozlrip.decode_mbps);
            print_result(&ozlrip, None);
            results.push(ozlrip);
        }

        if impl_filter
            .as_deref()
            .is_none_or(|filter| filter == "openzl-c-ffi")
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
        ("serial-4k", high_entropy_bytes(4 * 1024)),
        ("serial-1m", high_entropy_bytes(1024 * 1024)),
    ] {
        let frame = rust_openzl::compress_serial(&input).expect("openzl-c-ffi compress_serial");
        assert_eq!(
            ozlrip::decode(&frame).expect("ozlrip decode generated frame"),
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

fn bench_ozlrip(case: &BenchCase, target: Duration) -> BenchResult {
    let mut decoder = ozlrip::Decoder::default();
    let mut dst = Vec::new();
    let decode_ns = bench_loop(target, || {
        dst.clear();
        decoder
            .decode_into(black_box(&case.frame), black_box(&mut dst))
            .expect("ozlrip decode failed");
        black_box(&dst);
    });
    BenchResult::new("ozlrip", case, decode_ns)
}

fn bench_openzl_c_ffi(case: &BenchCase, target: Duration) -> BenchResult {
    let decode_ns = bench_loop(target, || {
        let decoded =
            rust_openzl::decompress_serial(black_box(&case.frame)).expect("openzl-c-ffi decode");
        black_box(decoded);
    });
    BenchResult::new("openzl-c-ffi", case, decode_ns)
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
    timestamp_unix: u64,
    git_rev: String,
}

impl BenchResult {
    fn new(impl_name: &'static str, case: &BenchCase, decode_ns: f64) -> Self {
        let decode_mbps = case.input_size as f64 / decode_ns * 1_000.0;
        Self {
            impl_name,
            input_name: case.name,
            profile: case.profile,
            input_size: case.input_size,
            frame_size: case.frame.len(),
            decode_ns,
            decode_mbps,
            timestamp_unix: timestamp_unix(),
            git_rev: git_rev(),
        }
    }

    fn to_json(&self) -> String {
        format!(
            concat!(
                r#"{{"impl": "{}", "input": "{}", "profile": "{}", "#,
                r#""input_size": {}, "frame_size": {}, "#,
                r#""decode_ns": {:.1}, "decode_mbps": {:.1}, "#,
                r#""timestamp_unix": {}, "git_rev": "{}"}}"#
            ),
            self.impl_name,
            self.input_name,
            self.profile,
            self.input_size,
            self.frame_size,
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
            "{:<12} {:<13} {:>9.1} MB/s {:>10.1} ns/decode ozlrip/openzl-c-ffi={relative:.2}x",
            result.input_name, result.impl_name, result.decode_mbps, result.decode_ns
        );
    } else {
        println!(
            "{:<12} {:<13} {:>9.1} MB/s {:>10.1} ns/decode",
            result.input_name, result.impl_name, result.decode_mbps, result.decode_ns
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
