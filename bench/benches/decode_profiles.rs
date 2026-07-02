use std::{
    env,
    ffi::{OsStr, OsString},
    fs,
    hint::black_box,
    io::Write,
    path::{Path, PathBuf},
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
    let zli = zli_path();
    let generated = generated_cases(zli.as_deref());
    let mut results = Vec::new();

    for case in &generated.cases {
        let ozlrip = bench_ozlrip(case, target);
        print_result(&ozlrip, None);
        results.push(ozlrip);

        if let Some(zli) = zli.as_deref() {
            let c = bench_openzl_c_cli(zli, case, target);
            let relative = results
                .iter()
                .find(|result| result.input_name == case.name && result.impl_name == "ozlrip")
                .map(|base| base.decode_mbps / c.decode_mbps);
            print_result(&c, relative);
            results.push(c);
        }
    }

    write_cache(&results);
}

fn generated_cases(zli: Option<&Path>) -> GeneratedCases {
    let mut cases = Vec::new();
    if let Some(zli) = zli {
        let work = WorkDir::new("ozlrip-bench");
        for (name, input) in [
            ("serial-4k", high_entropy_bytes(4 * 1024)),
            ("serial-1m", high_entropy_bytes(1024 * 1024)),
        ] {
            let input_path = work.path.join(format!("{name}.input"));
            let frame_path = work.path.join(format!("{name}.zl"));
            fs::write(&input_path, &input).expect("write benchmark input");
            run(
                zli,
                [
                    OsStr::new("compress"),
                    input_path.as_os_str(),
                    OsStr::new("--profile"),
                    OsStr::new("serial"),
                    OsStr::new("-o"),
                    frame_path.as_os_str(),
                    OsStr::new("-f"),
                ],
            );
            let frame = fs::read(&frame_path).expect("read generated frame");
            assert_eq!(
                ozlrip::decode(&frame).expect("ozlrip decode generated frame"),
                input
            );
            cases.push(BenchCase {
                name,
                profile: "serial",
                input_size: input.len(),
                frame,
                work: Some(work.path.clone()),
            });
        }
        return GeneratedCases {
            cases,
            _work: Some(work),
        };
    }

    cases.push(BenchCase {
        name: "store-4k",
        profile: "manual-store",
        input_size: 4 * 1024,
        frame: store_only_frame(4 * 1024),
        work: None,
    });
    cases.push(BenchCase {
        name: "store-1m",
        profile: "manual-store",
        input_size: 1024 * 1024,
        frame: store_only_frame(1024 * 1024),
        work: None,
    });
    eprintln!("set OZLRIP_ZLI to include openzl-c-cli baseline results");
    GeneratedCases { cases, _work: None }
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

fn bench_openzl_c_cli(zli: &Path, case: &BenchCase, target: Duration) -> BenchResult {
    let work = case.work.as_ref().expect("zli benchmark workdir missing");
    let frame_path = work.join(format!("{}.zl", case.name));
    let output_path = work.join(format!("{}.decoded", case.name));
    let args = [
        OsString::from("decompress"),
        frame_path.as_os_str().to_owned(),
        OsString::from("-o"),
        output_path.as_os_str().to_owned(),
        OsString::from("-f"),
    ];
    let decode_ns = bench_loop(target, || {
        run_owned(zli, &args);
        black_box(fs::metadata(&output_path).expect("decoded output metadata").len());
    });
    BenchResult::new("openzl-c-cli", case, decode_ns)
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
    work: Option<PathBuf>,
}

struct GeneratedCases {
    cases: Vec<BenchCase>,
    _work: Option<WorkDir>,
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
            "{:<12} {:<13} {:>9.1} MB/s {:>10.1} ns/decode ozlrip/openzl-c-cli={relative:.2}x",
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
    let dir = PathBuf::from(env::var_os("HOME").unwrap_or_else(|| OsString::from(".")))
        .join(".cache")
        .join("ozlrip")
        .join(env::consts::ARCH);
    fs::create_dir_all(&dir).expect("create benchmark cache dir");
    dir
}

fn zli_path() -> Option<PathBuf> {
    let raw = PathBuf::from(env::var_os("OZLRIP_ZLI")?);
    if raw.is_absolute() || raw.exists() {
        return Some(raw);
    }
    let repo_relative = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(&raw);
    Some(repo_relative)
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

fn run<'a>(program: &Path, args: impl IntoIterator<Item = &'a OsStr>) {
    let args: Vec<&OsStr> = args.into_iter().collect();
    let output = Command::new(program)
        .args(&args)
        .output()
        .expect("run zli");
    assert!(
        output.status.success(),
        "command failed: {} {:?}\nstdout:\n{}\nstderr:\n{}",
        program.display(),
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn run_owned(program: &Path, args: &[OsString]) {
    let output = Command::new(program)
        .args(args)
        .output()
        .expect("run zli");
    assert!(
        output.status.success(),
        "command failed: {} {:?}\nstdout:\n{}\nstderr:\n{}",
        program.display(),
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

const MAGIC_BASE: u32 = 0xd7b1_a5c0;

fn store_only_frame(payload_len: usize) -> Vec<u8> {
    let mut input = Vec::new();
    input.extend_from_slice(&(MAGIC_BASE + 21).to_le_bytes());
    input.push(0);
    input.push(1);
    push_var_u64(
        &mut input,
        u64::try_from(payload_len + 1).expect("payload length fits"),
    );
    input.push(1);
    input.push(1);
    push_var_u64(
        &mut input,
        u64::try_from(payload_len).expect("payload length fits"),
    );
    input.resize(input.len() + payload_len, 0x5a);
    input.push(0);
    input
}

fn push_var_u64(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push(u8::try_from(value & 0x7f).expect("varint byte fits") | 0x80);
        value >>= 7;
    }
    out.push(u8::try_from(value).expect("varint byte fits"));
}

struct WorkDir {
    path: PathBuf,
}

impl WorkDir {
    fn new(prefix: &str) -> Self {
        let path = env::temp_dir().join(format!(
            "{prefix}-{}-{}",
            std::process::id(),
            timestamp_unix()
        ));
        fs::create_dir_all(&path).expect("create benchmark workdir");
        Self { path }
    }
}

impl Drop for WorkDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
