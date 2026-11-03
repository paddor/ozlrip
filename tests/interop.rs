use std::{
    env,
    ffi::OsStr,
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

const RELEASE_MATRIX: &str = include_str!("fixtures/openzl-release-matrix.tsv");
const FEATURE_COMPATIBILITY: &str = include_str!("fixtures/feature-compatibility.tsv");

#[test]
#[ignore = "requires OZLRIP_ZLI (upstream zli binary)"]
fn upstream_zli_golden_roundtrips_match_ozlrip() {
    let zli = required_zli();
    let work = WorkDir::new("ozlrip-interop");
    let upstream_commit = upstream_commit(&zli).unwrap_or_else(|| "unknown".to_owned());
    let mut manifest = String::new();
    writeln!(manifest, "upstream_commit={upstream_commit}").unwrap();

    for case in supported_interop_cases() {
        run_roundtrip_case(&zli, &work, &case, &mut manifest);
    }

    let manifest_dir = Path::new("tmp").join("ozlrip-interop");
    fs::create_dir_all(&manifest_dir).unwrap();
    fs::write(manifest_dir.join("last-run.manifest"), manifest).unwrap();
}

#[test]
#[ignore = "requires OZLRIP_ZLI_<release> (release zli binary)"]
fn upstream_release_checkpoint_smoke_roundtrips_match_ozlrip() {
    let mut ran = 0usize;
    let mut manifest = String::new();

    for checkpoint in release_interop_checkpoints() {
        let env_var = release_zli_env_var(checkpoint);
        let Some(zli) = env::var_os(&env_var).map(PathBuf::from) else {
            continue;
        };
        ran += 1;
        let work = WorkDir::new(&format!("ozlrip-interop-{checkpoint}"));
        let upstream_commit = upstream_commit(&zli).unwrap_or_else(|| "unknown".to_owned());
        writeln!(
            manifest,
            "checkpoint={checkpoint}\nenv={env_var}\nupstream_commit={upstream_commit}"
        )
        .unwrap();
        let profiles = zli_profiles(&zli);
        let mut ran_cases = 0usize;
        for case in release_smoke_interop_cases() {
            if !profiles.iter().any(|profile| profile == case.profile) {
                writeln!(manifest, "skipped={} profile={}", case.name, case.profile).unwrap();
                continue;
            }
            ran_cases += 1;
            run_roundtrip_case(&zli, &work, &case, &mut manifest);
        }
        assert!(
            ran_cases > 0,
            "{checkpoint}: zli supports none of the release smoke profiles"
        );
    }

    assert!(
        ran > 0,
        "release interop smoke needs at least one of: {}",
        release_interop_checkpoints()
            .into_iter()
            .map(release_zli_env_var)
            .collect::<Vec<_>>()
            .join(", ")
    );

    let manifest_dir = Path::new("tmp").join("ozlrip-interop");
    fs::create_dir_all(&manifest_dir).unwrap();
    fs::write(manifest_dir.join("release-smoke.manifest"), manifest).unwrap();
}

#[test]
#[ignore = "requires OZLRIP_ZLI (upstream zli binary)"]
fn upstream_profile_discovery_records_frame_results() {
    let zli = required_zli();
    let work = WorkDir::new("ozlrip-interop-discovery");
    let mut manifest = String::new();
    let mut failures = Vec::new();

    for case in discovery_interop_cases() {
        let name = case.name;
        let input = case.load_input();
        let input_path = work.path.join(format!("{name}.input"));
        let frame_path = work.path.join(format!("{name}.zl"));
        fs::write(&input_path, &input).unwrap();

        let compress_args = compress_args(
            &input_path,
            case.profile,
            case.profile_arg,
            case.extra_args,
            &frame_path,
        );
        run(&zli, compress_args.iter().copied());
        let frame = fs::read(&frame_path).unwrap();
        let inspect = ozlrip::inspect(&frame);
        let decode = ozlrip::decode(&frame);
        writeln!(
            manifest,
            "fixture={name}\nprofile={}\ncompress_command={}\ninput_hash={:016x}\nframe_hash={:016x}\ninspect={:?}\ndecode={:?}\n",
            case.profile,
            command_line(&zli, compress_args.iter().copied()),
            hash64(&input),
            hash64(&frame),
            inspect.as_ref().map(|info| (
                info.format_version,
                info.chunks,
                info.transforms,
                info.stored_streams,
                info.regenerated_streams,
            )),
            decode.as_ref().map(Vec::len).map_err(|err| (
                err.kind(),
                err.detail().map(str::to_owned),
            )),
        )
        .unwrap();
        failures.extend(discovery_failure(name, &input, &inspect, &decode));
    }

    let manifest_dir = Path::new("tmp").join("ozlrip-interop");
    fs::create_dir_all(&manifest_dir).unwrap();
    fs::write(manifest_dir.join("discovery.manifest"), manifest).unwrap();
    assert!(
        failures.is_empty(),
        "discovery cases failed:\n{}",
        failures.join("\n")
    );
}

fn discovery_failure(
    name: &str,
    input: &[u8],
    inspect: &ozlrip::Result<ozlrip::FrameInfo>,
    decode: &ozlrip::Result<Vec<u8>>,
) -> Option<String> {
    if let Err(err) = inspect {
        return Some(format!("{name}: inspect failed: {err}"));
    }
    match decode {
        Err(err) => Some(format!("{name}: decode failed: {err}")),
        Ok(decoded) if decoded != input => Some(format!(
            "{name}: decoded {} bytes, expected {} matching bytes",
            decoded.len(),
            input.len()
        )),
        Ok(_) => None,
    }
}

#[test]
fn feature_compatibility_manifest_is_backed_by_interop_cases() {
    let cases = supported_interop_cases();
    for row in feature_compatibility_rows() {
        let case = cases
            .iter()
            .find(|case| case.name == row.case)
            .unwrap_or_else(|| panic!("missing interop case {}", row.case));
        assert_eq!(case.profile, row.profile, "{} profile mismatch", row.case);
        match (case.profile_arg, row.profile_arg) {
            (None, "none") => {}
            (Some(actual), expected) => {
                assert_eq!(actual, expected, "{} profile arg mismatch", row.case);
            }
            (None, expected) => panic!("{} missing profile arg {expected}", row.case),
        }
    }
}

fn run_roundtrip_case(zli: &Path, work: &WorkDir, case: &InteropCase, manifest: &mut String) {
    let name = case.name;
    let input = case.load_input();
    let profile = case.profile;
    let input_path = work.path.join(format!("{name}.input"));
    let frame_path = work.path.join(format!("{name}.zl"));
    let zli_decoded_path = work.path.join(format!("{name}.zli.decoded"));
    fs::write(&input_path, &input).unwrap();

    let compress_args = compress_args(
        &input_path,
        profile,
        case.profile_arg,
        case.extra_args,
        &frame_path,
    );
    let decompress_args = decompress_args(&frame_path, &zli_decoded_path);
    run(zli, compress_args.iter().copied());
    run(zli, decompress_args.iter().copied());

    let frame = fs::read(&frame_path).unwrap();
    let zli_decoded = fs::read(&zli_decoded_path).unwrap();
    assert_eq!(zli_decoded, input, "{name} upstream roundtrip changed data");

    let frame_info = ozlrip::inspect(&frame).unwrap_or_else(|err| {
        panic!("{name} ozlrip inspect failed: {err:?}");
    });
    let mut ozlrip_decoded = Vec::new();
    ozlrip::decode_into_with_options(
        &frame,
        &mut ozlrip_decoded,
        ozlrip::Options::from(case.limits()),
    )
    .unwrap_or_else(|err| {
        panic!("{name} ozlrip decode failed: {err:?}");
    });
    assert_eq!(ozlrip_decoded, input, "{name} ozlrip output mismatch");

    writeln!(
        manifest,
        "fixture={name}\nprofile={profile}\nformat_version={}\ncompress_command={}\ndecompress_command={}\ninput_hash={:016x}\nframe_hash={:016x}\ndecoded_hash={:016x}\n",
        frame_info.format_version,
        command_line(zli, compress_args.iter().copied()),
        command_line(zli, decompress_args.iter().copied()),
        hash64(&input),
        hash64(&frame),
        hash64(&zli_decoded),
    )
    .unwrap();
}

fn feature_compatibility_rows() -> Vec<FeatureCompatibilityRow<'static>> {
    let mut lines = FEATURE_COMPATIBILITY.lines();
    assert_eq!(
        lines.next(),
        Some("feature\tcase\tprofile\tprofile_arg\tcoverage")
    );
    lines
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let fields = line.split('\t').collect::<Vec<_>>();
            assert_eq!(fields.len(), 5, "bad feature compatibility row: {line}");
            FeatureCompatibilityRow {
                case: fields[1],
                profile: fields[2],
                profile_arg: fields[3],
            }
        })
        .collect()
}

struct FeatureCompatibilityRow<'a> {
    case: &'a str,
    profile: &'a str,
    profile_arg: &'a str,
}

fn supported_interop_cases() -> Vec<InteropCase> {
    [
        byte_interop_cases(),
        csv_interop_cases(),
        integer_interop_cases(),
        sao_interop_cases(),
        text_and_chunked_interop_cases(),
        parquet_and_sddl2_interop_cases(),
        getting_started_csv_interop_cases(),
        ml_selector_interop_cases(),
        zstd_interop_cases(),
    ]
    .into_iter()
    .flatten()
    .collect()
}

/// Serial and `u8` cases over small inline inputs and upstream samples.
fn byte_interop_cases() -> Vec<InteropCase> {
    vec![
        InteropCase::inline(
            "serial-small",
            "serial",
            b"openzl interop serial fixture\n".to_vec(),
        ),
        InteropCase::upstream(
            "upstream-serial-quick-brown-fox",
            "serial",
            "cli/tests/sample_files/serial/quick_brown_fox.txt",
        ),
        InteropCase::upstream(
            "upstream-serial-binary",
            "serial",
            "cli/tests/sample_files/serial/binary_sample.bin",
        ),
        InteropCase::inline("u8-ramp", "u8", (0..=31).collect()),
        InteropCase::upstream(
            "upstream-u8-random",
            "u8",
            "cli/tests/sample_files/u8/random_u8.bin",
        ),
        InteropCase::upstream(
            "upstream-u8-sequential",
            "u8",
            "cli/tests/sample_files/u8/sequential_u8.bin",
        ),
        InteropCase::upstream(
            "upstream-u8-repeated",
            "u8",
            "cli/tests/sample_files/u8/repeated_u8.bin",
        ),
    ]
}

/// CSV profile cases over upstream CSV and TBL samples.
fn csv_interop_cases() -> Vec<InteropCase> {
    vec![
        InteropCase::upstream(
            "upstream-csv-experiments",
            "csv",
            "cli/tests/sample_files/csv/input_experiments.csv",
        ),
        InteropCase::upstream(
            "upstream-csv-timeseries",
            "csv",
            "cli/tests/sample_files/csv/input_timeseries.csv",
        )
        .args(&["--chunk-size", "1M"]),
        InteropCase::upstream(
            "upstream-csv-output-neighbors",
            "csv",
            "cli/tests/sample_files/csv/output_neighbors.csv",
        ),
        InteropCase::upstream(
            "upstream-tbl-supplier",
            "csv",
            "cli/tests/sample_files/tbl/supplier_trunc.tbl",
        )
        .profile_arg("|"),
    ]
}

/// Fixed-width integer profile cases.
fn integer_interop_cases() -> Vec<InteropCase> {
    vec![
        InteropCase::inline(
            "i8-signed",
            "i8",
            [0i8, -1, 1, -2, 2, 63, -64, 100, -100]
                .into_iter()
                .map(i8::cast_unsigned)
                .collect(),
        ),
        InteropCase::inline(
            "le-u16-ramp",
            "le-u16",
            le_bytes([0u16, 1, 2, 255, 256, 1024, u16::MAX]),
        ),
        InteropCase::inline(
            "le-i16-signed",
            "le-i16",
            le_bytes([0i16, -1, 1, i16::MIN, i16::MAX, -1024, 1024]),
        ),
        InteropCase::upstream(
            "upstream-u16-zigzag",
            "le-u16",
            "cli/tests/sample_files/u16/zigzag_1000.bin",
        ),
        InteropCase::inline(
            "le-u32-ramp",
            "le-u32",
            le_bytes([0u32, 1, 255, 256, 65_535, 65_536, u32::MAX]),
        ),
        InteropCase::inline(
            "le-i32-signed",
            "le-i32",
            le_bytes([0i32, -1, 1, i32::MIN, i32::MAX, -65_536, 65_536]),
        ),
        InteropCase::inline(
            "le-u64-ramp",
            "le-u64",
            le_bytes([0u64, 1, 255, 65_536, u64::from(u32::MAX), u64::MAX]),
        ),
        InteropCase::inline(
            "le-i64-signed",
            "le-i64",
            le_bytes([
                0i64,
                -1,
                1,
                i64::MIN,
                i64::MAX,
                -4_294_967_296,
                4_294_967_296,
            ]),
        ),
    ]
}

/// SAO profile and SDDL cases over synthetic SAO records.
fn sao_interop_cases() -> Vec<InteropCase> {
    vec![
        InteropCase::inline("sao-synthetic", "sao", sao_synthetic()),
        InteropCase::inline("sao-sddl2-synthetic", "sddl2", sao_synthetic())
            .profile_arg("tmp/openzl-upstream/examples/sddl2/sao_silesia.sddl"),
        InteropCase::inline("sao-full-sddl2-synthetic", "sddl2", sao_full_synthetic())
            .profile_arg("tmp/openzl-upstream/examples/sddl2/sao_full.sddl"),
        InteropCase::inline("sao-sddl1-synthetic", "sddl", sao_synthetic())
            .profile_arg("tmp/openzl-upstream/examples/sddl/sao_silesia.oldv1.sddl"),
        InteropCase::inline("sao-full-sddl1-synthetic", "sddl", sao_full_synthetic())
            .profile_arg("tmp/openzl-upstream/examples/sddl/sao_full.oldv1.sddl"),
        InteropCase::inline("sao-sddl1-synthetic-forced-graph", "sddl", sao_synthetic())
            .profile_arg("tmp/openzl-upstream/examples/sddl/sao_silesia.oldv1.sddl")
            .args(&["--no-store-on-expansion"]),
        InteropCase::inline(
            "sao-full-sddl1-synthetic-forced-graph",
            "sddl",
            sao_full_synthetic(),
        )
        .profile_arg("tmp/openzl-upstream/examples/sddl/sao_full.oldv1.sddl")
        .args(&["--no-store-on-expansion"]),
    ]
}

/// Text inputs, large literal sections, and multi-chunk frames.
fn text_and_chunked_interop_cases() -> Vec<InteropCase> {
    vec![
        InteropCase::upstream(
            "upstream-serial-repeated-string",
            "serial",
            "cli/tests/sample_files/serial/repeated_string.txt",
        ),
        InteropCase::upstream(
            "upstream-ace-newlines-serial",
            "serial",
            "cli/tests/sample_files/ace/newlines.txt",
        ),
        InteropCase::inline("serial-pivco-words-1m", "serial", random_words(1 << 20)),
        InteropCase::inline("serial-chunked-2m", "serial", sequential_bytes(2_000_000))
            .args(&["--chunk-size", "1M"])
            .relaxed(),
        InteropCase::inline("u8-chunked-2m", "u8", sequential_bytes(2_000_000))
            .args(&["--chunk-size", "1M"])
            .relaxed(),
        InteropCase::upstream(
            "getting-started-era5-i32",
            "le-i32",
            "examples/getting_started/sample_inputs/era5_ints.bin",
        )
        .relaxed(),
        InteropCase::upstream(
            "getting-started-lorem-ipsum",
            "serial",
            "examples/getting_started/sample_inputs/lorem_ipsum.txt",
        ),
    ]
}

/// Parquet profile cases and SDDL2 cases over upstream samples.
fn parquet_and_sddl2_interop_cases() -> Vec<InteropCase> {
    const SIMPLE_DESCRIPTION: &str =
        "tmp/openzl-upstream/cli/tests/profile_files/sddl2/simple_description.sddl";
    vec![
        InteropCase::upstream(
            "upstream-parquet-simple",
            "parquet",
            "cli/tests/sample_files/parquet/simple.parquet",
        )
        .relaxed(),
        InteropCase::upstream(
            "upstream-parquet-nested",
            "parquet",
            "cli/tests/sample_files/parquet/nested.parquet",
        )
        .relaxed(),
        InteropCase::upstream(
            "upstream-sddl2-sample-0",
            "sddl2",
            "cli/tests/sample_files/sddl2/sample_0.bin",
        )
        .profile_arg(SIMPLE_DESCRIPTION),
        InteropCase::upstream(
            "upstream-sddl2-sample-1",
            "sddl2",
            "cli/tests/sample_files/sddl2/sample_1.bin",
        )
        .profile_arg(SIMPLE_DESCRIPTION),
        InteropCase::upstream(
            "upstream-sddl2-sample-2",
            "sddl2",
            "cli/tests/sample_files/sddl2/sample_2.bin",
        )
        .profile_arg(SIMPLE_DESCRIPTION),
        InteropCase::upstream(
            "upstream-sddl2-sample-2-forced-graph",
            "sddl2",
            "cli/tests/sample_files/sddl2/sample_2.bin",
        )
        .profile_arg(SIMPLE_DESCRIPTION)
        .args(&["--no-store-on-expansion"]),
        InteropCase::upstream(
            "upstream-sddl2-asm-sao-silesia-forced-graph",
            "sddl2",
            "examples/sddl2_asm/sao_silesia.bin",
        )
        .profile_arg("tmp/openzl-upstream/examples/sddl2/sao_silesia.sddl")
        .args(&["--no-store-on-expansion"]),
    ]
}

/// CSV profile cases over the getting-started CSV samples.
fn getting_started_csv_interop_cases() -> Vec<InteropCase> {
    upstream_cases(
        "csv",
        &[
            (
                "getting-started-csv-0001",
                "examples/getting_started/sample_inputs/csv_samples/0001.csv",
            ),
            (
                "getting-started-csv-0002",
                "examples/getting_started/sample_inputs/csv_samples/0002.csv",
            ),
            (
                "getting-started-csv-0003",
                "examples/getting_started/sample_inputs/csv_samples/0003.csv",
            ),
        ],
    )
}

/// Numeric ML selector profile cases over upstream samples.
fn ml_selector_interop_cases() -> Vec<InteropCase> {
    upstream_cases(
        "numeric-ml-selector-64",
        &[
            (
                "upstream-ml-selector-64-0",
                "cli/tests/sample_files/ml_selector/ml_sel_num_64_0",
            ),
            (
                "upstream-ml-selector-64-1",
                "cli/tests/sample_files/ml_selector/ml_sel_num_64_1",
            ),
            (
                "upstream-ml-selector-64-2",
                "cli/tests/sample_files/ml_selector/ml_sel_num_64_2",
            ),
            (
                "upstream-ml-selector-64-3",
                "cli/tests/sample_files/ml_selector/ml_sel_num_64_3",
            ),
            (
                "upstream-ml-selector-64-4",
                "cli/tests/sample_files/ml_selector/ml_sel_num_64_4",
            ),
        ],
    )
}

/// Zstd profile cases over the upstream zstd dictionary samples.
fn zstd_interop_cases() -> Vec<InteropCase> {
    upstream_cases(
        "zstd",
        &[
            (
                "upstream-zstd-profile-0",
                "cli/tests/sample_files/zstd_dict/0.txt",
            ),
            (
                "upstream-zstd-profile-1",
                "cli/tests/sample_files/zstd_dict/1.txt",
            ),
            (
                "upstream-zstd-profile-2",
                "cli/tests/sample_files/zstd_dict/2.txt",
            ),
            (
                "upstream-zstd-profile-3",
                "cli/tests/sample_files/zstd_dict/3.txt",
            ),
            (
                "upstream-zstd-profile-4",
                "cli/tests/sample_files/zstd_dict/4.txt",
            ),
            (
                "upstream-zstd-profile-5",
                "cli/tests/sample_files/zstd_dict/5.txt",
            ),
            (
                "upstream-zstd-profile-6",
                "cli/tests/sample_files/zstd_dict/6.txt",
            ),
            (
                "upstream-zstd-profile-7",
                "cli/tests/sample_files/zstd_dict/7.txt",
            ),
            (
                "upstream-zstd-profile-8",
                "cli/tests/sample_files/zstd_dict/8.txt",
            ),
            (
                "upstream-zstd-profile-9",
                "cli/tests/sample_files/zstd_dict/9.txt",
            ),
        ],
    )
}

/// Builds one upstream sample case per `(name, path)` pair, all with the same
/// profile and default arguments.
fn upstream_cases(
    profile: &'static str,
    samples: &[(&'static str, &'static str)],
) -> Vec<InteropCase> {
    samples
        .iter()
        .map(|&(name, path)| InteropCase::upstream(name, profile, path))
        .collect()
}

fn release_smoke_interop_cases() -> Vec<InteropCase> {
    vec![
        InteropCase::inline(
            "serial-small",
            "serial",
            b"openzl release smoke serial fixture\n".to_vec(),
        ),
        InteropCase::inline("u8-small", "u8", (0..=63).collect()),
        InteropCase::inline(
            "le-u32-small",
            "le-u32",
            (0u32..64)
                .flat_map(|value| (value * 7 + 3).to_le_bytes())
                .collect(),
        ),
    ]
}

fn zli_profiles(zli: &Path) -> Vec<String> {
    let output = Command::new(zli).arg("list-profiles").output().unwrap();
    assert!(output.status.success(), "zli list-profiles failed");
    // zli prints the profile list to stderr.
    let text = [output.stdout, output.stderr].concat();
    String::from_utf8_lossy(&text)
        .lines()
        .filter_map(|line| line.split_once("-| "))
        .filter_map(|(_, rest)| rest.split_whitespace().next())
        .map(str::to_owned)
        .collect()
}

fn discovery_interop_cases() -> Vec<InteropCase> {
    vec![
        InteropCase::upstream(
            "discovery-csv-output-neighbors",
            "csv",
            "cli/tests/sample_files/csv/output_neighbors.csv",
        )
        .args(&["--no-store-on-expansion"]),
        InteropCase::upstream(
            "discovery-sddl2-asm-sao-silesia",
            "sddl2",
            "examples/sddl2_asm/sao_silesia.bin",
        )
        .profile_arg("tmp/openzl-upstream/examples/sddl2/sao_silesia.sddl")
        .args(&["--no-store-on-expansion"]),
        InteropCase::upstream(
            "discovery-csv-pums-0001",
            "csv",
            "examples/getting_started/sample_inputs/csv_samples/0001.csv",
        )
        .args(&["--no-store-on-expansion"]),
    ]
}

fn release_interop_checkpoints() -> Vec<&'static str> {
    RELEASE_MATRIX
        .lines()
        .skip(1)
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| {
            let fields = line.split('\t').collect::<Vec<_>>();
            assert_eq!(fields.len(), 4, "bad OpenZL release-matrix row: {line}");
            (fields[1] == "release").then_some(fields[0])
        })
        .collect()
}

fn release_zli_env_var(checkpoint: &str) -> String {
    let suffix = checkpoint
        .chars()
        .map(|ch| match ch {
            'a'..='z' => ch.to_ascii_uppercase(),
            'A'..='Z' | '0'..='9' => ch,
            _ => '_',
        })
        .collect::<String>();
    format!("OZLRIP_ZLI_{suffix}")
}

fn sao_synthetic() -> Vec<u8> {
    let mut out = (0..28).collect::<Vec<u8>>();
    push_sao_records(&mut out);
    out
}

fn sao_full_synthetic() -> Vec<u8> {
    let mut out = Vec::new();
    for value in [0i32, 1, 10, 0, 1, 1, 28] {
        out.extend_from_slice(&value.to_le_bytes());
    }
    push_sao_records(&mut out);
    out
}

fn push_sao_records(out: &mut Vec<u8>) {
    for index in 0i16..10 {
        out.extend_from_slice(&(0.1f64 + f64::from(index)).to_le_bytes());
        out.extend_from_slice(&(-0.2f64 - f64::from(index)).to_le_bytes());
        out.extend_from_slice(b"G2");
        out.extend_from_slice(&(100i16 + index).to_le_bytes());
        out.extend_from_slice(&(0.01f32 * f32::from(index)).to_le_bytes());
        out.extend_from_slice(&(-0.02f32 * f32::from(index)).to_le_bytes());
    }
}

fn le_bytes<const N: usize, T: LeBytes>(values: [T; N]) -> Vec<u8> {
    let mut out = Vec::new();
    for value in values {
        out.extend_from_slice(&value.to_le_vec());
    }
    out
}

/// Words from a fixed vocabulary, in a fixed pseudo-random order. LZ leaves
/// more than 16 KiB of literals, which upstream codes with PivCo-Huffman
/// from format v27.
fn random_words(len: usize) -> Vec<u8> {
    let mut state = 5u64;
    let mut words = Vec::with_capacity(len + 8);
    while words.len() < len {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        words.extend_from_slice(format!("w{}x ", (state >> 33) % 3000).as_bytes());
    }
    words.truncate(len);
    words
}

fn sequential_bytes(len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| u8::try_from(index & 0xff).expect("masked to byte"))
        .collect()
}

trait LeBytes {
    fn to_le_vec(self) -> Vec<u8>;
}

impl LeBytes for u16 {
    fn to_le_vec(self) -> Vec<u8> {
        self.to_le_bytes().to_vec()
    }
}

impl LeBytes for i16 {
    fn to_le_vec(self) -> Vec<u8> {
        self.to_le_bytes().to_vec()
    }
}

impl LeBytes for u32 {
    fn to_le_vec(self) -> Vec<u8> {
        self.to_le_bytes().to_vec()
    }
}

impl LeBytes for i32 {
    fn to_le_vec(self) -> Vec<u8> {
        self.to_le_bytes().to_vec()
    }
}

impl LeBytes for u64 {
    fn to_le_vec(self) -> Vec<u8> {
        self.to_le_bytes().to_vec()
    }
}

impl LeBytes for i64 {
    fn to_le_vec(self) -> Vec<u8> {
        self.to_le_bytes().to_vec()
    }
}

struct InteropCase {
    name: &'static str,
    input: InteropInput,
    profile: &'static str,
    profile_arg: Option<&'static str>,
    extra_args: &'static [&'static str],
    relaxed_limits: bool,
}

impl InteropCase {
    /// Builds a case that compresses inline bytes with default arguments.
    fn inline(name: &'static str, profile: &'static str, bytes: Vec<u8>) -> Self {
        Self::new(name, profile, InteropInput::Inline(bytes))
    }

    /// Builds a case that compresses an upstream sample file with default
    /// arguments. The path is relative to the upstream checkout.
    fn upstream(name: &'static str, profile: &'static str, path: &'static str) -> Self {
        Self::new(name, profile, InteropInput::UpstreamFile(path))
    }

    /// Builds a case with no profile argument, no extra arguments, and default
    /// limits.
    fn new(name: &'static str, profile: &'static str, input: InteropInput) -> Self {
        Self {
            name,
            input,
            profile,
            profile_arg: None,
            extra_args: &[],
            relaxed_limits: false,
        }
    }

    /// Sets the `--profile-arg` value.
    fn profile_arg(mut self, profile_arg: &'static str) -> Self {
        self.profile_arg = Some(profile_arg);
        self
    }

    /// Sets extra arguments for `zli compress`.
    fn args(mut self, extra_args: &'static [&'static str]) -> Self {
        self.extra_args = extra_args;
        self
    }

    /// Decodes with relaxed limits for large outputs.
    fn relaxed(mut self) -> Self {
        self.relaxed_limits = true;
        self
    }

    fn limits(&self) -> ozlrip::Limits {
        if self.relaxed_limits {
            {
                let mut limits = ozlrip::Limits::default();
                limits.max_decoded_bytes = 8 * 1024 * 1024;
                limits.max_buffer_bytes = 8 * 1024 * 1024;
                limits.max_expansion_ratio = 1_000_000;
                limits
            }
        } else {
            ozlrip::Limits::default()
        }
    }

    fn load_input(&self) -> Vec<u8> {
        match &self.input {
            InteropInput::Inline(bytes) => bytes.clone(),
            InteropInput::UpstreamFile(path) => {
                fs::read(Path::new("tmp/openzl-upstream").join(path)).unwrap_or_else(|err| {
                    panic!("failed to read upstream sample {path}: {err}");
                })
            }
        }
    }
}

enum InteropInput {
    Inline(Vec<u8>),
    UpstreamFile(&'static str),
}

fn compress_args<'a>(
    input_path: &'a Path,
    profile: &'a str,
    profile_arg: Option<&'a str>,
    extra_args: &'a [&'a str],
    frame_path: &'a Path,
) -> Vec<&'a OsStr> {
    let mut args = vec![
        OsStr::new("compress"),
        input_path.as_os_str(),
        OsStr::new("--profile"),
        OsStr::new(profile),
    ];
    if let Some(profile_arg) = profile_arg {
        args.push(OsStr::new("--profile-arg"));
        args.push(OsStr::new(profile_arg));
    }
    for arg in extra_args {
        args.push(OsStr::new(arg));
    }
    args.extend([OsStr::new("-o"), frame_path.as_os_str(), OsStr::new("-f")]);
    args
}

fn decompress_args<'a>(frame_path: &'a Path, decoded_path: &'a Path) -> Vec<&'a OsStr> {
    vec![
        OsStr::new("decompress"),
        frame_path.as_os_str(),
        OsStr::new("-o"),
        decoded_path.as_os_str(),
        OsStr::new("-f"),
    ]
}

fn required_zli() -> PathBuf {
    let zli = env::var_os("OZLRIP_ZLI")
        .map(PathBuf::from)
        .expect("set OZLRIP_ZLI to an upstream zli binary to run interop tests");
    assert!(zli.exists(), "OZLRIP_ZLI does not exist: {}", zli.display());
    zli
}

fn upstream_commit(zli: &Path) -> Option<String> {
    let repo = zli.ancestors().find(|path| path.join(".git").is_dir())?;
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .arg("rev-parse")
        .arg("HEAD")
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn run<'a>(zli: &Path, args: impl IntoIterator<Item = &'a OsStr>) {
    let args: Vec<&OsStr> = args.into_iter().collect();
    let output = Command::new(zli)
        .args(&args)
        .output()
        .unwrap_or_else(|err| {
            panic!(
                "failed to run {}: {err}",
                command_line(zli, args.iter().copied())
            );
        });
    assert!(
        output.status.success(),
        "command failed: {}\nstdout:\n{}\nstderr:\n{}",
        command_line(zli, args.iter().copied()),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn command_line<'a>(program: &Path, args: impl IntoIterator<Item = &'a OsStr>) -> String {
    let mut out = shell_word(program.as_os_str());
    for arg in args {
        out.push(' ');
        out.push_str(&shell_word(arg));
    }
    out
}

fn shell_word(value: &OsStr) -> String {
    let value = value.to_string_lossy();
    if value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'-' | b'_'))
    {
        value.into_owned()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

fn hash64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

struct WorkDir {
    path: PathBuf,
}

impl WorkDir {
    fn new(prefix: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }
}

impl Drop for WorkDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
