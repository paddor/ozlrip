#![cfg(feature = "interop")]

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
fn upstream_zli_golden_roundtrips_match_ozlrip() {
    let Some(zli) = zli_path() else {
        eprintln!("skipping interop test: set OZLRIP_ZLI to an upstream zli binary");
        return;
    };
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
        for case in release_smoke_interop_cases() {
            run_roundtrip_case(&zli, &work, &case, &mut manifest);
        }
    }

    if ran == 0 {
        eprintln!(
            "skipping release interop smoke: set OZLRIP_ZLI_V0_0_23, \
             OZLRIP_ZLI_V0_1_0, or OZLRIP_ZLI_V0_2_0"
        );
        return;
    }

    let manifest_dir = Path::new("tmp").join("ozlrip-interop");
    fs::create_dir_all(&manifest_dir).unwrap();
    fs::write(manifest_dir.join("release-smoke.manifest"), manifest).unwrap();
}

#[test]
fn upstream_profile_discovery_records_frame_results() {
    let Some(zli) = zli_path() else {
        eprintln!("skipping interop discovery: set OZLRIP_ZLI to an upstream zli binary");
        return;
    };
    let work = WorkDir::new("ozlrip-interop-discovery");
    let mut manifest = String::new();

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
    }

    let manifest_dir = Path::new("tmp").join("ozlrip-interop");
    fs::create_dir_all(&manifest_dir).unwrap();
    fs::write(manifest_dir.join("discovery.manifest"), manifest).unwrap();
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
        ozlrip::Options {
            limits: case.limits(),
            ..ozlrip::Options::default()
        },
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
    vec![
        InteropCase {
            name: "serial-small",
            input: InteropInput::Inline(b"openzl interop serial fixture\n".to_vec()),
            profile: "serial",
            profile_arg: None,
            extra_args: &[],
            relaxed_limits: false,
        },
        InteropCase {
            name: "upstream-serial-quick-brown-fox",
            input: InteropInput::UpstreamFile("cli/tests/sample_files/serial/quick_brown_fox.txt"),
            profile: "serial",
            profile_arg: None,
            extra_args: &[],
            relaxed_limits: false,
        },
        InteropCase {
            name: "upstream-serial-binary",
            input: InteropInput::UpstreamFile("cli/tests/sample_files/serial/binary_sample.bin"),
            profile: "serial",
            profile_arg: None,
            extra_args: &[],
            relaxed_limits: false,
        },
        InteropCase {
            name: "u8-ramp",
            input: InteropInput::Inline((0..=31).collect()),
            profile: "u8",
            profile_arg: None,
            extra_args: &[],
            relaxed_limits: false,
        },
        InteropCase {
            name: "upstream-u8-random",
            input: InteropInput::UpstreamFile("cli/tests/sample_files/u8/random_u8.bin"),
            profile: "u8",
            profile_arg: None,
            extra_args: &[],
            relaxed_limits: false,
        },
        InteropCase {
            name: "upstream-u8-sequential",
            input: InteropInput::UpstreamFile("cli/tests/sample_files/u8/sequential_u8.bin"),
            profile: "u8",
            profile_arg: None,
            extra_args: &[],
            relaxed_limits: false,
        },
        InteropCase {
            name: "upstream-u8-repeated",
            input: InteropInput::UpstreamFile("cli/tests/sample_files/u8/repeated_u8.bin"),
            profile: "u8",
            profile_arg: None,
            extra_args: &[],
            relaxed_limits: false,
        },
        InteropCase {
            name: "upstream-csv-experiments",
            input: InteropInput::UpstreamFile("cli/tests/sample_files/csv/input_experiments.csv"),
            profile: "csv",
            profile_arg: None,
            extra_args: &[],
            relaxed_limits: false,
        },
        InteropCase {
            name: "upstream-csv-timeseries",
            input: InteropInput::UpstreamFile("cli/tests/sample_files/csv/input_timeseries.csv"),
            profile: "csv",
            profile_arg: None,
            extra_args: &["--chunk-size", "1M"],
            relaxed_limits: false,
        },
        InteropCase {
            name: "upstream-csv-output-neighbors",
            input: InteropInput::UpstreamFile("cli/tests/sample_files/csv/output_neighbors.csv"),
            profile: "csv",
            profile_arg: None,
            extra_args: &[],
            relaxed_limits: false,
        },
        InteropCase {
            name: "upstream-tbl-supplier",
            input: InteropInput::UpstreamFile("cli/tests/sample_files/tbl/supplier_trunc.tbl"),
            profile: "csv",
            profile_arg: Some("|"),
            extra_args: &[],
            relaxed_limits: false,
        },
        InteropCase {
            name: "i8-signed",
            input: InteropInput::Inline(
                [0i8, -1, 1, -2, 2, 63, -64, 100, -100]
                    .into_iter()
                    .map(i8::cast_unsigned)
                    .collect(),
            ),
            profile: "i8",
            profile_arg: None,
            extra_args: &[],
            relaxed_limits: false,
        },
        InteropCase {
            name: "le-u16-ramp",
            input: InteropInput::Inline(le_bytes([0u16, 1, 2, 255, 256, 1024, u16::MAX])),
            profile: "le-u16",
            profile_arg: None,
            extra_args: &[],
            relaxed_limits: false,
        },
        InteropCase {
            name: "le-i16-signed",
            input: InteropInput::Inline(le_bytes([0i16, -1, 1, i16::MIN, i16::MAX, -1024, 1024])),
            profile: "le-i16",
            profile_arg: None,
            extra_args: &[],
            relaxed_limits: false,
        },
        InteropCase {
            name: "upstream-u16-zigzag",
            input: InteropInput::UpstreamFile("cli/tests/sample_files/u16/zigzag_1000.bin"),
            profile: "le-u16",
            profile_arg: None,
            extra_args: &[],
            relaxed_limits: false,
        },
        InteropCase {
            name: "le-u32-ramp",
            input: InteropInput::Inline(le_bytes([0u32, 1, 255, 256, 65_535, 65_536, u32::MAX])),
            profile: "le-u32",
            profile_arg: None,
            extra_args: &[],
            relaxed_limits: false,
        },
        InteropCase {
            name: "le-i32-signed",
            input: InteropInput::Inline(le_bytes([
                0i32,
                -1,
                1,
                i32::MIN,
                i32::MAX,
                -65_536,
                65_536,
            ])),
            profile: "le-i32",
            profile_arg: None,
            extra_args: &[],
            relaxed_limits: false,
        },
        InteropCase {
            name: "le-u64-ramp",
            input: InteropInput::Inline(le_bytes([
                0u64,
                1,
                255,
                65_536,
                u64::from(u32::MAX),
                u64::MAX,
            ])),
            profile: "le-u64",
            profile_arg: None,
            extra_args: &[],
            relaxed_limits: false,
        },
        InteropCase {
            name: "le-i64-signed",
            input: InteropInput::Inline(le_bytes([
                0i64,
                -1,
                1,
                i64::MIN,
                i64::MAX,
                -4_294_967_296,
                4_294_967_296,
            ])),
            profile: "le-i64",
            profile_arg: None,
            extra_args: &[],
            relaxed_limits: false,
        },
        InteropCase {
            name: "sao-synthetic",
            input: InteropInput::Inline(sao_synthetic()),
            profile: "sao",
            profile_arg: None,
            extra_args: &[],
            relaxed_limits: false,
        },
        InteropCase {
            name: "sao-sddl2-synthetic",
            input: InteropInput::Inline(sao_synthetic()),
            profile: "sddl2",
            profile_arg: Some("tmp/openzl-upstream/examples/sddl2/sao_silesia.sddl"),
            extra_args: &[],
            relaxed_limits: false,
        },
        InteropCase {
            name: "sao-full-sddl2-synthetic",
            input: InteropInput::Inline(sao_full_synthetic()),
            profile: "sddl2",
            profile_arg: Some("tmp/openzl-upstream/examples/sddl2/sao_full.sddl"),
            extra_args: &[],
            relaxed_limits: false,
        },
        InteropCase {
            name: "sao-sddl1-synthetic",
            input: InteropInput::Inline(sao_synthetic()),
            profile: "sddl",
            profile_arg: Some("tmp/openzl-upstream/examples/sddl/sao_silesia.oldv1.sddl"),
            extra_args: &[],
            relaxed_limits: false,
        },
        InteropCase {
            name: "sao-full-sddl1-synthetic",
            input: InteropInput::Inline(sao_full_synthetic()),
            profile: "sddl",
            profile_arg: Some("tmp/openzl-upstream/examples/sddl/sao_full.oldv1.sddl"),
            extra_args: &[],
            relaxed_limits: false,
        },
        InteropCase {
            name: "sao-sddl1-synthetic-forced-graph",
            input: InteropInput::Inline(sao_synthetic()),
            profile: "sddl",
            profile_arg: Some("tmp/openzl-upstream/examples/sddl/sao_silesia.oldv1.sddl"),
            extra_args: &["--no-store-on-expansion"],
            relaxed_limits: false,
        },
        InteropCase {
            name: "sao-full-sddl1-synthetic-forced-graph",
            input: InteropInput::Inline(sao_full_synthetic()),
            profile: "sddl",
            profile_arg: Some("tmp/openzl-upstream/examples/sddl/sao_full.oldv1.sddl"),
            extra_args: &["--no-store-on-expansion"],
            relaxed_limits: false,
        },
        InteropCase {
            name: "upstream-serial-repeated-string",
            input: InteropInput::UpstreamFile("cli/tests/sample_files/serial/repeated_string.txt"),
            profile: "serial",
            profile_arg: None,
            extra_args: &[],
            relaxed_limits: false,
        },
        InteropCase {
            name: "upstream-ace-newlines-serial",
            input: InteropInput::UpstreamFile("cli/tests/sample_files/ace/newlines.txt"),
            profile: "serial",
            profile_arg: None,
            extra_args: &[],
            relaxed_limits: false,
        },
        InteropCase {
            name: "serial-chunked-2m",
            input: InteropInput::Inline(sequential_bytes(2_000_000)),
            profile: "serial",
            profile_arg: None,
            extra_args: &["--chunk-size", "1M"],
            relaxed_limits: true,
        },
        InteropCase {
            name: "u8-chunked-2m",
            input: InteropInput::Inline(sequential_bytes(2_000_000)),
            profile: "u8",
            profile_arg: None,
            extra_args: &["--chunk-size", "1M"],
            relaxed_limits: true,
        },
        InteropCase {
            name: "getting-started-era5-i32",
            input: InteropInput::UpstreamFile(
                "examples/getting_started/sample_inputs/era5_ints.bin",
            ),
            profile: "le-i32",
            profile_arg: None,
            extra_args: &[],
            relaxed_limits: true,
        },
        InteropCase {
            name: "getting-started-lorem-ipsum",
            input: InteropInput::UpstreamFile(
                "examples/getting_started/sample_inputs/lorem_ipsum.txt",
            ),
            profile: "serial",
            profile_arg: None,
            extra_args: &[],
            relaxed_limits: false,
        },
        InteropCase {
            name: "upstream-parquet-simple",
            input: InteropInput::UpstreamFile("cli/tests/sample_files/parquet/simple.parquet"),
            profile: "parquet",
            profile_arg: None,
            extra_args: &[],
            relaxed_limits: true,
        },
        InteropCase {
            name: "upstream-parquet-nested",
            input: InteropInput::UpstreamFile("cli/tests/sample_files/parquet/nested.parquet"),
            profile: "parquet",
            profile_arg: None,
            extra_args: &[],
            relaxed_limits: true,
        },
        InteropCase {
            name: "upstream-sddl2-sample-0",
            input: InteropInput::UpstreamFile("cli/tests/sample_files/sddl2/sample_0.bin"),
            profile: "sddl2",
            profile_arg: Some(
                "tmp/openzl-upstream/cli/tests/profile_files/sddl2/simple_description.sddl",
            ),
            extra_args: &[],
            relaxed_limits: false,
        },
        InteropCase {
            name: "upstream-sddl2-sample-1",
            input: InteropInput::UpstreamFile("cli/tests/sample_files/sddl2/sample_1.bin"),
            profile: "sddl2",
            profile_arg: Some(
                "tmp/openzl-upstream/cli/tests/profile_files/sddl2/simple_description.sddl",
            ),
            extra_args: &[],
            relaxed_limits: false,
        },
        InteropCase {
            name: "upstream-sddl2-sample-2",
            input: InteropInput::UpstreamFile("cli/tests/sample_files/sddl2/sample_2.bin"),
            profile: "sddl2",
            profile_arg: Some(
                "tmp/openzl-upstream/cli/tests/profile_files/sddl2/simple_description.sddl",
            ),
            extra_args: &[],
            relaxed_limits: false,
        },
        InteropCase {
            name: "upstream-sddl2-sample-2-forced-graph",
            input: InteropInput::UpstreamFile("cli/tests/sample_files/sddl2/sample_2.bin"),
            profile: "sddl2",
            profile_arg: Some(
                "tmp/openzl-upstream/cli/tests/profile_files/sddl2/simple_description.sddl",
            ),
            extra_args: &["--no-store-on-expansion"],
            relaxed_limits: false,
        },
        InteropCase {
            name: "upstream-sddl2-asm-sao-silesia-forced-graph",
            input: InteropInput::UpstreamFile("examples/sddl2_asm/sao_silesia.bin"),
            profile: "sddl2",
            profile_arg: Some("tmp/openzl-upstream/examples/sddl2/sao_silesia.sddl"),
            extra_args: &["--no-store-on-expansion"],
            relaxed_limits: false,
        },
        InteropCase {
            name: "getting-started-csv-0001",
            input: InteropInput::UpstreamFile(
                "examples/getting_started/sample_inputs/csv_samples/0001.csv",
            ),
            profile: "csv",
            profile_arg: None,
            extra_args: &[],
            relaxed_limits: false,
        },
        InteropCase {
            name: "getting-started-csv-0002",
            input: InteropInput::UpstreamFile(
                "examples/getting_started/sample_inputs/csv_samples/0002.csv",
            ),
            profile: "csv",
            profile_arg: None,
            extra_args: &[],
            relaxed_limits: false,
        },
        InteropCase {
            name: "getting-started-csv-0003",
            input: InteropInput::UpstreamFile(
                "examples/getting_started/sample_inputs/csv_samples/0003.csv",
            ),
            profile: "csv",
            profile_arg: None,
            extra_args: &[],
            relaxed_limits: false,
        },
        InteropCase {
            name: "upstream-ml-selector-64-0",
            input: InteropInput::UpstreamFile("cli/tests/sample_files/ml_selector/ml_sel_num_64_0"),
            profile: "numeric-ml-selector-64",
            profile_arg: None,
            extra_args: &[],
            relaxed_limits: false,
        },
        InteropCase {
            name: "upstream-ml-selector-64-1",
            input: InteropInput::UpstreamFile("cli/tests/sample_files/ml_selector/ml_sel_num_64_1"),
            profile: "numeric-ml-selector-64",
            profile_arg: None,
            extra_args: &[],
            relaxed_limits: false,
        },
        InteropCase {
            name: "upstream-ml-selector-64-2",
            input: InteropInput::UpstreamFile("cli/tests/sample_files/ml_selector/ml_sel_num_64_2"),
            profile: "numeric-ml-selector-64",
            profile_arg: None,
            extra_args: &[],
            relaxed_limits: false,
        },
        InteropCase {
            name: "upstream-ml-selector-64-3",
            input: InteropInput::UpstreamFile("cli/tests/sample_files/ml_selector/ml_sel_num_64_3"),
            profile: "numeric-ml-selector-64",
            profile_arg: None,
            extra_args: &[],
            relaxed_limits: false,
        },
        InteropCase {
            name: "upstream-ml-selector-64-4",
            input: InteropInput::UpstreamFile("cli/tests/sample_files/ml_selector/ml_sel_num_64_4"),
            profile: "numeric-ml-selector-64",
            profile_arg: None,
            extra_args: &[],
            relaxed_limits: false,
        },
        InteropCase {
            name: "upstream-zstd-profile-0",
            input: InteropInput::UpstreamFile("cli/tests/sample_files/zstd_dict/0.txt"),
            profile: "zstd",
            profile_arg: None,
            extra_args: &[],
            relaxed_limits: false,
        },
        InteropCase {
            name: "upstream-zstd-profile-1",
            input: InteropInput::UpstreamFile("cli/tests/sample_files/zstd_dict/1.txt"),
            profile: "zstd",
            profile_arg: None,
            extra_args: &[],
            relaxed_limits: false,
        },
        InteropCase {
            name: "upstream-zstd-profile-2",
            input: InteropInput::UpstreamFile("cli/tests/sample_files/zstd_dict/2.txt"),
            profile: "zstd",
            profile_arg: None,
            extra_args: &[],
            relaxed_limits: false,
        },
        InteropCase {
            name: "upstream-zstd-profile-3",
            input: InteropInput::UpstreamFile("cli/tests/sample_files/zstd_dict/3.txt"),
            profile: "zstd",
            profile_arg: None,
            extra_args: &[],
            relaxed_limits: false,
        },
        InteropCase {
            name: "upstream-zstd-profile-4",
            input: InteropInput::UpstreamFile("cli/tests/sample_files/zstd_dict/4.txt"),
            profile: "zstd",
            profile_arg: None,
            extra_args: &[],
            relaxed_limits: false,
        },
        InteropCase {
            name: "upstream-zstd-profile-5",
            input: InteropInput::UpstreamFile("cli/tests/sample_files/zstd_dict/5.txt"),
            profile: "zstd",
            profile_arg: None,
            extra_args: &[],
            relaxed_limits: false,
        },
        InteropCase {
            name: "upstream-zstd-profile-6",
            input: InteropInput::UpstreamFile("cli/tests/sample_files/zstd_dict/6.txt"),
            profile: "zstd",
            profile_arg: None,
            extra_args: &[],
            relaxed_limits: false,
        },
        InteropCase {
            name: "upstream-zstd-profile-7",
            input: InteropInput::UpstreamFile("cli/tests/sample_files/zstd_dict/7.txt"),
            profile: "zstd",
            profile_arg: None,
            extra_args: &[],
            relaxed_limits: false,
        },
        InteropCase {
            name: "upstream-zstd-profile-8",
            input: InteropInput::UpstreamFile("cli/tests/sample_files/zstd_dict/8.txt"),
            profile: "zstd",
            profile_arg: None,
            extra_args: &[],
            relaxed_limits: false,
        },
        InteropCase {
            name: "upstream-zstd-profile-9",
            input: InteropInput::UpstreamFile("cli/tests/sample_files/zstd_dict/9.txt"),
            profile: "zstd",
            profile_arg: None,
            extra_args: &[],
            relaxed_limits: false,
        },
    ]
}

fn release_smoke_interop_cases() -> Vec<InteropCase> {
    vec![
        InteropCase {
            name: "serial-small",
            input: InteropInput::Inline(b"openzl release smoke serial fixture\n".to_vec()),
            profile: "serial",
            profile_arg: None,
            extra_args: &[],
            relaxed_limits: false,
        },
        InteropCase {
            name: "u8-small",
            input: InteropInput::Inline((0..=63).collect()),
            profile: "u8",
            profile_arg: None,
            extra_args: &[],
            relaxed_limits: false,
        },
    ]
}

fn discovery_interop_cases() -> Vec<InteropCase> {
    vec![
        InteropCase {
            name: "discovery-csv-output-neighbors",
            input: InteropInput::UpstreamFile("cli/tests/sample_files/csv/output_neighbors.csv"),
            profile: "csv",
            profile_arg: None,
            extra_args: &["--no-store-on-expansion"],
            relaxed_limits: false,
        },
        InteropCase {
            name: "discovery-sddl2-asm-sao-silesia",
            input: InteropInput::UpstreamFile("examples/sddl2_asm/sao_silesia.bin"),
            profile: "sddl2",
            profile_arg: Some("tmp/openzl-upstream/examples/sddl2/sao_silesia.sddl"),
            extra_args: &["--no-store-on-expansion"],
            relaxed_limits: false,
        },
        InteropCase {
            name: "discovery-csv-pums-0001",
            input: InteropInput::UpstreamFile(
                "examples/getting_started/sample_inputs/csv_samples/0001.csv",
            ),
            profile: "csv",
            profile_arg: None,
            extra_args: &["--no-store-on-expansion"],
            relaxed_limits: false,
        },
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
    fn limits(&self) -> ozlrip::Limits {
        if self.relaxed_limits {
            ozlrip::Limits {
                max_decoded_bytes: 8 * 1024 * 1024,
                max_buffer_bytes: 8 * 1024 * 1024,
                max_expansion_ratio: 1_000_000,
                ..ozlrip::Limits::default()
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

fn zli_path() -> Option<PathBuf> {
    env::var_os("OZLRIP_ZLI").map(PathBuf::from)
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
