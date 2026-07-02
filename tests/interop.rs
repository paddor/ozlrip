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

#[test]
fn upstream_zli_golden_roundtrips_match_ozlrip() {
    let Some(zli) = zli_path() else {
        eprintln!("skipping interop test: set OZLRIP_ZLI to an upstream zli binary");
        return;
    };
    let work = WorkDir::new("ozlrip-interop");
    let upstream_commit = upstream_commit(&zli).unwrap_or_else(|| "unknown".to_owned());
    let mut manifest = String::new();
    writeln!(
        manifest,
        "upstream_commit={upstream_commit}\nformat_version=max"
    )
    .unwrap();

    for case in interop_cases() {
        let name = case.name;
        let input = case.input.as_slice();
        let profile = case.profile;
        let input_path = work.path.join(format!("{name}.input"));
        let frame_path = work.path.join(format!("{name}.zl"));
        let zli_decoded_path = work.path.join(format!("{name}.zli.decoded"));
        fs::write(&input_path, input).unwrap();

        run(
            &zli,
            [
                OsStr::new("compress"),
                input_path.as_os_str(),
                OsStr::new("--profile"),
                OsStr::new(profile),
                OsStr::new("-o"),
                frame_path.as_os_str(),
                OsStr::new("-f"),
            ],
        );
        run(
            &zli,
            [
                OsStr::new("decompress"),
                frame_path.as_os_str(),
                OsStr::new("-o"),
                zli_decoded_path.as_os_str(),
                OsStr::new("-f"),
            ],
        );

        let frame = fs::read(&frame_path).unwrap();
        let zli_decoded = fs::read(&zli_decoded_path).unwrap();
        assert_eq!(zli_decoded, input, "{name} upstream roundtrip changed data");

        let ozlrip_decoded = ozlrip::decode(&frame).unwrap_or_else(|err| {
            panic!("{name} ozlrip decode failed: {err:?}");
        });
        assert_eq!(ozlrip_decoded, input, "{name} ozlrip output mismatch");

        writeln!(
            manifest,
            "fixture={name}\nprofile={profile}\ncompress_command={}\ndecompress_command={}\ninput_hash={:016x}\nframe_hash={:016x}\ndecoded_hash={:016x}\n",
            command_line(
                &zli,
                [
                    OsStr::new("compress"),
                    input_path.as_os_str(),
                    OsStr::new("--profile"),
                    OsStr::new(profile),
                    OsStr::new("-o"),
                    frame_path.as_os_str(),
                    OsStr::new("-f"),
                ],
            ),
            command_line(
                &zli,
                [
                    OsStr::new("decompress"),
                    frame_path.as_os_str(),
                    OsStr::new("-o"),
                    zli_decoded_path.as_os_str(),
                    OsStr::new("-f"),
                ],
            ),
            hash64(input),
            hash64(&frame),
            hash64(&zli_decoded),
        )
        .unwrap();
    }

    let manifest_dir = Path::new("tmp").join("ozlrip-interop");
    fs::create_dir_all(&manifest_dir).unwrap();
    fs::write(manifest_dir.join("last-run.manifest"), manifest).unwrap();
}

fn interop_cases() -> Vec<InteropCase> {
    vec![
        InteropCase {
            name: "serial-small",
            input: b"openzl interop serial fixture\n".to_vec(),
            profile: "serial",
        },
        InteropCase {
            name: "u8-ramp",
            input: (0..=31).collect(),
            profile: "u8",
        },
        InteropCase {
            name: "i8-signed",
            input: [0i8, -1, 1, -2, 2, 63, -64, 100, -100]
                .into_iter()
                .map(i8::cast_unsigned)
                .collect(),
            profile: "i8",
        },
        InteropCase {
            name: "le-u16-ramp",
            input: le_bytes([0u16, 1, 2, 255, 256, 1024, u16::MAX]),
            profile: "le-u16",
        },
        InteropCase {
            name: "le-u32-ramp",
            input: le_bytes([0u32, 1, 255, 256, 65_535, 65_536, u32::MAX]),
            profile: "le-u32",
        },
    ]
}

fn le_bytes<const N: usize, T: LeBytes>(values: [T; N]) -> Vec<u8> {
    let mut out = Vec::new();
    for value in values {
        out.extend_from_slice(&value.to_le_vec());
    }
    out
}

trait LeBytes {
    fn to_le_vec(self) -> Vec<u8>;
}

impl LeBytes for u16 {
    fn to_le_vec(self) -> Vec<u8> {
        self.to_le_bytes().to_vec()
    }
}

impl LeBytes for u32 {
    fn to_le_vec(self) -> Vec<u8> {
        self.to_le_bytes().to_vec()
    }
}

struct InteropCase {
    name: &'static str,
    input: Vec<u8>,
    profile: &'static str,
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
