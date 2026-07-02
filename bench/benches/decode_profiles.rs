use std::{
    env,
    hint::black_box,
    time::{Duration, Instant},
};

const MAGIC_BASE: u32 = 0xd7b1_a5c0;
const DEFAULT_ITERS: usize = 10_000;

fn main() {
    let iters = env::var("OZLRIP_BENCH_ITERS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_ITERS);
    let cases = [
        ("store-only", store_only_frame(4096)),
        ("numeric-u8", store_only_frame(16 * 1024)),
        ("malformed-reject", malformed_frame()),
    ];

    for (name, frame) in cases {
        let elapsed = time_decode(&frame, iters);
        let bytes = frame.len().saturating_mul(iters);
        println!(
            "{name}: {} iters, {} bytes, {:?}",
            iters,
            bytes,
            elapsed
        );
    }
}

fn time_decode(frame: &[u8], iters: usize) -> Duration {
    let started = Instant::now();
    for _ in 0..iters {
        let _ = black_box(ozlrip::decode(black_box(frame)));
    }
    started.elapsed()
}

fn store_only_frame(payload_len: usize) -> Vec<u8> {
    let mut input = Vec::new();
    input.extend_from_slice(&(MAGIC_BASE + 21).to_le_bytes());
    input.push(0);
    input.push(1);
    push_var_u64(&mut input, u64::try_from(payload_len + 1).unwrap());
    input.push(1);
    input.push(1);
    push_var_u64(&mut input, u64::try_from(payload_len).unwrap());
    input.resize(input.len() + payload_len, 0x5a);
    input.push(0);
    input
}

fn malformed_frame() -> Vec<u8> {
    let mut input = Vec::new();
    input.extend_from_slice(&(MAGIC_BASE + 21).to_le_bytes());
    input.push(0);
    input.push(1);
    input.push(4);
    input.push(0);
    input.push(99);
    input
}

fn push_var_u64(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push(u8::try_from(value & 0x7f).unwrap() | 0x80);
        value >>= 7;
    }
    out.push(u8::try_from(value).unwrap());
}
