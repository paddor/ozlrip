#![no_main]

use libfuzzer_sys::fuzz_target;
use ozlrip::Limits;
use ozlrip_test_support::{MAGIC_BASE, push_var_u64, standard_transform_serial_frame};

const ZSTD_ID: u32 = 22;

// A zstd frame after the first byte. An odd first byte puts it in a
// format v8 frame, whose zstd frames keep their magic number.
fuzz_target!(|data: &[u8]| {
    let Some((&control, zstd)) = data.split_first() else {
        return;
    };
    let mut stored = Vec::new();
    push_var_u64(&mut stored, 1);
    stored.extend_from_slice(zstd);
    let frame = if control & 1 == 0 {
        zstd_serial_frame(&stored)
    } else {
        let decoded_len = zstd_content_size(zstd).unwrap_or(0);
        standard_transform_serial_frame(8, ZSTD_ID, &stored, decoded_len, &[])
    };
    let mut limits = Limits::strict();
    limits.max_frame_bytes = 8192;
    limits.max_decoded_bytes = 4096;
    limits.max_chunks = 1;
    limits.max_nodes = 1;
    limits.max_streams = 2;
    limits.max_transform_header_bytes = 0;
    limits.max_stored_stream_bytes = 8192;
    limits.max_buffer_bytes = 4096;
    limits.max_graph_depth = 1;
    limits.max_expansion_ratio = 4096;
    let mut output = Vec::new();
    let _ = ozlrip::decode_into_with_options(&frame, &mut output, ozlrip::Options::from(limits));
});

fn zstd_serial_frame(stored: &[u8]) -> Vec<u8> {
    let mut input = Vec::new();
    input.extend_from_slice(&(MAGIC_BASE + 21).to_le_bytes());
    input.push(0);
    input.push(1);
    input.push(0);
    input.push(2);
    input.push(1);
    input.push(0);
    input.push(22);
    input.push(0);
    input.push(0);
    input.push(0);
    input.push(0);
    push_var_u64(&mut input, u64::try_from(stored.len()).unwrap());
    input.extend_from_slice(stored);
    input.push(0);
    input
}

/// The single-byte frame content size of a zstd frame with its magic
/// number, when it has one.
fn zstd_content_size(frame: &[u8]) -> Option<usize> {
    let [0x28, 0xb5, 0x2f, 0xfd, descriptor, rest @ ..] = frame else {
        return None;
    };
    // A single-segment frame without a dictionary ID and a one-byte size.
    (descriptor & 0xe3 == 0x20).then(|| rest.first().map(|&size| usize::from(size)))?
}
