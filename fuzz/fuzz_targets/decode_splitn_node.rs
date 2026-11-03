#![no_main]

use libfuzzer_sys::fuzz_target;
use ozlrip::Limits;
use ozlrip_test_support::{MAGIC_BASE, push_var_u64};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let stream_count = usize::from(data[0] % 4);
    let payload = &data[1..];
    let frame = splitn_serial_frame(payload, stream_count);
    let mut limits = Limits::strict();
    limits.max_frame_bytes = 8192;
    limits.max_decoded_bytes = 4096;
    limits.max_chunks = 1;
    limits.max_nodes = 1;
    limits.max_streams = 4;
    limits.max_transform_header_bytes = 1;
    limits.max_stored_stream_bytes = 8192;
    limits.max_buffer_bytes = 4096;
    limits.max_graph_depth = 1;
    limits.max_expansion_ratio = 4096;
    let mut output = Vec::new();
    let _ = ozlrip::decode_into_with_options(&frame, &mut output, ozlrip::Options::from(limits));
});

fn splitn_serial_frame(payload: &[u8], stream_count: usize) -> Vec<u8> {
    let mut input = Vec::new();
    input.extend_from_slice(&(MAGIC_BASE + 21).to_le_bytes());
    input.push(0);
    input.push(1);
    push_var_u64(&mut input, u64::try_from(payload.len() + 1).unwrap());
    input.push(2);
    push_var_u64(&mut input, u64::try_from(stream_count).unwrap());
    input.push(0);
    input.push(40);
    if stream_count == 0 {
        input.push(1);
        input.push(0);
    } else {
        input.push(0);
    }
    if stream_count == 0 {
        input.push(0);
    } else {
        input.push(1);
        push_var_u64(&mut input, u64::try_from(stream_count - 1).unwrap());
    }
    input.push(0);
    if stream_count != 0 {
        input.push(0);
    }

    let base = if stream_count == 0 {
        0
    } else {
        payload.len() / stream_count
    };
    let extra = if stream_count == 0 {
        0
    } else {
        payload.len() % stream_count
    };
    for index in 0..stream_count {
        let len = base + usize::from(index < extra);
        push_var_u64(&mut input, u64::try_from(len).unwrap());
    }
    if stream_count == 0 {
        input.push(1);
    } else {
        let mut offset = 0usize;
        for index in 0..stream_count {
            let len = base + usize::from(index < extra);
            input.extend_from_slice(&payload[offset..offset + len]);
            offset += len;
        }
    }
    input.push(0);
    input
}
