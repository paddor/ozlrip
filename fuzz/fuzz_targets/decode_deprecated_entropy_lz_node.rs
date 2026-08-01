#![no_main]

use libfuzzer_sys::fuzz_target;
use ozlrip::Limits;

const MAGIC_BASE: u32 = 0xd7b1_a5c0;
const FSE_DEPRECATED_ID: u8 = 15;
const HUFFMAN_DEPRECATED_ID: u8 = 16;
const HUFFMAN_FIXED_DEPRECATED_ID: u8 = 17;
const ROLZ_DEPRECATED_ID: u8 = 20;
const FASTLZ_DEPRECATED_ID: u8 = 21;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }

    let decoded_len = u16::from_le_bytes([data[1], data[2]]) as usize & 0x0fff;
    let payload = &data[3..];
    let (transform_id, stored, header) = match data[0] % 5 {
        0 => {
            let header = match data[0] & 0x10 {
                0 => Vec::new(),
                _ => vec![if data[0] & 0x20 == 0 { 2 } else { 4 }],
            };
            (FSE_DEPRECATED_ID, payload.to_vec(), header)
        }
        1 => (HUFFMAN_DEPRECATED_ID, payload.to_vec(), Vec::new()),
        2 => {
            let width = if data[0] & 0x20 == 0 { 1 } else { 2 };
            (
                HUFFMAN_FIXED_DEPRECATED_ID,
                payload.to_vec(),
                vec![data[0] & 0x40, width],
            )
        }
        3 => (
            FASTLZ_DEPRECATED_ID,
            deprecated_lz_stored_stream(decoded_len, payload),
            Vec::new(),
        ),
        _ => (
            ROLZ_DEPRECATED_ID,
            deprecated_lz_stored_stream(decoded_len, &rolz_payload(payload)),
            Vec::new(),
        ),
    };

    let frame = standard_transform_serial_frame(21, transform_id, &stored, decoded_len, &header);
    let limits = Limits {
        max_frame_bytes: 8192,
        max_decoded_bytes: 4096,
        max_chunks: 1,
        max_nodes: 1,
        max_streams: 2,
        max_transform_header_bytes: 16,
        max_stored_stream_bytes: 8192,
        max_buffer_bytes: 4096,
        max_graph_depth: 1,
        max_expansion_ratio: 4096,
    };
    let mut output = Vec::new();
    let _ = ozlrip::decode_into_with_options(
        &frame,
        &mut output,
        ozlrip::Options {
            limits,
            ..ozlrip::Options::default()
        },
    );
});

fn standard_transform_serial_frame(
    version: u32,
    transform_id: u8,
    stored: &[u8],
    decoded_len: usize,
    transform_header: &[u8],
) -> Vec<u8> {
    let mut input = Vec::new();
    input.extend_from_slice(&(MAGIC_BASE + version).to_le_bytes());
    input.push(0);
    input.push(1);
    push_var_u64(&mut input, u64::try_from(decoded_len + 1).unwrap());
    input.push(2);
    input.push(1);
    input.push(0);
    input.push(transform_id);
    if transform_header.is_empty() {
        input.push(0);
    } else {
        input.push(1);
        push_var_u64(
            &mut input,
            u64::try_from(transform_header.len() - 1).unwrap(),
        );
    }
    input.push(0);
    input.push(0);
    input.push(0);
    push_var_u64(&mut input, u64::try_from(stored.len()).unwrap());
    input.extend_from_slice(transform_header);
    input.extend_from_slice(stored);
    input.push(0);
    input
}

fn deprecated_lz_stored_stream(decoded_size: usize, payload: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(&u32::try_from(decoded_size).unwrap().to_le_bytes());
    output.extend_from_slice(payload);
    output
}

fn rolz_payload(data: &[u8]) -> Vec<u8> {
    let num_literals = data.get(..2).map_or(0, |bytes| {
        u16::from_le_bytes([bytes[0], bytes[1]]) as u32 & 0x03ff
    });
    let num_sequences = data.get(2..4).map_or(0, |bytes| {
        u16::from_le_bytes([bytes[0], bytes[1]]) as u32 & 0x00ff
    });
    let body = data.get(4..).unwrap_or_default();

    let mut output = Vec::new();
    output.extend_from_slice(&[2, 12, 4, 3, 1, 7, 3]);
    output.extend_from_slice(&num_literals.to_le_bytes());
    output.extend_from_slice(&num_sequences.to_le_bytes());
    output.extend_from_slice(body);
    output
}

fn push_var_u64(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push(u8::try_from(value & 0x7f).unwrap() | 0x80);
        value >>= 7;
    }
    out.push(u8::try_from(value).unwrap());
}
