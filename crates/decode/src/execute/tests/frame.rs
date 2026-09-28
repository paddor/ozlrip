use super::*;

#[cfg(feature = "zstd")]
fn mixed_direct_append_frame() -> Vec<u8> {
    let zstd_output = b"zstd";
    let mut constant_header = Vec::new();
    push_var_u64(&mut constant_header, 3);

    FrameBuilder::new(21)
        .serial_output(zstd_output.len() + 3)
        .chunk(
            Chunk::new()
                .node(Node::new(22))
                .stored_stream(zstd_stored_stream(zstd_output)),
        )
        .chunk(
            Chunk::new()
                .node(Node::new(44).header(constant_header))
                .stored_stream(*b"!"),
        )
        .build()
}

#[test]
fn decodes_v21_stored_serial_output() {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(0);
    input.push(1);
    input.push(4);
    input.push(1);
    input.push(1);
    input.push(3);
    input.extend_from_slice(&[7, 8, 9]);
    input.push(0);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 3);
    assert_eq!(output, [7, 8, 9]);
}

#[test]
fn decodes_empty_v21_stored_serial_output() {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(0);
    input.push(1);
    input.push(1);
    input.push(0);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 0);
    assert_eq!(output, [1, 2]);
}

#[test]
fn decodes_v21_stored_serial_chunks() {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(0);
    input.push(1);
    input.push(8);
    input.push(1);
    input.push(1);
    input.push(3);
    input.extend_from_slice(&[7, 8, 9]);
    input.push(1);
    input.push(1);
    input.push(4);
    input.extend_from_slice(&[10, 11, 12, 13]);
    input.push(0);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 7);
    assert_eq!(output, [7, 8, 9, 10, 11, 12, 13]);
}

#[cfg(feature = "zstd")]
#[test]
fn chooses_direct_append_per_chunk() {
    let input = mixed_direct_append_frame();
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();

    let direct = plan
        .chunks
        .iter()
        .map(|chunk| direct_append_tail(&build_chunk_execution_plan(chunk).unwrap()).is_some())
        .collect::<Vec<_>>();

    assert_eq!(direct, [true, false]);
}

#[cfg(feature = "zstd")]
#[test]
fn decodes_mixed_direct_append_and_fallback_chunks() {
    let input = mixed_direct_append_frame();
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 7);
    assert_eq!(output, b"zstd!!!");
}

#[test]
fn rejects_size_mismatch_without_mutating_destination() {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(0);
    input.push(1);
    input.push(5);
    input.push(1);
    input.push(1);
    input.push(3);
    input.extend_from_slice(&[7, 8, 9]);
    input.push(0);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];

    let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
    assert_eq!(output, [1, 2]);
}

#[test]
fn enforces_expansion_ratio_without_mutating_destination() {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(0);
    input.push(1);
    input.push(4);
    input.push(1);
    input.push(1);
    input.push(3);
    input.extend_from_slice(&[7, 8, 9]);
    input.push(0);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];
    let mut limits = Limits::default();
    limits.max_expansion_ratio = 0;
    limits.expansion_ratio_exempt_bytes = 0;

    let err = decode_plan(&input, &plan, &mut output, limits).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::LimitExceeded);
    assert_eq!(output, [1, 2]);
}

#[test]
fn verifies_decoded_checksum() {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(1);
    input.push(1);
    input.push(4);
    input.push(1);
    input.push(1);
    input.push(3);
    input.extend_from_slice(&[7, 8, 9]);
    let checksum = (xxhash_rust::xxh3::xxh3_64(&[7, 8, 9]) & 0xffff_ffff) as u32;
    input.extend_from_slice(&checksum.to_le_bytes());
    input.push(0);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 3);
    assert_eq!(output, [7, 8, 9]);
}

#[test]
fn rejects_decoded_checksum_mismatch_without_mutating_destination() {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(1);
    input.push(1);
    input.push(4);
    input.push(1);
    input.push(1);
    input.push(3);
    input.extend_from_slice(&[7, 8, 9]);
    input.extend_from_slice(&0u32.to_le_bytes());
    input.push(0);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];

    let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::ChecksumMismatch);
    assert_eq!(output, [1, 2]);
}

#[test]
fn verifies_compressed_checksum() {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(1 << 1);
    input.push(1);
    input.push(4);
    let header_checksum = (xxhash_rust::xxh3::xxh3_64(&input) & 0xff) as u8;
    input.push(header_checksum);
    let chunk_start = input.len();
    input.push(1);
    input.push(1);
    input.push(3);
    input.extend_from_slice(&[7, 8, 9]);
    let checksum = (xxhash_rust::xxh3::xxh3_64(&input[chunk_start..]) & 0xffff_ffff) as u32;
    input.extend_from_slice(&checksum.to_le_bytes());
    input.push(0);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, 3);
    assert_eq!(output, [7, 8, 9]);
}

#[test]
fn rejects_compressed_checksum_mismatch() {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(1 << 1);
    input.push(1);
    input.push(4);
    let header_checksum = (xxhash_rust::xxh3::xxh3_64(&input) & 0xff) as u8;
    input.push(header_checksum);
    input.push(1);
    input.push(1);
    input.push(3);
    input.extend_from_slice(&[7, 8, 9]);
    input.extend_from_slice(&0u32.to_le_bytes());
    input.push(0);

    let err = parse_frame_plan(&input, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::ChecksumMismatch);
}

#[test]
fn rejects_compressed_checksum_before_decoded_checksum() {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push((1 << 0) | (1 << 1));
    input.push(1);
    input.push(4);
    let header_checksum = (xxhash_rust::xxh3::xxh3_64(&input) & 0xff) as u8;
    input.push(header_checksum);
    input.push(1);
    input.push(1);
    input.push(3);
    input.extend_from_slice(&[7, 8, 9]);
    input.extend_from_slice(&0u32.to_le_bytes());
    input.extend_from_slice(&0u32.to_le_bytes());
    input.push(0);

    let err = parse_frame_plan(&input, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::ChecksumMismatch);
    assert!(err.detail().unwrap().contains("compressed"));
}

#[test]
fn bounds_live_intermediate_stream_bytes() {
    // zigzag regenerates a 3-byte stream that delta consumes into the 4-byte
    // output, so at most 4 bytes are live at once.
    let input = zigzag_delta_graph_frame(&[2, 1, 6], 10);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut limits = Limits::default();

    limits.max_live_bytes = 3;
    let err = decode_plan(&input, &plan, &mut Vec::new(), limits).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::LimitExceeded);

    limits.max_live_bytes = 4;
    let mut output = Vec::new();
    decode_plan(&input, &plan, &mut output, limits).unwrap();
    assert_eq!(output.len(), 4);
}
