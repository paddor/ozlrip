use super::*;

/// Last format version of each deprecated transform (upstream
/// `decoder_registry.c`).
const ZSTD_FIXED_LAST_VERSION: u32 = 10;

fn lz4_serial_frame(stored: &[u8], decoded_len: usize) -> Vec<u8> {
    let mut transform_header = Vec::new();
    push_var_u64(&mut transform_header, u64::try_from(decoded_len).unwrap());
    let mut input = Vec::new();
    input.extend_from_slice(&magic(23));
    input.push(0);
    input.push(1);
    push_var_u64(&mut input, u64::try_from(decoded_len + 1).unwrap());
    input.push(2);
    input.push(1);
    input.push(0);
    input.push(62);
    input.push(1);
    push_var_u64(
        &mut input,
        u64::try_from(transform_header.len() - 1).unwrap(),
    );
    input.push(0);
    input.push(0);
    input.push(0);
    push_var_u64(&mut input, u64::try_from(stored.len()).unwrap());
    input.extend_from_slice(&transform_header);
    input.extend_from_slice(stored);
    input.push(0);
    input
}

fn zstd_serial_frame(stored: &[u8], decoded_len: usize) -> Vec<u8> {
    standard_transform_serial_frame(21, 22, stored, decoded_len, &[])
}

fn zstd_fixed_serial_frame(stored: &[u8], decoded_len: usize) -> Vec<u8> {
    standard_transform_serial_frame(ZSTD_FIXED_LAST_VERSION, 23, stored, decoded_len, &[])
}

#[cfg(feature = "lz4")]
#[test]
fn decodes_v23_lz4_serial_chunk() {
    let expected = b"lz4-backed OpenZL serial chunk";
    let compressed = lz4rip::block::compress(expected);
    let input = lz4_serial_frame(&compressed, expected.len());
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, expected.len());
    assert_eq!(output, expected);
}

#[cfg(feature = "zstd")]
#[test]
fn decodes_v21_zstd_serial_chunk() {
    let expected = b"zstd-backed OpenZL serial chunk";
    let compressed = zrip::compress(expected, 1).unwrap();
    let mut stored = Vec::new();
    push_var_u64(&mut stored, 1);
    stored.extend_from_slice(&compressed[4..]);
    let input = zstd_serial_frame(&stored, expected.len());
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, expected.len());
    assert_eq!(output, expected);
}

#[cfg(feature = "zstd")]
#[test]
fn decodes_v10_zstd_fixed_serial_chunk() {
    let expected = b"legacy zstd fixed OpenZL serial chunk";
    let stored = zstd_stored_stream(expected);
    let input = zstd_fixed_serial_frame(&stored, expected.len());
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    let written = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(written, expected.len());
    assert_eq!(output, expected);
}

/// Before format v9 zstd nodes hold whole zstd frames, magic number
/// included.
#[cfg(feature = "zstd")]
#[test]
fn decodes_v8_zstd_frames_with_their_magic_number() {
    let expected = b"zstd frame with its magic number";
    let mut stored = Vec::new();
    push_var_u64(&mut stored, 1);
    stored.extend_from_slice(&zrip::compress(expected, 1).unwrap());
    let input = standard_transform_serial_frame(8, 22, &stored, expected.len(), &[]);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = Vec::new();

    decode_plan(&input, &plan, &mut output, Limits::default()).unwrap();

    assert_eq!(output, expected);
}

#[cfg(feature = "zstd")]
#[test]
fn rejects_v8_zstd_frames_without_their_magic_number() {
    let expected = b"zstd frame without its magic number";
    let stored = zstd_stored_stream(expected);
    let input = standard_transform_serial_frame(8, 22, &stored, expected.len(), &[]);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];

    let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
    assert_eq!(err.detail(), Some("zstd magic number is missing"));
    assert_eq!(output, [1, 2]);
}

/// Runs one zstd or `zstd_fixed` node over `stored` in format v10.
#[cfg(feature = "zstd")]
fn run_zstd_node(standard_id: u32, stored: &[u8]) -> Result<OwnedStream> {
    let mut scratch = DecodeScratch::new();
    let mut dict_store = DictionaryStore::new();
    let mut zstd = None;
    let mut ctx = StandardNodeContext {
        format_version: ZSTD_FIXED_LAST_VERSION,
        limits: Limits::default(),
        scratch: &mut scratch,
        dictionary_bundle_id: None,
        dict_store: &mut dict_store,
        zstd: &mut zstd,
    };
    let input = StreamInput {
        bytes: stored,
        element_width: 1,
        string_lengths: None,
    };
    let mut outputs = execute_standard_node(standard_id, &[input], 0, 1, None, &[], &mut ctx)?;
    Ok(outputs.remove(0))
}

/// A zstd node's input from format v9: the element width, then a zstd frame
/// without its magic number.
#[cfg(feature = "zstd")]
fn zstd_node_input(element_width: u64, content: &[u8]) -> Vec<u8> {
    let mut stored = Vec::new();
    push_var_u64(&mut stored, element_width);
    stored.extend_from_slice(&zrip::compress(content, 1).unwrap()[4..]);
    stored
}

/// `zstd_fixed` outputs records of the width its input states.
#[cfg(feature = "zstd")]
#[test]
fn decodes_zstd_fixed_records() {
    let content = b"0123456789abcdef";
    for width in [2, 4, 8] {
        let stored = zstd_node_input(width, content);

        let output = run_zstd_node(standard::ZSTD_FIXED_ID, &stored).unwrap();

        assert_eq!(output.element_width, usize::try_from(width).unwrap());
        assert_eq!(output.bytes, content);
    }
}

#[cfg(feature = "zstd")]
#[test]
fn rejects_zstd_fixed_content_that_splits_a_record() {
    let stored = zstd_node_input(4, b"0123456789");

    let err = run_zstd_node(standard::ZSTD_FIXED_ID, &stored).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
    assert_eq!(
        err.detail(),
        Some("zstd content size is not a multiple of its element width")
    );
}

/// The `zstd` node outputs bytes. Upstream writes element width 1 only.
#[cfg(feature = "zstd")]
#[test]
fn rejects_wide_zstd_elements_outside_zstd_fixed() {
    let stored = zstd_node_input(2, b"0123");

    let err = run_zstd_node(standard::ZSTD_ID, &stored).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Unsupported);
    let err = run_zstd_node(standard::ZSTD_FIXED_ID, &zstd_node_input(0, b"01")).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Malformed);
}

/// zrip caps a zstd node's output at the zstd frame's content size. Output
/// past that size is a malformed frame.
#[cfg(feature = "zstd")]
#[test]
fn rejects_zstd_node_output_past_its_content_size() {
    let compressible = b"zstd content longer than its header says ".repeat(4);
    let incompressible = (0u8..200).map(|i| i.wrapping_mul(97) ^ 0x5a).collect();
    for payload in [compressible, incompressible] {
        let mut stored = zstd_stored_stream(&payload);
        // Single segment with a one-byte content size after the descriptor.
        assert_eq!(stored[1] & 0xe0, 0x20);
        assert_eq!(usize::from(stored[2]), payload.len());
        stored[2] -= 1;
        // The fixed-zstd node never decodes straight into the output.
        let input = zstd_fixed_serial_frame(&stored, payload.len());
        let plan = parse_frame_plan(&input, Limits::default()).unwrap();
        let mut output = vec![1, 2];

        let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Malformed);
        assert_eq!(output, [1, 2]);
    }
}

#[cfg(feature = "zstd")]
#[test]
fn rejects_malformed_zstd_chunk_without_mutating_destination() {
    let mut stored = Vec::new();
    push_var_u64(&mut stored, 1);
    stored.extend_from_slice(&[0]);
    let input = zstd_serial_frame(&stored, 8);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];

    let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
    assert_eq!(output, [1, 2]);
}

#[cfg(feature = "zstd")]
#[test]
fn rejects_zstd_non_byte_output_width_without_mutating_destination() {
    let expected = b"zstd-backed OpenZL serial chunk";
    let compressed = zrip::compress(expected, 1).unwrap();
    let mut stored = Vec::new();
    push_var_u64(&mut stored, 2);
    stored.extend_from_slice(&compressed[4..]);
    let input = zstd_serial_frame(&stored, expected.len());
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];

    let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Unsupported);
    assert_eq!(output, [1, 2]);
}

#[cfg(feature = "zstd")]
#[test]
fn rejects_zstd_transform_header_without_mutating_destination() {
    let expected = b"zstd-backed OpenZL serial chunk";
    let compressed = zrip::compress(expected, 1).unwrap();
    let mut stored = Vec::new();
    push_var_u64(&mut stored, 1);
    stored.extend_from_slice(&compressed[4..]);
    let input = standard_transform_serial_frame(21, 22, &stored, expected.len(), &[0]);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];

    let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Unsupported);
    assert_eq!(output, [1, 2]);
}

#[cfg(feature = "zstd")]
#[test]
fn enforces_zstd_output_limit_without_mutating_destination() {
    let expected = b"zstd output larger than configured limits";
    let compressed = zrip::compress(expected, 1).unwrap();
    let mut stored = Vec::new();
    push_var_u64(&mut stored, 1);
    stored.extend_from_slice(&compressed[4..]);
    let input = zstd_serial_frame(&stored, expected.len());
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];
    let mut limits = Limits::default();
    limits.max_decoded_bytes = 8;
    limits.max_buffer_bytes = 8;

    let err = decode_plan(&input, &plan, &mut output, limits).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::LimitExceeded);
    assert_eq!(output, [1, 2]);
}

#[cfg(not(feature = "zstd"))]
#[test]
fn rejects_zstd_chunk_when_feature_is_disabled() {
    let input = zstd_serial_frame(&[1, 0], 8);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];

    let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Unsupported);
    assert_eq!(output, [1, 2]);
}

#[cfg(not(feature = "zstd"))]
#[test]
fn rejects_zstd_fixed_chunk_when_feature_is_disabled() {
    let input = zstd_fixed_serial_frame(&[1, 0], 8);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];

    let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Unsupported);
    assert_eq!(output, [1, 2]);
}

#[cfg(feature = "lz4")]
#[test]
fn rejects_malformed_lz4_chunk_without_mutating_destination() {
    let input = lz4_serial_frame(&[0], 8);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];

    let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
    assert_eq!(output, [1, 2]);
}

/// An LZ4 block expands at most 255 times, so a larger declared size is
/// rejected before the output is allocated. A near-maximal real block still
/// decodes.
#[cfg(feature = "lz4")]
#[test]
fn rejects_lz4_declared_size_beyond_maximum_expansion() {
    let mut header = Vec::new();
    push_var_u64(&mut header, 3 * 255 + 1);
    let err = decode_lz4_chunk(&[0, 0, 0], &header, Limits::default()).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Malformed);
    assert!(err.detail().unwrap().contains("expansion"), "{err}");

    let zeros = vec![0u8; 1 << 20];
    let compressed = lz4rip::block::compress(&zeros);
    assert!(compressed.len() * 250 < zeros.len());
    let mut header = Vec::new();
    push_var_u64(&mut header, u64::try_from(zeros.len()).unwrap());
    let decoded = decode_lz4_chunk(&compressed, &header, Limits::default()).unwrap();
    assert_eq!(decoded.len(), zeros.len());
    assert!(decoded.iter().all(|&byte| byte == 0));
}

#[cfg(feature = "lz4")]
#[test]
fn enforces_lz4_header_output_limit_without_mutating_destination() {
    let input = lz4_serial_frame(&[0], 4096);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];
    let mut limits = Limits::default();
    limits.max_decoded_bytes = 1024;
    limits.max_buffer_bytes = 1024;

    let err = decode_plan(&input, &plan, &mut output, limits).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::LimitExceeded);
    assert_eq!(output, [1, 2]);
}

#[cfg(not(feature = "lz4"))]
#[test]
fn rejects_lz4_chunk_when_feature_is_disabled() {
    let input = lz4_serial_frame(&[0], 8);
    let plan = parse_frame_plan(&input, Limits::default()).unwrap();
    let mut output = vec![1, 2];

    let err = decode_plan(&input, &plan, &mut output, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Unsupported);
    assert_eq!(output, [1, 2]);
}
