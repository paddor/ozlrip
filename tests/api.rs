use ozlrip::{ErrorKind, Limits, Options};

const MAGIC_BASE: u32 = 0xd7b1_a5c0;
const BUNDLE_INFO_MAGIC: u32 = 0x4942_ccda;
const PACKED_DICT_MAGIC: u32 = 0x4944_ccda;
const UNIQUE_ID_BYTES: usize = 32;
const FAT_BUNDLE_FLAG: u8 = 1;
const ZSTD_ID: u32 = 22;
const LZ4_ID: u32 = 62;

fn magic(version: u32) -> [u8; 4] {
    (MAGIC_BASE + version).to_le_bytes()
}

fn stored_serial_frame(bytes: &[u8]) -> Vec<u8> {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(0);
    input.push(1);
    input.push(u8::try_from(bytes.len() + 1).unwrap());
    input.push(1);
    input.push(1);
    input.push(u8::try_from(bytes.len()).unwrap());
    input.extend_from_slice(bytes);
    input.push(0);
    input
}

fn transform_graph_frame() -> Vec<u8> {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(0);
    input.push(1);
    input.push(4);
    input.push(2);
    input.push(1);
    input.push(0);
    input.push(62);
    input.push(0);
    input.push(0);
    input.push(0);
    input.push(0);
    input.push(3);
    input.extend_from_slice(&[1, 2, 3]);
    input.push(0);
    input
}

fn custom_transform_frame() -> Vec<u8> {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(0);
    input.push(1);
    input.push(1);
    input.push(2);
    input.push(0);
    input.push(1);
    input.push(1);
    input
}

fn bundled_stored_frame(bytes: &[u8]) -> Vec<u8> {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(25));
    input.push(1 << 3);
    input.push(2);
    input.extend_from_slice(&[1, 2]);
    input.push(1);
    input.push(u8::try_from(bytes.len() + 1).unwrap());
    input.push(1);
    input.push(1);
    input.push(u8::try_from(bytes.len()).unwrap());
    input.extend_from_slice(bytes);
    input.push(0);
    input
}

fn dictionary_bundle(codec_id: u32, custom: bool) -> Vec<u8> {
    let bundle_id = [7; UNIQUE_ID_BYTES];
    let dict_id = [9; UNIQUE_ID_BYTES];
    let content = [1u32.to_le_bytes(), 1i32.to_le_bytes()].concat();

    let mut bundle = Vec::new();
    bundle.extend_from_slice(&BUNDLE_INFO_MAGIC.to_le_bytes());
    bundle.extend_from_slice(&bundle_id);
    bundle.push(FAT_BUNDLE_FLAG);
    bundle.extend_from_slice(&1u32.to_le_bytes());
    bundle.extend_from_slice(&dict_id);
    bundle.extend_from_slice(&PACKED_DICT_MAGIC.to_le_bytes());
    bundle.extend_from_slice(&dict_id);
    bundle.extend_from_slice(&codec_id.to_le_bytes());
    bundle.push(u8::from(custom));
    bundle.extend_from_slice(&u32::try_from(content.len()).unwrap().to_le_bytes());
    bundle.extend_from_slice(&content);
    bundle
}

fn unknown_size_frame() -> Vec<u8> {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(0);
    input.push(1);
    input.push(0);
    input
}

fn comment_frame(comment: &[u8]) -> Vec<u8> {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(22));
    input.push(1 << 2);
    input.push(1);
    input.push(4);
    input.push(u8::try_from(comment.len()).unwrap());
    input.extend_from_slice(comment);
    input
}

#[test]
fn inspect_rejects_non_openzl_input() {
    let err = ozlrip::inspect(b"not-openzl").unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Unsupported);
}

#[test]
fn decode_into_preserves_destination_on_unsupported_header() {
    let mut dst = vec![1, 2, 3];
    let err = ozlrip::decode_into(b"not-openzl", &mut dst).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Unsupported);
    assert_eq!(dst, [1, 2, 3]);
}

#[test]
fn decode_into_preserves_destination_on_unsupported_graph() {
    let frame = transform_graph_frame();
    let mut dst = vec![1, 2, 3];

    let err = ozlrip::decode_into(&frame, &mut dst).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Unsupported);
    assert_eq!(dst, [1, 2, 3]);
}

#[test]
fn decode_into_preserves_destination_on_custom_transform() {
    let frame = custom_transform_frame();
    let mut dst = vec![1, 2, 3];

    let err = ozlrip::decode_into(&frame, &mut dst).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Unsupported);
    assert_eq!(dst, [1, 2, 3]);
}

#[test]
fn load_dictionary_bundle_rejects_custom_materializer() {
    let bundle = dictionary_bundle(ZSTD_ID, true);
    let mut decoder = ozlrip::Decoder::new();

    let err = decoder.load_dictionary_bundle(&bundle).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Unsupported);
}

#[test]
fn load_dictionary_bundle_rejects_external_materializer() {
    let bundle = dictionary_bundle(LZ4_ID, false);
    let mut decoder = ozlrip::Decoder::new();

    let err = decoder.load_dictionary_bundle(&bundle).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Unsupported);
}

#[test]
fn decode_into_accepts_unused_dictionary_bundle_id() {
    let frame = bundled_stored_frame(&[7, 8, 9]);
    let mut dst = vec![1, 2, 3];

    let written = ozlrip::decode_into(&frame, &mut dst).unwrap();

    assert_eq!(written, 3);
    assert_eq!(dst, [1, 2, 3, 7, 8, 9]);
    assert_eq!(
        ozlrip::inspect(&frame)
            .unwrap()
            .dictionary_bundle_id
            .as_deref(),
        Some(&[1, 2][..])
    );
}

#[test]
fn inspect_and_decode_reject_unknown_output_size() {
    let frame = unknown_size_frame();
    let inspect_err = ozlrip::inspect(&frame).unwrap_err();
    let mut dst = vec![1, 2, 3];

    let decode_err = ozlrip::decode_into(&frame, &mut dst).unwrap_err();

    assert_eq!(inspect_err.kind(), ErrorKind::Unsupported);
    assert_eq!(decode_err.kind(), ErrorKind::Unsupported);
    assert_eq!(dst, [1, 2, 3]);
}

#[test]
fn decode_returns_stored_serial_output() {
    let frame = stored_serial_frame(&[7, 8, 9]);

    let decoded = ozlrip::decode(&frame).unwrap();

    assert_eq!(decoded, [7, 8, 9]);
}

#[test]
fn decode_with_options_returns_stored_serial_output() {
    let frame = stored_serial_frame(&[7, 8, 9]);

    let decoded = ozlrip::decode_with_options(&frame, Options::default()).unwrap();

    assert_eq!(decoded, [7, 8, 9]);
}

#[test]
fn decode_into_appends_stored_serial_output() {
    let frame = stored_serial_frame(&[7, 8, 9]);
    let mut dst = vec![1, 2];

    let written = ozlrip::decode_into(&frame, &mut dst).unwrap();

    assert_eq!(written, 3);
    assert_eq!(dst, [1, 2, 7, 8, 9]);
}

#[test]
fn reusable_decoder_appends_outputs() {
    let frame = stored_serial_frame(&[7, 8, 9]);
    let mut decoder = ozlrip::Decoder::new();
    let mut dst = Vec::new();

    let first = decoder.decode_into(&frame, &mut dst).unwrap();
    let second = decoder.decode_into(&frame, &mut dst).unwrap();

    assert_eq!(first, 3);
    assert_eq!(second, 3);
    assert_eq!(dst, [7, 8, 9, 7, 8, 9]);
}

#[test]
fn reusable_decoder_decode_returns_owned_output() {
    let frame = stored_serial_frame(&[7, 8, 9]);
    let mut decoder = ozlrip::Decoder::with_options(Options::default());

    let decoded = decoder.decode(&frame).unwrap();

    assert_eq!(decoded, [7, 8, 9]);
}

#[test]
fn reusable_decoder_options_can_disable_plan_cache() {
    let frame = stored_serial_frame(&[7, 8, 9]);
    let options = Options {
        plan_cache_max_frame_bytes: 0,
        ..Options::default()
    };
    let mut decoder = ozlrip::Decoder::with_options(options);
    let mut dst = Vec::new();

    let first = decoder.decode_into(&frame, &mut dst).unwrap();
    let second = decoder.decode_into(&frame, &mut dst).unwrap();

    assert_eq!(decoder.options(), options);
    assert_eq!(decoder.limits(), options.limits);
    assert_eq!(first, 3);
    assert_eq!(second, 3);
    assert_eq!(dst, [7, 8, 9, 7, 8, 9]);
}

#[test]
fn reusable_decoder_rejects_mutated_cached_frame_buffer() {
    let mut frame = stored_serial_frame(&[7, 8, 9]);
    let mut decoder = ozlrip::Decoder::new();
    let mut dst = Vec::new();

    let written = decoder.decode_into(&frame, &mut dst).unwrap();
    frame[..4].copy_from_slice(b"nope");
    let err = decoder.decode_into(&frame, &mut dst).unwrap_err();

    assert_eq!(written, 3);
    assert_eq!(err.kind(), ErrorKind::Unsupported);
    assert_eq!(dst, [7, 8, 9]);
}

#[test]
fn inspect_reports_stored_serial_metadata() {
    let frame = stored_serial_frame(&[7, 8, 9]);

    let info = ozlrip::inspect(&frame).unwrap();
    let info_with_options = ozlrip::inspect_with_options(&frame, Options::default()).unwrap();

    assert_eq!(info.header_bytes, 7);
    assert_eq!(info.decoded_bytes, Some(3));
    assert_eq!(info.chunks, 1);
    assert_eq!(info.stored_streams, 1);
    assert_eq!(info.transforms, 0);
    assert_eq!(info_with_options, info);
}

#[test]
fn inspect_reports_header_comment_bytes() {
    let frame = comment_frame(b"release notes");

    let info = ozlrip::inspect(&frame).unwrap();

    assert!(info.has_comment);
    assert_eq!(info.comment.as_deref(), Some(b"release notes".as_slice()));
}

#[test]
fn inspect_enforces_stored_stream_limit() {
    let frame = stored_serial_frame(&[7, 8, 9]);
    let limits = Limits {
        max_stored_stream_bytes: 2,
        ..Limits::default()
    };

    let err = ozlrip::decode_into_with_options(
        &frame,
        &mut Vec::new(),
        Options {
            limits,
            ..Options::default()
        },
    )
    .unwrap_err();

    assert_eq!(err.kind(), ErrorKind::LimitExceeded);
}
