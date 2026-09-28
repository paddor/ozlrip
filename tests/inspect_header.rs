//! `inspect_header` reads what a frame header states from a prefix that
//! holds only the header.

use ozlrip::{ErrorKind, FrameValueType, Options};
use ozlrip_test_support::{Chunk, FrameBuilder, OutputType};

fn typed_frame() -> Vec<u8> {
    FrameBuilder::new(22)
        .compressed_checksum(true)
        .comment(*b"note")
        .output(OutputType::Numeric, 8)
        .string_output(5, 2)
        .chunk(Chunk::stored(*b"payload that inspect_header never reads"))
        .build()
}

#[test]
fn reads_outputs_from_the_header_alone() {
    let frame = typed_frame();
    let header_bytes = ozlrip::inspect_header(&frame).unwrap().header_bytes;

    let header = ozlrip::inspect_header(&frame[..header_bytes]).unwrap();

    assert_eq!(header.format_version, 22);
    assert_eq!(header.header_bytes, header_bytes);
    assert_eq!(header.outputs, 2);
    assert_eq!(
        header.output_types,
        [FrameValueType::Numeric, FrameValueType::String]
    );
    assert_eq!(header.output_sizes, [Some(8), Some(5)]);
    assert_eq!(header.output_elements, [None, Some(2)]);
    assert_eq!(header.comment.as_deref(), Some(&b"note"[..]));
}

#[test]
fn rejects_prefixes_shorter_than_the_header() {
    let frame = typed_frame();
    let header_bytes = ozlrip::inspect_header(&frame).unwrap().header_bytes;

    for len in 0..header_bytes {
        let err = ozlrip::inspect_header(&frame[..len]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Truncated, "prefix {len}");
    }
}

#[test]
fn header_checksum_follows_the_compressed_checksum_option() {
    let mut frame = typed_frame();
    let header_bytes = ozlrip::inspect_header(&frame).unwrap().header_bytes;
    frame[header_bytes - 1] ^= 1;

    let err = ozlrip::inspect_header(&frame).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::ChecksumMismatch);

    let mut options = Options::default();
    options.verify_compressed_checksum = false;
    assert!(ozlrip::inspect_header_with_options(&frame, options).is_ok());
}

#[test]
fn reads_legacy_headers() {
    let frame = FrameBuilder::new(14)
        .output(OutputType::Struct, 6)
        .chunk(Chunk::stored(*b"abcdef"))
        .build();

    let header = ozlrip::inspect_header(&frame).unwrap();

    assert_eq!(header.output_types, [FrameValueType::Struct]);
    assert_eq!(header.output_sizes, [Some(6)]);
}
