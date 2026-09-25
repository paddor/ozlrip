//! Checks that `ozlrip-test-support` builds frames the parser accepts.

use ozlrip::FrameValueType;
use ozlrip_test_support::{Chunk, FrameBuilder, OutputType};

#[test]
fn stored_chunks_with_checksums_decode() {
    let frame = FrameBuilder::new(21)
        .content_checksum(true)
        .compressed_checksum(true)
        .serial_output(6)
        .chunk(Chunk::stored(*b"abc"))
        .chunk(Chunk::stored(*b"def"))
        .build();

    let info = ozlrip::inspect(&frame).unwrap();
    assert_eq!(info.chunks, 2);
    assert!(info.has_decoded_checksum && info.has_encoded_checksum);
    assert_eq!(ozlrip::decode(&frame).unwrap(), b"abcdef");
}

#[cfg(feature = "checksum")]
#[test]
fn corrupted_content_checksum_is_rejected() {
    let mut frame = FrameBuilder::new(21)
        .content_checksum(true)
        .serial_output(3)
        .chunk(Chunk::stored(*b"abc"))
        .build();
    let checksum = frame.len() - 5;
    frame[checksum] ^= 1;

    let err = ozlrip::decode(&frame).unwrap_err();
    assert_eq!(err.kind(), ozlrip::ErrorKind::ChecksumMismatch);
}

#[cfg(feature = "zstd")]
#[test]
fn zstd_node_chunk_decodes() {
    use ozlrip_test_support::{Node, ZSTD_TRANSFORM_ID};

    let payload = b"zstd node payload, zstd node payload".to_vec();
    let compressed = zrip::compress(&payload, 1).unwrap();
    let mut stored = Vec::new();
    ozlrip_test_support::push_var_u64(&mut stored, 1);
    stored.extend_from_slice(&compressed[4..]);

    let frame = FrameBuilder::new(21)
        .content_checksum(true)
        .compressed_checksum(true)
        .serial_output(payload.len())
        .chunk(
            Chunk::new()
                .node(Node::new(ZSTD_TRANSFORM_ID))
                .stored_stream(stored)
                .decoded(payload.clone()),
        )
        .build();

    assert_eq!(ozlrip::decode(&frame).unwrap(), payload);
}

#[test]
fn comment_and_typed_outputs_inspect() {
    let frame = FrameBuilder::new(22)
        .comment(*b"hello")
        .output(OutputType::Numeric, 8)
        .string_output(3, 2)
        .build();

    let info = ozlrip::inspect(&frame).unwrap();
    assert_eq!(info.comment.as_deref(), Some(&b"hello"[..]));
    assert_eq!(
        info.output_types,
        [FrameValueType::Numeric, FrameValueType::String]
    );
    assert_eq!(info.output_sizes, [Some(8), Some(3)]);
    assert_eq!(info.output_elements, [None, Some(2)]);
}
