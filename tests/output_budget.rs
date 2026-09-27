//! Decoded output is checked against the size the frame header declares:
//! before anything is reserved, after every chunk, and at the end.

use ozlrip::ErrorKind;
use ozlrip_test_support::{Chunk, FrameBuilder};

/// A tiny frame that declares 64 MiB of output fails on the expansion ratio
/// before the decoder reserves anything in the caller's buffer.
#[test]
fn declared_size_above_expansion_ratio_fails_before_reserving() {
    let frame = FrameBuilder::new(21)
        .serial_output(64 << 20)
        .chunk(Chunk::stored(*b"abc"))
        .build();
    let mut dst = Vec::new();

    let err = ozlrip::decode_into(&frame, &mut dst).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::LimitExceeded);
    assert_eq!(dst.capacity(), 0);
}

/// A chunk that overruns the declared size fails right away, not after later
/// chunks have been decoded and checked.
#[cfg(feature = "checksum")]
#[test]
fn stored_chunk_overrunning_declared_size_fails_before_later_chunks() {
    let frame = FrameBuilder::new(21)
        .content_checksum(true)
        .serial_output(3)
        .chunk(Chunk::stored(*b"abcd"))
        .chunk(Chunk::stored(*b"e").decoded(*b"not e"))
        .build();

    let err = ozlrip::decode(&frame).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
}

#[cfg(feature = "zstd")]
fn zstd_stored_stream(decoded: &[u8]) -> Vec<u8> {
    let compressed = zrip::compress(decoded, 1).unwrap();
    let mut stored = Vec::new();
    ozlrip_test_support::push_var_u64(&mut stored, 1);
    stored.extend_from_slice(&compressed[4..]);
    stored
}

#[cfg(feature = "zstd")]
fn zstd_chunk(decoded: &[u8]) -> Chunk {
    use ozlrip_test_support::{Node, ZSTD_TRANSFORM_ID};

    Chunk::new()
        .node(Node::new(ZSTD_TRANSFORM_ID))
        .stored_stream(zstd_stored_stream(decoded))
        .decoded(decoded)
}

/// A zstd chunk that decodes directly into the caller's buffer may not write
/// past the declared size.
#[cfg(all(feature = "zstd", feature = "checksum"))]
#[test]
fn zstd_chunk_overrunning_declared_size_fails_before_later_chunks() {
    let payload = b"zstd payload that is longer than declared ".repeat(100);
    let frame = FrameBuilder::new(21)
        .content_checksum(true)
        .serial_output(payload.len() - 1)
        .chunk(zstd_chunk(&payload))
        .chunk(Chunk::stored(*b"e").decoded(*b"not e"))
        .build();

    let err = ozlrip::decode(&frame).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
}

/// Single-zstd frames enforce the expansion ratio exactly, in the fast path
/// and in the plan-based path (a comment disables the fast path).
#[cfg(feature = "zstd")]
#[test]
fn single_zstd_frame_enforces_exact_expansion_ratio() {
    for comment in [None, Some(&b"note"[..])] {
        // Find a payload whose size exceeds frame_len * ratio by less than
        // frame_len, which a floor division would accept.
        let (frame, payload, ratio) = (3000usize..)
            .find_map(|len| {
                let payload = vec![0u8; len];
                let mut builder = FrameBuilder::new(22)
                    .serial_output(len)
                    .chunk(zstd_chunk(&payload));
                if let Some(comment) = comment {
                    builder = builder.comment(comment);
                }
                let frame = builder.build();
                (len % frame.len() != 0).then(|| {
                    let ratio = len / frame.len();
                    (frame, payload, ratio)
                })
            })
            .unwrap();

        let mut limits = ozlrip::Limits::strict();
        limits.max_expansion_ratio = ratio;
        let err = ozlrip::decode_with_options(&frame, limits.into()).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::LimitExceeded, "comment {comment:?}");

        limits.max_expansion_ratio = ratio + 1;
        let decoded = ozlrip::decode_with_options(&frame, limits.into()).unwrap();
        assert!(decoded == payload, "comment {comment:?}");
    }
}
