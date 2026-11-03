//! `Options::verify_content_checksum` and `verify_compressed_checksum` turn
//! off each kind of checksum verification separately.

use ozlrip::{ErrorKind, Options};
use ozlrip_test_support::{Chunk, FrameBuilder};

/// A stored frame with both checksums; the content checksum is the 4 bytes
/// before the compressed checksum, which ends before the end marker.
fn frame_with_checksums(chunk: Chunk, decoded_len: usize) -> Vec<u8> {
    FrameBuilder::new(21)
        .content_checksum(true)
        .compressed_checksum(true)
        .serial_output(decoded_len)
        .chunk(chunk)
        .build()
}

fn options(content: bool, compressed: bool) -> Options {
    let mut options = Options::default();
    options.verify_content_checksum = content;
    options.verify_compressed_checksum = compressed;
    options
}

fn decode(frame: &[u8], options: Options) -> Result<Vec<u8>, ErrorKind> {
    ozlrip::decode_with_options(frame, options).map_err(|err| err.kind())
}

#[test]
fn both_checksums_are_verified_by_default() {
    let options = Options::default();
    assert!(options.verify_content_checksum && options.verify_compressed_checksum);
}

#[test]
fn content_checksum_mismatch_passes_when_not_verified() {
    let mut frame = frame_with_checksums(Chunk::stored(*b"abc"), 3);
    let content_checksum = frame.len() - 9;
    frame[content_checksum] ^= 1;

    assert_eq!(
        decode(&frame, Options::default()),
        Err(ErrorKind::ChecksumMismatch)
    );
    // Flipping a content checksum byte also breaks the compressed checksum,
    // which covers it.
    assert_eq!(
        decode(&frame, options(false, true)),
        Err(ErrorKind::ChecksumMismatch)
    );
    assert_eq!(
        decode(&frame, options(true, false)),
        Err(ErrorKind::ChecksumMismatch)
    );
    assert_eq!(decode(&frame, options(false, false)).unwrap(), b"abc");
}

#[test]
fn compressed_checksum_mismatch_passes_when_not_verified() {
    let mut frame = frame_with_checksums(Chunk::stored(*b"abc"), 3);
    let compressed_checksum = frame.len() - 5;
    frame[compressed_checksum] ^= 1;

    assert_eq!(
        decode(&frame, Options::default()),
        Err(ErrorKind::ChecksumMismatch)
    );
    let err = ozlrip::inspect(&frame).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::ChecksumMismatch);

    assert_eq!(decode(&frame, options(true, false)).unwrap(), b"abc");
    assert!(ozlrip::inspect_with_options(&frame, options(true, false)).is_ok());
}

#[test]
fn header_checksum_follows_the_compressed_checksum_option() {
    let mut frame = frame_with_checksums(Chunk::stored(*b"abc"), 3);
    let header_checksum = ozlrip::inspect(&frame).unwrap().header_bytes - 1;
    frame[header_checksum] ^= 1;

    let err = ozlrip::inspect(&frame).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::ChecksumMismatch);
    assert_eq!(decode(&frame, options(true, false)).unwrap(), b"abc");
}

#[cfg(feature = "zstd")]
#[test]
fn single_zstd_frames_follow_both_options() {
    use ozlrip_test_support::{Node, ZSTD_TRANSFORM_ID, push_var_u64};

    let payload = b"zstd payload behind a content checksum".repeat(4);
    let compressed = zrip::compress(&payload, 1).unwrap();
    let mut stored = Vec::new();
    push_var_u64(&mut stored, 1);
    stored.extend_from_slice(&compressed[4..]);
    let chunk = Chunk::new()
        .node(Node::new(ZSTD_TRANSFORM_ID))
        .stored_stream(stored)
        .decoded(payload.clone());
    let clean = frame_with_checksums(chunk, payload.len());
    assert_eq!(decode(&clean, Options::default()).unwrap(), payload);

    let mut bad_content = clean.clone();
    let content_checksum = bad_content.len() - 9;
    bad_content[content_checksum] ^= 1;
    assert_eq!(
        decode(&bad_content, Options::default()),
        Err(ErrorKind::ChecksumMismatch)
    );
    assert_eq!(
        decode(&bad_content, options(false, false)).unwrap(),
        payload
    );

    let mut bad_compressed = clean;
    let compressed_checksum = bad_compressed.len() - 5;
    bad_compressed[compressed_checksum] ^= 1;
    assert_eq!(
        decode(&bad_compressed, Options::default()),
        Err(ErrorKind::ChecksumMismatch)
    );
    assert_eq!(
        decode(&bad_compressed, options(true, false)).unwrap(),
        payload
    );
}
