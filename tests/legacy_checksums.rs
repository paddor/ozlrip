//! Frames before format v21 carry their checksum flags in the chunk header
//! and end with the content checksum, then a compressed checksum over the
//! whole frame.

use ozlrip::ErrorKind;
use ozlrip_test_support::{Chunk, FrameBuilder};

const LEGACY_VERSIONS: [u32; 3] = [8, 14, 20];

fn legacy_frame(version: u32) -> Vec<u8> {
    FrameBuilder::new(version)
        .content_checksum(true)
        .compressed_checksum(true)
        .serial_output(3)
        .chunk(Chunk::stored(*b"abc"))
        .build()
}

#[test]
fn decodes_and_reports_pre_v21_checksums() {
    for version in LEGACY_VERSIONS {
        let frame = legacy_frame(version);

        assert_eq!(ozlrip::decode(&frame).unwrap(), b"abc", "v{version}");
        let info = ozlrip::inspect(&frame).unwrap();
        assert!(info.has_decoded_checksum, "v{version}");
        assert!(info.has_encoded_checksum, "v{version}");
    }
}

#[cfg(feature = "checksum")]
#[test]
fn rejects_corrupted_pre_v21_checksums() {
    for version in LEGACY_VERSIONS {
        let frame = legacy_frame(version);
        // Content checksum, compressed checksum, and a payload byte the
        // compressed checksum covers.
        for index in [frame.len() - 8, frame.len() - 1, frame.len() - 9] {
            let mut corrupted = frame.clone();
            corrupted[index] ^= 1;

            let err = ozlrip::decode(&corrupted).unwrap_err();

            assert_eq!(
                err.kind(),
                ErrorKind::ChecksumMismatch,
                "v{version} byte {index}"
            );
        }

        // Without a compressed checksum, the content checksum alone catches
        // a corrupted payload.
        let mut content_only = FrameBuilder::new(version)
            .content_checksum(true)
            .serial_output(3)
            .chunk(Chunk::stored(*b"abc"))
            .build();
        let payload_byte = content_only.len() - 5;
        content_only[payload_byte] ^= 1;

        let err = ozlrip::decode(&content_only).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::ChecksumMismatch, "v{version}");
    }
}

#[test]
fn rejects_truncated_pre_v21_checksums() {
    for version in LEGACY_VERSIONS {
        let frame = legacy_frame(version);
        for len in frame.len() - 8..frame.len() {
            let err = ozlrip::decode(&frame[..len]).unwrap_err();

            assert_eq!(err.kind(), ErrorKind::Truncated, "v{version} len {len}");
        }
    }
}

#[test]
fn rejects_trailing_bytes_after_pre_v21_frame() {
    for version in LEGACY_VERSIONS {
        let mut frame = legacy_frame(version);
        frame.push(0);

        let err = ozlrip::decode(&frame).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Malformed, "v{version}");
    }
}
