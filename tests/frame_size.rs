//! `frame_size` reports where the first frame in a buffer ends.

use ozlrip::ErrorKind;
use ozlrip_test_support::{Chunk, FrameBuilder};

#[test]
fn reports_the_size_of_a_whole_frame() {
    let frame = FrameBuilder::new(21)
        .content_checksum(true)
        .compressed_checksum(true)
        .serial_output(6)
        .chunk(Chunk::stored(*b"abc"))
        .chunk(Chunk::stored(*b"def"))
        .build();

    assert_eq!(ozlrip::frame_size(&frame).unwrap(), frame.len());
}

#[test]
fn ignores_bytes_after_the_frame() {
    let first = FrameBuilder::new(21)
        .serial_output(3)
        .chunk(Chunk::stored(*b"abc"))
        .build();
    let second = FrameBuilder::new(27)
        .serial_output(1)
        .chunk(Chunk::stored(*b"z"))
        .build();
    let both = [first.as_slice(), &second].concat();

    assert_eq!(ozlrip::frame_size(&both).unwrap(), first.len());
    assert_eq!(
        ozlrip::frame_size(&both[first.len()..]).unwrap(),
        second.len()
    );
}

#[test]
fn reports_legacy_frames() {
    let frame = FrameBuilder::new(14)
        .content_checksum(true)
        .compressed_checksum(true)
        .serial_output(3)
        .chunk(Chunk::stored(*b"abc"))
        .build();
    let with_tail = [frame.as_slice(), b"tail"].concat();

    assert_eq!(ozlrip::frame_size(&with_tail).unwrap(), frame.len());
}

#[test]
fn rejects_frames_cut_short() {
    let frame = FrameBuilder::new(21)
        .serial_output(3)
        .chunk(Chunk::stored(*b"abc"))
        .build();

    let err = ozlrip::frame_size(&frame[..frame.len() - 1]).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Truncated);
}

#[test]
fn does_not_check_checksums() {
    let mut frame = FrameBuilder::new(21)
        .compressed_checksum(true)
        .serial_output(3)
        .chunk(Chunk::stored(*b"abc"))
        .build();
    let checksum = frame.len() - 5;
    frame[checksum] ^= 1;

    assert!(ozlrip::decode(&frame).is_err());
    assert_eq!(ozlrip::frame_size(&frame).unwrap(), frame.len());
}
