//! `Decoder::decode_chunks` hands each decoded chunk to a callback.

use ozlrip::{Decoder, Error, ErrorKind};
use ozlrip_test_support::{Chunk, FrameBuilder, OutputType};
#[cfg(feature = "zstd")]
use ozlrip_test_support::{Node, ZSTD_TRANSFORM_ID, push_var_u64};

/// A chunk whose zstd node regenerates `content`.
#[cfg(feature = "zstd")]
fn zstd_chunk(content: &[u8]) -> Chunk {
    let mut stored = Vec::new();
    push_var_u64(&mut stored, 1);
    stored.extend_from_slice(&zrip::compress(content, 1).unwrap()[4..]);
    Chunk::new()
        .node(Node::new(ZSTD_TRANSFORM_ID))
        .stored_stream(stored)
        .decoded(content)
}

fn chunks_of(decoder: &mut Decoder, frame: &[u8]) -> (ozlrip::Result<usize>, Vec<Vec<u8>>) {
    let mut chunks = Vec::new();
    let result = decoder.decode_chunks(frame, |chunk| {
        chunks.push(chunk.to_vec());
        Ok(())
    });
    (result, chunks)
}

#[cfg(feature = "zstd")]
#[test]
fn passes_each_chunk_in_order() {
    let frame = FrameBuilder::new(21)
        .content_checksum(true)
        .serial_output(15)
        .chunk(Chunk::stored(*b"abc").decoded(*b"abc"))
        .chunk(zstd_chunk(b"defghi"))
        .chunk(zstd_chunk(b"jklmno"))
        .build();

    let (result, chunks) = chunks_of(&mut Decoder::new(), &frame);

    assert_eq!(result.unwrap(), 15);
    assert_eq!(chunks, [&b"abc"[..], b"defghi", b"jklmno"]);
    assert_eq!(chunks.concat(), ozlrip::decode(&frame).unwrap());
}

/// Chunks that decode into the buffer reuse it, so decoded memory stays at
/// one chunk.
#[cfg(feature = "zstd")]
#[test]
fn reuses_one_buffer_for_every_chunk() {
    let content = [7u8; 4096];
    let mut builder = FrameBuilder::new(21).serial_output(4 * content.len());
    for _ in 0..4 {
        builder = builder.chunk(zstd_chunk(&content));
    }
    let frame = builder.build();
    let mut buffers = Vec::new();

    let written = Decoder::new()
        .decode_chunks(&frame, |chunk| {
            assert_eq!(chunk, content);
            buffers.push(chunk.as_ptr());
            Ok(())
        })
        .unwrap();

    assert_eq!(written, 4 * content.len());
    assert!(buffers.iter().all(|&buffer| buffer == buffers[0]));
}

#[test]
fn stops_at_the_first_sink_error() {
    let frame = FrameBuilder::new(21)
        .serial_output(6)
        .chunk(Chunk::stored(*b"ab"))
        .chunk(Chunk::stored(*b"cd"))
        .chunk(Chunk::stored(*b"ef"))
        .build();
    let mut calls = 0;

    let err = Decoder::new()
        .decode_chunks(&frame, |_| {
            calls += 1;
            if calls == 2 {
                return Err(Error::new(ErrorKind::LimitExceeded).with_detail("sink is full"));
            }
            Ok(())
        })
        .unwrap_err();

    assert_eq!(calls, 2);
    assert_eq!(err.kind(), ErrorKind::LimitExceeded);
    assert_eq!(err.detail(), Some("sink is full"));
}

/// A chunk fails its content checksum before it reaches the sink.
#[test]
fn checks_each_chunk_before_passing_it_on() {
    let mut frame = FrameBuilder::new(21)
        .content_checksum(true)
        .serial_output(4)
        .chunk(Chunk::stored(*b"ab").decoded(*b"ab"))
        .chunk(Chunk::stored(*b"cd").decoded(*b"cd"))
        .build();
    // The second chunk's content checksum precedes the end marker.
    let checksum = frame.len() - 5;
    frame[checksum] ^= 1;

    let (result, chunks) = chunks_of(&mut Decoder::new(), &frame);

    assert_eq!(result.unwrap_err().kind(), ErrorKind::ChecksumMismatch);
    assert_eq!(chunks, [b"ab"]);
}

/// The declared output size is checked as chunks arrive and at the end.
#[test]
fn rejects_output_that_misses_the_declared_size() {
    let long = FrameBuilder::new(21)
        .serial_output(3)
        .chunk(Chunk::stored(*b"ab"))
        .chunk(Chunk::stored(*b"cd"))
        .build();
    let short = FrameBuilder::new(21)
        .serial_output(5)
        .chunk(Chunk::stored(*b"ab"))
        .chunk(Chunk::stored(*b"cd"))
        .build();

    let (long_result, long_chunks) = chunks_of(&mut Decoder::new(), &long);
    let (short_result, short_chunks) = chunks_of(&mut Decoder::new(), &short);

    assert_eq!(long_result.unwrap_err().kind(), ErrorKind::Malformed);
    assert_eq!(long_chunks, [b"ab"]);
    assert_eq!(short_result.unwrap_err().kind(), ErrorKind::Malformed);
    assert_eq!(short_chunks, [b"ab", b"cd"]);
}

#[test]
fn rejects_typed_frames() {
    let frame = FrameBuilder::new(21)
        .output(OutputType::Struct, 2)
        .chunk(Chunk::stored(*b"ab"))
        .build();

    let (result, chunks) = chunks_of(&mut Decoder::new(), &frame);

    assert_eq!(result.unwrap_err().kind(), ErrorKind::Unsupported);
    assert_eq!(chunks, Vec::<Vec<u8>>::new());
}
