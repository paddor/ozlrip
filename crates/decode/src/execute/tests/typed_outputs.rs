use super::*;
use crate::execute::outputs::{DecodedOutput, decode_outputs_with_context};
use ozlrip_test_support::{Chunk, FrameBuilder, Node, OutputType};

const CONVERT_NUM_TO_SERIAL_LE: u32 = 10;
const SEPARATE_STRING_COMPONENTS: u32 = 12;

fn decode_typed(input: &[u8]) -> Result<Vec<DecodedOutput>> {
    let plan = parse_frame_plan(input, Limits::default())?;
    let mut scratch = DecodeScratch::new();
    let mut dict_store = DictionaryStore::new();
    #[cfg(feature = "zstd")]
    let mut zstd = None;
    let mut runtime = DecodeRuntime::new(
        &mut scratch,
        &mut dict_store,
        #[cfg(feature = "zstd")]
        &mut zstd,
    );
    let mut outputs = Vec::new();
    decode_outputs_with_context(
        input,
        &plan,
        &mut outputs,
        Limits::default(),
        true,
        &mut runtime,
    )?;
    Ok(outputs)
}

/// Output 0 is the chunk's last stream: 16-bit numbers converted from the
/// first stored stream. Output 1 is the second stored stream.
fn numeric_and_serial_chunk(numbers: &[u16], serial: &[u8]) -> Chunk {
    let raw = numbers
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect::<Vec<_>>();
    let decoded = [raw.as_slice(), serial].concat();
    Chunk::new()
        .stored_stream(raw)
        .stored_stream(serial)
        .node(Node::new(CONVERT_NUM_TO_SERIAL_LE).header([1]))
        .distances(vec![1])
        .decoded(decoded)
}

/// One string output from `separate_string_components`.
fn string_chunk(strings: &[&[u8]]) -> Chunk {
    let sizes = strings
        .iter()
        .map(|string| u8::try_from(string.len()).unwrap())
        .collect::<Vec<_>>();
    let content = strings.concat();
    let lengths = strings
        .iter()
        .flat_map(|string| u32::try_from(string.len()).unwrap().to_le_bytes())
        .collect::<Vec<_>>();
    Chunk::new()
        .stored_stream(sizes)
        .stored_stream(content.clone())
        .node(Node::new(SEPARATE_STRING_COMPONENTS))
        .decoded([content, lengths].concat())
}

#[test]
fn decodes_numeric_and_serial_outputs() {
    let input = FrameBuilder::new(21)
        .content_checksum(true)
        .output(OutputType::Numeric, 6)
        .output(OutputType::Serial, 3)
        .chunk(numeric_and_serial_chunk(&[1, 2, 0x0302], b"abc"))
        .build();

    let outputs = decode_typed(&input).unwrap();

    assert_eq!(outputs.len(), 2);
    assert_eq!(outputs[0].value_type, Some(FrameValueType::Numeric));
    assert_eq!(outputs[0].width, 2);
    assert_eq!(outputs[0].bytes, [1, 0, 2, 0, 2, 3]);
    assert_eq!(outputs[1].value_type, Some(FrameValueType::Serial));
    assert_eq!(outputs[1].width, 1);
    assert_eq!(outputs[1].bytes, b"abc");
}

#[test]
fn appends_string_outputs_across_chunks() {
    let input = FrameBuilder::new(21)
        .content_checksum(true)
        .string_output(8, 4)
        .chunk(string_chunk(&[b"ab", b"", b"cde"]))
        .chunk(string_chunk(&[b"fgh"]))
        .build();

    let outputs = decode_typed(&input).unwrap();

    assert_eq!(outputs[0].value_type, Some(FrameValueType::String));
    assert_eq!(outputs[0].bytes, b"abcdefgh");
    assert_eq!(outputs[0].lengths, [2, 0, 3, 3]);
}

#[test]
fn rejects_corrupted_typed_content_checksums() {
    let mut input = FrameBuilder::new(21)
        .content_checksum(true)
        .string_output(5, 3)
        .chunk(string_chunk(&[b"ab", b"", b"cde"]))
        .build();
    let checksum = input.len() - 5;
    input[checksum] ^= 1;

    let err = decode_typed(&input).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::ChecksumMismatch);
}

#[test]
fn rejects_outputs_whose_type_differs_from_the_header() {
    let input = FrameBuilder::new(21)
        .output(OutputType::Struct, 4)
        .output(OutputType::Serial, 1)
        .chunk(numeric_and_serial_chunk(&[1, 2], b"x"))
        .build();

    let err = decode_typed(&input).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
    assert_eq!(
        err.detail(),
        Some("final stream type does not match header")
    );
}

#[test]
fn rejects_numeric_width_changes_between_chunks() {
    let wide = Chunk::new()
        .stored_stream([1, 0, 0, 0])
        .stored_stream(*b"y")
        .node(Node::new(CONVERT_NUM_TO_SERIAL_LE).header([2]))
        .distances(vec![1]);
    let input = FrameBuilder::new(21)
        .output(OutputType::Numeric, 6)
        .output(OutputType::Serial, 2)
        .chunk(numeric_and_serial_chunk(&[1], b"x"))
        .chunk(wide)
        .build();

    let err = decode_typed(&input).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
    assert_eq!(
        err.detail(),
        Some("output element width changes between chunks")
    );
}

#[test]
fn rejects_outputs_that_miss_their_declared_size() {
    let input = FrameBuilder::new(21)
        .output(OutputType::Numeric, 4)
        .output(OutputType::Serial, 4)
        .chunk(numeric_and_serial_chunk(&[1, 2], b"abc"))
        .build();

    let err = decode_typed(&input).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
}

#[test]
fn rejects_string_counts_that_miss_the_header() {
    let input = FrameBuilder::new(21)
        .string_output(5, 4)
        .chunk(string_chunk(&[b"ab", b"", b"cde"]))
        .build();

    let err = decode_typed(&input).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Malformed);
}

#[test]
fn decodes_a_single_serial_output_like_decode_plan() {
    let input = FrameBuilder::new(21)
        .serial_output(3)
        .chunk(Chunk::stored(*b"abc"))
        .build();

    let outputs = decode_typed(&input).unwrap();

    assert_eq!(outputs.len(), 1);
    assert_eq!(outputs[0].bytes, b"abc");
}
