//! `decode_outputs` returns every frame output with its type.

use ozlrip::{Decoder, ErrorKind, Output};
use ozlrip_test_support::{Chunk, FrameBuilder, Node, OutputType};

const CONVERT_NUM_TO_SERIAL_LE: u32 = 10;
const SEPARATE_STRING_COMPONENTS: u32 = 12;

/// Output 0 is 16-bit numbers converted from the first stored stream,
/// output 1 the second stored stream.
fn numeric_and_serial_frame(numbers: &[u16], serial: &[u8]) -> Vec<u8> {
    let raw = numbers
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect::<Vec<_>>();
    FrameBuilder::new(21)
        .content_checksum(true)
        .output(OutputType::Numeric, raw.len())
        .output(OutputType::Serial, serial.len())
        .chunk(
            Chunk::new()
                .stored_stream(raw.clone())
                .stored_stream(serial)
                .node(Node::new(CONVERT_NUM_TO_SERIAL_LE).header([1]))
                .distances(vec![1])
                .decoded([raw.as_slice(), serial].concat()),
        )
        .build()
}

fn string_frame(strings: &[&[u8]]) -> Vec<u8> {
    let sizes = strings
        .iter()
        .map(|string| u8::try_from(string.len()).unwrap())
        .collect::<Vec<_>>();
    let content = strings.concat();
    FrameBuilder::new(21)
        .string_output(content.len(), strings.len())
        .chunk(
            Chunk::new()
                .stored_stream(sizes)
                .stored_stream(content)
                .node(Node::new(SEPARATE_STRING_COMPONENTS)),
        )
        .build()
}

#[test]
fn decodes_numeric_and_serial_outputs() {
    let frame = numeric_and_serial_frame(&[1, 0x0302], b"abc");

    let outputs = ozlrip::decode_outputs(&frame).unwrap();

    assert_eq!(
        outputs,
        [
            Output::Numeric {
                width: 2,
                bytes: vec![1, 0, 2, 3],
            },
            Output::Serial(b"abc".to_vec()),
        ]
    );
    assert_eq!(outputs[0].value_type(), ozlrip::FrameValueType::Numeric);
    assert_eq!(outputs[1].bytes(), b"abc");
}

#[test]
fn decodes_string_outputs() {
    let frame = string_frame(&[b"ab", b"", b"cde"]);

    let outputs = ozlrip::decode_outputs(&frame).unwrap();

    assert_eq!(
        outputs,
        [Output::String {
            bytes: b"abcde".to_vec(),
            lengths: vec![2, 0, 3],
        }]
    );
}

#[test]
fn decode_keeps_its_single_serial_contract() {
    let frame = numeric_and_serial_frame(&[1], b"a");

    let err = ozlrip::decode(&frame).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Unsupported);
}

#[test]
fn single_serial_frames_decode_the_same_way() {
    let frame = FrameBuilder::new(21)
        .serial_output(6)
        .chunk(Chunk::stored(*b"abc"))
        .chunk(Chunk::stored(*b"def"))
        .build();

    let outputs = ozlrip::decode_outputs(&frame).unwrap();

    assert_eq!(outputs, [Output::Serial(ozlrip::decode(&frame).unwrap())]);
}

#[test]
fn decode_outputs_into_reuses_buffers() {
    let frame = numeric_and_serial_frame(&[1, 2, 3], b"abc");
    let mut decoder = Decoder::new();
    let mut outputs = vec![
        Output::Numeric {
            width: 2,
            bytes: Vec::with_capacity(64),
        },
        Output::Serial(Vec::with_capacity(64)),
    ];
    let buffers = outputs
        .iter()
        .map(|output| output.bytes().as_ptr())
        .collect::<Vec<_>>();

    decoder.decode_outputs_into(&frame, &mut outputs).unwrap();

    assert_eq!(outputs, decoder.decode_outputs(&frame).unwrap());
    let reused = outputs
        .iter()
        .map(|output| output.bytes().as_ptr())
        .collect::<Vec<_>>();
    assert_eq!(reused, buffers);
}

#[test]
fn decode_outputs_into_resizes_to_the_output_count() {
    let mut outputs = vec![Output::Serial(Vec::new()); 5];

    ozlrip::decode_outputs_into(&string_frame(&[b"x"]), &mut outputs).unwrap();

    assert_eq!(outputs.len(), 1);
}
