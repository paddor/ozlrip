#![no_main]

use libfuzzer_sys::fuzz_target;
use ozlrip::Limits;
use ozlrip_test_support::{Chunk, FrameBuilder, Node};

const CONVERT_NUM_TO_SERIAL_LE_ID: u32 = 10;
const BITUNPACK_ID: u32 = 34;

// `data[0]` picks the input width and whether the header has trailing
// bits, `data[1]` the bit count and `data[2]` the trailing bits; the
// values follow.
fuzz_target!(|data: &[u8]| {
    let [control, bits, trailing, values @ ..] = data else {
        return;
    };
    let input_code = control & 3;
    let input_width = 1usize << input_code;
    let bits = bits % (8 * u8::try_from(input_width).unwrap()) + 1;
    let mut header = vec![bits];
    if control & 0x10 != 0 {
        header.push(*trailing);
    }
    let values = &values[..values.len() / input_width * input_width];
    let decoded_len = (values.len() / input_width * usize::from(bits)).div_ceil(8);
    let mut chunk = Chunk::new().stored_stream(values);
    if input_width > 1 {
        chunk = chunk.node(Node::new(CONVERT_NUM_TO_SERIAL_LE_ID).header([input_code]));
    }
    let frame = FrameBuilder::new(21)
        .serial_output(decoded_len)
        .chunk(chunk.node(Node::new(BITUNPACK_ID).header(header)))
        .build();
    let mut limits = Limits::strict();
    limits.max_frame_bytes = 8192;
    limits.max_decoded_bytes = 65_536;
    limits.max_chunks = 1;
    limits.max_nodes = 2;
    limits.max_streams = 3;
    limits.max_transform_header_bytes = 3;
    limits.max_stored_stream_bytes = 8192;
    limits.max_buffer_bytes = 65_536;
    limits.max_graph_depth = 2;
    limits.max_expansion_ratio = 4096;
    let mut output = Vec::new();
    let _ = ozlrip::decode_into_with_options(&frame, &mut output, ozlrip::Options::from(limits));
});
