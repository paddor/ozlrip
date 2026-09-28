#![no_main]

use libfuzzer_sys::fuzz_target;
use ozlrip::Limits;
use ozlrip_test_support::{Chunk, FrameBuilder, Node, OutputType};

const CONVERT_NUM_TO_SERIAL_LE_ID: u32 = 10;
const RANGE_PACK_ID: u32 = 35;

// `data[0]` picks the input and output widths and whether the header has a
// minimum; the minimum and then the packed values follow.
fuzz_target!(|data: &[u8]| {
    let Some((&control, rest)) = data.split_first() else {
        return;
    };
    let input_code = control & 3;
    let input_width = 1usize << input_code;
    let output_width = 1usize << ((control >> 2) & 3);
    let mut header = vec![u8::try_from(output_width).unwrap()];
    let values = if control & 0x10 != 0 && rest.len() >= output_width {
        header.extend_from_slice(&rest[..output_width]);
        &rest[output_width..]
    } else {
        rest
    };
    let values = &values[..values.len() / input_width * input_width];
    let mut chunk = Chunk::new().stored_stream(values);
    if input_width > 1 {
        chunk = chunk.node(Node::new(CONVERT_NUM_TO_SERIAL_LE_ID).header([input_code]));
    }
    let frame = FrameBuilder::new(21)
        .output(
            OutputType::Numeric,
            values.len() / input_width * output_width,
        )
        .chunk(chunk.node(Node::new(RANGE_PACK_ID).header(header)))
        .build();
    let mut limits = Limits::strict();
    limits.max_frame_bytes = 8192;
    limits.max_decoded_bytes = 65_536;
    limits.max_chunks = 1;
    limits.max_nodes = 2;
    limits.max_streams = 3;
    limits.max_transform_header_bytes = 10;
    limits.max_stored_stream_bytes = 8192;
    limits.max_buffer_bytes = 65_536;
    limits.max_graph_depth = 2;
    limits.max_expansion_ratio = 4096;
    let _ = ozlrip::decode_outputs_with_options(&frame, ozlrip::Options::from(limits));
});
