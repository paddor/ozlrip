#![cfg_attr(feature = "paranoid", forbid(unsafe_code))]

use alloc::vec::Vec;

use super::StreamInput;

#[cfg(not(feature = "paranoid"))]
pub(super) fn write_transpose_split_output(
    inputs: &[StreamInput<'_>],
    output_len: usize,
    output: &mut Vec<u8>,
) {
    debug_assert!(output.is_empty());
    debug_assert!(output.capacity() >= output_len);
    match inputs {
        [lane0, lane1] => {
            write_2(lane0.bytes, lane1.bytes, output);
        }
        [lane0, lane1, lane2, lane3] => {
            write_4(lane0.bytes, lane1.bytes, lane2.bytes, lane3.bytes, output);
        }
        [lane0, lane1, lane2, lane3, lane4, lane5, lane6, lane7] => {
            write_8(
                lane0.bytes,
                lane1.bytes,
                lane2.bytes,
                lane3.bytes,
                lane4.bytes,
                lane5.bytes,
                lane6.bytes,
                lane7.bytes,
                output,
            );
        }
        _ => write_transpose_split_output_safe(inputs, output_len, output),
    }
}

#[cfg(feature = "paranoid")]
pub(super) fn write_transpose_split_output(
    inputs: &[StreamInput<'_>],
    output_len: usize,
    output: &mut Vec<u8>,
) {
    write_transpose_split_output_safe(inputs, output_len, output);
}

fn write_transpose_split_output_safe(
    inputs: &[StreamInput<'_>],
    output_len: usize,
    output: &mut Vec<u8>,
) {
    output.resize(output_len, 0);
    let width = inputs.len();
    for (element, out) in output.chunks_exact_mut(width).enumerate() {
        for (byte, lane) in out.iter_mut().zip(inputs) {
            *byte = lane.bytes[element];
        }
    }
}

#[cfg(not(feature = "paranoid"))]
fn write_2(lane0: &[u8], lane1: &[u8], output: &mut Vec<u8>) {
    let len = lane0.len();
    debug_assert_eq!(lane1.len(), len);
    unsafe {
        let dst = output.as_mut_ptr();
        let src0 = lane0.as_ptr();
        let src1 = lane1.as_ptr();
        for index in 0..len {
            let out = dst.add(index * 2);
            out.write(src0.add(index).read());
            out.add(1).write(src1.add(index).read());
        }
        output.set_len(len * 2);
    }
}

#[cfg(not(feature = "paranoid"))]
fn write_4(lane0: &[u8], lane1: &[u8], lane2: &[u8], lane3: &[u8], output: &mut Vec<u8>) {
    let len = lane0.len();
    debug_assert_eq!(lane1.len(), len);
    debug_assert_eq!(lane2.len(), len);
    debug_assert_eq!(lane3.len(), len);
    unsafe {
        let dst = output.as_mut_ptr();
        let src0 = lane0.as_ptr();
        let src1 = lane1.as_ptr();
        let src2 = lane2.as_ptr();
        let src3 = lane3.as_ptr();
        for index in 0..len {
            let out = dst.add(index * 4);
            out.write(src0.add(index).read());
            out.add(1).write(src1.add(index).read());
            out.add(2).write(src2.add(index).read());
            out.add(3).write(src3.add(index).read());
        }
        output.set_len(len * 4);
    }
}

#[cfg(not(feature = "paranoid"))]
#[expect(clippy::too_many_arguments, reason = "fixed-width lane writer")]
fn write_8(
    lane0: &[u8],
    lane1: &[u8],
    lane2: &[u8],
    lane3: &[u8],
    lane4: &[u8],
    lane5: &[u8],
    lane6: &[u8],
    lane7: &[u8],
    output: &mut Vec<u8>,
) {
    let len = lane0.len();
    debug_assert_eq!(lane1.len(), len);
    debug_assert_eq!(lane2.len(), len);
    debug_assert_eq!(lane3.len(), len);
    debug_assert_eq!(lane4.len(), len);
    debug_assert_eq!(lane5.len(), len);
    debug_assert_eq!(lane6.len(), len);
    debug_assert_eq!(lane7.len(), len);
    unsafe {
        let dst = output.as_mut_ptr();
        let src0 = lane0.as_ptr();
        let src1 = lane1.as_ptr();
        let src2 = lane2.as_ptr();
        let src3 = lane3.as_ptr();
        let src4 = lane4.as_ptr();
        let src5 = lane5.as_ptr();
        let src6 = lane6.as_ptr();
        let src7 = lane7.as_ptr();
        for index in 0..len {
            let out = dst.add(index * 8);
            out.write(src0.add(index).read());
            out.add(1).write(src1.add(index).read());
            out.add(2).write(src2.add(index).read());
            out.add(3).write(src3.add(index).read());
            out.add(4).write(src4.add(index).read());
            out.add(5).write(src5.add(index).read());
            out.add(6).write(src6.add(index).read());
            out.add(7).write(src7.add(index).read());
        }
        output.set_len(len * 8);
    }
}
