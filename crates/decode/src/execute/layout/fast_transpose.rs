use alloc::vec::Vec;

use crate::execute::streams::StreamInput;

/// Replaces `output` with the interleaved lanes. `output` may hold stale
/// bytes: it is resized to `output_len` and every byte is overwritten.
pub(super) fn write_transpose_split_output(
    inputs: &[StreamInput<'_>],
    output_len: usize,
    output: &mut Vec<u8>,
) {
    // Portable builds only target the baseline CPU. Dispatch compiles the
    // lane writers once per SIMD level, where they auto-vectorize.
    #[cfg(feature = "std")]
    fearless_simd::dispatch!(
        fearless_simd::Level::new(),
        _simd => write_lanes(inputs, output_len, output)
    );
    #[cfg(not(feature = "std"))]
    write_lanes(inputs, output_len, output);
}

#[expect(
    clippy::inline_always,
    reason = "inlining into the dispatched closure applies its target features"
)]
#[inline(always)]
fn write_lanes(inputs: &[StreamInput<'_>], output_len: usize, output: &mut Vec<u8>) {
    match inputs {
        [lane0, lane1] => {
            write_2(lane0.bytes, lane1.bytes, output);
            return;
        }
        [lane0, lane1, lane2, lane3] => {
            write_4(lane0.bytes, lane1.bytes, lane2.bytes, lane3.bytes, output);
            return;
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
            return;
        }
        _ => {}
    }

    output.resize(output_len, 0);
    let width = inputs.len();
    for (element, out) in output.chunks_exact_mut(width).enumerate() {
        for (byte, lane) in out.iter_mut().zip(inputs) {
            *byte = lane.bytes[element];
        }
    }
}

#[expect(
    clippy::inline_always,
    reason = "inlining into the dispatched closure applies its target features"
)]
#[inline(always)]
fn write_2(lane0: &[u8], lane1: &[u8], output: &mut Vec<u8>) {
    let len = lane0.len();
    debug_assert_eq!(lane1.len(), len);
    output.resize(len * 2, 0);
    for (index, out) in output.as_chunks_mut::<2>().0.iter_mut().enumerate() {
        out[0] = lane0[index];
        out[1] = lane1[index];
    }
}

#[expect(
    clippy::inline_always,
    reason = "inlining into the dispatched closure applies its target features"
)]
#[inline(always)]
fn write_4(lane0: &[u8], lane1: &[u8], lane2: &[u8], lane3: &[u8], output: &mut Vec<u8>) {
    let len = lane0.len();
    debug_assert_eq!(lane1.len(), len);
    debug_assert_eq!(lane2.len(), len);
    debug_assert_eq!(lane3.len(), len);
    output.resize(len * 4, 0);
    for (index, out) in output.as_chunks_mut::<4>().0.iter_mut().enumerate() {
        out[0] = lane0[index];
        out[1] = lane1[index];
        out[2] = lane2[index];
        out[3] = lane3[index];
    }
}

#[expect(clippy::too_many_arguments, reason = "fixed-width lane writer")]
#[expect(
    clippy::inline_always,
    reason = "inlining into the dispatched closure applies its target features"
)]
#[inline(always)]
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
    output.resize(len * 8, 0);
    for (index, out) in output.as_chunks_mut::<8>().0.iter_mut().enumerate() {
        out[0] = lane0[index];
        out[1] = lane1[index];
        out[2] = lane2[index];
        out[3] = lane3[index];
        out[4] = lane4[index];
        out[5] = lane5[index];
        out[6] = lane6[index];
        out[7] = lane7[index];
    }
}
