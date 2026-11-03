use alloc::vec::Vec;

use crate::execute::streams::StreamInput;

pub(super) fn append_split_by_struct_output(inputs: &[StreamInput<'_>], output: &mut Vec<u8>) {
    if inputs.len() == 6 {
        let widths = [
            inputs[0].element_width,
            inputs[1].element_width,
            inputs[2].element_width,
            inputs[3].element_width,
            inputs[4].element_width,
            inputs[5].element_width,
        ];
        if widths == [8, 8, 2, 2, 4, 4] {
            append_6_8_8_2_2_4_4(inputs, output);
            return;
        }
        if widths == [4, 4, 2, 2, 8, 8] {
            append_6_4_4_2_2_8_8(inputs, output);
            return;
        }
    }

    let element_count = inputs[0].bytes.len() / inputs[0].element_width;
    let struct_width = inputs
        .iter()
        .fold(0usize, |sum, input| sum + input.element_width);
    let start_len = output.len();
    let output_len = element_count * struct_width;
    output.resize(start_len + output_len, 0);

    for (element, out) in output[start_len..]
        .chunks_exact_mut(struct_width)
        .enumerate()
    {
        let mut offset = 0;
        for input in inputs {
            let width = input.element_width;
            let start = element * width;
            let end = start + width;
            out[offset..offset + width].copy_from_slice(&input.bytes[start..end]);
            offset += width;
        }
    }
}

fn append_6_8_8_2_2_4_4(inputs: &[StreamInput<'_>], output: &mut Vec<u8>) {
    let element_count = inputs[0].bytes.len() / 8;
    output.reserve(element_count * 28);
    for (((((src0, src1), src2), src3), src4), src5) in inputs[0]
        .bytes
        .as_chunks::<8>()
        .0
        .iter()
        .zip(inputs[1].bytes.as_chunks::<8>().0)
        .zip(inputs[2].bytes.as_chunks::<2>().0)
        .zip(inputs[3].bytes.as_chunks::<2>().0)
        .zip(inputs[4].bytes.as_chunks::<4>().0)
        .zip(inputs[5].bytes.as_chunks::<4>().0)
    {
        let mut row = [0; 28];
        copy_8(&mut row[0..8], src0);
        copy_8(&mut row[8..16], src1);
        copy_2(&mut row[16..18], src2);
        copy_2(&mut row[18..20], src3);
        copy_4(&mut row[20..24], src4);
        copy_4(&mut row[24..28], src5);
        output.extend_from_slice(&row);
    }
}

fn append_6_4_4_2_2_8_8(inputs: &[StreamInput<'_>], output: &mut Vec<u8>) {
    let element_count = inputs[0].bytes.len() / 4;
    output.reserve(element_count * 28);
    for (((((src0, src1), src2), src3), src4), src5) in inputs[0]
        .bytes
        .as_chunks::<4>()
        .0
        .iter()
        .zip(inputs[1].bytes.as_chunks::<4>().0)
        .zip(inputs[2].bytes.as_chunks::<2>().0)
        .zip(inputs[3].bytes.as_chunks::<2>().0)
        .zip(inputs[4].bytes.as_chunks::<8>().0)
        .zip(inputs[5].bytes.as_chunks::<8>().0)
    {
        let mut row = [0; 28];
        copy_4(&mut row[0..4], src0);
        copy_4(&mut row[4..8], src1);
        copy_2(&mut row[8..10], src2);
        copy_2(&mut row[10..12], src3);
        copy_8(&mut row[12..20], src4);
        copy_8(&mut row[20..28], src5);
        output.extend_from_slice(&row);
    }
}

#[expect(clippy::inline_always, reason = "profiled: one call per field per row")]
#[inline(always)]
fn copy_2(dst: &mut [u8], src: &[u8]) {
    dst[0] = src[0];
    dst[1] = src[1];
}

#[expect(clippy::inline_always, reason = "profiled: one call per field per row")]
#[inline(always)]
fn copy_4(dst: &mut [u8], src: &[u8]) {
    dst[0] = src[0];
    dst[1] = src[1];
    dst[2] = src[2];
    dst[3] = src[3];
}

#[expect(clippy::inline_always, reason = "profiled: one call per field per row")]
#[inline(always)]
fn copy_8(dst: &mut [u8], src: &[u8]) {
    dst[0] = src[0];
    dst[1] = src[1];
    dst[2] = src[2];
    dst[3] = src[3];
    dst[4] = src[4];
    dst[5] = src[5];
    dst[6] = src[6];
    dst[7] = src[7];
}
