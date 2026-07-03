#![cfg_attr(feature = "paranoid", forbid(unsafe_code))]

use alloc::vec::Vec;

use super::StreamInput;

#[cfg(not(feature = "paranoid"))]
pub(super) fn append_split_by_struct_output(inputs: &[StreamInput<'_>], output: &mut Vec<u8>) {
    if inputs.len() == 6 {
        append_split_by_struct_output_fast(inputs, output);
    } else {
        append_split_by_struct_output_safe(inputs, output);
    }
}

#[cfg(feature = "paranoid")]
pub(super) fn append_split_by_struct_output(inputs: &[StreamInput<'_>], output: &mut Vec<u8>) {
    append_split_by_struct_output_safe(inputs, output);
}

fn append_split_by_struct_output_safe(inputs: &[StreamInput<'_>], output: &mut Vec<u8>) {
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
            append_6_8_8_2_2_4_4_safe(inputs, output);
            return;
        }
        if widths == [4, 4, 2, 2, 8, 8] {
            append_6_4_4_2_2_8_8_safe(inputs, output);
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

fn append_6_8_8_2_2_4_4_safe(inputs: &[StreamInput<'_>], output: &mut Vec<u8>) {
    let element_count = inputs[0].bytes.len() / 8;
    let start_len = output.len();
    output.resize(start_len + element_count * 28, 0);
    let output = &mut output[start_len..];
    for (element, out) in output.chunks_exact_mut(28).enumerate() {
        copy_8(
            &mut out[0..8],
            &inputs[0].bytes[element * 8..element * 8 + 8],
        );
        copy_8(
            &mut out[8..16],
            &inputs[1].bytes[element * 8..element * 8 + 8],
        );
        copy_2(
            &mut out[16..18],
            &inputs[2].bytes[element * 2..element * 2 + 2],
        );
        copy_2(
            &mut out[18..20],
            &inputs[3].bytes[element * 2..element * 2 + 2],
        );
        copy_4(
            &mut out[20..24],
            &inputs[4].bytes[element * 4..element * 4 + 4],
        );
        copy_4(
            &mut out[24..28],
            &inputs[5].bytes[element * 4..element * 4 + 4],
        );
    }
}

fn append_6_4_4_2_2_8_8_safe(inputs: &[StreamInput<'_>], output: &mut Vec<u8>) {
    let element_count = inputs[0].bytes.len() / 4;
    let start_len = output.len();
    output.resize(start_len + element_count * 28, 0);
    let output = &mut output[start_len..];
    for (element, out) in output.chunks_exact_mut(28).enumerate() {
        copy_4(
            &mut out[0..4],
            &inputs[0].bytes[element * 4..element * 4 + 4],
        );
        copy_4(
            &mut out[4..8],
            &inputs[1].bytes[element * 4..element * 4 + 4],
        );
        copy_2(
            &mut out[8..10],
            &inputs[2].bytes[element * 2..element * 2 + 2],
        );
        copy_2(
            &mut out[10..12],
            &inputs[3].bytes[element * 2..element * 2 + 2],
        );
        copy_8(
            &mut out[12..20],
            &inputs[4].bytes[element * 8..element * 8 + 8],
        );
        copy_8(
            &mut out[20..28],
            &inputs[5].bytes[element * 8..element * 8 + 8],
        );
    }
}

#[inline(always)]
fn copy_2(dst: &mut [u8], src: &[u8]) {
    dst[0] = src[0];
    dst[1] = src[1];
}

#[inline(always)]
fn copy_4(dst: &mut [u8], src: &[u8]) {
    dst[0] = src[0];
    dst[1] = src[1];
    dst[2] = src[2];
    dst[3] = src[3];
}

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

#[cfg(not(feature = "paranoid"))]
fn append_split_by_struct_output_fast(inputs: &[StreamInput<'_>], output: &mut Vec<u8>) {
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

    let element_count = inputs[0].bytes.len() / inputs[0].element_width;
    let struct_width = inputs
        .iter()
        .fold(0usize, |sum, input| sum + input.element_width);
    let output_len = element_count * struct_width;
    let start_len = output.len();

    unsafe {
        let mut dst = output.as_mut_ptr().add(start_len);
        let end = dst.add(output_len);
        let src0 = inputs[0].bytes.as_ptr();
        let src1 = inputs[1].bytes.as_ptr();
        let src2 = inputs[2].bytes.as_ptr();
        let src3 = inputs[3].bytes.as_ptr();
        let src4 = inputs[4].bytes.as_ptr();
        let src5 = inputs[5].bytes.as_ptr();
        let w0 = inputs[0].element_width;
        let w1 = inputs[1].element_width;
        let w2 = inputs[2].element_width;
        let w3 = inputs[3].element_width;
        let w4 = inputs[4].element_width;
        let w5 = inputs[5].element_width;

        for element in 0..element_count {
            copy_field(src0.add(element * w0), &mut dst, w0);
            copy_field(src1.add(element * w1), &mut dst, w1);
            copy_field(src2.add(element * w2), &mut dst, w2);
            copy_field(src3.add(element * w3), &mut dst, w3);
            copy_field(src4.add(element * w4), &mut dst, w4);
            copy_field(src5.add(element * w5), &mut dst, w5);
        }
        debug_assert_eq!(dst, end);
        output.set_len(start_len + output_len);
    }
}

#[cfg(not(feature = "paranoid"))]
fn append_6_8_8_2_2_4_4(inputs: &[StreamInput<'_>], output: &mut Vec<u8>) {
    let element_count = inputs[0].bytes.len() / 8;
    let output_len = element_count * 28;
    let start_len = output.len();
    unsafe {
        let mut dst = output.as_mut_ptr().add(start_len);
        let src0 = inputs[0].bytes.as_ptr();
        let src1 = inputs[1].bytes.as_ptr();
        let src2 = inputs[2].bytes.as_ptr();
        let src3 = inputs[3].bytes.as_ptr();
        let src4 = inputs[4].bytes.as_ptr();
        let src5 = inputs[5].bytes.as_ptr();
        for element in 0..element_count {
            (dst as *mut u64)
                .write_unaligned((src0.add(element * 8) as *const u64).read_unaligned());
            (dst.add(8) as *mut u64)
                .write_unaligned((src1.add(element * 8) as *const u64).read_unaligned());
            (dst.add(16) as *mut u16)
                .write_unaligned((src2.add(element * 2) as *const u16).read_unaligned());
            (dst.add(18) as *mut u16)
                .write_unaligned((src3.add(element * 2) as *const u16).read_unaligned());
            (dst.add(20) as *mut u32)
                .write_unaligned((src4.add(element * 4) as *const u32).read_unaligned());
            (dst.add(24) as *mut u32)
                .write_unaligned((src5.add(element * 4) as *const u32).read_unaligned());
            dst = dst.add(28);
        }
        output.set_len(start_len + output_len);
    }
}

#[cfg(not(feature = "paranoid"))]
fn append_6_4_4_2_2_8_8(inputs: &[StreamInput<'_>], output: &mut Vec<u8>) {
    let element_count = inputs[0].bytes.len() / 4;
    let output_len = element_count * 28;
    let start_len = output.len();
    unsafe {
        let mut dst = output.as_mut_ptr().add(start_len);
        let src0 = inputs[0].bytes.as_ptr();
        let src1 = inputs[1].bytes.as_ptr();
        let src2 = inputs[2].bytes.as_ptr();
        let src3 = inputs[3].bytes.as_ptr();
        let src4 = inputs[4].bytes.as_ptr();
        let src5 = inputs[5].bytes.as_ptr();
        for element in 0..element_count {
            (dst as *mut u32)
                .write_unaligned((src0.add(element * 4) as *const u32).read_unaligned());
            (dst.add(4) as *mut u32)
                .write_unaligned((src1.add(element * 4) as *const u32).read_unaligned());
            (dst.add(8) as *mut u16)
                .write_unaligned((src2.add(element * 2) as *const u16).read_unaligned());
            (dst.add(10) as *mut u16)
                .write_unaligned((src3.add(element * 2) as *const u16).read_unaligned());
            (dst.add(12) as *mut u64)
                .write_unaligned((src4.add(element * 8) as *const u64).read_unaligned());
            (dst.add(20) as *mut u64)
                .write_unaligned((src5.add(element * 8) as *const u64).read_unaligned());
            dst = dst.add(28);
        }
        output.set_len(start_len + output_len);
    }
}

#[cfg(not(feature = "paranoid"))]
unsafe fn copy_field(src: *const u8, dst: &mut *mut u8, width: usize) {
    match width {
        1 => unsafe {
            (*dst).write(src.read());
            *dst = (*dst).add(1);
        },
        2 => unsafe {
            (*dst as *mut u16).write_unaligned((src as *const u16).read_unaligned());
            *dst = (*dst).add(2);
        },
        4 => unsafe {
            (*dst as *mut u32).write_unaligned((src as *const u32).read_unaligned());
            *dst = (*dst).add(4);
        },
        8 => unsafe {
            (*dst as *mut u64).write_unaligned((src as *const u64).read_unaligned());
            *dst = (*dst).add(8);
        },
        _ => unsafe {
            core::ptr::copy_nonoverlapping(src, *dst, width);
            *dst = (*dst).add(width);
        },
    }
}
