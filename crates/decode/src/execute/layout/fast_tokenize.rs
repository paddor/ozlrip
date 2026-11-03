use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Result};

/// Replaces `output` with the tokens. `output` may hold stale bytes: every
/// byte is overwritten. On error `output` holds unspecified bytes.
pub(super) fn decode_tokenize_indices(
    alphabet: &[u8],
    alphabet_size: usize,
    element_width: usize,
    indices: &[u8],
    index_width: usize,
    output: &mut Vec<u8>,
) -> Result<()> {
    match (index_width, element_width) {
        (1, 1) => decode_index_width_1::<1>(alphabet, alphabet_size, indices, output),
        (1, 2) => decode_index_width_1::<2>(alphabet, alphabet_size, indices, output),
        (1, 4) => decode_index_width_1::<4>(alphabet, alphabet_size, indices, output),
        (1, 8) => decode_index_width_1::<8>(alphabet, alphabet_size, indices, output),
        (2, 1) => decode_index_width_2::<1>(alphabet, alphabet_size, indices, output),
        (2, 2) => decode_index_width_2::<2>(alphabet, alphabet_size, indices, output),
        (2, 4) => decode_index_width_2::<4>(alphabet, alphabet_size, indices, output),
        (2, 8) => decode_index_width_2::<8>(alphabet, alphabet_size, indices, output),
        (4, 1) => decode_index_width_4::<1>(alphabet, alphabet_size, indices, output),
        (4, 2) => decode_index_width_4::<2>(alphabet, alphabet_size, indices, output),
        (4, 4) => decode_index_width_4::<4>(alphabet, alphabet_size, indices, output),
        (4, 8) => decode_index_width_4::<8>(alphabet, alphabet_size, indices, output),
        (8, 1) => decode_index_width_8::<1>(alphabet, alphabet_size, indices, output),
        (8, 2) => decode_index_width_8::<2>(alphabet, alphabet_size, indices, output),
        (8, 4) => decode_index_width_8::<4>(alphabet, alphabet_size, indices, output),
        (8, 8) => decode_index_width_8::<8>(alphabet, alphabet_size, indices, output),
        _ => decode_tokenize_indices_generic(
            alphabet,
            alphabet_size,
            element_width,
            indices,
            index_width,
            output,
        ),
    }
}

fn decode_index_width_1<const ELEMENT_WIDTH: usize>(
    alphabet: &[u8],
    alphabet_size: usize,
    indices: &[u8],
    output: &mut Vec<u8>,
) -> Result<()> {
    let tokens = alphabet.as_chunks::<ELEMENT_WIDTH>().0;
    debug_assert_eq!(tokens.len(), alphabet_size);
    output.resize(indices.len() * ELEMENT_WIDTH, 0);
    for (&index, out) in indices
        .iter()
        .zip(output.as_chunks_mut::<ELEMENT_WIDTH>().0)
    {
        write_tokenized_element_fixed(tokens, usize::from(index), out)?;
    }
    Ok(())
}

fn decode_index_width_2<const ELEMENT_WIDTH: usize>(
    alphabet: &[u8],
    alphabet_size: usize,
    indices: &[u8],
    output: &mut Vec<u8>,
) -> Result<()> {
    let elements = indices.len() / 2;
    let tokens = alphabet.as_chunks::<ELEMENT_WIDTH>().0;
    debug_assert_eq!(tokens.len(), alphabet_size);
    output.resize(elements * ELEMENT_WIDTH, 0);
    for (index, out) in indices
        .as_chunks::<2>()
        .0
        .iter()
        .zip(output.as_chunks_mut::<ELEMENT_WIDTH>().0)
    {
        write_tokenized_element_fixed(tokens, usize::from(u16::from_le_bytes(*index)), out)?;
    }
    Ok(())
}

fn decode_index_width_4<const ELEMENT_WIDTH: usize>(
    alphabet: &[u8],
    alphabet_size: usize,
    indices: &[u8],
    output: &mut Vec<u8>,
) -> Result<()> {
    let elements = indices.len() / 4;
    let tokens = alphabet.as_chunks::<ELEMENT_WIDTH>().0;
    debug_assert_eq!(tokens.len(), alphabet_size);
    output.resize(elements * ELEMENT_WIDTH, 0);
    for (index, out) in indices
        .as_chunks::<4>()
        .0
        .iter()
        .zip(output.as_chunks_mut::<ELEMENT_WIDTH>().0)
    {
        write_tokenized_element_fixed(
            tokens,
            u32::from_le_bytes(*index)
                .try_into()
                .map_err(|_| numeric_too_large())?,
            out,
        )?;
    }
    Ok(())
}

fn decode_index_width_8<const ELEMENT_WIDTH: usize>(
    alphabet: &[u8],
    alphabet_size: usize,
    indices: &[u8],
    output: &mut Vec<u8>,
) -> Result<()> {
    let elements = indices.len() / 8;
    let tokens = alphabet.as_chunks::<ELEMENT_WIDTH>().0;
    debug_assert_eq!(tokens.len(), alphabet_size);
    output.resize(elements * ELEMENT_WIDTH, 0);
    for (index, out) in indices
        .as_chunks::<8>()
        .0
        .iter()
        .zip(output.as_chunks_mut::<ELEMENT_WIDTH>().0)
    {
        write_tokenized_element_fixed(
            tokens,
            u64::from_le_bytes(*index)
                .try_into()
                .map_err(|_| numeric_too_large())?,
            out,
        )?;
    }
    Ok(())
}

fn decode_tokenize_indices_generic(
    alphabet: &[u8],
    alphabet_size: usize,
    element_width: usize,
    indices: &[u8],
    index_width: usize,
    output: &mut Vec<u8>,
) -> Result<()> {
    output.clear();
    match index_width {
        1 => {
            for &index in indices {
                append_tokenized_element(
                    alphabet,
                    alphabet_size,
                    element_width,
                    index.into(),
                    output,
                )?;
            }
        }
        2 => {
            for index in indices.as_chunks::<2>().0 {
                append_tokenized_element(
                    alphabet,
                    alphabet_size,
                    element_width,
                    u16::from_le_bytes(*index).into(),
                    output,
                )?;
            }
        }
        4 => {
            for index in indices.as_chunks::<4>().0 {
                append_tokenized_element(
                    alphabet,
                    alphabet_size,
                    element_width,
                    u32::from_le_bytes(*index)
                        .try_into()
                        .map_err(|_| numeric_too_large())?,
                    output,
                )?;
            }
        }
        8 => {
            for index in indices.as_chunks::<8>().0 {
                append_tokenized_element(
                    alphabet,
                    alphabet_size,
                    element_width,
                    u64::from_le_bytes(*index)
                        .try_into()
                        .map_err(|_| numeric_too_large())?,
                    output,
                )?;
            }
        }
        _ => unreachable!("validate_numeric_stream_width accepted only supported widths"),
    }
    Ok(())
}

#[expect(clippy::inline_always, reason = "profiled: one call per token")]
#[inline(always)]
fn write_tokenized_element_fixed<const ELEMENT_WIDTH: usize>(
    tokens: &[[u8; ELEMENT_WIDTH]],
    index: usize,
    out: &mut [u8; ELEMENT_WIDTH],
) -> Result<()> {
    // One check both validates the index and bounds the token read.
    *out = *tokens.get(index).ok_or_else(index_out_of_bounds)?;
    Ok(())
}

#[expect(clippy::inline_always, reason = "profiled: one call per token")]
#[inline(always)]
fn append_tokenized_element(
    alphabet: &[u8],
    alphabet_size: usize,
    element_width: usize,
    index: usize,
    output: &mut Vec<u8>,
) -> Result<()> {
    validate_index(index, alphabet_size)?;
    let start = index * element_width;
    output.extend_from_slice(&alphabet[start..start + element_width]);
    Ok(())
}

#[expect(clippy::inline_always, reason = "profiled: one call per token")]
#[inline(always)]
fn validate_index(index: usize, alphabet_size: usize) -> Result<()> {
    if index >= alphabet_size {
        return Err(index_out_of_bounds());
    }
    Ok(())
}

fn index_out_of_bounds() -> Error {
    Error::new(ErrorKind::Malformed).with_detail("tokenize_fixed index is out of bounds")
}

fn numeric_too_large() -> Error {
    Error::new(ErrorKind::LimitExceeded).with_detail("numeric value is too large")
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::decode_tokenize_indices;
    use ozlrip_core::ErrorKind;

    #[test]
    fn overwrites_stale_output() {
        let alphabet = *b"aabbcc";
        let indices = [2, 0, 1];
        let mut output = b"stale bytes".to_vec();

        decode_tokenize_indices(&alphabet, 3, 2, &indices, 1, &mut output).unwrap();

        assert_eq!(output, b"ccaabb");
    }

    #[test]
    fn overwrites_stale_output_for_odd_widths() {
        let alphabet = *b"aaabbb";
        let indices = [1, 0];
        let mut output = b"stale bytes".to_vec();

        decode_tokenize_indices(&alphabet, 2, 3, &indices, 1, &mut output).unwrap();

        assert_eq!(output, b"bbbaaa");
    }

    #[test]
    fn rejects_invalid_index() {
        let alphabet = *b"aabb";
        let indices = [1, 2];
        let mut output = Vec::new();

        let err = decode_tokenize_indices(&alphabet, 2, 2, &indices, 1, &mut output).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Malformed);
    }
}
