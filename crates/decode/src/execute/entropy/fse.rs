//! FSE nodes: `fse_ncount` and `fse_v2`, and the interleaved FSE symbol
//! decoder the legacy container shares.

use alloc::format;
use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Limits, Result};
use zrip_core::bitstream::reader::BitReader;
use zrip_core::bitstream::reader_reverse::ReverseBitReader;
use zrip_core::fse::FseDecodeEntry;
use zrip_core::fse::table_builder::{build_decode_table, parse_fse_table_description};

use crate::execute::elements::{numeric_element_count, require_numeric_width};
use crate::execute::header::require_empty_header;
use crate::execute::output::{alloc_output, check_output_len};
use crate::execute::streams::{OwnedStream, StreamInput};

pub(in crate::execute) fn decode_fse_ncount_node(
    source: StreamInput<'_>,
    header: &[u8],
    limits: Limits,
) -> Result<OwnedStream> {
    require_empty_header(header, "fse_ncount headers are unsupported")?;
    if source.element_width != 1 {
        return Err(
            Error::new(ErrorKind::InvalidType).with_detail("fse_ncount input must be serial")
        );
    }

    let mut reader = BitReader::new(source.bytes);
    let (mut distribution, _accuracy_log) = parse_fse_table_description(&mut reader, u8::MAX)
        .map_err(|err| {
            Error::new(ErrorKind::Malformed).with_detail(format!("invalid fse_ncount: {err}"))
        })?;
    if reader.bytes_consumed() != source.bytes.len() {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("fse_ncount input has trailing bytes")
        );
    }
    while distribution.last().copied() == Some(0) {
        distribution.pop();
    }

    let output_len = distribution
        .len()
        .checked_mul(2)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let mut output = alloc_output(output_len, limits, "fse_ncount allocation failed")?;
    for count in distribution {
        output.extend_from_slice(&count.to_le_bytes());
    }
    Ok(OwnedStream::typed(output, 2))
}

pub(in crate::execute) fn decode_fse_v2_node(
    inputs: &[StreamInput<'_>],
    header: &[u8],
    limits: Limits,
) -> Result<Vec<u8>> {
    let [norm, bits] = inputs else {
        return Err(Error::new(ErrorKind::InvalidGraph)
            .with_detail("fse_v2 input count does not match node shape"));
    };
    require_numeric_width(norm, 2, "fse_v2 normalized counts")?;
    if bits.element_width != 1 {
        return Err(Error::new(ErrorKind::InvalidType).with_detail("fse_v2 bits must be serial"));
    }

    let parsed = parse_fse_v2_header(header)?;
    check_output_len(parsed.output_len, limits)?;

    let mut distribution = Vec::new();
    distribution
        .try_reserve_exact(numeric_element_count(norm.bytes, 2)?)
        .map_err(|_| {
            Error::new(ErrorKind::AllocationFailed)
                .with_detail("fse distribution allocation failed")
        })?;
    for count in norm.bytes.as_chunks::<2>().0 {
        distribution.push(i16::from_le_bytes(*count));
    }
    let accuracy_log = validate_fse_distribution(&distribution)?;
    let table = build_decode_table(&distribution, accuracy_log).map_err(|err| {
        Error::new(ErrorKind::Malformed).with_detail(format!("invalid fse_v2 table: {err}"))
    })?;
    decode_fse_symbols(
        bits.bytes,
        parsed.output_len,
        parsed.nb_states,
        &table,
        accuracy_log,
        "fse_v2",
    )
}

#[derive(Clone, Copy)]
struct FseV2Header {
    nb_states: usize,
    output_len: usize,
}

fn parse_fse_v2_header(header: &[u8]) -> Result<FseV2Header> {
    if !(2..=9).contains(&header.len()) {
        return Err(Error::new(ErrorKind::Malformed).with_detail("fse_v2 header is malformed"));
    }
    let nb_states = usize::from(header[0]);
    if !matches!(nb_states, 2 | 4) {
        return Err(
            Error::new(ErrorKind::Unsupported).with_detail("fse_v2 state count is unsupported")
        );
    }
    let mut output_len = 0u64;
    for (shift, &byte) in header[1..].iter().enumerate() {
        let bit_shift = shift
            .checked_mul(8)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        output_len |= u64::from(byte) << bit_shift;
    }
    if output_len < 2 {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("fse_v2 output count must be at least two"));
    }
    let output_len = usize::try_from(output_len).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("fse_v2 output size is too large")
    })?;
    Ok(FseV2Header {
        nb_states,
        output_len,
    })
}

fn validate_fse_distribution(distribution: &[i16]) -> Result<u8> {
    if distribution.len() < 2 || distribution.len() > 256 {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("fse_v2 normalized count size is invalid")
        );
    }
    let mut sum = 0u32;
    for &count in distribution {
        if count < -1 {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("fse_v2 normalized count is invalid")
            );
        }
        if count == -1 {
            sum = sum
                .checked_add(1)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        } else {
            sum = sum
                .checked_add(u32::try_from(count).map_err(|_| {
                    Error::new(ErrorKind::Malformed).with_detail("fse_v2 count is invalid")
                })?)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        }
    }
    if sum == 0 || !sum.is_power_of_two() {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("fse_v2 normalized count sum is invalid")
        );
    }
    let accuracy_log = u8::try_from(sum.ilog2()).map_err(|_| Error::new(ErrorKind::Malformed))?;
    if !(zrip_core::fse::MIN_TABLE_LOG..=zrip_core::fse::MAX_TABLE_LOG).contains(&accuracy_log) {
        return Err(Error::new(ErrorKind::Malformed).with_detail("fse_v2 table log is unsupported"));
    }
    Ok(accuracy_log)
}

#[derive(Clone, Copy)]
struct OpenZlFseState<'a> {
    table: &'a [FseDecodeEntry],
    state: u32,
}

impl<'a> OpenZlFseState<'a> {
    #[expect(
        clippy::inline_always,
        reason = "profiled FSE v2 loops benefit from inlining state setup"
    )]
    #[inline(always)]
    fn new(
        table: &'a [FseDecodeEntry],
        accuracy_log: u8,
        reader: &mut ReverseBitReader<'_>,
    ) -> Result<Self> {
        let state = reader
            .read_bits(accuracy_log)
            .map_err(|err| Error::new(ErrorKind::Malformed).with_detail(format!("{err}")))?;
        Ok(Self { table, state })
    }

    #[expect(
        clippy::inline_always,
        reason = "profiled FSE v2 loops pay measurable call overhead"
    )]
    #[inline(always)]
    fn symbol(self) -> Result<u8> {
        let index = usize::try_from(self.state).map_err(|_| Error::new(ErrorKind::Malformed))?;
        Ok(self
            .table
            .get(index)
            .ok_or_else(|| Error::new(ErrorKind::Malformed).with_detail("fse state is invalid"))?
            .symbol)
    }

    #[expect(
        clippy::inline_always,
        reason = "disassembly showed standalone update calls in the FSE hot loop"
    )]
    #[inline(always)]
    fn update(&mut self, reader: &mut ReverseBitReader<'_>) -> Result<()> {
        let index = usize::try_from(self.state).map_err(|_| Error::new(ErrorKind::Malformed))?;
        let entry = self
            .table
            .get(index)
            .ok_or_else(|| Error::new(ErrorKind::Malformed).with_detail("fse state is invalid"))?;
        let bits = reader
            .read_bits(entry.num_bits)
            .map_err(|err| Error::new(ErrorKind::Malformed).with_detail(format!("{err}")))?;
        self.state = u32::from(entry.base_line)
            .checked_add(bits)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        Ok(())
    }
}

pub(in crate::execute) fn decode_fse_symbols(
    bits: &[u8],
    output_len: usize,
    nb_states: usize,
    table: &[FseDecodeEntry],
    accuracy_log: u8,
    transform_name: &str,
) -> Result<Vec<u8>> {
    if output_len < nb_states {
        return Err(Error::new(ErrorKind::Malformed).with_detail(format!(
            "{transform_name} output count is smaller than state count"
        )));
    }
    let mut reader = ReverseBitReader::new(bits)
        .map_err(|err| Error::new(ErrorKind::Malformed).with_detail(format!("{err}")))?;

    let mut output = Vec::new();
    output.try_reserve_exact(output_len).map_err(|_| {
        Error::new(ErrorKind::AllocationFailed).with_detail("fse output allocation failed")
    })?;
    match nb_states {
        2 => {
            decode_fse_interleaved::<2>(&mut reader, table, accuracy_log, output_len, &mut output)?;
        }
        4 => {
            decode_fse_interleaved::<4>(&mut reader, table, accuracy_log, output_len, &mut output)?;
        }
        _ => {
            return Err(Error::new(ErrorKind::Unsupported)
                .with_detail(format!("{transform_name} state count is unsupported")));
        }
    }
    if reader.bits_remaining() != 0 {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail(format!("{transform_name} input has trailing bits")));
    }
    Ok(output)
}

/// Updates per refill in the batched loop. Each reads at most
/// `FSE_BATCH_MAX_LOG` bits, and a refill leaves at least 57 bits in the
/// container, so a batch never needs a second refill.
const FSE_BATCH: usize = 4;

const FSE_BATCH_MAX_LOG: u8 = 12;

/// Decodes `N` interleaved FSE states: every symbol but the last `N` is
/// followed by a state update, and the last `N` are read from the final
/// states.
fn decode_fse_interleaved<const N: usize>(
    reader: &mut ReverseBitReader<'_>,
    table: &[FseDecodeEntry],
    accuracy_log: u8,
    output_len: usize,
    output: &mut Vec<u8>,
) -> Result<()> {
    let mut states = [0u32; N];
    for state in &mut states {
        *state = OpenZlFseState::new(table, accuracy_log, reader)?.state;
    }
    let update_len = output_len - N;
    let mut index = 0usize;

    // Batched loop: refill once per batch and read without checks.
    // `bits_remaining` is the only overrun guard, so a batch runs only
    // while the stream still holds its worst case. `FSE_BATCH` is a
    // multiple of `N`, so lane `k` of every batch is state `k % N`.
    let table_len = table.len();
    if accuracy_log <= FSE_BATCH_MAX_LOG && table_len == 1usize << accuracy_log {
        let mask = table_len - 1;
        let batch_bits = FSE_BATCH * usize::from(accuracy_log);
        while update_len - index >= FSE_BATCH {
            reader.refill_fast_or_regular();
            if reader.bits_remaining() < batch_bits {
                break;
            }
            for lane in 0..FSE_BATCH {
                let state = &mut states[lane % N];
                let entry = table[*state as usize & mask];
                output.push(entry.symbol);
                *state = u32::from(entry.base_line) + reader.read_bits_branchless(entry.num_bits);
            }
            index += FSE_BATCH;
        }
    }

    // Checked tail: the stream end, and tables the batch cannot take.
    let mut lanes = states.map(|state| OpenZlFseState { table, state });
    while index < update_len {
        let lane = &mut lanes[index % N];
        output.push(lane.symbol()?);
        lane.update(reader)?;
        index += 1;
    }
    while index < output_len {
        output.push(lanes[index % N].symbol()?);
        index += 1;
    }
    Ok(())
}
