//! The deprecated `rolz` node: its header, literal streams and the
//! per-state sequence values.

use alloc::boxed::Box;
use alloc::format;
use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Limits, Result};
use zrip_core::bitstream::reader_reverse::ReverseBitReader;

use super::legacy_literals::{
    decode_deprecated_lz_entropy_payload_to_vec, parse_deprecated_lz_stored_stream,
    parse_legacy_literal_entropy_payload, read_deprecated_lz_le_u32,
};
use super::rolz_decoder::{
    ROLZ_DEPRECATED_MATCH_TYPE_REP, RolzDeprecatedLiterals, RolzDeprecatedO1Literals,
    RolzDeprecatedParams, RolzDeprecatedPayload, decode_rolz_deprecated_payload,
};
use crate::execute::entropy::LegacyPayload;
use crate::execute::header::require_empty_header;
use crate::execute::streams::StreamInput;

const ROLZ_DEPRECATED_PARAMS: RolzDeprecatedParams = RolzDeprecatedParams {
    context_depth: 2,
    context_log: 12,
    row_log: 4,
    min_length: 3,
    predict_match_length: true,
    lz_min_length: 7,
    rep_min_length: 3,
};

const ROLZ_DEPRECATED_HEADER_LEN: usize = 15;

const ROLZ_DEPRECATED_MARKOV_STATES: usize = 6;

const ROLZ_DEPRECATED_VALUE_BASE: [usize; 59] = [
    0,
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
    12,
    13,
    14,
    15,
    16,
    17,
    18,
    19,
    20,
    21,
    22,
    23,
    24,
    25,
    26,
    27,
    28,
    29,
    30,
    31,
    0x20,
    0x40,
    0x80,
    0x100,
    0x200,
    0x400,
    0x800,
    0x1000,
    0x2000,
    0x4000,
    0x8000,
    0x1_0000,
    0x2_0000,
    0x4_0000,
    0x8_0000,
    0x10_0000,
    0x20_0000,
    0x40_0000,
    0x80_0000,
    0x100_0000,
    0x200_0000,
    0x400_0000,
    0x800_0000,
    0x1000_0000,
    0x2000_0000,
    0x4000_0000,
    0x8000_0000,
];

const ROLZ_DEPRECATED_VALUE_BITS: [u8; 59] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
    30, 31,
];

pub(in crate::execute) fn decode_rolz_deprecated_node(
    source: StreamInput<'_>,
    header: &[u8],
    limits: Limits,
) -> Result<Vec<u8>> {
    require_empty_header(header, "rolz_deprecated headers are unsupported")?;
    let (decoded_size, payload) =
        parse_deprecated_lz_stored_stream(source, limits, "rolz_deprecated")?;
    let payload = parse_rolz_deprecated_payload(payload, limits)?;
    decode_rolz_deprecated_payload(payload, decoded_size, limits)
}

fn parse_rolz_deprecated_payload(
    payload: &[u8],
    limits: Limits,
) -> Result<RolzDeprecatedPayload<'_>> {
    let RolzDeprecatedHeader {
        params,
        num_literals,
        num_sequences,
    } = parse_rolz_deprecated_header(payload, limits)?;

    let mut offset = ROLZ_DEPRECATED_HEADER_LEN;
    let literals = parse_rolz_deprecated_literals(payload, &mut offset, num_literals, limits)?;
    if literals.byte_len()? != num_literals {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("rolz_deprecated literal count is invalid"));
    }

    let match_types =
        decode_rolz_deprecated_match_types(payload, &mut offset, num_sequences, limits)?;
    let literal_lengths = decode_rolz_deprecated_seq_values(
        payload,
        &mut offset,
        &match_types,
        limits,
        "rolz_deprecated literal lengths",
    )?;
    let match_lengths = decode_rolz_deprecated_seq_values(
        payload,
        &mut offset,
        &match_types,
        limits,
        "rolz_deprecated match lengths",
    )?;
    let match_codes = decode_rolz_deprecated_seq_values(
        payload,
        &mut offset,
        &match_types,
        limits,
        "rolz_deprecated match codes",
    )?;
    if offset != payload.len() {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("rolz_deprecated payload has trailing bytes"));
    }
    Ok(RolzDeprecatedPayload {
        params,
        literals,
        match_types,
        literal_lengths,
        match_lengths,
        match_codes,
    })
}

/// The fixed-size ROLZ payload header: the parameters and the literal and
/// sequence counts.
struct RolzDeprecatedHeader {
    params: RolzDeprecatedParams,
    num_literals: usize,
    num_sequences: usize,
}

/// Parses the ROLZ payload header and checks the sequence count against the
/// buffer limit.
fn parse_rolz_deprecated_header(payload: &[u8], limits: Limits) -> Result<RolzDeprecatedHeader> {
    let header = payload.get(..ROLZ_DEPRECATED_HEADER_LEN).ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail("rolz_deprecated header is truncated")
    })?;
    let params = parse_rolz_deprecated_params(header)?;
    let num_literals = usize::try_from(read_deprecated_lz_le_u32(
        header,
        7,
        "rolz_deprecated literals",
    )?)
    .map_err(|_| {
        Error::new(ErrorKind::LimitExceeded)
            .with_detail("rolz_deprecated literal count is too large")
    })?;
    let num_sequences = usize::try_from(read_deprecated_lz_le_u32(
        header,
        11,
        "rolz_deprecated sequences",
    )?)
    .map_err(|_| {
        Error::new(ErrorKind::LimitExceeded)
            .with_detail("rolz_deprecated sequence count is too large")
    })?;
    if num_sequences > limits.max_buffer_bytes / 16 {
        return Err(Error::new(ErrorKind::LimitExceeded)
            .with_detail("rolz_deprecated sequence count exceeds buffer limit"));
    }
    Ok(RolzDeprecatedHeader {
        params,
        num_literals,
        num_sequences,
    })
}

/// Decodes one match type per sequence and rejects unknown types.
fn decode_rolz_deprecated_match_types(
    payload: &[u8],
    offset: &mut usize,
    num_sequences: usize,
    limits: Limits,
) -> Result<Vec<u8>> {
    let match_types = decode_deprecated_lz_entropy_payload_to_vec(
        payload,
        offset,
        num_sequences,
        limits,
        "rolz_deprecated match types",
    )?;
    for &match_type in &match_types {
        if match_type > ROLZ_DEPRECATED_MATCH_TYPE_REP {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("rolz_deprecated match type is invalid"));
        }
    }
    Ok(match_types)
}

fn parse_rolz_deprecated_literals<'a>(
    payload: &'a [u8],
    offset: &mut usize,
    num_literals: usize,
    limits: Limits,
) -> Result<RolzDeprecatedLiterals<'a>> {
    if num_literals == 0 {
        return Ok(RolzDeprecatedLiterals::Linear(LegacyPayload::Raw(&[])));
    }

    let order = *payload.get(*offset).ok_or_else(|| {
        Error::new(ErrorKind::Malformed)
            .with_detail("rolz_deprecated literal order flag is truncated")
    })?;
    *offset = (*offset)
        .checked_add(1)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    match order {
        0 => parse_legacy_literal_entropy_payload(
            payload,
            offset,
            1,
            limits,
            "rolz_deprecated literals",
        )
        .map(RolzDeprecatedLiterals::Linear),
        1 => parse_rolz_deprecated_o1_literals(payload, offset, num_literals, limits),
        _ => Err(Error::new(ErrorKind::Malformed)
            .with_detail("rolz_deprecated literal order flag is invalid")),
    }
}

fn parse_rolz_deprecated_o1_literals<'a>(
    payload: &'a [u8],
    offset: &mut usize,
    num_literals: usize,
    limits: Limits,
) -> Result<RolzDeprecatedLiterals<'a>> {
    let max_context = *payload.get(*offset).ok_or_else(|| {
        Error::new(ErrorKind::Malformed)
            .with_detail("rolz_deprecated literal clustering is truncated")
    })?;
    *offset = (*offset)
        .checked_add(1)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;

    let map_len = usize::from(max_context)
        .checked_add(1)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let map_end = (*offset)
        .checked_add(map_len)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let map = payload.get(*offset..map_end).ok_or_else(|| {
        Error::new(ErrorKind::Malformed)
            .with_detail("rolz_deprecated literal clustering is truncated")
    })?;
    *offset = map_end;

    let mut context_to_cluster = [0u8; 256];
    context_to_cluster[..map_len].copy_from_slice(map);
    let num_clusters = map
        .iter()
        .copied()
        .max()
        .map_or(0, |cluster| usize::from(cluster) + 1);
    let cluster_limit = limits
        .max_buffer_bytes
        .checked_div(core::mem::size_of::<LegacyPayload<'_>>().max(1))
        .unwrap_or(0);
    if num_clusters > cluster_limit {
        return Err(Error::new(ErrorKind::LimitExceeded)
            .with_detail("rolz_deprecated literal clusters exceed buffer limit"));
    }

    let clusters = parse_rolz_deprecated_literal_clusters(
        payload,
        offset,
        num_clusters,
        num_literals,
        limits,
    )?;

    Ok(RolzDeprecatedLiterals::O1(Box::new(
        RolzDeprecatedO1Literals {
            max_context,
            context_to_cluster,
            clusters,
            total_len: num_literals,
        },
    )))
}

/// Parses the order-1 literal clusters, each a literal count followed by its
/// entropy payload. The counts must add up to `num_literals`.
fn parse_rolz_deprecated_literal_clusters<'a>(
    payload: &'a [u8],
    offset: &mut usize,
    num_clusters: usize,
    num_literals: usize,
    limits: Limits,
) -> Result<Vec<LegacyPayload<'a>>> {
    let mut clusters = Vec::new();
    clusters.try_reserve_exact(num_clusters).map_err(|_| {
        Error::new(ErrorKind::AllocationFailed)
            .with_detail("rolz_deprecated literal cluster allocation failed")
    })?;
    let mut total = 0usize;
    for _ in 0..num_clusters {
        let count = usize::try_from(read_deprecated_lz_le_u32(
            payload,
            *offset,
            "rolz_deprecated literal cluster",
        )?)
        .map_err(|_| {
            Error::new(ErrorKind::LimitExceeded)
                .with_detail("rolz_deprecated literal cluster is too large")
        })?;
        *offset = (*offset)
            .checked_add(4)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        total = total
            .checked_add(count)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        if total > num_literals {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("rolz_deprecated literal cluster count is invalid"));
        }

        let cluster = parse_legacy_literal_entropy_payload(
            payload,
            offset,
            1,
            limits,
            "rolz_deprecated literals",
        )?;
        if cluster.byte_len()? != count {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("rolz_deprecated literal cluster count is invalid"));
        }
        clusters.push(cluster);
    }
    if total != num_literals {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("rolz_deprecated literal cluster count is invalid"));
    }
    Ok(clusters)
}

fn parse_rolz_deprecated_params(header: &[u8]) -> Result<RolzDeprecatedParams> {
    let params = RolzDeprecatedParams {
        context_depth: usize::from(header[0]),
        context_log: usize::from(header[1]),
        row_log: usize::from(header[2]),
        min_length: usize::from(header[3]),
        predict_match_length: header[4] != 0,
        lz_min_length: usize::from(header[5]),
        rep_min_length: usize::from(header[6]),
    };
    if params.context_depth != ROLZ_DEPRECATED_PARAMS.context_depth
        || params.context_log != ROLZ_DEPRECATED_PARAMS.context_log
        || params.row_log != ROLZ_DEPRECATED_PARAMS.row_log
        || params.min_length != ROLZ_DEPRECATED_PARAMS.min_length
        || params.predict_match_length != ROLZ_DEPRECATED_PARAMS.predict_match_length
        || params.lz_min_length != ROLZ_DEPRECATED_PARAMS.lz_min_length
        || params.rep_min_length != ROLZ_DEPRECATED_PARAMS.rep_min_length
    {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("rolz_deprecated parameters are unsupported"));
    }
    Ok(params)
}

fn decode_rolz_deprecated_seq_values(
    source: &[u8],
    offset: &mut usize,
    match_types: &[u8],
    limits: Limits,
    transform_name: &str,
) -> Result<Vec<usize>> {
    let num_sequences = match_types.len();
    let mut values = Vec::new();
    values.try_reserve_exact(num_sequences).map_err(|_| {
        Error::new(ErrorKind::AllocationFailed)
            .with_detail(format!("{transform_name} allocation failed"))
    })?;
    if num_sequences == 0 {
        return Ok(values);
    }

    let (bit_size, totals) =
        read_rolz_deprecated_seq_header(source, offset, num_sequences, transform_name)?;

    let bit_end = (*offset)
        .checked_add(bit_size)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let bitstream = source.get(*offset..bit_end).ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail(format!("{transform_name} is truncated"))
    })?;
    *offset = bit_end;

    let codes = decode_rolz_deprecated_seq_codes(
        source,
        offset,
        &totals,
        num_sequences,
        limits,
        transform_name,
    )?;

    let mut reader = ReverseBitReader::new(bitstream)
        .map_err(|err| Error::new(ErrorKind::Malformed).with_detail(format!("{err}")))?;
    let mut positions = [0usize; ROLZ_DEPRECATED_MARKOV_STATES];
    positions[1..ROLZ_DEPRECATED_MARKOV_STATES]
        .copy_from_slice(&totals[..(ROLZ_DEPRECATED_MARKOV_STATES - 1)]);
    let mut state = 0usize;
    for &match_type in match_types {
        state = rolz_deprecated_markov_next_state(state, match_type)?;
        let index = positions[state];
        if index >= totals[state] {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail(format!("{transform_name} state totals are invalid")));
        }
        positions[state] = positions[state]
            .checked_add(1)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        values.push(read_rolz_deprecated_seq_value(
            &mut reader,
            codes[index],
            transform_name,
        )?);
    }
    validate_rolz_deprecated_seq_positions(&positions, &totals, transform_name)?;
    if reader.bits_remaining() != 0 {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail(format!("{transform_name} bitstream has trailing bits")));
    }
    Ok(values)
}

/// Reads the bitstream size and the per-state totals that precede a ROLZ
/// sequence value stream, and validates the totals.
fn read_rolz_deprecated_seq_header(
    source: &[u8],
    offset: &mut usize,
    num_sequences: usize,
    transform_name: &str,
) -> Result<(usize, [usize; ROLZ_DEPRECATED_MARKOV_STATES])> {
    let bit_size = usize::try_from(read_deprecated_lz_le_u32(source, *offset, transform_name)?)
        .map_err(|_| {
            Error::new(ErrorKind::LimitExceeded)
                .with_detail(format!("{transform_name} bitstream is too large"))
        })?;
    *offset = (*offset)
        .checked_add(4)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let mut totals = [0usize; ROLZ_DEPRECATED_MARKOV_STATES];
    for total in &mut totals {
        *total = usize::try_from(read_deprecated_lz_le_u32(source, *offset, transform_name)?)
            .map_err(|_| {
                Error::new(ErrorKind::LimitExceeded)
                    .with_detail(format!("{transform_name} state total is too large"))
            })?;
        *offset = (*offset)
            .checked_add(4)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    }
    validate_rolz_deprecated_seq_totals(&totals, num_sequences, transform_name)?;
    Ok((bit_size, totals))
}

/// Decodes the value codes, one entropy payload per Markov state. Each
/// state's codes fill the range its totals give.
fn decode_rolz_deprecated_seq_codes(
    source: &[u8],
    offset: &mut usize,
    totals: &[usize; ROLZ_DEPRECATED_MARKOV_STATES],
    num_sequences: usize,
    limits: Limits,
    transform_name: &str,
) -> Result<Vec<u8>> {
    let mut codes = Vec::new();
    codes.try_reserve_exact(num_sequences).map_err(|_| {
        Error::new(ErrorKind::AllocationFailed)
            .with_detail(format!("{transform_name} code allocation failed"))
    })?;
    codes.resize(num_sequences, 0);
    for state in 0..ROLZ_DEPRECATED_MARKOV_STATES {
        let begin = if state == 0 { 0 } else { totals[state - 1] };
        let end = totals[state];
        let decoded = decode_deprecated_lz_entropy_payload_to_vec(
            source,
            offset,
            end - begin,
            limits,
            transform_name,
        )?;
        codes[begin..end].copy_from_slice(&decoded);
    }
    Ok(codes)
}

/// Reads one sequence value: the base of its code plus the code's extra
/// bits from the reverse bitstream.
fn read_rolz_deprecated_seq_value(
    reader: &mut ReverseBitReader<'_>,
    code: u8,
    transform_name: &str,
) -> Result<usize> {
    let code = usize::from(code);
    let base = *ROLZ_DEPRECATED_VALUE_BASE.get(code).ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail(format!("{transform_name} code is invalid"))
    })?;
    let bits = *ROLZ_DEPRECATED_VALUE_BITS.get(code).ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail(format!("{transform_name} code is invalid"))
    })?;
    let extra = usize::try_from(reader.read_bits(bits).map_err(|err| {
        Error::new(ErrorKind::Malformed).with_detail(format!("{transform_name}: {err}"))
    })?)
    .map_err(|_| Error::new(ErrorKind::IntegerOverflow))?;
    base.checked_add(extra)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))
}

fn validate_rolz_deprecated_seq_totals(
    totals: &[usize; ROLZ_DEPRECATED_MARKOV_STATES],
    num_sequences: usize,
    transform_name: &str,
) -> Result<()> {
    let mut previous = 0usize;
    for &total in totals {
        if total < previous {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail(format!("{transform_name} state totals are invalid")));
        }
        previous = total;
    }
    if totals[ROLZ_DEPRECATED_MARKOV_STATES - 1] != num_sequences {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail(format!("{transform_name} sequence count is invalid")));
    }
    Ok(())
}

fn validate_rolz_deprecated_seq_positions(
    positions: &[usize; ROLZ_DEPRECATED_MARKOV_STATES],
    totals: &[usize; ROLZ_DEPRECATED_MARKOV_STATES],
    transform_name: &str,
) -> Result<()> {
    for state in 0..ROLZ_DEPRECATED_MARKOV_STATES {
        if positions[state] != totals[state] {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail(format!("{transform_name} state totals are invalid")));
        }
    }
    Ok(())
}

fn rolz_deprecated_markov_next_state(state: usize, match_type: u8) -> Result<usize> {
    const NEXT: [[usize; 4]; ROLZ_DEPRECATED_MARKOV_STATES] = [
        [0, 1, 2, 5],
        [0, 1, 3, 5],
        [0, 1, 4, 5],
        [0, 1, 4, 5],
        [0, 1, 4, 5],
        [0, 1, 2, 5],
    ];
    let match_type = usize::from(match_type);
    NEXT.get(state)
        .and_then(|row| row.get(match_type))
        .copied()
        .ok_or_else(|| {
            Error::new(ErrorKind::Malformed).with_detail("rolz_deprecated match type is invalid")
        })
}
