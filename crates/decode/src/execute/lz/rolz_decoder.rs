//! The deprecated `rolz` node's decoder: the parsed payload, the ROLZ
//! match table, repeat offsets and match copies.

use alloc::boxed::Box;
use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Limits, Result};

use super::legacy_literals::{LegacyLiteralCursor, read_legacy_literal_byte};
use super::sequences::append_lz_match;
use crate::execute::entropy::LegacyPayload;

#[derive(Clone, Copy)]
pub(super) struct RolzDeprecatedParams {
    pub(super) context_depth: usize,
    pub(super) context_log: usize,
    pub(super) row_log: usize,
    pub(super) min_length: usize,
    pub(super) predict_match_length: bool,
    pub(super) lz_min_length: usize,
    pub(super) rep_min_length: usize,
}

pub(super) struct RolzDeprecatedPayload<'a> {
    pub(super) params: RolzDeprecatedParams,
    pub(super) literals: RolzDeprecatedLiterals<'a>,
    pub(super) match_types: Vec<u8>,
    pub(super) literal_lengths: Vec<usize>,
    pub(super) match_lengths: Vec<usize>,
    pub(super) match_codes: Vec<usize>,
}

pub(super) enum RolzDeprecatedLiterals<'a> {
    Linear(LegacyPayload<'a>),
    O1(Box<RolzDeprecatedO1Literals<'a>>),
}

pub(super) struct RolzDeprecatedO1Literals<'a> {
    pub(super) max_context: u8,
    pub(super) context_to_cluster: [u8; 256],
    pub(super) clusters: Vec<LegacyPayload<'a>>,
    pub(super) total_len: usize,
}

enum RolzDeprecatedLiteralCursor<'a> {
    Linear(LegacyLiteralCursor<'a>),
    O1 {
        payload: Box<RolzDeprecatedO1Literals<'a>>,
        cluster_offsets: Box<[usize; 256]>,
        consumed: usize,
    },
}

#[derive(Clone, Copy, Default)]
struct RolzDeprecatedTableEntry {
    index: usize,
    predicted_match_length: u8,
}

struct RolzDeprecatedTable {
    heads: Vec<usize>,
    entries: Vec<RolzDeprecatedTableEntry>,
    row_log: usize,
    row_mask: usize,
}

const ROLZ_DEPRECATED_INITIAL_REPS: [usize; 3] = [1, 4, 8];

const ROLZ_DEPRECATED_REP_SUB: usize = 4;

const ROLZ_DEPRECATED_MATCH_TYPE_LZ: u8 = 0;

const ROLZ_DEPRECATED_MATCH_TYPE_ROLZ: u8 = 1;

const ROLZ_DEPRECATED_MATCH_TYPE_REP0: u8 = 2;

pub(super) const ROLZ_DEPRECATED_MATCH_TYPE_REP: u8 = 3;

impl RolzDeprecatedTable {
    fn new(params: RolzDeprecatedParams, limits: Limits) -> Result<Self> {
        let contexts = 1usize
            .checked_shl(u32::try_from(params.context_log).map_err(|_| {
                Error::new(ErrorKind::LimitExceeded)
                    .with_detail("rolz_deprecated context log is too large")
            })?)
            .ok_or_else(|| {
                Error::new(ErrorKind::LimitExceeded)
                    .with_detail("rolz_deprecated context table is too large")
            })?;
        let row_size = 1usize
            .checked_shl(u32::try_from(params.row_log).map_err(|_| {
                Error::new(ErrorKind::LimitExceeded)
                    .with_detail("rolz_deprecated row log is too large")
            })?)
            .ok_or_else(|| {
                Error::new(ErrorKind::LimitExceeded)
                    .with_detail("rolz_deprecated row table is too large")
            })?;
        let entries_len = contexts
            .checked_mul(row_size)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        let entry_limit = limits
            .max_buffer_bytes
            .checked_div(core::mem::size_of::<RolzDeprecatedTableEntry>().max(1))
            .unwrap_or(0);
        if entries_len > entry_limit {
            return Err(Error::new(ErrorKind::LimitExceeded)
                .with_detail("rolz_deprecated table exceeds buffer limit"));
        }

        let mut heads = Vec::new();
        heads.try_reserve_exact(contexts).map_err(|_| {
            Error::new(ErrorKind::AllocationFailed)
                .with_detail("rolz_deprecated head table allocation failed")
        })?;
        heads.resize(contexts, 0);
        let mut entries = Vec::new();
        entries.try_reserve_exact(entries_len).map_err(|_| {
            Error::new(ErrorKind::AllocationFailed)
                .with_detail("rolz_deprecated table allocation failed")
        })?;
        entries.resize(entries_len, RolzDeprecatedTableEntry::default());
        Ok(Self {
            heads,
            entries,
            row_log: params.row_log,
            row_mask: row_size - 1,
        })
    }

    fn get(
        &self,
        context: usize,
        index: usize,
        encoded_match_length: usize,
        params: RolzDeprecatedParams,
    ) -> Result<(usize, usize)> {
        if index > self.row_mask {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("rolz_deprecated match code is invalid"));
        }
        let row_start = context
            .checked_shl(u32::try_from(self.row_log).map_err(|_| {
                Error::new(ErrorKind::LimitExceeded)
                    .with_detail("rolz_deprecated row log is too large")
            })?)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        let head = *self
            .heads
            .get(context)
            .ok_or_else(|| Error::new(ErrorKind::Malformed))?;
        let pos = row_start
            .checked_add((head + index) & self.row_mask)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        let entry = *self.entries.get(pos).ok_or_else(|| {
            Error::new(ErrorKind::Malformed).with_detail("rolz_deprecated table index is invalid")
        })?;
        if entry.index == 0 {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("rolz_deprecated match index is invalid"));
        }
        let match_length = rolz_deprecated_decode_match_length(
            params.min_length,
            usize::from(entry.predicted_match_length),
            encoded_match_length,
        )?;
        Ok((entry.index - 1, match_length))
    }

    fn put(&mut self, context: usize, index: usize, match_length: usize) -> Result<()> {
        let head = self
            .heads
            .get_mut(context)
            .ok_or_else(|| Error::new(ErrorKind::Malformed))?;
        let pos_in_row = head.wrapping_sub(1) & self.row_mask;
        *head = pos_in_row;
        let row_start = context
            .checked_shl(u32::try_from(self.row_log).map_err(|_| {
                Error::new(ErrorKind::LimitExceeded)
                    .with_detail("rolz_deprecated row log is too large")
            })?)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        let pos = row_start
            .checked_add(pos_in_row)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        let entry = self.entries.get_mut(pos).ok_or_else(|| {
            Error::new(ErrorKind::Malformed).with_detail("rolz_deprecated table index is invalid")
        })?;
        entry.index = index;
        entry.predicted_match_length = u8::try_from(match_length.min(usize::from(u8::MAX)))
            .map_err(|_| Error::new(ErrorKind::IntegerOverflow))?;
        Ok(())
    }
}

impl RolzDeprecatedLiterals<'_> {
    pub(super) fn byte_len(&self) -> Result<usize> {
        match self {
            Self::Linear(payload) => payload.byte_len(),
            Self::O1(payload) => Ok(payload.total_len),
        }
    }
}

impl<'a> RolzDeprecatedLiteralCursor<'a> {
    fn new(payload: RolzDeprecatedLiterals<'a>) -> Self {
        match payload {
            RolzDeprecatedLiterals::Linear(payload) => {
                Self::Linear(LegacyLiteralCursor::new(payload))
            }
            RolzDeprecatedLiterals::O1(payload) => Self::O1 {
                payload,
                cluster_offsets: Box::new([0; 256]),
                consumed: 0,
            },
        }
    }

    fn remaining_len(&self) -> Result<usize> {
        match self {
            Self::Linear(cursor) => cursor.remaining_len(),
            Self::O1 {
                payload, consumed, ..
            } => payload.total_len.checked_sub(*consumed).ok_or_else(|| {
                Error::new(ErrorKind::Malformed)
                    .with_detail("rolz_deprecated literal stream is too short")
            }),
        }
    }

    fn extend_next(&mut self, len: usize, output: &mut Vec<u8>) -> Result<()> {
        match self {
            Self::Linear(cursor) => cursor.extend_next(len, output),
            Self::O1 {
                payload,
                cluster_offsets,
                consumed,
            } => {
                let end = consumed
                    .checked_add(len)
                    .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
                if end > payload.total_len {
                    return Err(Error::new(ErrorKind::Malformed)
                        .with_detail("rolz_deprecated literal stream is too short"));
                }

                let mut context = output.last().copied().unwrap_or(0);
                for _ in 0..len {
                    if context > payload.max_context {
                        return Err(Error::new(ErrorKind::Malformed)
                            .with_detail("rolz_deprecated literal context is invalid"));
                    }
                    let cluster = usize::from(payload.context_to_cluster[usize::from(context)]);
                    let cluster_payload = payload.clusters.get(cluster).ok_or_else(|| {
                        Error::new(ErrorKind::Malformed)
                            .with_detail("rolz_deprecated literal cluster is invalid")
                    })?;
                    let cluster_offset = cluster_offsets.get_mut(cluster).ok_or_else(|| {
                        Error::new(ErrorKind::Malformed)
                            .with_detail("rolz_deprecated literal cluster is invalid")
                    })?;
                    context = read_legacy_literal_byte(
                        cluster_payload,
                        *cluster_offset,
                        "rolz_deprecated literals",
                    )?;
                    *cluster_offset = (*cluster_offset)
                        .checked_add(1)
                        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
                    *consumed = (*consumed)
                        .checked_add(1)
                        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
                    output.push(context);
                }
                Ok(())
            }
        }
    }

    fn extend_remaining(&mut self, output: &mut Vec<u8>) -> Result<()> {
        let len = self.remaining_len()?;
        self.extend_next(len, output)
    }
}

pub(super) fn decode_rolz_deprecated_payload(
    payload: RolzDeprecatedPayload<'_>,
    decoded_size: usize,
    limits: Limits,
) -> Result<Vec<u8>> {
    let mut decoder = RolzDeprecatedDecoder::new(
        payload.literals,
        &payload.match_types,
        payload.params,
        decoded_size,
        limits,
    )?;
    for index in 0..payload.match_types.len() {
        decoder.append_literals(payload.literal_lengths[index])?;
        decoder.append_match(
            payload.match_types[index],
            payload.match_codes[index],
            payload.match_lengths[index],
        )?;
    }
    decoder.finish()
}

/// Decoder state for a ROLZ payload: the output, the literal cursor, the
/// repeat offsets and the ROLZ table, which exists only if a ROLZ match does.
struct RolzDeprecatedDecoder<'a> {
    output: Vec<u8>,
    literals: RolzDeprecatedLiteralCursor<'a>,
    reps: [usize; 3],
    table: Option<RolzDeprecatedTable>,
    params: RolzDeprecatedParams,
    decoded_size: usize,
}

impl<'a> RolzDeprecatedDecoder<'a> {
    fn new(
        literals: RolzDeprecatedLiterals<'a>,
        match_types: &[u8],
        params: RolzDeprecatedParams,
        decoded_size: usize,
        limits: Limits,
    ) -> Result<Self> {
        let mut output = Vec::new();
        output.try_reserve_exact(decoded_size).map_err(|_| {
            Error::new(ErrorKind::AllocationFailed).with_detail("rolz_deprecated allocation failed")
        })?;
        let literals = RolzDeprecatedLiteralCursor::new(literals);
        let table = if match_types.contains(&ROLZ_DEPRECATED_MATCH_TYPE_ROLZ) {
            Some(RolzDeprecatedTable::new(params, limits)?)
        } else {
            None
        };
        Ok(Self {
            output,
            literals,
            reps: ROLZ_DEPRECATED_INITIAL_REPS,
            table,
            params,
            decoded_size,
        })
    }

    /// Appends the literals of one sequence and inserts their positions into
    /// the ROLZ table.
    fn append_literals(&mut self, len: usize) -> Result<()> {
        let literal_start = self.output.len();
        append_rolz_deprecated_literals(
            &mut self.literals,
            &mut self.output,
            len,
            self.decoded_size,
        )?;
        if let Some(table) = self.table.as_mut() {
            insert_rolz_deprecated_literals(table, &self.output, literal_start, len, self.params)?;
        }
        Ok(())
    }

    /// Resolves, checks and copies the match of one sequence, then updates
    /// the repeat offsets and the ROLZ table.
    fn append_match(&mut self, match_type: u8, match_code: usize, match_len: usize) -> Result<()> {
        let match_start = self.output.len();
        let (match_offset, match_len) =
            self.resolve_match(match_start, match_type, match_code, match_len)?;
        self.check_match(match_offset, match_len)?;
        update_rolz_deprecated_reps(&mut self.reps, match_type, match_code, match_offset)?;
        if match_type == ROLZ_DEPRECATED_MATCH_TYPE_ROLZ
            && let Some(table) = self.table.as_mut()
        {
            let context = rolz_deprecated_context(&self.output, match_start, self.params)?;
            table.put(
                context,
                rolz_deprecated_output_index(match_start)?,
                match_len,
            )?;
        }
        append_lz_match(&mut self.output, match_start, match_offset, match_len);
        if match_type != ROLZ_DEPRECATED_MATCH_TYPE_ROLZ
            && let Some(table) = self.table.as_mut()
        {
            insert_rolz_deprecated_lz_match(
                table,
                &self.output,
                match_start,
                match_len,
                self.params,
            )?;
        }
        Ok(())
    }

    /// The match offset and length: from the ROLZ table for a ROLZ match,
    /// otherwise from the code and the repeat offsets.
    fn resolve_match(
        &self,
        match_start: usize,
        match_type: u8,
        match_code: usize,
        match_len: usize,
    ) -> Result<(usize, usize)> {
        if match_type == ROLZ_DEPRECATED_MATCH_TYPE_ROLZ {
            let table = self
                .table
                .as_ref()
                .ok_or_else(|| Error::new(ErrorKind::Malformed))?;
            resolve_rolz_deprecated_rolz_match(
                table,
                &self.output,
                match_start,
                match_code,
                match_len,
                self.params,
            )
        } else {
            resolve_rolz_deprecated_match(
                match_type,
                match_code,
                match_len,
                self.params,
                &self.reps,
            )
        }
    }

    /// Checks a match against the decoded prefix and the output size.
    fn check_match(&self, match_offset: usize, match_len: usize) -> Result<()> {
        if match_offset == 0 {
            return Err(
                Error::new(ErrorKind::Malformed).with_detail("rolz_deprecated offset is zero")
            );
        }
        if match_offset > self.output.len() {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("rolz_deprecated offset exceeds decoded prefix"));
        }
        let match_end = self
            .output
            .len()
            .checked_add(match_len)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        if match_end > self.decoded_size {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("rolz_deprecated match length exceeds output size"));
        }
        Ok(())
    }

    /// Appends the literals after the last sequence, which must end the
    /// output at exactly the decoded size.
    fn finish(mut self) -> Result<Vec<u8>> {
        let remaining_literals = self.literals.remaining_len()?;
        let output_end = self
            .output
            .len()
            .checked_add(remaining_literals)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        if output_end != self.decoded_size {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("rolz_deprecated output size does not match prefix"));
        }
        self.literals.extend_remaining(&mut self.output)?;
        Ok(self.output)
    }
}

fn append_rolz_deprecated_literals(
    literals: &mut RolzDeprecatedLiteralCursor<'_>,
    output: &mut Vec<u8>,
    len: usize,
    decoded_size: usize,
) -> Result<()> {
    let output_end = output
        .len()
        .checked_add(len)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if output_end > decoded_size {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("rolz_deprecated literal length exceeds output size"));
    }
    literals.extend_next(len, output)
}

fn insert_rolz_deprecated_literals(
    table: &mut RolzDeprecatedTable,
    output: &[u8],
    start: usize,
    len: usize,
    params: RolzDeprecatedParams,
) -> Result<()> {
    let end = start
        .checked_add(len)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let first = start.max(params.context_depth);
    for pos in first..end {
        let context = rolz_deprecated_context(output, pos, params)?;
        table.put(context, rolz_deprecated_output_index(pos)?, 0)?;
    }
    Ok(())
}

fn insert_rolz_deprecated_lz_match(
    table: &mut RolzDeprecatedTable,
    output: &[u8],
    match_start: usize,
    match_len: usize,
    params: RolzDeprecatedParams,
) -> Result<()> {
    if match_start < params.context_depth {
        return Ok(());
    }
    let context = rolz_deprecated_context(output, match_start, params)?;
    table.put(
        context,
        rolz_deprecated_output_index(match_start)?,
        match_len,
    )?;
    let next_pos = match_start
        .checked_add(1)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    let context = rolz_deprecated_context(output, next_pos, params)?;
    table.put(
        context,
        rolz_deprecated_output_index(next_pos)?,
        match_len - 1,
    )
}

fn resolve_rolz_deprecated_rolz_match(
    table: &RolzDeprecatedTable,
    output: &[u8],
    match_start: usize,
    match_code: usize,
    encoded_match_len: usize,
    params: RolzDeprecatedParams,
) -> Result<(usize, usize)> {
    let context = rolz_deprecated_context(output, match_start, params)?;
    let (match_pos, match_len) = table.get(context, match_code, encoded_match_len, params)?;
    if match_pos >= match_start {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("rolz_deprecated match index is invalid")
        );
    }
    let match_offset = match_start
        .checked_sub(match_pos)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    Ok((match_offset, match_len))
}

fn resolve_rolz_deprecated_match(
    match_type: u8,
    match_code: usize,
    match_len: usize,
    params: RolzDeprecatedParams,
    reps: &[usize; 3],
) -> Result<(usize, usize)> {
    match match_type {
        ROLZ_DEPRECATED_MATCH_TYPE_LZ => {
            if match_code == 0 {
                return Err(Error::new(ErrorKind::Malformed)
                    .with_detail("rolz_deprecated lz offset is zero"));
            }
            let match_len = match_len
                .checked_add(params.lz_min_length)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
            Ok((match_code, match_len))
        }
        ROLZ_DEPRECATED_MATCH_TYPE_ROLZ => Err(Error::new(ErrorKind::Malformed)
            .with_detail("rolz_deprecated rolz match used non-rolz resolver")),
        ROLZ_DEPRECATED_MATCH_TYPE_REP0 | ROLZ_DEPRECATED_MATCH_TYPE_REP => {
            if match_code & 3 == 3 {
                return Err(Error::new(ErrorKind::Malformed)
                    .with_detail("rolz_deprecated rep code is invalid"));
            }
            let match_len = match_len
                .checked_add(params.rep_min_length)
                .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
            let match_offset = rolz_deprecated_rep_offset(match_code, reps)?;
            Ok((match_offset, match_len))
        }
        _ => {
            Err(Error::new(ErrorKind::Malformed)
                .with_detail("rolz_deprecated match type is invalid"))
        }
    }
}

fn rolz_deprecated_rep_offset(match_code: usize, reps: &[usize; 3]) -> Result<usize> {
    let rep = match_code & 3;
    let prev = reps
        .get(rep)
        .copied()
        .ok_or_else(|| Error::new(ErrorKind::Malformed))?;
    if match_code == 0 {
        return Ok(prev);
    }
    let delta = match_code >> 2;
    // The rep update assumes rep0 keeps its offset, so upstream (cfcdf49)
    // rejects a rep0 code with any delta other than the neutral one.
    if rep == 0 && delta != ROLZ_DEPRECATED_REP_SUB {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("rolz_deprecated rep0 code carries an offset delta"));
    }
    if delta >= ROLZ_DEPRECATED_REP_SUB {
        prev.checked_add(delta - ROLZ_DEPRECATED_REP_SUB)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))
    } else {
        prev.checked_sub(ROLZ_DEPRECATED_REP_SUB - delta)
            .ok_or_else(|| {
                Error::new(ErrorKind::Malformed)
                    .with_detail("rolz_deprecated rep offset is invalid")
            })
    }
}

fn rolz_deprecated_decode_match_length(
    min_length: usize,
    expected: usize,
    encoded: usize,
) -> Result<usize> {
    let encoded_plus_min = encoded
        .checked_add(min_length)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
    if encoded_plus_min
        >= expected
            .checked_add(1)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?
    {
        return Ok(encoded_plus_min);
    }
    if encoded >= 1 {
        return encoded_plus_min
            .checked_sub(1)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow));
    }
    expected
        .checked_add(encoded)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))
}

fn rolz_deprecated_output_index(position: usize) -> Result<usize> {
    position
        .checked_add(1)
        .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))
}

fn rolz_deprecated_context(
    output: &[u8],
    position: usize,
    params: RolzDeprecatedParams,
) -> Result<usize> {
    if params.context_depth != 2 || params.context_log > 32 {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("rolz_deprecated parameters are unsupported"));
    }
    let context_start = position.checked_sub(params.context_depth).ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail("rolz_deprecated context is unavailable")
    })?;
    let context = output.get(context_start..position).ok_or_else(|| {
        Error::new(ErrorKind::Malformed).with_detail("rolz_deprecated context is unavailable")
    })?;
    let value = u32::from(u16::from_le_bytes([context[0], context[1]]));
    let hash = value
        .wrapping_shl(16)
        .wrapping_mul(506_832_829)
        .wrapping_shr(
            32 - u32::try_from(params.context_log).map_err(|_| {
                Error::new(ErrorKind::LimitExceeded)
                    .with_detail("rolz_deprecated context log is too large")
            })?,
        );
    usize::try_from(hash).map_err(|_| Error::new(ErrorKind::IntegerOverflow))
}

fn update_rolz_deprecated_reps(
    reps: &mut [usize; 3],
    match_type: u8,
    match_code: usize,
    offset: usize,
) -> Result<()> {
    match match_type {
        ROLZ_DEPRECATED_MATCH_TYPE_LZ | ROLZ_DEPRECATED_MATCH_TYPE_ROLZ => {
            reps[2] = reps[1];
            reps[1] = reps[0];
            reps[0] = offset;
        }
        ROLZ_DEPRECATED_MATCH_TYPE_REP0 | ROLZ_DEPRECATED_MATCH_TYPE_REP => match match_code & 3 {
            0 => {}
            1 => {
                reps[1] = reps[0];
                reps[0] = offset;
            }
            2 => {
                reps[2] = reps[1];
                reps[1] = reps[0];
                reps[0] = offset;
            }
            _ => {
                return Err(Error::new(ErrorKind::Malformed)
                    .with_detail("rolz_deprecated rep code is invalid"));
            }
        },
        _ => {
            return Err(Error::new(ErrorKind::Malformed)
                .with_detail("rolz_deprecated match type is invalid"));
        }
    }
    Ok(())
}
