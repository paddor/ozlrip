use ozlrip_core::{Error, ErrorKind, Result};

/// Reads an OpenZL varint (unsigned LEB128, at most ten bytes) from `bytes`
/// at `*offset` and moves `offset` past it. `offset` is unchanged on error.
pub(crate) fn read_var_u64(bytes: &[u8], offset: &mut usize) -> Result<u64> {
    let start = *offset;
    let mut value = 0u64;
    for index in 0..10 {
        let position = start
            .checked_add(index)
            .ok_or_else(|| Error::at(ErrorKind::IntegerOverflow, start))?;
        let byte = *bytes
            .get(position)
            .ok_or_else(|| Error::at(ErrorKind::Truncated, position))?;
        let payload = u64::from(byte & 0x7f);
        if index == 9 && payload > 1 {
            return Err(Error::at(ErrorKind::IntegerOverflow, start)
                .with_detail("u64 varint payload overflows"));
        }
        value |= payload << (7 * index);
        if byte & 0x80 == 0 {
            // `position` indexes `bytes`, so this cannot overflow.
            *offset = position + 1;
            return Ok(value);
        }
    }
    Err(Error::at(ErrorKind::Malformed, start).with_detail("u64 varint is too long"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(bytes: &[u8]) -> Result<(u64, usize)> {
        let mut offset = 0;
        read_var_u64(bytes, &mut offset).map(|value| (value, offset))
    }

    #[test]
    fn reads_values_and_advances() {
        assert_eq!(read(&[0]).unwrap(), (0, 1));
        assert_eq!(read(&[0x7f, 9]).unwrap(), (127, 1));
        assert_eq!(read(&[0x80, 1]).unwrap(), (128, 2));
        let max = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1];
        assert_eq!(read(&max).unwrap(), (u64::MAX, 10));
    }

    #[test]
    fn rejects_bad_varints_without_moving() {
        let mut offset = 1;
        let err = read_var_u64(&[9, 0x80, 0x80], &mut offset).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Truncated);
        assert_eq!(offset, 1);

        let overflow = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 2];
        assert_eq!(
            read(&overflow).unwrap_err().kind(),
            ErrorKind::IntegerOverflow
        );
        let too_long = [
            0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0,
        ];
        assert_eq!(read(&too_long).unwrap_err().kind(), ErrorKind::Malformed);
    }
}
