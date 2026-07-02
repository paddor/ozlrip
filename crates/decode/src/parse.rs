use ozlrip_core::{Error, ErrorKind, FrameInfo, Limits, Result};

const OPENZL_MAGIC: [u8; 4] = [0x28, 0x5a, 0x4c, 0x29];

pub(crate) fn inspect_frame(input: &[u8], limits: Limits) -> Result<FrameInfo> {
    check_limit(
        input.len(),
        limits.max_frame_bytes,
        ErrorKind::LimitExceeded,
    )?;

    let mut reader = Reader::new(input);
    let magic = reader.read_array::<4>()?;
    if magic != OPENZL_MAGIC {
        return Err(
            Error::at(ErrorKind::Unsupported, 0).with_detail("unrecognized OpenZL frame magic")
        );
    }

    let format_version = reader.read_var_u32()?;
    validate_format_version(format_version, reader.offset())?;

    Err(Error::at(ErrorKind::Unsupported, reader.offset())
        .with_detail("OpenZL frame header parsing is not implemented yet"))
}

fn validate_format_version(version: u32, offset: usize) -> Result<()> {
    const MIN_RELEASE_VERSION: u32 = 1;
    #[cfg(feature = "dev-format")]
    const MAX_DEV_VERSION: u32 = 255;
    #[cfg(not(feature = "dev-format"))]
    const MAX_DEV_VERSION: u32 = 25;

    if !(MIN_RELEASE_VERSION..=MAX_DEV_VERSION).contains(&version) {
        return Err(Error::at(ErrorKind::Unsupported, offset)
            .with_detail("unsupported OpenZL format version"));
    }
    Ok(())
}

fn check_limit(value: usize, limit: usize, kind: ErrorKind) -> Result<()> {
    if value > limit {
        return Err(Error::new(kind).with_detail("configured limit exceeded"));
    }
    Ok(())
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    const fn offset(&self) -> usize {
        self.offset
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or_else(|| Error::at(ErrorKind::IntegerOverflow, self.offset))?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| Error::at(ErrorKind::Truncated, self.offset))?;
        let mut out = [0; N];
        out.copy_from_slice(slice);
        self.offset = end;
        Ok(out)
    }

    fn read_byte(&mut self) -> Result<u8> {
        let byte = *self
            .bytes
            .get(self.offset)
            .ok_or_else(|| Error::at(ErrorKind::Truncated, self.offset))?;
        self.offset = self
            .offset
            .checked_add(1)
            .ok_or_else(|| Error::at(ErrorKind::IntegerOverflow, self.offset))?;
        Ok(byte)
    }

    fn read_var_u32(&mut self) -> Result<u32> {
        let start = self.offset;
        let mut value = 0u32;
        let mut shift = 0u32;
        for _ in 0..5 {
            let byte = self.read_byte()?;
            let payload = u32::from(byte & 0x7f);
            value = value
                .checked_add(
                    payload
                        .checked_shl(shift)
                        .ok_or_else(|| Error::at(ErrorKind::IntegerOverflow, start))?,
                )
                .ok_or_else(|| Error::at(ErrorKind::IntegerOverflow, start))?;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
            shift = shift
                .checked_add(7)
                .ok_or_else(|| Error::at(ErrorKind::IntegerOverflow, start))?;
        }
        Err(Error::at(ErrorKind::Malformed, start).with_detail("u32 varint is too long"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_truncated_magic() {
        let err = inspect_frame(&[0x28, 0x5a], Limits::default()).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Truncated);
        assert_eq!(err.offset(), Some(0));
    }

    #[test]
    fn rejects_unknown_magic() {
        let err = inspect_frame(b"not-openzl", Limits::default()).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Unsupported);
        assert_eq!(err.offset(), Some(0));
    }

    #[test]
    fn rejects_overlong_varint() {
        let input = [0x28, 0x5a, 0x4c, 0x29, 0x80, 0x80, 0x80, 0x80, 0x80];
        let err = inspect_frame(&input, Limits::default()).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Malformed);
        assert_eq!(err.offset(), Some(4));
    }

    #[test]
    fn enforces_frame_limit_before_parsing() {
        let limits = Limits {
            max_frame_bytes: 1,
            ..Limits::default()
        };
        let err = inspect_frame(&[0; 2], limits).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::LimitExceeded);
    }
}
