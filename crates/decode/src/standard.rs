use ozlrip_core::{Error, ErrorKind, Result};

pub(crate) const LZ4_ID: u32 = 62;

pub(crate) fn validate_transform_id(id: u32, format_version: u32) -> Result<()> {
    let Some(min_version) = min_version(id) else {
        return Err(
            Error::new(ErrorKind::Unsupported).with_detail("unknown OpenZL standard transform ID")
        );
    };
    if format_version < min_version {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("standard transform ID is not available in this format version"));
    }
    Ok(())
}

const fn min_version(id: u32) -> Option<u32> {
    match id {
        1..=3 | 5..=10 | 15..=17 | 20..=32 => Some(3),
        33 => Some(4),
        34 => Some(6),
        35..=37 => Some(8),
        40..=43 => Some(9),
        11 | 12 | 38 | 44..=46 => Some(11),
        4 | 47 | 48 => Some(14),
        49..=52 => Some(15),
        53..=56 => Some(16),
        57 | 58 => Some(17),
        59 => Some(18),
        60 => Some(19),
        61 => Some(20),
        13 | 14 => Some(21),
        62 => Some(23),
        18 | 19 | 63..=65 => Some(24),
        66 => Some(26),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_reserved_transform_zero() {
        let err = validate_transform_id(0, 26).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Unsupported);
    }

    #[test]
    fn enforces_standard_transform_min_version() {
        let err = validate_transform_id(66, 25).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Unsupported);
        validate_transform_id(66, 26).unwrap();
    }
}
