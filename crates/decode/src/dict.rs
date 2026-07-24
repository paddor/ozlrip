use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Result};

use crate::standard;

const BUNDLE_INFO_MAGIC: u32 = 0x4942_ccda;
const PACKED_DICT_MAGIC: u32 = 0x4944_ccda;
const UNIQUE_ID_BYTES: usize = 32;
const FAT_BUNDLE_FLAG: u8 = 1;
const MAX_DICTS_PER_BUNDLE: u32 = 0xffff;
const ZSTD_DICT_ENVELOPE_VERSION: u32 = 1;

#[derive(Default)]
pub(crate) struct DictionaryStore {
    bundles: Vec<DictionaryBundle>,
}

impl DictionaryStore {
    pub(crate) const fn new() -> Self {
        Self {
            bundles: Vec::new(),
        }
    }

    pub(crate) fn clear(&mut self) {
        self.bundles.clear();
    }

    pub(crate) fn load_fat_bundle(&mut self, bytes: &[u8]) -> Result<()> {
        let bundle = parse_fat_bundle(bytes)?;
        if let Some(existing) = self
            .bundles
            .iter_mut()
            .find(|existing| existing.id == bundle.id)
        {
            *existing = bundle;
        } else {
            self.bundles.try_reserve_exact(1).map_err(|_| {
                Error::new(ErrorKind::LimitExceeded)
                    .with_detail("dictionary bundle allocation failed")
            })?;
            self.bundles.push(bundle);
        }
        Ok(())
    }

    #[cfg(feature = "zstd")]
    pub(crate) fn zstd_dict(&self, bundle_id: &[u8], dict_index: u32) -> Result<&zrip::Dictionary> {
        let bundle_id: [u8; UNIQUE_ID_BYTES] = bundle_id.try_into().map_err(|_| {
            Error::new(ErrorKind::Malformed).with_detail("dictionary bundle ID must be 32 bytes")
        })?;
        let bundle = self
            .bundles
            .iter()
            .find(|bundle| bundle.id == bundle_id)
            .ok_or_else(|| {
                Error::new(ErrorKind::Unsupported).with_detail("dictionary bundle is not loaded")
            })?;
        let index = usize::try_from(dict_index).map_err(|_| {
            Error::new(ErrorKind::LimitExceeded).with_detail("dictionary index is too large")
        })?;
        let loaded = bundle.dicts.get(index).ok_or_else(|| {
            Error::new(ErrorKind::Unsupported)
                .with_detail("dictionary index is not in loaded bundle")
        })?;
        match &loaded.kind {
            LoadedDictKind::Zstd(dict) => Ok(dict),
        }
    }
}

struct DictionaryBundle {
    id: [u8; UNIQUE_ID_BYTES],
    #[cfg_attr(not(feature = "zstd"), allow(dead_code))]
    dicts: Vec<LoadedDict>,
}

#[cfg_attr(not(feature = "zstd"), allow(dead_code))]
struct LoadedDict {
    kind: LoadedDictKind,
}

enum LoadedDictKind {
    #[cfg(feature = "zstd")]
    Zstd(zrip::Dictionary),
}

fn parse_fat_bundle(bytes: &[u8]) -> Result<DictionaryBundle> {
    let mut reader = BundleReader::new(bytes);
    if reader.read_u32_le()? != BUNDLE_INFO_MAGIC {
        return Err(Error::new(ErrorKind::Malformed).with_detail("invalid dictionary bundle magic"));
    }
    let bundle_id = reader.read_id()?;
    let fat_flag = reader.read_byte()?;
    if fat_flag != FAT_BUNDLE_FLAG {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("thin dictionary bundles are unsupported"));
    }
    let dict_count = reader.read_u32_le()?;
    if dict_count > MAX_DICTS_PER_BUNDLE {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("dictionary bundle has too many dictionaries"));
    }
    let dict_count = usize::try_from(dict_count).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("dictionary count is too large")
    })?;
    let mut dict_ids = Vec::new();
    dict_ids.try_reserve_exact(dict_count).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("dictionary ID allocation failed")
    })?;
    for _ in 0..dict_count {
        dict_ids.push(reader.read_id()?);
    }

    let mut dicts = Vec::new();
    dicts.try_reserve_exact(dict_count).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("dictionary allocation failed")
    })?;
    for expected_id in dict_ids {
        dicts.push(parse_packed_dict(&mut reader, expected_id)?);
    }
    if !reader.is_empty() {
        return Err(
            Error::new(ErrorKind::Malformed).with_detail("trailing bytes after dictionary bundle")
        );
    }

    Ok(DictionaryBundle {
        id: bundle_id,
        dicts,
    })
}

fn parse_packed_dict(
    reader: &mut BundleReader<'_>,
    expected_id: [u8; UNIQUE_ID_BYTES],
) -> Result<LoadedDict> {
    if reader.read_u32_le()? != PACKED_DICT_MAGIC {
        return Err(Error::new(ErrorKind::Malformed).with_detail("invalid dictionary magic"));
    }
    let dict_id = reader.read_id()?;
    if dict_id != expected_id {
        return Err(Error::new(ErrorKind::Malformed).with_detail("dictionary ID mismatch"));
    }
    let codec_id = reader.read_u32_le()?;
    let is_custom_codec = reader.read_byte()? != 0;
    let content_size = usize::try_from(reader.read_u32_le()?).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded).with_detail("dictionary content size is too large")
    })?;
    let content = reader.read_slice(content_size)?;

    if is_custom_codec {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("custom dictionary materializers are unsupported"));
    }
    if codec_id != standard::ZSTD_ID {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("only zstd dictionary materialization is implemented"));
    }

    parse_zstd_dict(content).map(|kind| LoadedDict { kind })
}

fn parse_zstd_dict(content: &[u8]) -> Result<LoadedDictKind> {
    let mut reader = BundleReader::new(content);
    let version = reader.read_u32_le()?;
    if version != ZSTD_DICT_ENVELOPE_VERSION {
        return Err(Error::new(ErrorKind::Malformed)
            .with_detail("unsupported zstd dictionary envelope version"));
    }
    let _compression_level = reader.read_i32_le()?;
    let raw_dict = reader.remaining();

    #[cfg(feature = "zstd")]
    {
        let dict = zrip::Dictionary::from_bytes(raw_dict)
            .map_err(|_| Error::new(ErrorKind::Malformed).with_detail("invalid zstd dictionary"))?;
        Ok(LoadedDictKind::Zstd(dict))
    }

    #[cfg(not(feature = "zstd"))]
    {
        let _ = raw_dict;
        Err(Error::new(ErrorKind::Unsupported)
            .with_detail("zstd dictionary materialization requires zstd support"))
    }
}

struct BundleReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> BundleReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_byte(&mut self) -> Result<u8> {
        let byte = *self.bytes.get(self.offset).ok_or_else(|| {
            Error::at(ErrorKind::Truncated, self.offset)
                .with_detail("dictionary bundle is truncated")
        })?;
        self.offset += 1;
        Ok(byte)
    }

    fn read_u32_le(&mut self) -> Result<u32> {
        let bytes = self.read_array::<4>()?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn read_i32_le(&mut self) -> Result<i32> {
        let bytes = self.read_array::<4>()?;
        Ok(i32::from_le_bytes(bytes))
    }

    fn read_id(&mut self) -> Result<[u8; UNIQUE_ID_BYTES]> {
        self.read_array()
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let bytes = self.read_slice(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    fn read_slice(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| Error::new(ErrorKind::IntegerOverflow))?;
        let bytes = self.bytes.get(self.offset..end).ok_or_else(|| {
            Error::at(ErrorKind::Truncated, self.offset)
                .with_detail("dictionary bundle is truncated")
        })?;
        self.offset = end;
        Ok(bytes)
    }

    fn remaining(&self) -> &'a [u8] {
        &self.bytes[self.offset..]
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUNDLE_ID: [u8; UNIQUE_ID_BYTES] = [7; UNIQUE_ID_BYTES];
    const DICT_ID: [u8; UNIQUE_ID_BYTES] = [9; UNIQUE_ID_BYTES];

    fn bundle_with_dict(codec_id: u32, custom: bool, content: &[u8]) -> Vec<u8> {
        let mut bundle = Vec::new();
        bundle.extend_from_slice(&BUNDLE_INFO_MAGIC.to_le_bytes());
        bundle.extend_from_slice(&BUNDLE_ID);
        bundle.push(FAT_BUNDLE_FLAG);
        bundle.extend_from_slice(&1u32.to_le_bytes());
        bundle.extend_from_slice(&DICT_ID);
        bundle.extend_from_slice(&PACKED_DICT_MAGIC.to_le_bytes());
        bundle.extend_from_slice(&DICT_ID);
        bundle.extend_from_slice(&codec_id.to_le_bytes());
        bundle.push(u8::from(custom));
        bundle.extend_from_slice(&u32::try_from(content.len()).unwrap().to_le_bytes());
        bundle.extend_from_slice(content);
        bundle
    }

    fn zstd_envelope(version: u32, raw_dict: &[u8]) -> Vec<u8> {
        let mut content = Vec::new();
        content.extend_from_slice(&version.to_le_bytes());
        content.extend_from_slice(&1i32.to_le_bytes());
        content.extend_from_slice(raw_dict);
        content
    }

    #[test]
    fn rejects_empty_bundle() {
        let err = parse_fat_bundle(&[]).err().unwrap();

        assert_eq!(err.kind(), ErrorKind::Truncated);
    }

    #[test]
    fn rejects_bad_bundle_magic() {
        let mut bundle = Vec::new();
        bundle.extend_from_slice(&0u32.to_le_bytes());

        let err = parse_fat_bundle(&bundle).err().unwrap();

        assert_eq!(err.kind(), ErrorKind::Malformed);
    }

    #[test]
    fn rejects_non_fat_bundle() {
        let mut bundle = Vec::new();
        bundle.extend_from_slice(&BUNDLE_INFO_MAGIC.to_le_bytes());
        bundle.extend_from_slice(&BUNDLE_ID);
        bundle.push(0);
        bundle.extend_from_slice(&0u32.to_le_bytes());

        let err = parse_fat_bundle(&bundle).err().unwrap();

        assert_eq!(err.kind(), ErrorKind::Unsupported);
    }

    #[test]
    fn rejects_dictionary_id_mismatch() {
        let mut bundle = bundle_with_dict(standard::ZSTD_ID, false, &zstd_envelope(1, b"dict"));
        let packed_id = 4 + UNIQUE_ID_BYTES + 1 + 4 + UNIQUE_ID_BYTES + 4;
        bundle[packed_id] ^= 1;

        let err = parse_fat_bundle(&bundle).err().unwrap();

        assert_eq!(err.kind(), ErrorKind::Malformed);
    }

    #[test]
    fn rejects_custom_dictionary_materializer() {
        let content = zstd_envelope(1, b"dict");
        let bundle = bundle_with_dict(standard::ZSTD_ID, true, &content);

        let err = parse_fat_bundle(&bundle).err().unwrap();

        assert_eq!(err.kind(), ErrorKind::Unsupported);
    }

    #[test]
    fn rejects_non_zstd_materializer() {
        let bundle = bundle_with_dict(standard::LZ4_ID, false, b"dict");

        let err = parse_fat_bundle(&bundle).err().unwrap();

        assert_eq!(err.kind(), ErrorKind::Unsupported);
    }

    #[test]
    fn rejects_bad_zstd_envelope_version() {
        let bundle = bundle_with_dict(standard::ZSTD_ID, false, &zstd_envelope(2, b"dict"));

        let err = parse_fat_bundle(&bundle).err().unwrap();

        assert_eq!(err.kind(), ErrorKind::Malformed);
    }

    #[cfg(not(feature = "zstd"))]
    #[test]
    fn rejects_zstd_materializer_when_zstd_feature_is_disabled() {
        let bundle = bundle_with_dict(standard::ZSTD_ID, false, &zstd_envelope(1, b"dict"));

        let err = parse_fat_bundle(&bundle).err().unwrap();

        assert_eq!(err.kind(), ErrorKind::Unsupported);
    }
}
