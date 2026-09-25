//! OpenZL frame and dictionary bundle builders for ozlrip tests.
//!
//! [`FrameBuilder`] writes format v21 and later (chunked frames). Frames in
//! older formats come from upstream OpenZL through `tools/openzl-shim`.
//! Not published.

/// OpenZL frame magic for format version 0; add the version.
pub const MAGIC_BASE: u32 = 0xd7b1_a5c0;
/// Standard transform ID of the zstd codec.
pub const ZSTD_TRANSFORM_ID: u32 = 22;

const BUNDLE_INFO_MAGIC: u32 = 0x4942_ccda;
const PACKED_DICT_MAGIC: u32 = 0x4944_ccda;

/// Frame magic for `version`.
pub fn magic(version: u32) -> [u8; 4] {
    (MAGIC_BASE + version).to_le_bytes()
}

/// Appends an LEB128 varint.
pub fn push_var_u64(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push(u8::try_from(value & 0x7f).expect("masked to 7 bits") | 0x80);
        value >>= 7;
    }
    out.push(u8::try_from(value).expect("below 0x80"));
}

/// Appends `values` packed LSB-first at `bits` bits each.
pub fn push_bitpacked_u32(out: &mut Vec<u8>, values: &[u32], bits: usize) {
    if values.is_empty() || bits == 0 {
        return;
    }
    let mut packed = vec![0; (values.len() * bits).div_ceil(8)];
    for (index, &value) in values.iter().enumerate() {
        let bit_offset = index * bits;
        let byte_offset = bit_offset / 8;
        let bit_shift = bit_offset % 8;
        let lane_bytes = (u64::from(value) << bit_shift).to_le_bytes();
        for byte_index in 0..(bit_shift + bits).div_ceil(8) {
            packed[byte_offset + byte_index] |= lane_bytes[byte_index];
        }
    }
    out.extend_from_slice(&packed);
}

/// Bits needed to encode values below `max_value`.
pub fn bits_needed(max_value: usize) -> usize {
    if max_value <= 1 {
        0
    } else {
        usize::BITS as usize - (max_value - 1).leading_zeros() as usize
    }
}

fn xxh3_low32(bytes: &[u8]) -> u32 {
    u32::try_from(xxhash_rust::xxh3::xxh3_64(bytes) & 0xffff_ffff).expect("masked to 32 bits")
}

/// Type of a frame output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputType {
    Serial = 0,
    Struct = 1,
    Numeric = 2,
    String = 3,
}

/// A standard transform node in a chunk graph.
#[derive(Clone, Debug)]
pub struct Node {
    transform_id: u32,
    header: Vec<u8>,
    variable_inputs: u32,
    outputs: usize,
}

impl Node {
    /// A node with no header, no variable inputs and one regenerated stream.
    pub fn new(transform_id: u32) -> Self {
        Self {
            transform_id,
            header: Vec::new(),
            variable_inputs: 0,
            outputs: 1,
        }
    }

    #[must_use]
    pub fn header(mut self, header: impl Into<Vec<u8>>) -> Self {
        self.header = header.into();
        self
    }

    #[must_use]
    pub fn variable_inputs(mut self, count: u32) -> Self {
        self.variable_inputs = count;
        self
    }

    /// Number of streams this node regenerates. Must be at least 1.
    #[must_use]
    pub fn outputs(mut self, count: usize) -> Self {
        assert!(count >= 1, "a node regenerates at least one stream");
        self.outputs = count;
        self
    }
}

/// One chunk: a node graph and its stored streams.
#[derive(Clone, Debug, Default)]
pub struct Chunk {
    nodes: Vec<Node>,
    stored: Vec<Vec<u8>>,
    distances: Option<Vec<u32>>,
    decoded: Option<Vec<u8>>,
}

impl Chunk {
    /// An empty chunk; add nodes and stored streams.
    pub fn new() -> Self {
        Self::default()
    }

    /// A chunk with no transforms and one stored stream, which is also its
    /// decoded content.
    pub fn stored(bytes: impl Into<Vec<u8>>) -> Self {
        let bytes = bytes.into();
        Self {
            decoded: Some(bytes.clone()),
            stored: vec![bytes],
            ..Self::default()
        }
    }

    #[must_use]
    pub fn node(mut self, node: Node) -> Self {
        self.nodes.push(node);
        self
    }

    /// Adds a stored stream. Streams are numbered in the order added.
    #[must_use]
    pub fn stored_stream(mut self, bytes: impl Into<Vec<u8>>) -> Self {
        self.stored.push(bytes.into());
        self
    }

    /// Overrides the regenerated-stream distances. By default node `i`'s
    /// output `k` gets distance `k`.
    #[must_use]
    pub fn distances(mut self, distances: Vec<u32>) -> Self {
        self.distances = Some(distances);
        self
    }

    /// Decoded content of this chunk, needed for the content checksum.
    #[must_use]
    pub fn decoded(mut self, bytes: impl Into<Vec<u8>>) -> Self {
        self.decoded = Some(bytes.into());
        self
    }

    fn encode(&self, version: u32, out: &mut Vec<u8>) {
        push_var_u64(out, (self.nodes.len() + 1) as u64);
        push_var_u64(out, self.stored.len() as u64);
        if !self.nodes.is_empty() {
            self.encode_nodes(version, out);
        }
        for stream in self.stored.iter().rev() {
            push_var_u64(out, stream.len() as u64);
        }
        for node in &self.nodes {
            out.extend_from_slice(&node.header);
        }
        for stream in self.stored.iter().rev() {
            out.extend_from_slice(stream);
        }
    }

    fn encode_nodes(&self, version: u32, out: &mut Vec<u8>) {
        let nodes = &self.nodes;
        push_bitpacked_u32(out, &vec![0; nodes.len()], 1);
        let ids = nodes
            .iter()
            .map(|node| node.transform_id)
            .collect::<Vec<_>>();
        push_bitpacked_u32(out, &ids, if version < 24 { 6 } else { 7 });
        let has_header = nodes
            .iter()
            .map(|node| u32::from(!node.header.is_empty()))
            .collect::<Vec<_>>();
        push_bitpacked_u32(out, &has_header, 1);
        for node in nodes.iter().filter(|node| !node.header.is_empty()) {
            push_var_u64(out, (node.header.len() - 1) as u64);
        }
        let has_variable = nodes
            .iter()
            .map(|node| u32::from(node.variable_inputs != 0))
            .collect::<Vec<_>>();
        push_bitpacked_u32(out, &has_variable, 1);
        for node in nodes.iter().filter(|node| node.variable_inputs != 0) {
            push_var_u64(out, u64::from(node.variable_inputs - 1));
        }
        let multi_output = nodes
            .iter()
            .map(|node| u32::from(node.outputs != 1))
            .collect::<Vec<_>>();
        push_bitpacked_u32(out, &multi_output, 1);
        for node in nodes.iter().filter(|node| node.outputs != 1) {
            push_var_u64(out, (node.outputs - 2) as u64);
        }
        let regenerated = nodes.iter().map(|node| node.outputs).sum::<usize>();
        let distances = self.distances.clone().unwrap_or_else(|| {
            nodes
                .iter()
                .flat_map(|node| (0..node.outputs).map(|k| u32::try_from(k).expect("small")))
                .collect()
        });
        assert_eq!(distances.len(), regenerated, "one distance per output");
        push_bitpacked_u32(
            out,
            &distances,
            bits_needed(regenerated + self.stored.len()),
        );
    }
}

#[derive(Clone, Debug)]
struct Output {
    ty: OutputType,
    size: u64,
    elements: Option<u64>,
}

/// Builds an OpenZL frame in format v21 or later.
///
/// ```
/// use ozlrip_test_support::{Chunk, FrameBuilder};
///
/// let frame = FrameBuilder::new(21)
///     .serial_output(3)
///     .chunk(Chunk::stored(*b"abc"))
///     .build();
/// assert_eq!(frame.last(), Some(&0));
/// ```
#[derive(Clone, Debug)]
pub struct FrameBuilder {
    version: u32,
    content_checksum: bool,
    compressed_checksum: bool,
    comment: Option<Vec<u8>>,
    bundle_id: Option<Vec<u8>>,
    outputs: Vec<Output>,
    chunks: Vec<Chunk>,
}

impl FrameBuilder {
    pub fn new(version: u32) -> Self {
        assert!(version >= 21, "FrameBuilder writes format v21 and later");
        Self {
            version,
            content_checksum: false,
            compressed_checksum: false,
            comment: None,
            bundle_id: None,
            outputs: Vec::new(),
            chunks: Vec::new(),
        }
    }

    /// Adds per-chunk checksums of the decoded content. Every chunk then
    /// needs its decoded bytes (see [`Chunk::decoded`]).
    #[must_use]
    pub fn content_checksum(mut self, enabled: bool) -> Self {
        self.content_checksum = enabled;
        self
    }

    /// Adds the header checksum and per-chunk checksums of the encoded bytes.
    #[must_use]
    pub fn compressed_checksum(mut self, enabled: bool) -> Self {
        self.compressed_checksum = enabled;
        self
    }

    /// Adds a header comment (format v22 and later).
    #[must_use]
    pub fn comment(mut self, comment: impl Into<Vec<u8>>) -> Self {
        assert!(self.version >= 22, "comments need format v22");
        self.comment = Some(comment.into());
        self
    }

    /// Adds a dictionary bundle ID (format v25 and later). Chunks with nodes
    /// are not supported together with a bundle ID yet.
    #[must_use]
    pub fn bundle_id(mut self, id: impl Into<Vec<u8>>) -> Self {
        assert!(self.version >= 25, "bundle IDs need format v25");
        self.bundle_id = Some(id.into());
        self
    }

    /// Adds a serial output of `size` bytes.
    #[must_use]
    pub fn serial_output(self, size: usize) -> Self {
        self.output(OutputType::Serial, size)
    }

    /// Adds a serial, struct or numeric output of `size` bytes.
    #[must_use]
    pub fn output(mut self, ty: OutputType, size: usize) -> Self {
        assert_ne!(ty, OutputType::String, "use string_output");
        self.outputs.push(Output {
            ty,
            size: size as u64,
            elements: None,
        });
        self
    }

    /// Adds a string output of `size` content bytes and `elements` strings.
    #[must_use]
    pub fn string_output(mut self, size: usize, elements: usize) -> Self {
        self.outputs.push(Output {
            ty: OutputType::String,
            size: size as u64,
            elements: Some(elements as u64),
        });
        self
    }

    #[must_use]
    pub fn chunk(mut self, chunk: Chunk) -> Self {
        self.chunks.push(chunk);
        self
    }

    pub fn build(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&magic(self.version));
        let flags = u8::from(self.content_checksum)
            | u8::from(self.compressed_checksum) << 1
            | u8::from(self.comment.is_some()) << 2
            | u8::from(self.bundle_id.is_some()) << 3;
        out.push(flags);
        if let Some(id) = &self.bundle_id {
            assert!(
                self.chunks.iter().all(|chunk| chunk.nodes.is_empty()),
                "bundle IDs with transform chunks need dictionary indexes, which are not supported"
            );
            out.push(u8::try_from(id.len()).expect("bundle ID length fits u8"));
            out.extend_from_slice(id);
        }
        self.encode_outputs(&mut out);
        if let Some(comment) = &self.comment {
            push_var_u64(&mut out, comment.len() as u64);
            out.extend_from_slice(comment);
        }
        if self.compressed_checksum {
            out.push(u8::try_from(xxhash_rust::xxh3::xxh3_64(&out) & 0xff).expect("masked"));
        }
        for chunk in &self.chunks {
            let start = out.len();
            chunk.encode(self.version, &mut out);
            if self.content_checksum {
                let decoded = chunk
                    .decoded
                    .as_deref()
                    .expect("content checksum needs Chunk::decoded");
                out.extend_from_slice(&xxh3_low32(decoded).to_le_bytes());
            }
            if self.compressed_checksum {
                let checksum = xxh3_low32(&out[start..]);
                out.extend_from_slice(&checksum.to_le_bytes());
            }
        }
        out.push(0);
        out
    }

    fn encode_outputs(&self, out: &mut Vec<u8>) {
        let count = self.outputs.len();
        assert!(
            (1..=14).contains(&count),
            "FrameBuilder supports 1 to 14 outputs"
        );
        let types = self
            .outputs
            .iter()
            .map(|output| output.ty as u8)
            .collect::<Vec<_>>();
        let mut token = u8::try_from(count).expect("at most 14");
        for (index, ty) in types.iter().take(2).enumerate() {
            token |= ty << (4 + 2 * index);
        }
        out.push(token);
        for group in types[types.len().min(2)..].chunks(4) {
            let mut byte = 0;
            for (index, ty) in group.iter().enumerate() {
                byte |= ty << (2 * index);
            }
            out.push(byte);
        }
        for output in &self.outputs {
            push_var_u64(out, output.size + 1);
        }
        for output in &self.outputs {
            if let Some(elements) = output.elements {
                push_var_u64(out, elements);
            }
        }
    }
}

/// A fat dictionary bundle holding one zstd dictionary.
pub fn zstd_fat_bundle(bundle_id: [u8; 32], dict_id: [u8; 32], raw_dict: &[u8]) -> Vec<u8> {
    let mut content = Vec::new();
    content.extend_from_slice(&1u32.to_le_bytes());
    content.extend_from_slice(&1i32.to_le_bytes());
    content.extend_from_slice(raw_dict);

    let mut bundle = Vec::new();
    bundle.extend_from_slice(&BUNDLE_INFO_MAGIC.to_le_bytes());
    bundle.extend_from_slice(&bundle_id);
    bundle.push(1);
    bundle.extend_from_slice(&1u32.to_le_bytes());
    bundle.extend_from_slice(&dict_id);
    bundle.extend_from_slice(&PACKED_DICT_MAGIC.to_le_bytes());
    bundle.extend_from_slice(&dict_id);
    bundle.extend_from_slice(&ZSTD_TRANSFORM_ID.to_le_bytes());
    bundle.push(0);
    bundle.extend_from_slice(
        &u32::try_from(content.len())
            .expect("content fits u32")
            .to_le_bytes(),
    );
    bundle.extend_from_slice(&content);
    bundle
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_frame_matches_hand_encoded_bytes() {
        let frame = FrameBuilder::new(21)
            .serial_output(3)
            .chunk(Chunk::stored(*b"abc"))
            .build();
        let mut expected = magic(21).to_vec();
        expected.extend_from_slice(&[0, 1, 4, 1, 1, 3, b'a', b'b', b'c', 0]);
        assert_eq!(frame, expected);
    }

    #[test]
    fn single_node_chunk_matches_hand_encoded_bytes() {
        let frame = FrameBuilder::new(23)
            .serial_output(3)
            .chunk(
                Chunk::new()
                    .node(Node::new(62).header([3]))
                    .stored_stream(*b"xy"),
            )
            .build();
        let mut expected = magic(23).to_vec();
        expected.extend_from_slice(&[0, 1, 4, 2, 1, 0, 62, 1, 0, 0, 0, 0, 2, 3, b'x', b'y', 0]);
        assert_eq!(frame, expected);
    }

    #[test]
    fn packs_output_types() {
        let frame = FrameBuilder::new(21)
            .output(OutputType::Numeric, 4)
            .string_output(3, 2)
            .output(OutputType::Struct, 6)
            .build();
        assert_eq!(&frame[4..], &[0, 3 | 2 << 4 | 3 << 6, 1, 5, 4, 7, 2, 0]);
    }
}
