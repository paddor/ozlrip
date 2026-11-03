#![no_main]

//! Decodes CSV-shaped `dispatch_string` frames, the shapes the fast CSV row
//! writers take, and compares the result with a model of the generic loop.

use libfuzzer_sys::fuzz_target;
use ozlrip_test_support::{Chunk, FrameBuilder, Node};

const SEPARATE_STRING_COMPONENTS: u32 = 12;
const CONVERT_NUM_TO_SERIAL_LE: u32 = 10;
const DISPATCH_STRING: u32 = 54;
const CONVERT_STRING_TO_SERIAL: u32 = 11;

/// Reads decisions from the fuzz input, then zeros.
struct Input<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Input<'_> {
    fn byte(&mut self) -> u8 {
        let byte = self.data.get(self.pos).copied().unwrap_or(0);
        self.pos += 1;
        byte
    }

    fn below(&mut self, bound: usize) -> usize {
        usize::from(self.byte()) % bound
    }
}

#[derive(Default)]
struct Source {
    strings: Vec<Vec<u8>>,
}

fn field(input: &mut Input<'_>, len: Option<usize>) -> Vec<u8> {
    let len = len.unwrap_or_else(|| input.below(8));
    (0..len).map(|_| input.byte()).collect()
}

fn delimiter(input: &mut Input<'_>, comma: Option<u8>) -> Vec<u8> {
    vec![comma.unwrap_or_else(|| input.byte())]
}

fuzz_target!(|data: &[u8]| {
    let mut input = Input { data, pos: 0 };
    let shape = input.below(4);
    let fixed_prefix = input.below(2) == 0;
    let comma = input.below(2) == 0;
    let rows = input.below(9);
    let data_sources = match shape {
        0 | 1 => 4,
        _ => 3 + input.below(5),
    };
    let delimiter_source = data_sources;
    let header_source = data_sources + 1;
    let source_count = if shape == 0 { 5 } else { data_sources + 2 };
    let mut sources = (0..source_count)
        .map(|_| Source::default())
        .collect::<Vec<_>>();
    let mut indices = Vec::<u16>::new();
    let fixed_len = |source: usize| match (fixed_prefix, source) {
        (true, 0) => Some(10),
        (true, 1) => Some(3),
        _ => None,
    };

    if shape == 0 {
        for _ in 0..rows {
            for source in 0..4 {
                sources[source]
                    .strings
                    .push(field(&mut input, fixed_len(source)));
                indices.push(source as u16);
                let comma = comma.then_some(if source == 3 { b'\n' } else { b',' });
                sources[delimiter_source]
                    .strings
                    .push(delimiter(&mut input, comma));
                indices.push(delimiter_source as u16);
            }
        }
    } else {
        let header_fields = if shape == 1 { 7 } else { data_sources * 2 - 1 };
        for _ in 0..header_fields {
            sources[header_source].strings.push(field(&mut input, None));
            indices.push(header_source as u16);
        }
        for _ in 0..rows {
            for source in 0..data_sources {
                let comma = comma.then_some(if source == 0 { b'\n' } else { b',' });
                sources[delimiter_source]
                    .strings
                    .push(delimiter(&mut input, comma));
                indices.push(delimiter_source as u16);
                sources[source]
                    .strings
                    .push(field(&mut input, fixed_len(source)));
                indices.push(source as u16);
            }
        }
        let comma = comma.then_some(b'\n');
        sources[delimiter_source]
            .strings
            .push(delimiter(&mut input, comma));
        indices.push(delimiter_source as u16);
    }

    // Now and then break the shape the way the fast paths check for.
    match input.below(8) {
        0 if !indices.is_empty() => {
            let at = input.below(indices.len());
            indices[at] = input.below(source_count + 1) as u16;
        }
        1 => {
            let source = input.below(source_count);
            sources[source].strings.pop();
        }
        2 => {
            let source = input.below(source_count);
            let string = field(&mut input, None);
            sources[source].strings.push(string);
        }
        3 => {
            if let Some(first) = sources[delimiter_source].strings.first_mut() {
                first.push(b',');
            }
        }
        _ => {}
    }

    let expected = generic_dispatch(&indices, &sources);
    let declared = expected.as_ref().map_or_else(
        |()| sources.iter().flat_map(|s| &s.strings).map(Vec::len).sum(),
        Vec::len,
    );
    let frame = csv_frame(&indices, &sources, declared);
    let mut limits = ozlrip::Limits::strict();
    limits.max_expansion_ratio = 1 << 20;
    let decoded = ozlrip::decode_with_options(&frame, ozlrip::Options::from(limits));
    match (&expected, &decoded) {
        (Ok(expected), Ok(decoded)) => assert_eq!(decoded, expected),
        (Err(()), Err(_)) => {}
        _ => panic!("model {expected:?} but ozlrip {decoded:?}"),
    }
});

/// What the generic `dispatch_string` loop produces: the next string of the
/// source each index names, with every string used exactly once.
fn generic_dispatch(indices: &[u16], sources: &[Source]) -> Result<Vec<u8>, ()> {
    let total_strings = sources
        .iter()
        .map(|source| source.strings.len())
        .sum::<usize>();
    if indices.len() != total_strings {
        return Err(());
    }
    let mut next = vec![0usize; sources.len()];
    let mut output = Vec::new();
    for &index in indices {
        let source = sources.get(usize::from(index)).ok_or(())?;
        let position = &mut next[usize::from(index)];
        let string = source.strings.get(*position).ok_or(())?;
        output.extend_from_slice(string);
        *position += 1;
    }
    Ok(output)
}

/// One chunk: a `separate_string_components` node per source, the indices
/// converted to 2-byte numbers, `dispatch_string`, and
/// `convert_string_to_serial` into the frame output.
fn csv_frame(indices: &[u16], sources: &[Source], declared: usize) -> Vec<u8> {
    let count = sources.len();
    // Stored slots: source `k`'s field sizes at `2k` and content at `2k + 1`,
    // the raw indices at `2 * count`. A node reads its input slots last to
    // first, so `dispatch_string` takes the converted indices from its last
    // slot, `3 * count + 1`, and source `k` from `3 * count - k`.
    let mut chunk = Chunk::new();
    for source in sources {
        let lengths = source
            .strings
            .iter()
            .map(|string| u8::try_from(string.len()).expect("fields are short"))
            .collect::<Vec<_>>();
        chunk = chunk
            .stored_stream(lengths)
            .stored_stream(source.strings.concat());
    }
    let raw_indices = indices
        .iter()
        .flat_map(|index| index.to_le_bytes())
        .collect::<Vec<_>>();
    chunk = chunk.stored_stream(raw_indices);
    for _ in 0..count {
        chunk = chunk.node(Node::new(SEPARATE_STRING_COMPONENTS));
    }
    chunk = chunk
        .node(Node::new(CONVERT_NUM_TO_SERIAL_LE).header([1]))
        .node(Node::new(DISPATCH_STRING).variable_inputs(u32::try_from(count).unwrap()))
        .node(Node::new(CONVERT_STRING_TO_SERIAL));
    let mut distances = (0..count)
        .map(|k| u32::try_from(3 * count - 3 * k - 2).unwrap())
        .collect::<Vec<_>>();
    distances.extend([u32::try_from(count).unwrap(), 0, 0]);
    FrameBuilder::new(21)
        .serial_output(declared)
        .chunk(chunk.distances(distances))
        .build()
}
