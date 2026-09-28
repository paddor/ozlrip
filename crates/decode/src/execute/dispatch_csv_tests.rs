//! The CSV fast paths of `dispatch_string` must decode exactly like the
//! generic loop, including when a shape almost matches and falls back.

use alloc::{vec, vec::Vec};

use ozlrip_core::Limits;

use super::dispatch::decode_dispatch_string_to_serial;
use super::streams::StreamInput;

/// Reproducible xorshift generator.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(bound).unwrap()).unwrap()
    }

    fn chance(&mut self, one_in: usize) -> bool {
        self.below(one_in) == 0
    }
}

#[derive(Default)]
struct Source {
    bytes: Vec<u8>,
    lengths: Vec<u32>,
}

impl Source {
    fn push(&mut self, string: &[u8]) {
        self.lengths.push(u32::try_from(string.len()).unwrap());
        self.bytes.extend_from_slice(string);
    }
}

#[derive(Clone, Copy)]
enum Shape {
    /// Four data sources and delimiters: the 5-source pattern.
    Plain,
    /// The 5-source pattern after a 7-field header source.
    Header,
    /// `data_sources` data sources, delimiters and a header source.
    Wide(usize),
}

struct Case {
    indices: Vec<u8>,
    sources: Vec<Source>,
}

impl Case {
    fn index(&mut self, source: usize) {
        let source = u16::try_from(source).unwrap();
        self.indices.extend_from_slice(&source.to_le_bytes());
    }
}

fn field(rng: &mut Rng, len: Option<usize>) -> Vec<u8> {
    let len = len.unwrap_or_else(|| rng.below(7));
    (0..len)
        .map(|_| b'a' + u8::try_from(rng.below(26)).unwrap())
        .collect()
}

fn delimiter(rng: &mut Rng, comma: Option<u8>) -> Vec<u8> {
    vec![comma.unwrap_or_else(|| b",;|\t\n"[rng.below(5)])]
}

fn csv_case(rng: &mut Rng, shape: Shape, rows: usize) -> Case {
    let fixed_prefix = rng.chance(2);
    let comma = rng.chance(2);
    let data_sources = match shape {
        Shape::Plain | Shape::Header => 4,
        Shape::Wide(data_sources) => data_sources,
    };
    let delimiter_source = data_sources;
    let header_source = data_sources + 1;
    let source_count = match shape {
        Shape::Plain => 5,
        Shape::Header | Shape::Wide(_) => data_sources + 2,
    };
    let mut case = Case {
        indices: Vec::new(),
        sources: (0..source_count).map(|_| Source::default()).collect(),
    };
    let fixed_len = |source: usize| match (fixed_prefix, source) {
        (true, 0) => Some(10),
        (true, 1) => Some(3),
        _ => None,
    };
    match shape {
        Shape::Plain => {
            for _ in 0..rows {
                for source in 0..4 {
                    let string = field(rng, fixed_len(source));
                    case.sources[source].push(&string);
                    case.index(source);
                    let comma = comma.then_some(if source == 3 { b'\n' } else { b',' });
                    case.sources[delimiter_source].push(&delimiter(rng, comma));
                    case.index(delimiter_source);
                }
            }
        }
        Shape::Header | Shape::Wide(_) => {
            let header_fields = match shape {
                Shape::Header => 7,
                _ => data_sources * 2 - 1,
            };
            for _ in 0..header_fields {
                let string = field(rng, None);
                case.sources[header_source].push(&string);
                case.index(header_source);
            }
            for _ in 0..rows {
                for source in 0..data_sources {
                    let comma = comma.then_some(if source == 0 { b'\n' } else { b',' });
                    case.sources[delimiter_source].push(&delimiter(rng, comma));
                    case.index(delimiter_source);
                    let string = field(rng, fixed_len(source));
                    case.sources[source].push(&string);
                    case.index(source);
                }
            }
            let comma = comma.then_some(b'\n');
            case.sources[delimiter_source].push(&delimiter(rng, comma));
            case.index(delimiter_source);
        }
    }
    case
}

/// Breaks the case in one of the ways the fast paths check for.
fn perturb(rng: &mut Rng, case: &mut Case) {
    let source_count = case.sources.len();
    match rng.below(5) {
        0 if !case.indices.is_empty() => {
            let at = rng.below(case.indices.len() / 2) * 2;
            let source = u16::try_from(rng.below(source_count)).unwrap();
            case.indices[at..at + 2].copy_from_slice(&source.to_le_bytes());
        }
        1 => {
            let source = &mut case.sources[rng.below(source_count)];
            if let Some(len) = source.lengths.pop() {
                let len = usize::try_from(len).unwrap();
                source.bytes.truncate(source.bytes.len() - len);
            }
        }
        2 => {
            let string = field(rng, None);
            case.sources[rng.below(source_count)].push(&string);
        }
        3 => {
            let source = &mut case.sources[source_count - 2];
            if let Some(len) = source.lengths.first_mut() {
                *len += 1;
                source.bytes.push(b',');
            }
        }
        _ => {
            let out_of_range = u16::try_from(source_count).unwrap();
            case.indices.extend_from_slice(&out_of_range.to_le_bytes());
        }
    }
}

fn decode(case: &Case, allow_fast: bool) -> Result<Vec<u8>, ozlrip_core::ErrorKind> {
    let mut inputs = vec![StreamInput {
        bytes: &case.indices,
        element_width: 2,
        string_lengths: None,
    }];
    inputs.extend(case.sources.iter().map(|source| StreamInput {
        bytes: &source.bytes,
        element_width: 1,
        string_lengths: Some(&source.lengths),
    }));
    let mut output = b"pre".to_vec();
    decode_dispatch_string_to_serial(
        &inputs,
        u32::try_from(case.sources.len()).unwrap(),
        &[],
        21,
        Limits::default(),
        &mut output,
        allow_fast,
    )
    .map(|()| output)
    .map_err(|err| err.kind())
}

#[test]
fn csv_fast_paths_match_the_generic_loop() {
    let cases = if cfg!(miri) { 60 } else { 3000 };
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut fast_successes = 0;
    for case_index in 0..cases {
        let shape = match case_index % 4 {
            0 => Shape::Plain,
            1 => Shape::Header,
            _ => Shape::Wide(3 + rng.below(4)),
        };
        let rows = rng.below(6);
        let mut case = csv_case(&mut rng, shape, rows);
        if rng.chance(3) {
            perturb(&mut rng, &mut case);
        }

        let fast = decode(&case, true);
        let generic = decode(&case, false);

        assert_eq!(fast, generic, "case {case_index}");
        fast_successes += usize::from(fast.is_ok());
    }
    assert!(fast_successes > cases / 2, "{fast_successes} of {cases}");
}
