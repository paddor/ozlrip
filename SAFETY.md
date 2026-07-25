# Safety

The default build permits small encapsulated unsafe leaf modules after profiling.
The `paranoid` feature applies `#![forbid(unsafe_code)]` inside each crate and
uses safe fallbacks.

The baseline implementation uses safe scalar kernels unless a hot path has a
documented unsafe leaf. Unsafe code must not call C, widen parser trust, or skip
format validation.

Current unsafe leaves live under `ozlrip-decode::execute::fast_*`. The main
executor validates graph shape, stream sizes, limits, and output capacity before
entering these leaves. The `paranoid` feature forbids unsafe code and selects
safe implementations in the same leaf modules.

Current unsafe leaves:

- `ozlrip-decode::execute::fast_bitpack`: unpacks validated bitpacked
  1/2/4/8-byte elements into pre-reserved `Vec<u8>` storage and sets the length
  after all bytes are initialized. The caller validates bit width, element
  width, output size, allocation limits, and capacity before entry.
- `ozlrip-decode::execute::fast_bitreader`: performs bounded unaligned
  little-endian window loads after checking that enough bytes remain. The safe
  fallback builds the same window byte by byte.
- `ozlrip-decode::execute::fast_csv`: appends validated dispatch-string CSV
  patterns into pre-reserved output storage and publishes `Vec::len` only after
  the full pattern has been written. The caller validates source counts, source
  length tables, delimiter shape, index pattern, output size, allocation limits,
  and capacity before entry.
- `ozlrip-decode::execute::fast_delta`: reconstructs validated 1/2/4/8-byte
  delta streams into pre-reserved `Vec<u8>` storage and sets the length after
  all bytes are initialized. The caller validates element width, header size,
  output size, allocation limits, and capacity before entry.
- `ozlrip-decode::execute::fast_dispatch`: copies validated dispatchN_byTag
  segments into pre-reserved `Vec<u8>` storage and sets the length after all
  bytes are initialized. The caller validates tag widths, segment-size widths,
  source totals, output size, allocation limits, and capacity before entry.
- `ozlrip-decode::execute::fast_field_lz`: writes validated Field-LZ literal
  and match streams into pre-reserved output storage. The leaf validates numeric
  stream element boundaries, literal ranges, match offsets, and final output
  length before publishing the output length.
- `ozlrip-decode::execute::fast_lengths`: decodes validated one-byte string
  length streams into pre-reserved `Vec<u32>` storage and sets the length after
  all entries are initialized. The caller validates output element count and
  capacity before entry.
- `ozlrip-decode::execute::fast_lz`: writes validated LZ literal and match
  streams into pre-reserved output storage. The leaf validates stream counts,
  literal ranges, match offsets, and final output length before publishing the
  output length.
- `ozlrip-decode::execute::fast_partition`: decodes validated u32 partition
  outputs into pre-reserved `Vec<u8>` storage and sets the length after all
  4-byte values are initialized. The safe paranoid implementation writes through
  normal slices.
- `ozlrip-decode::execute::fast_split_struct`: appends validated
  split-by-struct streams into pre-reserved `Vec<u8>` storage and sets the
  length after all bytes are initialized. The caller validates equal element
  counts, nonzero field widths, output size, allocation limits, and capacity
  before entry.
- `ozlrip-decode::execute::fast_tokenize`: copies validated fixed-width tokens
  from an alphabet into pre-reserved output storage and sets the length after
  all token bytes are initialized. Index bounds are checked before each token
  copy.
- `ozlrip-decode::execute::fast_transpose`: writes validated 2/4/8-lane
  transpose outputs into pre-reserved `Vec<u8>` storage and sets the length
  after all bytes are initialized. The caller validates equal lane lengths,
  output size, allocation limits, and capacity before entry.
- `ozlrip-decode::execute::fast_zigzag`: decodes validated 2/4/8-byte zigzag
  numeric streams into pre-reserved `Vec<u8>` storage and sets the length after
  all elements are initialized. The safe fallback handles all supported widths.

PivCo-Huffman uses `fearless_simd` for a std-gated constant-leaf merge path
under `not(feature = "paranoid")`. The module itself remains safe Rust; SIMD
dispatch is selected through the safe abstraction and falls back to scalar code.

Primary defenses:

- Bounded frame, chunk, stream, node, buffer, and graph-depth limits
- Checked arithmetic for every size and offset
- Parse into bounded intermediate types before allocation
- Validate the full graph before node execution
- Borrow stored streams from the input frame
- Allocate regenerated streams only after limit checks
- Return typed `Unsupported` errors for unknown codecs, custom transforms,
  custom dictionary materializers, and non-zstd dictionary materializers

Regression tests should cover OpenZL memory-safety history recorded in
`info/openzl/VULNS.md`.
