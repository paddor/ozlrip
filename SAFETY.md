# Safety

The default build permits small encapsulated unsafe leaf modules after profiling.
The `paranoid` feature applies `#![forbid(unsafe_code)]` inside each crate and
uses safe fallbacks. It also enables `paranoid` in `zrip-core`, `zrip-decode`,
and `lz4rip-decode`, so the zstd, lz4, Huffman, and FSE code ozlrip calls is
forbidden from using unsafe code too.

The baseline implementation uses safe scalar kernels unless a hot path has a
documented unsafe leaf. Unsafe code must not call C, widen parser trust, or skip
format validation.

Current unsafe leaves live under `ozlrip-decode::execute::fast_*`. The main
executor validates graph shape, stream sizes, limits, and output capacity before
entering these leaves. The `paranoid` feature forbids unsafe code and selects
safe implementations in the same leaf modules.

Each leaf entry point either checks what its unsafe code relies on, in O(1)
per call (it reserves its own output, compares lengths, or falls back to the
safe path), or is an `unsafe fn` whose `# Safety` section lists the checks its
caller must have made. Every `unsafe` block has a `SAFETY:` comment naming the
checks it relies on; `clippy::undocumented_unsafe_blocks` enforces this.

Current unsafe leaves:

- `ozlrip-decode::execute::fast_bitpack`: unpacks bitpacked 1/2/4/8-byte
  elements into output it reserves itself and sets the length after all bytes
  are initialized.
- `ozlrip-decode::execute::fast_csv`: appends dispatch-string CSV patterns into
  spare capacity and publishes `Vec::len` only after the full pattern has been
  written. It checks the output capacity; its row writers are `unsafe fn`s, and
  `execute::dispatch` validates the source length tables, delimiter shape, and
  index pattern before each call.
- `ozlrip-decode::execute::fast_delta`: reconstructs 1/2/4/8-byte delta streams
  into output it reserves itself and sets the length after all bytes are
  initialized.
- `ozlrip-decode::execute::fast_dispatch`: copies dispatchN_byTag segments into
  output it reserves itself, checking each segment against the total, and sets
  the length after all bytes are initialized.
- `ozlrip-decode::execute::fast_field_lz`: writes Field-LZ literal and match
  streams into spare capacity. It checks the output length and capacity on
  entry, and every literal range and match offset, before publishing the
  output length.
- `ozlrip-decode::execute::fast_lengths`: decodes one-byte string length
  streams into `Vec<u32>` storage it reserves itself and sets the length after
  all entries are initialized.
- `ozlrip-decode::execute::fast_lz`: writes LZ literal and match streams into
  spare capacity. It validates stream counts, literal ranges, match offsets,
  and the final output length before writing. The generic LZ loop in
  `execute::lz_nodes` calls its match copy, an `unsafe fn`, after checking the
  output capacity once and each match range.
- `ozlrip-decode::execute::fast_partition`: decodes u32 partition outputs into
  spare capacity after checking that the output size matches the bucket count,
  and sets the length after all 4-byte values are initialized.
- `ozlrip-decode::execute::fast_split_struct`: appends split-by-struct streams
  into output it reserves itself. It checks equal element counts and nonzero
  field widths first and takes the safe path otherwise.
- `ozlrip-decode::execute::fast_tokenize`: copies fixed-width tokens from an
  alphabet into output it reserves itself. It checks that the alphabet holds
  every token, and each index before its token is copied.
- `ozlrip-decode::execute::fast_transpose`: writes 2/4/8-lane transpose outputs
  into output it reserves itself, after asserting equal lane lengths, and sets
  the length after all bytes are initialized.
- `ozlrip-decode::execute::fast_zigzag`: decodes 2/4/8-byte zigzag numeric
  streams into output it reserves itself and sets the length after all
  elements are initialized. The safe fallback handles all supported widths.

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

Upstream OpenZL has fixed decoder memory-safety bugs of the kinds these
defenses target, for example a Field-LZ over-copy
([facebook/openzl#544](https://github.com/facebook/openzl/pull/544)), LZ
length and offset overflows
([facebook/openzl#779](https://github.com/facebook/openzl/pull/779)), and a
stack buffer overflow in `decode4`
([facebook/openzl#632](https://github.com/facebook/openzl/pull/632)). No CVE
or GitHub security advisory for OpenZL was published as of 2026-07.
