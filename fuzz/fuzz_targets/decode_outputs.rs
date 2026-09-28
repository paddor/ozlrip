#![no_main]

//! `decode_outputs` agrees with `decode` on single serial frames, decoding
//! into reused buffers matches a fresh decode, and every output is
//! well-formed.

use libfuzzer_sys::fuzz_target;
use ozlrip::{Limits, Options, Output};

fuzz_target!(|data: &[u8]| {
    let mut limits = Limits::strict();
    limits.max_decoded_bytes = 1 << 20;
    limits.max_buffer_bytes = 1 << 20;
    let options = Options::from(limits);

    let outputs = ozlrip::decode_outputs_with_options(data, options);
    if let Ok(serial) = ozlrip::decode_with_options(data, options) {
        assert_eq!(outputs.as_deref().ok(), Some(&[Output::Serial(serial)][..]));
    }

    let mut reused = vec![
        Output::String {
            bytes: vec![1; 3],
            lengths: vec![3],
        },
        Output::Numeric {
            width: 8,
            bytes: vec![0; 8],
        },
    ];
    let into = ozlrip::decode_outputs_into_with_options(data, &mut reused, options);
    match (&outputs, into) {
        (Ok(outputs), Ok(())) => assert_eq!(outputs, &reused),
        (Err(fresh), Err(reused)) => assert_eq!(fresh.kind(), reused.kind()),
        (fresh, reused) => panic!("fresh {fresh:?} but reused {reused:?}"),
    }

    for output in outputs.iter().flatten() {
        match output {
            Output::Struct { width, bytes } | Output::Numeric { width, bytes } => {
                // A frame without chunks never states the width.
                assert!(if *width == 0 {
                    bytes.is_empty()
                } else {
                    bytes.len() % width == 0
                });
            }
            Output::String { bytes, lengths } => {
                let total = lengths.iter().map(|&len| len as usize).sum::<usize>();
                assert_eq!(total, bytes.len());
            }
            _ => {}
        }
    }
});
