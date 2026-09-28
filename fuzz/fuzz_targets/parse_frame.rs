#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let info = ozlrip::inspect(data);
    let size = ozlrip::frame_size(data);
    // A frame that parses is exactly one frame.
    if let Ok(info) = &info {
        assert_eq!(size.as_ref().ok(), Some(&info.frame_bytes));
        assert_eq!(info.frame_bytes, data.len());
    }
    // The size of a frame does not depend on what follows it.
    if let Ok(size) = size {
        assert!(size <= data.len());
        assert_eq!(ozlrip::frame_size(&data[..size]).ok(), Some(size));
    }
});
