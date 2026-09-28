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
    // A header reads the same from any prefix that holds it, and matches
    // the frame it starts.
    if let Ok(header) = ozlrip::inspect_header(data) {
        assert!(header.header_bytes <= data.len());
        let prefix = ozlrip::inspect_header(&data[..header.header_bytes]);
        assert_eq!(prefix.as_ref().ok(), Some(&header));
        if let Ok(info) = &info {
            assert_eq!(header.header_bytes, info.header_bytes);
            assert_eq!(header.output_types, info.output_types);
            assert_eq!(header.output_sizes, info.output_sizes);
            assert_eq!(header.output_elements, info.output_elements);
        }
    } else {
        assert!(info.is_err());
    }
});
