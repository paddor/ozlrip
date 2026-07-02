# Security

Report security issues privately to the repository owner. Do not file public
issues for suspected memory-safety, denial-of-service, or malformed-frame bugs
until the issue has been assessed.

`ozlrip` treats compressed input as hostile. The decoder must reject malformed
frames without panics, excessive allocation, or unbounded recursion.

The current crate is not a complete OpenZL decoder. Unsupported format regions
return `ErrorKind::Unsupported`.

