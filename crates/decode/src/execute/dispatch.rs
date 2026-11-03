//! Dispatch nodes: `dispatch_string` and `dispatch_n_by_tag`, which
//! interleave several sources in the order an index or tag stream gives.

mod csv;
mod fast_dispatch;
mod n_by_tag;
mod source;
mod string;

pub(super) use n_by_tag::decode_dispatch_n_by_tag_node;
pub(super) use string::{
    decode_dispatch_string_node, decode_dispatch_string_node_to_serial_output,
};
