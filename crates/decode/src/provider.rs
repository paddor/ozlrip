use alloc::borrow::Cow;

use ozlrip_core::Result;

/// Supplies dictionary bundles on demand, like upstream's `ZL_DictLoader`.
///
/// A [`Decoder`](crate::Decoder) with a provider asks it for a bundle when a
/// frame names one the decoder has not loaded. The decoder then keeps the
/// bundle loaded, as if it came from
/// [`Decoder::load_dictionary_bundle`](crate::Decoder::load_dictionary_bundle),
/// so it asks for each bundle once until
/// [`Decoder::clear_dictionary_bundles`](crate::Decoder::clear_dictionary_bundles).
pub trait DictionaryProvider {
    /// Returns the fat bundle whose ID is `bundle_id`, packed as upstream
    /// packs it, or `Ok(None)` when this provider does not have it.
    ///
    /// # Errors
    ///
    /// An error stops the decode that asked for the bundle, which returns
    /// it.
    fn fat_bundle(&self, bundle_id: &[u8; 32]) -> Result<Option<Cow<'_, [u8]>>>;
}
