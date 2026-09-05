use crate::datadictionary::DataDictionary;
use crate::message::{Message, ParseError};
use enum_dispatch::enum_dispatch;
use std::sync::Arc;

pub mod fixml;
pub mod json;
pub mod tagvalue;

/// Decodes raw wire bytes into a [`Message`] and encodes a [`Message`] back
/// into wire bytes. Each FIX encoding (`TagValue`, JSON, FIXML, SBE, FAST, GPB)
/// implements this trait.
#[allow(async_fn_in_trait)] // dispatched via enum_dispatch, not used as trait object
#[enum_dispatch]
pub trait Codec: Send + Sync {
    /// Decode raw bytes into a [`Message`], using optional data dictionaries to
    /// classify header/trailer fields.
    fn decode(
        &self,
        data: &bytes::Bytes,
        transport_dd: &Option<Arc<DataDictionary>>,
        app_dd: &Option<Arc<DataDictionary>>,
    ) -> Result<Message, ParseError>;

    /// Encode a [`Message`] into wire-format bytes.
    fn encode(&self, msg: &mut Message) -> Vec<u8>;
}

/// Enum-dispatched wrapper over all [`Codec`] implementations.
///
/// Uses `#[enum_dispatch]` for zero-cost match-based dispatch — no vtable
/// indirection, no monomorphization bloat.
#[enum_dispatch(Codec)]
pub enum AnyCodec {
    TagValue(tagvalue::TagValueCodec),
    Json(json::JsonCodec),
    Fixml(fixml::FixmlCodec),
}

impl Default for AnyCodec {
    fn default() -> Self {
        Self::TagValue(tagvalue::TagValueCodec)
    }
}
