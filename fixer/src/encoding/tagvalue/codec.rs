use crate::datadictionary::DataDictionary;
use crate::encoding::Codec;
use crate::message::{Message, ParseError};
use std::sync::Arc;

/// TagValue (classic FIX) codec — encodes/decodes the `tag=value\x01` wire
/// format defined in ISO 11568-1 / FIX TagValue encoding.
pub struct TagValueCodec;

impl Codec for TagValueCodec {
    fn decode(
        &self,
        data: &bytes::Bytes,
        transport_dd: &Option<Arc<DataDictionary>>,
        app_dd: &Option<Arc<DataDictionary>>,
    ) -> Result<Message, ParseError> {
        let mut msg = Message::new();
        msg.parse_message_with_dd_shared(data, transport_dd, app_dd)?;
        Ok(msg)
    }

    fn encode(&self, msg: &mut Message) -> Vec<u8> {
        msg.build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tagvalue_codec_round_trip() {
        let codec = TagValueCodec;

        let raw = b"8=FIX.4.2\x019=30\x0135=D\x0149=TW\x0156=ISLD\x0111=id\x0121=3\x0110=079\x01";
        let data = bytes::Bytes::from_static(raw);

        let msg = codec.decode(&data, &None, &None).unwrap();
        assert!(msg.is_msg_type_of("D"));
        assert_eq!(msg.body.get_string(11).unwrap(), "id");

        let mut msg2 = msg;
        let encoded = codec.encode(&mut msg2);
        assert!(!encoded.is_empty());
    }
}
