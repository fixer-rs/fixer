use crate::{
    BEGIN_STRING_FIX40,
    datadictionary::DataDictionary,
    errors::{MessageRejectErrorEnum, MessageRejectErrorResult},
    field::{
        Field, FieldGroupReader, FieldGroupWriter, FieldValueReader, FieldValueWriter, FieldWriter,
    },
    field_map::{FieldMap, LocalField, TagOrderType},
    fix_string::FIXString,
    registry::Messageable,
    tag::*,
    tag_value::TagValue,
};
use delegate::delegate;
use jiff::Timestamp;
use std::{
    error::Error,
    fmt::{self, Display, Formatter},
    sync::Arc,
};

/// The header section of a FIX [`Message`].
///
/// Delegates all field access to the inner [`FieldMap`], which uses
/// [`TagOrderType::Header`] ordering so that `BeginString` (8),
/// `BodyLength` (9), and `MsgType` (35) always serialize first.
#[derive(Debug, Default, Clone)]
pub struct Header {
    pub field_map: FieldMap,
}

impl Header {
    pub fn init() -> Self {
        let mut field_map = FieldMap::default();
        field_map.init_with_ordering(TagOrderType::Header);
        Header { field_map }
    }

    delegate! {
        to self.field_map {
            pub fn get<P: Field + FieldValueReader>(&self, parser: &mut P) -> MessageRejectErrorResult;
            pub fn has(&self, tag: Tag) -> bool;
            pub fn get_field<P: FieldValueReader>(
                &self,
                tag: Tag,
                parser: &mut P,
            ) -> MessageRejectErrorResult;
            pub fn get_bytes(&self, tag: Tag) -> Result<&[u8], MessageRejectErrorEnum>;
            pub fn get_bool(&self, tag: Tag) -> Result<bool, MessageRejectErrorEnum>;
            pub fn get_int(&self, tag: Tag) -> Result<isize, MessageRejectErrorEnum>;
            pub fn get_time(&self, tag: Tag) -> Result<Timestamp, MessageRejectErrorEnum>;
            pub fn get_string(&self, tag: Tag) -> Result<String, MessageRejectErrorEnum>;
            pub fn get_group<P: FieldGroupReader>(&self, parser: P) -> Result<P, MessageRejectErrorEnum>;
            pub fn set_field<F: FieldValueWriter>(&mut self, tag: Tag, field: F) -> &FieldMap;
            pub fn set_bytes(&mut self, tag: Tag, value: &[u8]) -> &FieldMap;
            pub fn set_bool(&mut self, tag: Tag, value: bool) -> &FieldMap;
            pub fn set_int(&mut self, tag: Tag, value: isize) -> &FieldMap;
            pub fn set_string(&mut self, tag: Tag, value: &str) -> &FieldMap;
            pub fn remove(&mut self, tag: Tag);
            pub fn clear(&mut self);
            pub fn copy_into(&self, to: &mut FieldMap);
            pub fn add(&mut self, f: LocalField);
            pub fn set<F: FieldWriter>(&mut self, field: F) -> &FieldMap;
            pub fn set_group<F: FieldGroupWriter>(&mut self, field: F) -> &FieldMap;
            pub fn write(&mut self, buffer: &mut Vec<u8>);
            pub fn total(&self) -> isize;
            pub fn length(&self) -> isize;
        }
    }
}

/// The body section of a FIX [`Message`].
///
/// Delegates all field access to the inner [`FieldMap`], which uses ascending
/// tag order.
#[derive(Debug, Default, Clone)]
pub struct Body {
    pub field_map: FieldMap,
}

impl Body {
    pub fn init() -> Self {
        let field_map = FieldMap::default().init();
        Body { field_map }
    }

    delegate! {
        to self.field_map {
            pub fn get<P: Field + FieldValueReader>(&self, parser: &mut P) -> MessageRejectErrorResult;
            pub fn has(&self, tag: Tag) -> bool;
            pub fn get_field<P: FieldValueReader>(
                &self,
                tag: Tag,
                parser: &mut P,
            ) -> MessageRejectErrorResult;
            pub fn get_bytes(&self, tag: Tag) -> Result<&[u8], MessageRejectErrorEnum>;
            pub fn get_bool(&self, tag: Tag) -> Result<bool, MessageRejectErrorEnum>;
            pub fn get_int(&self, tag: Tag) -> Result<isize, MessageRejectErrorEnum>;
            pub fn get_time(&self, tag: Tag) -> Result<Timestamp, MessageRejectErrorEnum>;
            pub fn get_string(&self, tag: Tag) -> Result<String, MessageRejectErrorEnum>;
            pub fn get_group<P: FieldGroupReader>(&self, parser: P) -> Result<P, MessageRejectErrorEnum>;
            pub fn set_field<F: FieldValueWriter>(&mut self, tag: Tag, field: F) -> &FieldMap;
            pub fn set_bytes(&mut self, tag: Tag, value: &[u8]) -> &FieldMap;
            pub fn set_bool(&mut self, tag: Tag, value: bool) -> &FieldMap;
            pub fn set_int(&mut self, tag: Tag, value: isize) -> &FieldMap;
            pub fn set_string(&mut self, tag: Tag, value: &str) -> &FieldMap;
            pub fn remove(&mut self, tag: Tag);
            pub fn clear(&mut self);
            pub fn copy_into(&self, to: &mut FieldMap);
            pub fn add(&mut self, f: LocalField);
            pub fn set<F: FieldWriter>(&mut self, field: F) -> &FieldMap;
            pub fn set_group<F: FieldGroupWriter>(&mut self, field: F) -> &FieldMap;
            pub fn write(&mut self, buffer: &mut Vec<u8>);
            pub fn total(&self) -> isize;
            pub fn length(&self) -> isize;
        }
    }
}

/// The trailer section of a FIX [`Message`].
///
/// Delegates all field access to the inner [`FieldMap`], which uses
/// [`TagOrderType::Trailer`] ordering so that `CheckSum` (10) always
/// serializes last.
#[derive(Debug, Default, Clone)]
pub struct Trailer {
    pub field_map: FieldMap,
}

impl Trailer {
    pub fn init() -> Self {
        let mut field_map = FieldMap::default();
        field_map.init_with_ordering(TagOrderType::Trailer);
        Trailer { field_map }
    }

    delegate! {
        to self.field_map {
            pub fn get<P: Field + FieldValueReader>(&self, parser: &mut P) -> MessageRejectErrorResult;
            pub fn has(&self, tag: Tag) -> bool;
            pub fn get_field<P: FieldValueReader>(
                &self,
                tag: Tag,
                parser: &mut P,
            ) -> MessageRejectErrorResult;
            pub fn get_bytes(&self, tag: Tag) -> Result<&[u8], MessageRejectErrorEnum>;
            pub fn get_bool(&self, tag: Tag) -> Result<bool, MessageRejectErrorEnum>;
            pub fn get_int(&self, tag: Tag) -> Result<isize, MessageRejectErrorEnum>;
            pub fn get_time(&self, tag: Tag) -> Result<Timestamp, MessageRejectErrorEnum>;
            pub fn get_string(&self, tag: Tag) -> Result<String, MessageRejectErrorEnum>;
            pub fn get_group<P: FieldGroupReader>(&self, parser: P) -> Result<P, MessageRejectErrorEnum>;
            pub fn set_field<F: FieldValueWriter>(&mut self, tag: Tag, field: F) -> &FieldMap;
            pub fn set_bytes(&mut self, tag: Tag, value: &[u8]) -> &FieldMap;
            pub fn set_bool(&mut self, tag: Tag, value: bool) -> &FieldMap;
            pub fn set_int(&mut self, tag: Tag, value: isize) -> &FieldMap;
            pub fn set_string(&mut self, tag: Tag, value: &str) -> &FieldMap;
            pub fn remove(&mut self, tag: Tag);
            pub fn clear(&mut self);
            pub fn copy_into(&self, to: &mut FieldMap);
            pub fn add(&mut self, f: LocalField);
            pub fn set<F: FieldWriter>(&mut self, field: F) -> &FieldMap;
            pub fn set_group<F: FieldGroupWriter>(&mut self, field: F) -> &FieldMap;
            pub fn write(&mut self, buffer: &mut Vec<u8>);
            pub fn total(&self) -> isize;
            pub fn length(&self) -> isize;
        }
    }
}

/// A parsed or constructed FIX message.
///
/// A `Message` is split into three [`FieldMap`] sections --
/// [`header`](Message::header), [`body`](Message::body), and
/// [`trailer`](Message::trailer) -- mirroring the wire format of a FIX
/// message. Each section has its own tag ordering rules.
///
/// # Building a Message
///
/// ```
/// use fixer::message::Message;
/// use fixer::tag::*;
/// use fixer::fix_string::FIXString;
///
/// let mut msg = Message::new();
/// msg.header.set_field(TAG_BEGIN_STRING, FIXString::from("FIX.4.2"));
/// msg.header.set_field(TAG_MSG_TYPE, FIXString::from("D"));
/// msg.header.set_field(TAG_SENDING_TIME, FIXString::from("20140615-19:49:56"));
/// msg.body.set_string(11, "order-1");
/// msg.body.set_int(21, 1);
///
/// let bytes = msg.build();
/// assert!(!bytes.is_empty());
/// ```
///
/// # Parsing a Message
///
/// ```
/// use fixer::message::Message;
///
/// let raw = b"8=FIX.4.2\x019=30\x0135=D\x0149=TW\x0156=ISLD\x0111=id\x0121=3\x0110=079\x01";
/// let mut msg = Message::new();
/// msg.parse_message(raw).unwrap();
///
/// assert!(msg.is_msg_type_of("D"));
/// assert_eq!(msg.body.get_string(11).unwrap(), "id");
/// ```
#[derive(Debug, Default, Clone)]
#[allow(clippy::struct_field_names)]
pub struct Message {
    pub header: Header,
    pub trailer: Trailer,
    pub body: Body,
    // receive_time is the time that this message was read from the socket connection
    pub receive_time: Timestamp,
    raw_message: Vec<u8>,
    // slice of Bytes corresponding to the message body
    pub(crate) body_bytes: Vec<u8>,
    // All parsed fields in order, used by validation.
    // Shared via Arc with body.field_map.content.parsed_fields to avoid
    // cloning body fields during parsing.
    pub fields: Arc<[TagValue]>,
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if !self.raw_message.is_empty() {
            let s = std::str::from_utf8(&self.raw_message).unwrap_or("<invalid utf8>");
            return f.write_str(s);
        }

        let built = self.clone().build();
        let s = std::str::from_utf8(&built).unwrap_or("<invalid utf8>");
        f.write_str(s)
    }
}

impl Messageable for Message {
    fn to_message(&self) -> &Message {
        self
    }
}

impl Message {
    /// Creates a new empty message with initialized header, body, and trailer.
    pub fn new() -> Self {
        Message {
            header: Header::init(),
            body: Body::init(),
            trailer: Trailer::init(),
            ..Default::default()
        }
    }

    /// Deep-copies this message into `to`.
    pub fn copy_into(&self, to: &mut Message) {
        self.header.copy_into(&mut to.header.field_map);
        self.body.copy_into(&mut to.body.field_map);
        self.trailer.copy_into(&mut to.trailer.field_map);
        to.receive_time = self.receive_time;
        to.body_bytes.clone_from(&self.body_bytes);
        to.fields = Arc::clone(&self.fields);
    }

    /// Parses a FIX message from raw bytes, populating header, body, and
    /// trailer fields. Returns an error if the message is malformed.
    pub fn parse_message(&mut self, raw_message: &[u8]) -> Result<(), ParseError> {
        self.parse_message_with_data_dictionary(raw_message, &None, &None)
    }

    /// Parses a FIX message using optional transport and application
    /// [`DataDictionary`] instances to correctly classify header and trailer
    /// fields.
    #[allow(clippy::ref_option)]
    pub fn parse_message_with_data_dictionary(
        &mut self,
        raw_message: &[u8],
        transport_data_dictionary: &Option<Arc<DataDictionary>>,
        _application_data_dictionary: &Option<Arc<DataDictionary>>,
    ) -> Result<(), ParseError> {
        self.header.clear();
        self.body.clear();
        self.trailer.clear();
        self.raw_message = raw_message.to_vec();

        // Count SOH delimiters to pre-allocate fields.
        #[allow(clippy::naive_bytecount)]
        let field_count = self.raw_message.iter().filter(|&&b| b == 0x01).count();

        if field_count == 0 {
            return Err(ParseError {
                orig_error: format!(
                    "No Fields detected in {}",
                    std::str::from_utf8(&self.raw_message).unwrap_or("<invalid utf8>")
                ),
            });
        }

        // Shared buffer: all TagValues hold Bytes slices of this single allocation.
        let shared = bytes::Bytes::copy_from_slice(raw_message);
        let msg_len = raw_message.len();

        let mut parsed_fields: Vec<TagValue> = vec![TagValue::default(); field_count];
        let mut field_index = 0;

        // message must start with begin string, body length, msg type
        let raw_bytes = extract_specific_field_shared(
            &mut parsed_fields[field_index],
            TAG_BEGIN_STRING,
            raw_message,
            &shared,
            msg_len,
        )?;
        self.header
            .add(LocalField::new(vec![parsed_fields[field_index].clone()]));
        field_index += 1;

        let raw_bytes = extract_specific_field_shared(
            &mut parsed_fields[field_index],
            TAG_BODY_LENGTH,
            raw_bytes,
            &shared,
            msg_len,
        )?;
        self.header
            .add(LocalField::new(vec![parsed_fields[field_index].clone()]));
        field_index += 1;

        let mut raw_bytes = extract_specific_field_shared(
            &mut parsed_fields[field_index],
            TAG_MSG_TYPE,
            raw_bytes,
            &shared,
            msg_len,
        )?;
        let mut xml_data_len = 0_isize;
        let mut xml_data_msg = false;
        self.header
            .add(LocalField::new(vec![parsed_fields[field_index].clone()]));
        field_index += 1;

        let mut trailer_bytes: &[u8] = &[];
        let mut found_body = false;
        let mut body_start: &[u8] = &[];

        loop {
            let pf = &mut parsed_fields[field_index];
            raw_bytes = if xml_data_len.is_positive() {
                // XML data fields may span across SOH boundaries; use allocating parse.
                let raw_bytes = extract_xml_data_field(pf, raw_bytes, xml_data_len)?;
                xml_data_len = 0;
                xml_data_msg = true;
                raw_bytes
            } else {
                extract_field_shared(pf, raw_bytes, &shared, msg_len)?
            };

            let tag = pf.tag;
            let field_lf = LocalField::new(vec![pf.clone()]);

            if is_header_field(&tag, transport_data_dictionary) {
                self.header.add(field_lf);
            } else if is_trailer_field(&tag, transport_data_dictionary) {
                self.trailer.add(field_lf);
            } else {
                found_body = true;
                trailer_bytes = raw_bytes;
                self.body.add(field_lf);
            }

            if tag == TAG_CHECK_SUM {
                break;
            }

            if !found_body {
                body_start = raw_bytes;
            }

            if tag == TAG_XML_DATA_LEN {
                xml_data_len = self.header.get_int(TAG_XML_DATA_LEN).unwrap();
            }

            field_index += 1;
        }

        // Compute body_bytes once from the tracked slice boundaries.
        if !found_body {
            self.body_bytes.clear();
        } else if body_start.len() > trailer_bytes.len() {
            let body_len = body_start.len() - trailer_bytes.len();
            self.body_bytes = body_start[..body_len].to_vec();
        } else {
            self.body_bytes.clear();
        }

        parsed_fields.truncate(field_index + 1);
        let fields: Arc<[TagValue]> = parsed_fields.into();
        self.fields = Arc::clone(&fields);
        self.body.field_map.content.parsed_fields = Some(fields);

        let mut length = 0;
        for field in self.fields.iter() {
            match field.tag {
                TAG_BEGIN_STRING | TAG_BODY_LENGTH | TAG_CHECK_SUM => {} // tags do not contribute to length
                _ => length += field.length(),
            }
        }

        let body_length = self
            .header
            .get_int(TAG_BODY_LENGTH)
            .map_err(|e| ParseError {
                orig_error: e.to_string(),
            });

        if let Ok(bl) = body_length {
            if bl != length && !xml_data_msg {
                return Err(ParseError {
                    orig_error: format!("Incorrect Message Length, expected {bl} , got {length}"),
                });
            }
        }

        Ok(())
    }

    /// Returns the `MsgType` (tag 35) value from the header.
    pub fn msg_type(&self) -> Result<String, MessageRejectErrorEnum> {
        self.header.get_string(TAG_MSG_TYPE)
    }

    /// Returns `true` if the header's `MsgType` (tag 35) equals `msg_type`.
    pub fn is_msg_type_of(&self, msg_type: &str) -> bool {
        let v = self.msg_type();
        if let Ok(w_unwrap) = v {
            return w_unwrap == msg_type;
        }
        false
    }

    /// Creates a new message with routing header fields (sender/target comp
    /// IDs, sub IDs, location IDs, etc.) swapped from this message.
    #[must_use]
    pub fn reverse_route(&self) -> Message {
        let mut reverse_msg = Message::new();

        let copy = |reverse_header: &mut Header, src: Tag, dest: Tag, self_header: &Header| {
            let mut field = FIXString::new();
            let get_field = self_header.get_field(src, &mut field);
            if get_field.is_ok() && !field.is_empty() {
                reverse_header.set_field(dest, field);
            }
        };

        copy(
            &mut reverse_msg.header,
            TAG_SENDER_COMP_ID,
            TAG_TARGET_COMP_ID,
            &self.header,
        );
        copy(
            &mut reverse_msg.header,
            TAG_SENDER_SUB_ID,
            TAG_TARGET_SUB_ID,
            &self.header,
        );
        copy(
            &mut reverse_msg.header,
            TAG_SENDER_LOCATION_ID,
            TAG_TARGET_LOCATION_ID,
            &self.header,
        );

        copy(
            &mut reverse_msg.header,
            TAG_TARGET_COMP_ID,
            TAG_SENDER_COMP_ID,
            &self.header,
        );
        copy(
            &mut reverse_msg.header,
            TAG_TARGET_SUB_ID,
            TAG_SENDER_SUB_ID,
            &self.header,
        );
        copy(
            &mut reverse_msg.header,
            TAG_TARGET_LOCATION_ID,
            TAG_SENDER_LOCATION_ID,
            &self.header,
        );

        copy(
            &mut reverse_msg.header,
            TAG_ON_BEHALF_OF_COMP_ID,
            TAG_DELIVER_TO_COMP_ID,
            &self.header,
        );
        copy(
            &mut reverse_msg.header,
            TAG_ON_BEHALF_OF_SUB_ID,
            TAG_DELIVER_TO_SUB_ID,
            &self.header,
        );
        copy(
            &mut reverse_msg.header,
            TAG_DELIVER_TO_COMP_ID,
            TAG_ON_BEHALF_OF_COMP_ID,
            &self.header,
        );
        copy(
            &mut reverse_msg.header,
            TAG_DELIVER_TO_SUB_ID,
            TAG_ON_BEHALF_OF_SUB_ID,
            &self.header,
        );

        // tags added in 4.1
        let mut begin_string = FIXString::new();
        let get_field = self.header.get_field(TAG_BEGIN_STRING, &mut begin_string);
        if get_field.is_ok() && begin_string != BEGIN_STRING_FIX40 {
            copy(
                &mut reverse_msg.header,
                TAG_ON_BEHALF_OF_LOCATION_ID,
                TAG_DELIVER_TO_LOCATION_ID,
                &self.header,
            );
            copy(
                &mut reverse_msg.header,
                TAG_DELIVER_TO_LOCATION_ID,
                TAG_ON_BEHALF_OF_LOCATION_ID,
                &self.header,
            );
        }

        reverse_msg
    }

    /// Serializes this message to FIX wire format, computing `BodyLength`
    /// and `CheckSum` automatically.
    pub fn build(&mut self) -> Vec<u8> {
        self.cook(self.body.length(), self.body.total());

        let mut b = vec![];
        self.header.write(&mut b);
        self.body.write(&mut b);
        self.trailer.write(&mut b);
        b
    }

    /// Constructs a `Vec<u8>` from a Message instance, using the given `body_bytes`.
    /// This is a workaround for the fact that repeating group field ordering is
    /// not preserved through parse → field map → serialize round-trips.
    /// This lets us pull the Message from the Store, parse it, update the Header
    /// (e.g. `PossDupFlag`, `OrigSendingTime`), and then build it back into bytes
    /// using the original raw body, bypassing field map serialization.
    #[allow(clippy::cast_possible_wrap)]
    pub fn build_with_body_bytes(&mut self, body_bytes: &[u8]) -> Vec<u8> {
        self.cook(body_bytes.len() as isize, bytes_total(body_bytes));

        let mut b = vec![];
        self.header.write(&mut b);
        b.extend_from_slice(body_bytes);
        self.trailer.write(&mut b);
        b
    }

    fn cook(&mut self, body_len: isize, body_total: isize) {
        let body_length = self.header.length() + body_len + self.trailer.length();
        self.header.set_int(TAG_BODY_LENGTH, body_length);
        let check_sum = (self.header.total() + body_total + self.trailer.total()) % 256;
        self.trailer
            .set_string(TAG_CHECK_SUM, &format_check_sum(check_sum));
    }

    /// Returns the raw message bytes if available (from parsing), otherwise
    /// rebuilds the message from the field maps.
    pub fn as_bytes(&mut self) -> Vec<u8> {
        if !self.raw_message.is_empty() {
            return self.raw_message.clone();
        }

        self.build()
    }
}

/// Error returned when a raw byte slice cannot be parsed as a valid FIX
/// message.
#[derive(Debug)]
pub struct ParseError {
    pub orig_error: String,
}

impl Display for ParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.orig_error)
    }
}

impl Error for ParseError {
    fn description(&self) -> &str {
        &self.orig_error
    }
}

#[allow(clippy::ref_option, clippy::trivially_copy_pass_by_ref)]
fn is_header_field(tag: &Tag, data_dict: &Option<Arc<DataDictionary>>) -> bool {
    if tag.is_header() {
        return true;
    }

    if data_dict.is_none() {
        return false;
    }

    data_dict.as_ref().unwrap().header.fields.contains_key(tag)
}

#[allow(clippy::ref_option, clippy::trivially_copy_pass_by_ref)]
fn is_trailer_field(tag: &Tag, data_dict: &Option<Arc<DataDictionary>>) -> bool {
    if tag.is_trailer() {
        return true;
    }

    if data_dict.is_none() {
        return false;
    }

    data_dict.as_ref().unwrap().trailer.fields.contains_key(tag)
}

fn extract_specific_field<'a>(
    field: &mut TagValue,
    expected_tag: Tag,
    buffer: &'a [u8],
) -> Result<&'a [u8], ParseError> {
    let rem_buffer = extract_field(field, buffer)?;
    if field.tag != expected_tag {
        return Err(ParseError {
            orig_error: format!(
                "extract_specific_field: Fields out of order, expected {}, got {}",
                expected_tag, field.tag
            ),
        });
    }
    Ok(rem_buffer)
}

/// Shared-buffer variant: parses the field using a zero-copy Bytes slice.
fn extract_specific_field_shared<'a>(
    field: &mut TagValue,
    expected_tag: Tag,
    buffer: &'a [u8],
    shared: &bytes::Bytes,
    msg_len: usize,
) -> Result<&'a [u8], ParseError> {
    let rem_buffer = extract_field_shared(field, buffer, shared, msg_len)?;
    if field.tag != expected_tag {
        return Err(ParseError {
            orig_error: format!(
                "extract_specific_field: Fields out of order, expected {}, got {}",
                expected_tag, field.tag
            ),
        });
    }
    Ok(rem_buffer)
}

#[allow(clippy::cast_sign_loss)]
fn extract_xml_data_field<'a>(
    parsed_field_bytes: &mut TagValue,
    buffer: &'a [u8],
    data_len: isize,
) -> Result<&'a [u8], ParseError> {
    let mut end_index = buffer.iter().position(|x| *x == b'=').ok_or(ParseError {
        orig_error: format!(
            "extract_field: No Trailing Delim in {}",
            std::str::from_utf8(buffer).unwrap_or("<invalid utf8>")
        ),
    })?;
    end_index += data_len as usize + 1;
    let buffer_slice = buffer.get(..(end_index + 1)).unwrap();
    parsed_field_bytes
        .parse(buffer_slice)
        .map_err(|err| ParseError { orig_error: err })?;

    Ok(buffer.get((end_index + 1)..).unwrap())
}

fn extract_field<'a>(
    parsed_field_bytes: &mut TagValue,
    buffer: &'a [u8],
) -> Result<&'a [u8], ParseError> {
    let end_index = buffer.iter().position(|x| *x == 1).ok_or(ParseError {
        orig_error: format!(
            "extract_field: No Trailing Delim in {}",
            std::str::from_utf8(buffer).unwrap_or("<invalid utf8>")
        ),
    })?;
    let buffer_slice = buffer.get(..(end_index + 1)).unwrap();
    parsed_field_bytes
        .parse(buffer_slice)
        .map_err(|err| ParseError { orig_error: err })?;
    Ok(buffer.get((end_index + 1)..).unwrap())
}

/// Shared-buffer variant: uses `parse_shared` for zero-copy field bytes.
fn extract_field_shared<'a>(
    parsed_field_bytes: &mut TagValue,
    buffer: &'a [u8],
    shared: &bytes::Bytes,
    msg_len: usize,
) -> Result<&'a [u8], ParseError> {
    let end_index = buffer.iter().position(|x| *x == 1).ok_or(ParseError {
        orig_error: format!(
            "extract_field: No Trailing Delim in {}",
            std::str::from_utf8(buffer).unwrap_or("<invalid utf8>")
        ),
    })?;
    let field_len = end_index + 1;
    let field_start = msg_len - buffer.len();
    let buffer_slice = &buffer[..field_len];
    parsed_field_bytes
        .parse_shared(buffer_slice, shared.slice(field_start..field_start + field_len))
        .map_err(|err| ParseError { orig_error: err })?;
    Ok(&buffer[field_len..])
}

/// Compute the total (sum of all byte values) for a raw byte slice.
fn bytes_total(bytes: &[u8]) -> isize {
    let mut total: isize = 0;
    for b in bytes {
        total += *b as isize;
    }
    total
}

fn format_check_sum(value: isize) -> String {
    format!("{value:03}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BEGIN_STRING_FIX44;
    use crate::datadictionary::{DataDictionary, FieldDef, MessageDef};
    use crate::fixer_test::{FieldEqual, FixerSuite};
    use crate::tag::Tag;
    use delegate::delegate;

    struct MessageSuite {
        suite: FixerSuite,
        msg: Message,
    }

    fn setup_test() -> MessageSuite {
        MessageSuite {
            suite: FixerSuite::default(),
            msg: Message::new(),
        }
    }

    impl MessageSuite {
        delegate! {
            to self.suite {
                fn field_equals(&self, tag: Tag, expected_value: FieldEqual, field_map: &FieldMap) ;
            }
        }
    }

    #[test]
    fn test_xml_non_fix() {
        let raw_message = "8=FIX.4.29=37235=n34=25512369=148152=20200522-07:05:33.75649=CME50=G56=OAEAAAN57=TRADE_CAPTURE143=US,IL212=261213=<RTRF>8=FIX.4.29=22535=BZ34=6549369=651852=20200522-07:05:33.74649=CME50=G56=9Q5000N57=DUMMY143=US,IL11=ACP159013113373460=20200522-07:05:33.734533=0893=Y1028=Y1300=991369=99612:325081373=31374=91375=15979=159013113373461769710=167</RTRF>10=245\"".as_bytes();
        let mut msg = Message::new();
        let parse_result = msg.parse_message(raw_message);
        assert!(parse_result.is_ok());
        assert!(
            msg.header.field_map.has(TAG_XML_DATA),
            "Expected xmldata tag"
        );
    }

    #[test]
    fn test_parse_message_empty() {
        let mut s = setup_test();
        let raw_message = "".as_bytes();

        let parse_result = s.msg.parse_message(raw_message);
        assert!(parse_result.is_err());
    }

    #[test]
    fn test_parse_message() {
        let mut s = setup_test();
        let raw_message = "8=FIX.4.29=10435=D34=249=TW52=20140515-19:49:56.65956=ISLD11=10021=140=154=155=TSLA60=00010101-00:00:00.00010=039".as_bytes();

        let res = s.msg.parse_message(raw_message);
        assert!(res.is_ok());
        assert_eq!(
            raw_message, &s.msg.raw_message,
            "Expected msg bytes to equal raw bytes"
        );

        let expected_body_bytes =
            "11=10021=140=154=155=TSLA60=00010101-00:00:00.000".as_bytes();
        assert_eq!(
            &s.msg.body_bytes,
            expected_body_bytes,
            "Incorrect body bytes, got {}",
            std::str::from_utf8(&s.msg.body_bytes).unwrap()
        );
        assert_eq!(14, s.msg.fields.len());
        let msg_type_result = s.msg.msg_type();
        assert!(msg_type_result.is_ok());
        let msg_type = msg_type_result.unwrap();
        assert_eq!("D", &msg_type);
        assert!(s.msg.is_msg_type_of("D"));
        assert!(!s.msg.is_msg_type_of("A"));
    }

    #[test]
    fn test_parse_message_with_data_dictionary() {
        let mut s = setup_test();
        let mut dict = DataDictionary {
            header: MessageDef::default(),
            ..DataDictionary::default()
        };
        let mut hd_fields = hashmap! {};
        let hd_fd = FieldDef::default();
        hd_fields.insert(10030, hd_fd);
        dict.header.fields = hd_fields;

        let mut tr_fields = hashmap! {};
        let tr_fd = FieldDef::default();
        tr_fields.insert(5050, tr_fd);
        dict.trailer.fields = tr_fields;

        let raw_message = "8=FIX.4.29=12635=D34=249=TW52=20140515-19:49:56.65956=ISLD10030=CUST11=10021=140=154=155=TSLA60=00010101-00:00:00.0005050=HELLO10=039".as_bytes();

        let dict_ref = &Some(Arc::new(dict));

        let parse_result =
            s.msg
                .parse_message_with_data_dictionary(raw_message, dict_ref, dict_ref);
        assert!(parse_result.is_ok());
        s.field_equals(
            10030 as Tag,
            FieldEqual::Str("CUST"),
            &s.msg.header.field_map,
        );
        s.field_equals(
            5050 as Tag,
            FieldEqual::Str("HELLO"),
            &s.msg.trailer.field_map,
        );
    }

    #[test]
    fn test_parse_out_of_order() {
        // allow fields out of order, save for validation
        let mut s = setup_test();
        let raw_message =  "8=FIX.4.09=8135=D11=id21=338=10040=154=155=MSFT34=249=TW52=20140521-22:07:0956=ISLD10=250".as_bytes();
        let parse_result = s.msg.parse_message(raw_message);
        assert!(parse_result.is_ok());
    }

    #[test]
    fn test_build() {
        let mut s = setup_test();
        s.msg
            .header
            .set_field(TAG_BEGIN_STRING, FIXString::from(BEGIN_STRING_FIX44));
        s.msg.header.set_field(TAG_MSG_TYPE, FIXString::from("A"));
        s.msg
            .header
            .set_field(TAG_SENDING_TIME, FIXString::from("20140615-19:49:56"));

        s.msg.body.set_field(553 as Tag, FIXString::from("my_user"));
        s.msg.body.set_field(554 as Tag, FIXString::from("secret"));

        let expected_bytes =
            "8=FIX.4.49=4935=A52=20140615-19:49:56553=my_user554=secret10=072".as_bytes();
        let result = s.msg.build();
        assert_eq!(
            expected_bytes,
            result,
            "Unexpected bytes, got {}",
            std::str::from_utf8(&result).unwrap()
        );
    }

    #[test]
    fn test_re_build() {
        let mut s = setup_test();
        let raw_message =  "8=FIX.4.29=10435=D34=249=TW52=20140515-19:49:56.65956=ISLD11=10021=140=154=155=TSLA60=00010101-00:00:00.00010=039".as_bytes();

        let parse_result = s.msg.parse_message(raw_message);
        assert!(parse_result.is_ok());

        s.msg.header.set_field(
            TAG_ORIG_SENDING_TIME,
            FIXString::from("20140515-19:49:56.659"),
        );
        s.msg
            .header
            .set_field(TAG_SENDING_TIME, FIXString::from("20140615-19:49:56"));

        let rebuild_bytes = s.msg.build();
        let expected_bytes = "8=FIX.4.29=12635=D34=249=TW52=20140615-19:49:5656=ISLD122=20140515-19:49:56.65911=10021=140=154=155=TSLA60=00010101-00:00:00.00010=128".as_bytes();

        assert_eq!(
            expected_bytes,
            &rebuild_bytes,
            "Unexpected bytes,\n +{}\n-{}",
            std::str::from_utf8(&rebuild_bytes).unwrap(),
            std::str::from_utf8(expected_bytes).unwrap(),
        );

        let expected_body_bytes =
            "11=10021=140=154=155=TSLA60=00010101-00:00:00.000".as_bytes();

        assert_eq!(
            &s.msg.body_bytes,
            expected_body_bytes,
            "Incorrect body bytes, got {}",
            std::str::from_utf8(&s.msg.body_bytes).unwrap()
        );
    }

    #[test]
    fn test_reverse_route() {
        struct TestCase<'a> {
            tag: Tag,
            expected_value: &'a str,
        }

        let mut s = setup_test();
        let raw_message = "8=FIX.4.29=17135=D34=249=TW50=KK52=20060102-15:04:0556=ISLD57=AP144=BB115=JCD116=CS128=MG129=CB142=JV143=RY145=BH11=ID21=338=10040=w54=155=INTC60=20060102-15:04:0510=123".as_bytes();

        let parse_result = s.msg.parse_message(raw_message);
        assert!(parse_result.is_ok());

        let builder = s.msg.reverse_route();

        let tests = vec![
            TestCase {
                tag: TAG_TARGET_COMP_ID,
                expected_value: "TW",
            },
            TestCase {
                tag: TAG_TARGET_SUB_ID,
                expected_value: "KK",
            },
            TestCase {
                tag: TAG_TARGET_LOCATION_ID,
                expected_value: "JV",
            },
            TestCase {
                tag: TAG_SENDER_COMP_ID,
                expected_value: "ISLD",
            },
            TestCase {
                tag: TAG_SENDER_SUB_ID,
                expected_value: "AP",
            },
            TestCase {
                tag: TAG_SENDER_LOCATION_ID,
                expected_value: "RY",
            },
            TestCase {
                tag: TAG_DELIVER_TO_COMP_ID,
                expected_value: "JCD",
            },
            TestCase {
                tag: TAG_DELIVER_TO_SUB_ID,
                expected_value: "CS",
            },
            TestCase {
                tag: TAG_DELIVER_TO_LOCATION_ID,
                expected_value: "BB",
            },
            TestCase {
                tag: TAG_ON_BEHALF_OF_COMP_ID,
                expected_value: "MG",
            },
            TestCase {
                tag: TAG_ON_BEHALF_OF_SUB_ID,
                expected_value: "CB",
            },
            TestCase {
                tag: TAG_ON_BEHALF_OF_LOCATION_ID,
                expected_value: "BH",
            },
        ];

        for tc in &tests {
            let mut field = FIXString::default();
            let field_result = builder.header.get_field(tc.tag, &mut field);
            assert!(field_result.is_ok());
            assert_eq!(tc.expected_value, &field);
        }
    }

    #[test]
    fn test_reverse_route_ignore_empty() {
        let mut s = setup_test();
        let raw_message = "8=FIX.4.09=12835=D34=249=TW52=20060102-15:04:0556=ISLD115=116=CS128=MG129=CB11=ID21=338=10040=w54=155=INTC60=20060102-15:04:0510=123".as_bytes();
        let parse_result = s.msg.parse_message(raw_message);
        assert!(parse_result.is_ok());

        let builder = s.msg.reverse_route();
        assert!(
            !builder.header.has(TAG_DELIVER_TO_COMP_ID),
            "Should not reverse if empty"
        );
    }

    #[test]
    fn test_reverse_route_fix40() {
        //onbehalfof/deliverto location id not supported in fix 4.0
        let mut s = setup_test();
        let raw_message = "8=FIX.4.09=17135=D34=249=TW50=KK52=20060102-15:04:0556=ISLD57=AP144=BB115=JCD116=CS128=MG129=CB142=JV143=RY145=BH11=ID21=338=10040=w54=155=INTC60=20060102-15:04:0510=123".as_bytes();
        let parse_result = s.msg.parse_message(raw_message);
        assert!(parse_result.is_ok());

        let builder = s.msg.reverse_route();
        assert!(
            !builder.header.has(TAG_DELIVER_TO_LOCATION_ID),
            "delivertolocation id not supported in fix40"
        );
        assert!(
            !builder.header.has(TAG_ON_BEHALF_OF_LOCATION_ID),
            "onbehalfof location id not supported in fix40"
        );
    }

    #[test]
    fn test_copy_into_message() {
        let mut s = setup_test();
        let raw_message = "8=FIX.4.29=17135=D34=249=TW50=KK52=20060102-15:04:0556=ISLD57=AP144=BB115=JCD116=CS128=MG129=CB142=JV143=RY145=BH11=ID21=338=10040=w54=155=INTC60=20060102-15:04:0510=123".as_bytes();
        let parse_result = s.msg.parse_message(raw_message);
        assert!(parse_result.is_ok());

        let mut dest = Message::new();
        s.msg.copy_into(&mut dest);

        check_field_int(&s, &dest.header.field_map, TAG_MSG_SEQ_NUM, 2);
        check_field_int(&s, &dest.body.field_map, 21, 3);
        check_field_string(&s, &dest.body.field_map, 11, "ID");
        assert_eq!(dest.body_bytes.len(), s.msg.body_bytes.len());

        // copying decouples the message from its input buffer, so the raw message will be re-rendered
        let rendered_string = "8=FIX.4.29=17135=D34=249=TW50=KK52=20060102-15:04:0556=ISLD57=AP115=JCD116=CS128=MG129=CB142=JV143=RY144=BB145=BH11=ID21=338=10040=w54=155=INTC60=20060102-15:04:0510=033";
        assert_eq!(&dest.to_string(), rendered_string);

        assert_eq!(s.msg.body_bytes, dest.body_bytes);
        assert!(s.msg.is_msg_type_of("D"));
        assert_eq!(s.msg.receive_time, dest.receive_time);

        assert_eq!(s.msg.fields, dest.fields);

        // update the source message to validate the copy is truly deep
        let new_msg_string =
            "8=FIX.4.49=4935=A52=20140615-19:49:56553=my_user554=secret10=072".as_bytes();
        let parse_result = s.msg.parse_message(new_msg_string);
        assert!(parse_result.is_ok());
        assert!(s.msg.is_msg_type_of("A"));
        assert_eq!(s.msg.to_string().as_bytes(), new_msg_string);
        assert_eq!(s.msg.as_bytes(), new_msg_string);

        assert!(&dest.is_msg_type_of("D"));
        assert_eq!(&dest.to_string(), rendered_string);
        assert_eq!(dest.as_bytes(), rendered_string.as_bytes());
    }

    fn check_field_int(_s: &MessageSuite, fields: &FieldMap, tag: isize, expected: isize) {
        let to_check_result = fields.get_int(tag as Tag);
        assert!(to_check_result.is_ok());
        let to_check = to_check_result.unwrap();
        assert_eq!(expected, to_check);
    }

    fn check_field_string(_s: &MessageSuite, fields: &FieldMap, tag: isize, expected: &str) {
        let to_check_result = fields.get_string(tag as Tag);
        assert!(to_check_result.is_ok());
        let to_check = to_check_result.unwrap();
        assert_eq!(expected, &to_check);
    }
}
