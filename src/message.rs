use crate::{
    datadictionary::DataDictionary,
    errors::{MessageRejectErrorEnum, MessageRejectErrorResult},
    field::{
        Field, FieldGroupReader, FieldGroupWriter, FieldValueReader, FieldValueWriter, FieldWriter,
    },
    field_map::{FieldMap, LocalField},
    fix_string::FIXString,
    tag::*,
    tag_value::TagValue,
    BEGIN_STRING_FIX40,
};
use chrono::{DateTime, Utc};
use delegate::delegate;
use std::{
    cmp::Ordering,
    error::Error,
    fmt::{Display, Formatter},
    string::ToString,
};

#[derive(Debug, Default, Clone)]
pub struct Header {
    pub field_map: FieldMap,
}

// in the message header, the first 3 tags in the message header must be 8,9,35
pub fn header_field_ordering(i: &Tag, j: &Tag) -> Ordering {
    fn ordering(t: &Tag) -> isize {
        match *t {
            TAG_BEGIN_STRING => 1,
            TAG_BODY_LENGTH => 2,
            TAG_MSG_TYPE => 3,
            _ => isize::MAX,
        }
    }

    let orderi = ordering(i);
    let orderj = ordering(j);

    match orderi.cmp(&orderj) {
        Ordering::Less => return Ordering::Less,
        Ordering::Equal => {}
        Ordering::Greater => return Ordering::Greater,
    }

    if i < j {
        return Ordering::Less;
    }

    Ordering::Greater
}

impl Header {
    pub fn init() -> Self {
        let field_map = FieldMap::default().init_with_ordering(header_field_ordering);
        Header { field_map }
    }

    delegate! {
        to self.field_map {
            pub fn tags(&self) -> Vec<Tag>;
            pub fn get<P: Field + FieldValueReader>(&self, parser: &mut P) -> MessageRejectErrorResult;
            pub fn has(&self, tag: Tag) -> bool;
            pub fn get_field<P: FieldValueReader>(
                &self,
                tag: Tag,
                parser: &mut P,
            ) -> MessageRejectErrorResult;
            pub fn get_bytes(&self, tag: Tag) -> Result<Vec<u8>, MessageRejectErrorEnum>;
            pub fn get_bool(&self, tag: Tag) -> Result<bool, MessageRejectErrorEnum>;
            pub fn get_int(&self, tag: Tag) -> Result<isize, MessageRejectErrorEnum>;
            pub fn get_time(&self, tag: Tag) -> Result<DateTime<Utc>, MessageRejectErrorEnum>;
            pub fn get_string(&self, tag: Tag) -> Result<String, MessageRejectErrorEnum>;
            pub fn get_group<P: FieldGroupReader>(&self, parser: P) -> MessageRejectErrorResult;
            pub fn set_field<F: FieldValueWriter>(&self, tag: Tag, field: F) -> &FieldMap;
            pub fn set_bytes(&self, tag: Tag, value: &[u8]) -> &FieldMap;
            pub fn set_bool(&self, tag: Tag, value: bool) -> &FieldMap;
            pub fn set_int(&self, tag: Tag, value: isize) -> &FieldMap;
            pub fn set_string(&self, tag: Tag, value: &str) -> &FieldMap;
            pub fn clear(&self);
            pub fn copy_into(&self, to: &mut FieldMap);
            pub fn add(&mut self, f: &LocalField);
            pub fn set<F: FieldWriter>(&self, field: F) -> &FieldMap;
            pub fn set_group<F: FieldGroupWriter>(&mut self, field: F) -> &FieldMap;
            pub fn write(&self, buffer: &mut Vec<u8>);
            pub fn total(&self) -> isize;
            pub fn length(&self) -> isize;
        }
    }
}

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
            pub fn tags(&self) -> Vec<Tag>;
            pub fn get<P: Field + FieldValueReader>(&self, parser: &mut P) -> MessageRejectErrorResult;
            pub fn has(&self, tag: Tag) -> bool;
            pub fn get_field<P: FieldValueReader>(
                &self,
                tag: Tag,
                parser: &mut P,
            ) -> MessageRejectErrorResult;
            pub fn get_bytes(&self, tag: Tag) -> Result<Vec<u8>, MessageRejectErrorEnum>;
            pub fn get_bool(&self, tag: Tag) -> Result<bool, MessageRejectErrorEnum>;
            pub fn get_int(&self, tag: Tag) -> Result<isize, MessageRejectErrorEnum>;
            pub fn get_time(&self, tag: Tag) -> Result<DateTime<Utc>, MessageRejectErrorEnum>;
            pub fn get_string(&self, tag: Tag) -> Result<String, MessageRejectErrorEnum>;
            pub fn get_group<P: FieldGroupReader>(&self, parser: P) -> MessageRejectErrorResult;
            pub fn set_field<F: FieldValueWriter>(&self, tag: Tag, field: F) -> &FieldMap;
            pub fn set_bytes(&self, tag: Tag, value: &[u8]) -> &FieldMap;
            pub fn set_bool(&self, tag: Tag, value: bool) -> &FieldMap;
            pub fn set_int(&self, tag: Tag, value: isize) -> &FieldMap;
            pub fn set_string(&self, tag: Tag, value: &str) -> &FieldMap;
            pub fn clear(&self);
            pub fn copy_into(&self, to: &mut FieldMap);
            pub fn add(&mut self, f: &LocalField);
            pub fn set<F: FieldWriter>(&self, field: F) -> &FieldMap;
            pub fn set_group<F: FieldGroupWriter>(&mut self, field: F) -> &FieldMap;
            pub fn write(&self, buffer: &mut Vec<u8>);
            pub fn total(&self) -> isize;
            pub fn length(&self) -> isize;
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct Trailer {
    pub field_map: FieldMap,
}

// In the trailer, CheckSum (tag 10) must be last
fn trailer_field_ordering(i: &Tag, j: &Tag) -> Ordering {
    if *i == TAG_CHECK_SUM {
        return Ordering::Greater;
    }
    if *j == TAG_CHECK_SUM {
        return Ordering::Less;
    }
    if i < j {
        return Ordering::Less;
    }
    Ordering::Greater
}

impl Trailer {
    pub fn init() -> Self {
        let field_map = FieldMap::default().init_with_ordering(trailer_field_ordering);
        Trailer { field_map }
    }

    delegate! {
        to self.field_map {
            pub fn tags(&self) -> Vec<Tag>;
            pub fn get<P: Field + FieldValueReader>(&self, parser: &mut P) -> MessageRejectErrorResult;
            pub fn has(&self, tag: Tag) -> bool;
            pub fn get_field<P: FieldValueReader>(
                &self,
                tag: Tag,
                parser: &mut P,
            ) -> MessageRejectErrorResult;
            pub fn get_bytes(&self, tag: Tag) -> Result<Vec<u8>, MessageRejectErrorEnum>;
            pub fn get_bool(&self, tag: Tag) -> Result<bool, MessageRejectErrorEnum>;
            pub fn get_int(&self, tag: Tag) -> Result<isize, MessageRejectErrorEnum>;
            pub fn get_time(&self, tag: Tag) -> Result<DateTime<Utc>, MessageRejectErrorEnum>;
            pub fn get_string(&self, tag: Tag) -> Result<String, MessageRejectErrorEnum>;
            pub fn get_group<P: FieldGroupReader>(&self, parser: P) -> MessageRejectErrorResult;
            pub fn set_field<F: FieldValueWriter>(&self, tag: Tag, field: F) -> &FieldMap;
            pub fn set_bytes(&self, tag: Tag, value: &[u8]) -> &FieldMap;
            pub fn set_bool(&self, tag: Tag, value: bool) -> &FieldMap;
            pub fn set_int(&self, tag: Tag, value: isize) -> &FieldMap;
            pub fn set_string(&self, tag: Tag, value: &str) -> &FieldMap;
            pub fn clear(&self);
            pub fn copy_into(&self, to: &mut FieldMap);
            pub fn add(&mut self, f: &LocalField);
            pub fn set<F: FieldWriter>(&self, field: F) -> &FieldMap;
            pub fn set_group<F: FieldGroupWriter>(&mut self, field: F) -> &FieldMap;
            pub fn write(&self, buffer: &mut Vec<u8>);
            pub fn total(&self) -> isize;
            pub fn length(&self) -> isize;
        }
    }
}

//Message is a FIX Message abstraction.
#[derive(Debug, Default, Clone)]
pub struct Message {
    pub header: Header,
    pub trailer: Trailer,
    pub body: Body,
    // receive_time is the time that this message was read from the socket connection
    pub receive_time: DateTime<Utc>,
    raw_message: Vec<u8>,
    // slice of Bytes corresponding to the message body
    body_bytes: Vec<u8>,
    // field bytes as they appear in the raw message
    pub fields: LocalField,
    // flag is true if this message should not be returned to pool after use
    pub keep_message: bool,
}

impl ToString for Message {
    fn to_string(&self) -> String {
        if !self.raw_message.is_empty() {
            return String::from_utf8_lossy(&self.raw_message).to_string();
        }

        String::from_utf8_lossy(&self.build()).to_string()
    }
}

impl Message {
    pub fn new() -> Self {
        Message {
            header: Header::init(),
            body: Body::init(),
            trailer: Trailer::init(),
            ..Default::default()
        }
    }

    pub fn to_message(self) -> Self {
        self
    }

    pub fn copy_into(&self, to: &mut Message) {
        self.header.copy_into(&mut to.header.field_map);
        self.body.copy_into(&mut to.body.field_map);
        self.trailer.copy_into(&mut to.trailer.field_map);
        to.receive_time = self.receive_time;
        to.body_bytes = self.body_bytes.clone();
        to.fields = self.fields.clone();
    }

    pub fn parse_message(&mut self, raw_message: &[u8]) -> Result<(), ParseError> {
        self.parse_message_with_data_dictionary(raw_message, &None, &None)
    }

    // parse_message_with_data_dictionary constructs a Message from a byte slice wrapping a FIX message using an optional session and application DataDictionary for reference.
    pub fn parse_message_with_data_dictionary(
        &mut self,
        raw_message: &[u8],
        transport_data_dictionary: &Option<DataDictionary>,
        _application_data_dictionary: &Option<DataDictionary>,
    ) -> Result<(), ParseError> {
        self.header.clear();
        self.body.clear();
        self.trailer.clear();
        self.raw_message = raw_message.to_vec();

        // allocate fields in one chunk
        let mut field_count = 0;
        for b in &self.raw_message {
            if *b == 0o001 {
                field_count += 1;
            }
        }

        if field_count == 0 {
            return Err(ParseError {
                orig_error: format!(
                    "No Fields detected in {}",
                    String::from_utf8_lossy(&self.raw_message)
                ),
            });
        }

        if self.fields.capacity() < field_count {
            self.fields = vec![TagValue::default(); field_count];
        } else {
            self.fields = self.fields[0..field_count].to_vec();
        }

        let mut field_index = 0;

        // message must start with begin string, body length, msg type
        let field = self.fields.get_mut(field_index).unwrap();
        let raw_bytes = extract_specific_field(field, TAG_BEGIN_STRING, raw_message)?;

        self.header.add(&vec![field.clone()]);
        field_index += 1;

        let parsed_field_bytes = self.fields.get_mut(field_index).unwrap();
        let raw_bytes = extract_specific_field(parsed_field_bytes, TAG_BODY_LENGTH, &raw_bytes)?;

        self.header.add(&vec![parsed_field_bytes.clone()]);
        field_index += 1;

        let parsed_field_bytes = self.fields.get_mut(field_index).unwrap();
        let mut raw_bytes = extract_specific_field(parsed_field_bytes, TAG_MSG_TYPE, &raw_bytes)?;

        let mut xml_data_len = 0_isize;
        let mut xml_data_msg = false;

        self.header.add(&vec![parsed_field_bytes.clone()]);
        field_index += 1;

        let mut trailer_bytes = vec![];
        let mut found_body = false;

        loop {
            let parsed_field_bytes = self.fields.get_mut(field_index).unwrap();
            raw_bytes = if xml_data_len.is_positive() {
                let raw_bytes =
                    extract_xml_data_field(parsed_field_bytes, &raw_bytes, xml_data_len)?;
                xml_data_len = 0;
                xml_data_msg = true;
                raw_bytes
            } else {
                extract_field(parsed_field_bytes, &raw_bytes)?
            };

            let fields = vec![parsed_field_bytes.clone()];

            if is_header_field(&parsed_field_bytes.tag, transport_data_dictionary) {
                self.header.add(&fields);
            } else if is_trailer_field(&parsed_field_bytes.tag, transport_data_dictionary) {
                self.trailer.add(&fields);
            } else {
                found_body = true;
                trailer_bytes = raw_bytes.clone();
                self.body.add(&fields);
            }

            if parsed_field_bytes.tag == TAG_CHECK_SUM {
                break;
            }

            if !found_body {
                self.body_bytes = raw_bytes.clone();
            }

            if parsed_field_bytes.tag == TAG_XML_DATA_LEN {
                xml_data_len = self.header.get_int(TAG_XML_DATA_LEN).unwrap();
            }

            field_index += 1;
        }

        if self.body_bytes.len() > trailer_bytes.len() {
            self.body_bytes = self
                .body_bytes
                .get(..self.body_bytes.len() - trailer_bytes.len())
                .unwrap()
                .to_vec();
        }

        let mut length = 0;

        for field in self.fields.iter() {
            match field.tag {
                TAG_BEGIN_STRING | TAG_BODY_LENGTH | TAG_CHECK_SUM => continue, // tags do not contribute to length
                _ => length += field.length(),
            }
        }

        let body_length = self
            .header
            .get_int(TAG_BODY_LENGTH)
            .map_err(|e| ParseError {
                orig_error: format!("{}", e),
            });

        if let Ok(bl) = body_length {
            if bl != length && !xml_data_msg {
                return Err(ParseError {
                    orig_error: format!(
                        "Incorrect Message Length, expected {} , got {}",
                        bl, length
                    ),
                });
            }
        }

        Ok(())
    }

    // MsgType returns MsgType (tag 35) field's value
    pub fn msg_type(&self) -> Result<String, MessageRejectErrorEnum> {
        self.header.get_string(TAG_MSG_TYPE)
    }

    // is_msg_type_of returns true if the Header contains MsgType (tag 35) field and its value is the specified one.
    fn is_msg_type_of(&self, msg_type: &str) -> bool {
        let v = self.msg_type();
        if let Ok(w_unwrap) = v {
            return w_unwrap == msg_type;
        }
        false
    }

    // reverseRoute returns a message builder with routing header fields initialized as the reverse of this message.
    pub fn reverse_route(&self) -> Message {
        let reverse_msg = Message::default();

        let copy = |src: Tag, dest: Tag| {
            let mut field = FIXString::new();
            let get_field = self.header.get_field(src, &mut field);
            if get_field.is_ok() && !field.is_empty() {
                reverse_msg.header.set_field(dest, field);
            }
        };

        copy(TAG_SENDER_COMP_ID, TAG_TARGET_COMP_ID);
        copy(TAG_SENDER_SUB_ID, TAG_TARGET_SUB_ID);
        copy(TAG_SENDER_LOCATION_ID, TAG_TARGET_LOCATION_ID);

        copy(TAG_TARGET_COMP_ID, TAG_SENDER_COMP_ID);
        copy(TAG_TARGET_SUB_ID, TAG_SENDER_SUB_ID);
        copy(TAG_TARGET_LOCATION_ID, TAG_SENDER_LOCATION_ID);

        copy(TAG_ON_BEHALF_OF_COMP_ID, TAG_DELIVER_TO_COMP_ID);
        copy(TAG_ON_BEHALF_OF_SUB_ID, TAG_DELIVER_TO_SUB_ID);
        copy(TAG_DELIVER_TO_COMP_ID, TAG_ON_BEHALF_OF_COMP_ID);
        copy(TAG_DELIVER_TO_SUB_ID, TAG_ON_BEHALF_OF_SUB_ID);

        // tags added in 4.1
        let mut begin_string = FIXString::new();
        let get_field = self.header.get_field(TAG_BEGIN_STRING, &mut begin_string);
        if get_field.is_ok() && begin_string != BEGIN_STRING_FIX40 {
            copy(TAG_ON_BEHALF_OF_LOCATION_ID, TAG_DELIVER_TO_LOCATION_ID);
            copy(TAG_DELIVER_TO_LOCATION_ID, TAG_ON_BEHALF_OF_LOCATION_ID);
        }

        reverse_msg
    }

    // build constructs a []byte from a Message instance
    pub fn build(&self) -> Vec<u8> {
        self.cook();

        let mut b = vec![];
        self.header.write(&mut b);
        self.body.write(&mut b);
        self.trailer.write(&mut b);
        b
    }

    fn cook(&self) {
        let body_length = self.header.length() + self.body.length() + self.trailer.length();
        self.header.set_int(TAG_BODY_LENGTH, body_length);
        let check_sum = (self.header.total() + self.body.total() + self.trailer.total()) % 256;
        self.trailer
            .set_string(TAG_CHECK_SUM, &format_check_sum(check_sum));
    }
}

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

fn is_header_field(tag: &Tag, data_dict: &Option<DataDictionary>) -> bool {
    if tag.is_header() {
        return true;
    }

    if data_dict.is_none() {
        return false;
    }

    data_dict.as_ref().unwrap().header.fields.contains_key(tag)
}

fn is_trailer_field(tag: &Tag, data_dict: &Option<DataDictionary>) -> bool {
    if tag.is_trailer() {
        return true;
    }

    if data_dict.is_none() {
        return false;
    }

    data_dict.as_ref().unwrap().trailer.fields.contains_key(tag)
}

fn extract_specific_field(
    field: &mut TagValue,
    expected_tag: Tag,
    buffer: &[u8],
) -> Result<Vec<u8>, ParseError> {
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

fn extract_xml_data_field(
    parsed_field_bytes: &mut TagValue,
    buffer: &[u8],
    data_len: isize,
) -> Result<Vec<u8>, ParseError> {
    let mut end_index = buffer.iter().position(|x| *x == b'=').ok_or(ParseError {
        orig_error: format!(
            "extract_field: No Trailing Delim in {}",
            String::from_utf8_lossy(buffer).as_ref()
        ),
    })?;
    end_index += data_len as usize + 1;
    let buffer_slice = buffer.get(..(end_index + 1)).unwrap();
    parsed_field_bytes
        .parse(buffer_slice)
        .map_err(|err| ParseError { orig_error: err })?;

    Ok(buffer.get((end_index + 1)..).unwrap().to_vec())
}

fn extract_field(parsed_field_bytes: &mut TagValue, buffer: &[u8]) -> Result<Vec<u8>, ParseError> {
    let end_index = buffer.iter().position(|x| *x == 1).ok_or(ParseError {
        orig_error: format!(
            "extract_field: No Trailing Delim in {}",
            String::from_utf8_lossy(buffer).as_ref()
        ),
    })?;
    let buffer_slice = buffer.get(..(end_index + 1)).unwrap();
    parsed_field_bytes
        .parse(buffer_slice)
        .map_err(|err| ParseError { orig_error: err })?;
    Ok(buffer.get((end_index + 1)..).unwrap().to_vec())
}

fn format_check_sum(value: isize) -> String {
    format!("{:03}", value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::datadictionary::{DataDictionary, FieldDef, MessageDef};
    use crate::fixer_test::{FieldEqual, FixerSuite};
    use crate::tag::Tag;
    use crate::BEGIN_STRING_FIX44;
    use delegate::delegate;
    use std::collections::HashMap;

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
                fn field_equals<'a>(&self, tag: Tag, expected_value: FieldEqual<'a>, field_map: &FieldMap) ;
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

        let expected_body_bytes = "11=10021=140=154=155=TSLA60=00010101-00:00:00.000".as_bytes();
        assert_eq!(
            &s.msg.body_bytes,
            expected_body_bytes,
            "Incorrect body bytes, got {}",
            String::from_utf8_lossy(&s.msg.body_bytes)
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
        let mut dict = DataDictionary::default();
        dict.header = MessageDef::default();
        let mut hd_fields = HashMap::<isize, FieldDef>::default();
        let hd_fd = FieldDef::default();
        hd_fields.insert(10030, hd_fd);
        dict.header.fields = hd_fields;

        let mut tr_fields = HashMap::<isize, FieldDef>::default();
        let tr_fd = FieldDef::default();
        tr_fields.insert(5050, tr_fd);
        dict.trailer.fields = tr_fields;

        let raw_message = "8=FIX.4.29=12635=D34=249=TW52=20140515-19:49:56.65956=ISLD10030=CUST11=10021=140=154=155=TSLA60=00010101-00:00:00.0005050=HELLO10=039".as_bytes();

        let dict_ref = &Some(dict);

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
        assert!(parse_result.is_ok())
    }

    #[test]
    fn test_build() {
        let s = setup_test();
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
            String::from_utf8_lossy(&result)
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
            String::from_utf8_lossy(&rebuild_bytes),
            String::from_utf8_lossy(expected_bytes),
        );

        let expected_body_bytes = "11=10021=140=154=155=TSLA60=00010101-00:00:00.000".as_bytes();

        assert_eq!(
            &s.msg.body_bytes,
            expected_body_bytes,
            "Incorrect body bytes, got {}",
            String::from_utf8_lossy(&s.msg.body_bytes)
        );
    }

    #[test]
    fn test_reverse_route() {
        let mut s = setup_test();
        let raw_message = "8=FIX.4.29=17135=D34=249=TW50=KK52=20060102-15:04:0556=ISLD57=AP144=BB115=JCD116=CS128=MG129=CB142=JV143=RY145=BH11=ID21=338=10040=w54=155=INTC60=20060102-15:04:0510=123".as_bytes();

        let parse_result = s.msg.parse_message(raw_message);
        assert!(parse_result.is_ok());

        let builder = s.msg.reverse_route();

        struct TestCase<'a> {
            tag: Tag,
            expected_value: &'a str,
        }
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

        for tc in tests.iter() {
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

        check_field_int(&s, &dest.header.field_map, TAG_MSG_SEQ_NUM as isize, 2);
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

        assert!(&dest.is_msg_type_of("D"));
        assert_eq!(&dest.to_string(), rendered_string);
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
