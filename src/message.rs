use crate::{
    datadictionary::DataDictionary,
    errors::MessageRejectErrorTrait,
    field_map::{FieldMap, LocalField},
    fix_string::FIXString,
    tag::*,
    tag_value::TagValue,
    BEGIN_STRING_FIX40,
};
use chrono::NaiveDateTime;
use std::{
    cmp::Ordering,
    error::Error,
    fmt::{Display, Formatter},
    string::ToString,
};

#[derive(Debug, Default)]
pub struct Header {
    pub field_map: FieldMap,
}

// in the message header, the first 3 tags in the message header must be 8,9,35
pub fn header_field_ordering(i: &Tag, j: &Tag) -> Ordering {
    fn ordering(t: &Tag) -> u32 {
        match *t {
            TAG_BEGIN_STRING => 1,
            TAG_BODY_LENGTH => 2,
            TAG_MSG_TYPE => 3,
            _ => u32::MAX,
        }
    }

    let orderi = ordering(i);
    let orderj = ordering(j);

    if orderi < orderj {
        return Ordering::Less;
    }
    if orderi > orderj {
        return Ordering::Greater;
    }

    if i < j {
        return Ordering::Less;
    }

    Ordering::Greater
}

impl Header {
    pub fn init() -> Self {
        let field_map = FieldMap::init_with_ordering(header_field_ordering);
        Header { field_map }
    }
}

#[derive(Debug, Default)]
pub struct Body {
    pub field_map: FieldMap,
}

impl Body {
    pub fn init() -> Self {
        let field_map = FieldMap::init();
        Body { field_map }
    }
}

#[derive(Debug, Default)]
pub struct Trailer {
    pub field_map: FieldMap,
}

// In the trailer, CheckSum (tag 10) must be last
fn trailer_field_ordering(i: &Tag, j: &Tag) -> Ordering {
    if *i == TAG_CHECK_SUM {
        return Ordering::Less;
    }
    if *j == TAG_CHECK_SUM {
        return Ordering::Greater;
    }
    if i < j {
        return Ordering::Less;
    }
    Ordering::Greater
}

impl Trailer {
    pub fn init() -> Self {
        let field_map = FieldMap::init_with_ordering(trailer_field_ordering);
        Trailer { field_map }
    }
}

//Message is a FIX Message abstraction.
#[derive(Debug, Default)]
pub struct Message {
    pub header: Header,
    pub trailer: Trailer,
    pub body: Body,
    // receive_time is the time that this message was read from the socket connection
    pub receive_time: NaiveDateTime,
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
            return todo!();
        }

        // self.build()
        todo!()
    }
}

impl Message {
    pub fn new() -> Self {
        Message {
            header: Header::default(),
            body: Body::default(),
            trailer: Trailer::default(),
            ..Default::default()
        }
    }

    pub fn to_message(self) -> Self {
        self
    }

    pub fn copy_into(&mut self, to: &mut Message) {
        self.header.field_map.copy_into(&mut to.header.field_map);
        self.body.field_map.copy_into(&mut to.body.field_map);
        self.trailer.field_map.copy_into(&mut to.trailer.field_map);
        to.receive_time = self.receive_time;
        to.body_bytes = self.body_bytes.clone();
        to.fields = self.fields.clone();
    }

    pub fn parse_message(&mut self, raw_message: &[u8]) -> Result<(), ParseError> {
        self.parse_message_with_data_dictionary(raw_message, None, None)
    }

    // parse_message_with_data_dictionary constructs a Message from a byte slice wrapping a FIX message using an optional session and application DataDictionary for reference.
    pub fn parse_message_with_data_dictionary(
        &mut self,
        raw_message: &[u8],
        transport_data_dictionary: Option<&DataDictionary>,
        application_data_dictionary: Option<&DataDictionary>,
    ) -> Result<(), ParseError> {
        self.header.field_map.clear();
        self.body.field_map.clear();
        self.trailer.field_map.clear();
        self.raw_message = raw_message.to_vec();

        // allocate fields in one chunk
        let mut field_count = 0;
        for b in self.raw_message.iter() {
            if *b as i32 == 0o001 {
                field_count += 1;
            }
        }

        if field_count == 0 {
            return Err(ParseError {
                orig_error: format!(
                    "No Fields detected in {}",
                    String::from_utf8_lossy(&self.raw_message).as_ref()
                ),
            });
        }

        self.fields = vec![TagValue::default(); field_count];

        let mut field_index = 0;

        // message must start with begin string, body length, msg type
        let field = self.fields.get_mut(field_index).unwrap();
        let raw_bytes = extract_specific_field(field, TAG_BEGIN_STRING, &self.raw_message)?;

        self.header.field_map.add(
            self.fields
                .get(field_index..field_index + 1)
                .unwrap()
                .to_vec(),
        );
        field_index += 1;

        let parsed_field_bytes = self.fields.get_mut(field_index).unwrap();
        let raw_bytes = extract_specific_field(parsed_field_bytes, TAG_BODY_LENGTH, &raw_bytes)?;

        self.header.field_map.add(
            self.fields
                .get(field_index..field_index + 1)
                .unwrap()
                .to_vec(),
        );
        field_index += 1;

        let mut parsed_field_bytes = self.fields.get_mut(field_index).unwrap();
        let raw_bytes = extract_specific_field(parsed_field_bytes, TAG_MSG_TYPE, &raw_bytes)?;

        let mut tag = parsed_field_bytes.tag.clone();

        self.header.field_map.add(
            self.fields
                .get(field_index..field_index + 1)
                .unwrap()
                .to_vec(),
        );
        field_index += 1;

        let mut trailer_bytes = vec![];
        let mut found_body = false;

        while tag != TAG_CHECK_SUM {
            parsed_field_bytes = self.fields.get_mut(field_index).unwrap();
            let raw_bytes = extract_field(parsed_field_bytes, &raw_bytes)?;

            let fields = self
                .fields
                .clone()
                .get(field_index..field_index + 1)
                .unwrap()
                .to_vec();

            if is_header_field(&tag, transport_data_dictionary) {
                self.header.field_map.add(fields);
            } else if is_trailer_field(&tag, transport_data_dictionary) {
                self.trailer.field_map.add(fields);
            } else {
                found_body = true;
                trailer_bytes = raw_bytes.clone();
                self.body.field_map.add(fields);
            }

            tag = parsed_field_bytes.tag.clone();

            if !found_body {
                self.body_bytes = raw_bytes.clone();
            }

            field_index += 1;
        }

        if self.body_bytes.len() > trailer_bytes.len() {
            self.body_bytes =
                self.body_bytes[..self.body_bytes.len() - trailer_bytes.len()].to_vec();
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
            .field_map
            .get_int(TAG_BODY_LENGTH)
            .map_err(|e| ParseError {
                orig_error: format!("{}", e),
            });

        if let Ok(bl) = body_length {
            if bl != length {
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
    pub fn msg_type(&self) -> Result<String, Box<dyn MessageRejectErrorTrait>> {
        self.header.field_map.get_string(TAG_MSG_TYPE)
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
    fn reverse_route(&self) -> Message {
        let mut reverse_msg = Message::default();

        let mut copy = |src: Tag, dest: Tag| {
            let mut field = FIXString::new();
            let get_field = self.header.field_map.get_field(src, &mut field);
            if get_field.is_ok() && !field.is_empty() {
                reverse_msg.header.field_map.set_field(dest, field);
            }
        };

        copy(TAG_SENDER_COMP_ID, TAG_TARGET_COMP_ID);
        copy(TAG_SENDER_SUB_ID, TAG_TARGET_SUB_ID);
        copy(TAG_SENDER_LOCATION_ID, TAG_TARGET_LOCATION_ID);

        copy(TAG_TARGET_COMP_ID, TAG_SENDER_COMP_ID);
        copy(TAG_TARGET_SUB_ID, TAG_SENDER_COMP_ID);
        copy(TAG_TARGET_LOCATION_ID, TAG_SENDER_LOCATION_ID);

        copy(TAG_ON_BEHALF_OF_COMP_ID, TAG_DELIVER_TO_COMP_ID);
        copy(TAG_ON_BEHALF_OF_SUB_ID, TAG_DELIVER_TO_SUB_ID);
        copy(TAG_DELIVER_TO_COMP_ID, TAG_ON_BEHALF_OF_COMP_ID);
        copy(TAG_DELIVER_TO_SUB_ID, TAG_ON_BEHALF_OF_SUB_ID);

        // tags added in 4.1
        let mut begin_string = FIXString::new();
        let get_field = self
            .header
            .field_map
            .get_field(TAG_BEGIN_STRING, &mut begin_string);
        if get_field.is_ok() && begin_string != BEGIN_STRING_FIX40 {
            copy(TAG_ON_BEHALF_OF_LOCATION_ID, TAG_DELIVER_TO_LOCATION_ID);
            copy(TAG_DELIVER_TO_LOCATION_ID, TAG_ON_BEHALF_OF_LOCATION_ID);
        }

        reverse_msg
    }

    // build constructs a []byte from a Message instance
    pub fn build(&mut self) -> Vec<u8> {
        self.cook();

        let mut b = vec![];
        self.header.field_map.write(&mut b);
        self.body.field_map.write(&mut b);
        self.trailer.field_map.write(&mut b);
        b
    }

    fn cook(&mut self) {
        let body_length = self.header.field_map.length()
            + self.body.field_map.length()
            + self.trailer.field_map.length();
        self.header.field_map.set_int(TAG_BODY_LENGTH, body_length);
        let check_sum = (self.header.field_map.total()
            + self.body.field_map.total()
            + self.trailer.field_map.total())
            % 256;
        self.trailer
            .field_map
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

fn is_header_field(tag: &Tag, data_dict: Option<&DataDictionary>) -> bool {
    if tag.is_header() {
        return true;
    }

    if data_dict.is_none() {
        return false;
    }

    data_dict.unwrap().header.fields.contains_key(tag)
}

fn is_trailer_field(tag: &Tag, data_dict: Option<&DataDictionary>) -> bool {
    if tag.is_trailer() {
        return true;
    }

    if data_dict.is_none() {
        return false;
    }

    data_dict.unwrap().trailer.fields.contains_key(tag)
}

fn extract_specific_field(
    field: &mut TagValue,
    expected_tag: Tag,
    buffer: &[u8],
) -> Result<Vec<u8>, ParseError> {
    let rem_buffer = extract_field(field, &buffer)?;
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

fn extract_field(parsed_field_bytes: &mut TagValue, buffer: &[u8]) -> Result<Vec<u8>, ParseError> {
    let end_index = buffer.iter().position(|x| *x == 0o001).ok_or(ParseError {
        orig_error: format!(
            "extract_field: No Trailing Delim in {}",
            String::from_utf8_lossy(&buffer).as_ref()
        ),
    })?;
    parsed_field_bytes
        .parse(&buffer[..end_index + 1])
        .map_err(|err| ParseError { orig_error: err })?;
    Ok(buffer.get((end_index + 1)..).unwrap().to_vec())
}

fn format_check_sum(value: isize) -> String {
    format!("{:03}", value)
}

#[cfg(test)]
mod tests {
    use super::*;
    //     "bytes"
    //     "reflect"
    //     "testing"

    //     "github.com/stretchr/testify/suite"

    //     "github.com/quickfixgo/quickfix/datadictionary"

    // #[test]
    // fn benchmark_parse_message(b *testing.B) {
    // 	rawMsg := bytes.NewBufferString("8=FIX.4.29=10435=D34=249=TW52=20140515-19:49:56.65956=ISLD11=10021=140=154=155=TSLA60=00010101-00:00:00.00010=039")

    // 	var msg Message
    // 	for i := 0; i < b.N; i++ {
    // 		_ = ParseMessage(&msg, rawMsg)
    // 	}
    // }

    // type MessageSuite struct {
    // 	QuickFIXSuite
    // 	msg *Message
    // }

    // #[test]
    // fn test_message_suite(t *testing.T) {
    // 	suite.Run(t, new(MessageSuite))
    // }

    // #[test]
    // fn (s *MessageSuite) SetupTest() {
    // 	s.msg = NewMessage()
    // }

    // #[test]
    // fn (s *MessageSuite) TestParseMessageEmpty() {
    // 	rawMsg := bytes.NewBufferString("")

    // 	err := ParseMessage(s.msg, rawMsg)
    // 	s.NotNil(err)
    // }

    // #[test]
    // fn (s *MessageSuite) TestParseMessage() {
    // 	rawMsg := bytes.NewBufferString("8=FIX.4.29=10435=D34=249=TW52=20140515-19:49:56.65956=ISLD11=10021=140=154=155=TSLA60=00010101-00:00:00.00010=039")

    // 	err := ParseMessage(s.msg, rawMsg)
    // 	s.Nil(err)

    // 	s.True(bytes.Equal(rawMsg.Bytes(), s.msg.rawMessage.Bytes()), "Expected msg bytes to equal raw bytes")

    // 	expectedBodyBytes := []byte("11=10021=140=154=155=TSLA60=00010101-00:00:00.000")

    // 	s.True(bytes.Equal(s.msg.bodyBytes, expectedBodyBytes), "Incorrect body bytes, got %s", string(s.msg.bodyBytes))

    // 	s.Equal(14, len(s.msg.fields))

    // 	msgType, err := s.msg.MsgType()
    // 	s.Nil(err)

    // 	s.Equal("D", msgType)
    // 	s.True(s.msg.IsMsgTypeOf("D"))

    // 	s.False(s.msg.IsMsgTypeOf("A"))
    // }

    // #[test]
    // fn (s *MessageSuite) TestParseMessageWithDataDictionary() {
    // 	dict := new(datadictionary.DataDictionary)
    // 	dict.Header = &datadictionary.MessageDef{
    // 		Fields: map[int]*datadictionary.FieldDef{
    // 			10030: nil,
    // 		},
    // 	}
    // 	dict.Trailer = &datadictionary.MessageDef{
    // 		Fields: map[int]*datadictionary.FieldDef{
    // 			5050: nil,
    // 		},
    // 	}
    // 	rawMsg := bytes.NewBufferString("8=FIX.4.29=12635=D34=249=TW52=20140515-19:49:56.65956=ISLD10030=CUST11=10021=140=154=155=TSLA60=00010101-00:00:00.0005050=HELLO10=039")

    // 	err := ParseMessageWithDataDictionary(s.msg, rawMsg, dict, dict)
    // 	s.Nil(err)
    // 	s.FieldEquals(Tag(10030), "CUST", s.msg.Header)
    // 	s.FieldEquals(Tag(5050), "HELLO", s.msg.Trailer)
    // }

    // #[test]
    // fn (s *MessageSuite) TestParseOutOfOrder() {
    // 	//allow fields out of order, save for validation
    // 	rawMsg := bytes.NewBufferString("8=FIX.4.09=8135=D11=id21=338=10040=154=155=MSFT34=249=TW52=20140521-22:07:0956=ISLD10=250")
    // 	s.Nil(ParseMessage(s.msg, rawMsg))
    // }

    // #[test]
    // fn (s *MessageSuite) TestBuild() {
    // 	s.msg.Header.SetField(tagBeginString, FIXString(BeginStringFIX44))
    // 	s.msg.Header.SetField(tagMsgType, FIXString("A"))
    // 	s.msg.Header.SetField(tagSendingTime, FIXString("20140615-19:49:56"))

    // 	s.msg.Body.SetField(Tag(553), FIXString("my_user"))
    // 	s.msg.Body.SetField(Tag(554), FIXString("secret"))

    // 	expectedBytes := []byte("8=FIX.4.49=4935=A52=20140615-19:49:56553=my_user554=secret10=072")
    // 	result := s.msg.build()
    // 	s.True(bytes.Equal(expectedBytes, result), "Unexpected bytes, got %s", string(result))
    // }

    // #[test]
    // fn (s *MessageSuite) TestReBuild() {
    // 	rawMsg := bytes.NewBufferString("8=FIX.4.29=10435=D34=249=TW52=20140515-19:49:56.65956=ISLD11=10021=140=154=155=TSLA60=00010101-00:00:00.00010=039")

    // 	s.Nil(ParseMessage(s.msg, rawMsg))

    // 	s.msg.Header.SetField(tagOrigSendingTime, FIXString("20140515-19:49:56.659"))
    // 	s.msg.Header.SetField(tagSendingTime, FIXString("20140615-19:49:56"))

    // 	rebuildBytes := s.msg.build()

    // 	expectedBytes := []byte("8=FIX.4.29=12635=D34=249=TW52=20140615-19:49:5656=ISLD122=20140515-19:49:56.65911=10021=140=154=155=TSLA60=00010101-00:00:00.00010=128")

    // 	s.True(bytes.Equal(expectedBytes, rebuildBytes), "Unexpected bytes,\n +%s\n-%s", rebuildBytes, expectedBytes)

    // 	expectedBodyBytes := []byte("11=10021=140=154=155=TSLA60=00010101-00:00:00.000")

    // 	s.True(bytes.Equal(s.msg.bodyBytes, expectedBodyBytes), "Incorrect body bytes, got %s", string(s.msg.bodyBytes))
    // }

    // #[test]
    // fn (s *MessageSuite) TestReverseRoute() {
    // 	s.Nil(ParseMessage(s.msg, bytes.NewBufferString("8=FIX.4.29=17135=D34=249=TW50=KK52=20060102-15:04:0556=ISLD57=AP144=BB115=JCD116=CS128=MG129=CB142=JV143=RY145=BH11=ID21=338=10040=w54=155=INTC60=20060102-15:04:0510=123")))

    // 	builder := s.msg.reverseRoute()

    // 	var testCases = []struct {
    // 		tag           Tag
    // 		expectedValue string
    // 	}{
    // 		{tagTargetCompID, "TW"},
    // 		{tagTargetSubID, "KK"},
    // 		{tagTargetLocationID, "JV"},
    // 		{tagSenderCompID, "ISLD"},
    // 		{tagSenderSubID, "AP"},
    // 		{tagSenderLocationID, "RY"},
    // 		{tagDeliverToCompID, "JCD"},
    // 		{tagDeliverToSubID, "CS"},
    // 		{tagDeliverToLocationID, "BB"},
    // 		{tagOnBehalfOfCompID, "MG"},
    // 		{tagOnBehalfOfSubID, "CB"},
    // 		{tagOnBehalfOfLocationID, "BH"},
    // 	}

    // 	for _, tc := range testCases {
    // 		var field FIXString
    // 		s.Nil(builder.Header.GetField(tc.tag, &field))

    // 		s.Equal(tc.expectedValue, string(field))
    // 	}
    // }

    // #[test]
    // fn (s *MessageSuite) TestReverseRouteIgnoreEmpty() {
    // 	s.Nil(ParseMessage(s.msg, bytes.NewBufferString("8=FIX.4.09=12835=D34=249=TW52=20060102-15:04:0556=ISLD115=116=CS128=MG129=CB11=ID21=338=10040=w54=155=INTC60=20060102-15:04:0510=123")))
    // 	builder := s.msg.reverseRoute()

    // 	s.False(builder.Header.Has(tagDeliverToCompID), "Should not reverse if empty")
    // }

    // #[test]
    // fn (s *MessageSuite) TestReverseRouteFIX40() {
    // 	//onbehalfof/deliverto location id not supported in fix 4.0
    // 	s.Nil(ParseMessage(s.msg, bytes.NewBufferString("8=FIX.4.09=17135=D34=249=TW50=KK52=20060102-15:04:0556=ISLD57=AP144=BB115=JCD116=CS128=MG129=CB142=JV143=RY145=BH11=ID21=338=10040=w54=155=INTC60=20060102-15:04:0510=123")))

    // 	builder := s.msg.reverseRoute()

    // 	s.False(builder.Header.Has(tagDeliverToLocationID), "delivertolocation id not supported in fix40")

    // 	s.False(builder.Header.Has(tagOnBehalfOfLocationID), "onbehalfof location id not supported in fix40")
    // }

    // #[test]
    // fn (s *MessageSuite) TestCopyIntoMessage() {
    // 	msgString := "8=FIX.4.29=17135=D34=249=TW50=KK52=20060102-15:04:0556=ISLD57=AP144=BB115=JCD116=CS128=MG129=CB142=JV143=RY145=BH11=ID21=338=10040=w54=155=INTC60=20060102-15:04:0510=123"
    // 	msgBuf := bytes.NewBufferString(msgString)
    // 	s.Nil(ParseMessage(s.msg, msgBuf))

    // 	dest := NewMessage()
    // 	s.msg.CopyInto(dest)

    // 	checkFieldInt(s, dest.Header.FieldMap, int(tagMsgSeqNum), 2)
    // 	checkFieldInt(s, dest.Body.FieldMap, 21, 3)
    // 	checkFieldString(s, dest.Body.FieldMap, 11, "ID")
    // 	s.Equal(len(dest.bodyBytes), len(s.msg.bodyBytes))

    // 	// copying decouples the message from its input buffer, so the raw message will be re-rendered
    // 	renderedString := "8=FIX.4.29=17135=D34=249=TW50=KK52=20060102-15:04:0556=ISLD57=AP115=JCD116=CS128=MG129=CB142=JV143=RY144=BB145=BH11=ID21=338=10040=w54=155=INTC60=20060102-15:04:0510=033"
    // 	s.Equal(dest.String(), renderedString)

    // 	s.True(reflect.DeepEqual(s.msg.bodyBytes, dest.bodyBytes))
    // 	s.True(s.msg.IsMsgTypeOf("D"))
    // 	s.Equal(s.msg.ReceiveTime, dest.ReceiveTime)

    // 	s.True(reflect.DeepEqual(s.msg.fields, dest.fields))

    // 	// update the source message to validate the copy is truly deep
    // 	newMsgString := "8=FIX.4.49=4935=A52=20140615-19:49:56553=my_user554=secret10=072"
    // 	s.Nil(ParseMessage(s.msg, bytes.NewBufferString(newMsgString)))
    // 	s.True(s.msg.IsMsgTypeOf("A"))
    // 	s.Equal(s.msg.String(), newMsgString)

    // 	// clear the source buffer also
    // 	msgBuf.Reset()

    // 	s.True(dest.IsMsgTypeOf("D"))
    // 	s.Equal(dest.String(), renderedString)
    // }

    // #[test]
    // fn check_field_int(s *MessageSuite, fields FieldMap, tag, expected int) {
    // 	toCheck, _ := fields.GetInt(Tag(tag))
    // 	s.Equal(expected, toCheck)
    // }

    // #[test]
    // fn check_field_string(s *MessageSuite, fields FieldMap, tag int, expected string) {
    // 	toCheck, err := fields.GetString(Tag(tag))
    // 	s.NoError(err)
    // 	s.Equal(expected, toCheck)
    // }
}
