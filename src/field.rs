use crate::errors::MessageRejectErrorEnum;
use crate::fix_boolean::FIXBoolean;
use crate::{field_map::LocalField, tag::Tag};
use simple_error::SimpleResult;

pub trait FieldTag {
    fn tag(&self) -> Tag;
}

// FieldValueWriter is an interface for writing field values
pub trait FieldValueWriter {
    // write writes out the contents of the FieldValue to a []byte
    fn write(&self) -> Vec<u8>;
}

// FieldValueReader is an interface for reading field values
pub trait FieldValueReader {
    // read reads the contents of the []byte into FieldValue.
    // returns an error if there are issues in the data processing
    fn read(&mut self, input: &[u8]) -> SimpleResult<()>;
}

// The FieldValue interface is used to write/extract typed field values to/from raw bytes
pub trait FieldValue: FieldValueWriter + FieldValueReader {}

// FieldWriter is an interface for a writing a field
pub trait FieldWriter: FieldValueWriter + FieldTag {}

// Field is the interface implemented by all typed Fields in a Message
pub trait Field: FieldWriter + FieldValueReader {}

// FieldGroupWriter is an interface for writing a FieldGroup
pub trait FieldGroupWriter: FieldTag {
    fn write(&self) -> LocalField;
}

// FieldGroupReader is an interface for reading a FieldGroup
pub trait FieldGroupReader: FieldTag {
    fn read(&mut self, tag_value: LocalField) -> Result<LocalField, MessageRejectErrorEnum>;
}

// FieldGroup is the interface implemented by all typed Groups in a Message
pub trait FieldGroup: FieldTag + FieldGroupWriter + FieldGroupReader {}

impl dyn FieldValue {
    pub fn default() -> Box<dyn FieldValue + Send> {
        Box::<FIXBoolean>::default()
    }
}
