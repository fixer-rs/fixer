use crate::errors::MessageRejectErrorEnum;
use crate::fix_boolean::FIXBoolean;
use crate::{field_map::LocalField, tag::Tag};
use simple_error::SimpleError;

// FieldValueWriter is an interface for writing field values
pub trait FieldValueWriter {
    // write writes out the contents of the FieldValue to a []byte
    fn write(&self) -> Vec<u8>;
}

// FieldValueReader is an interface for reading field values
pub trait FieldValueReader {
    // read reads the contents of the []byte into FieldValue.
    // returns an error if there are issues in the data processing
    fn read(&mut self, input: &[u8]) -> Result<(), SimpleError>;
}

// The FieldValue interface is used to write/extract typed field values to/from raw bytes
pub trait FieldValue: FieldValueWriter + FieldValueReader {}

// FieldWriter is an interface for a writing a field
pub trait FieldWriter: FieldValueWriter {
    fn tag(&self) -> Tag;
}

// Field is the interface implemented by all typed Fields in a Message
pub trait Field: FieldWriter + FieldValueReader {}

// FieldGroupWriter is an interface for writing a FieldGroup
pub trait FieldGroupWriter {
    fn tag(&self) -> Tag;
    fn write(&self) -> LocalField;
}

// FieldGroupReader is an interface for reading a FieldGroup
pub trait FieldGroupReader {
    fn tag(&self) -> Tag;
    fn read(&self, tag_value: &LocalField) -> Result<LocalField, MessageRejectErrorEnum>;
}

// FieldGroup is the interface implemented by all typed Groups in a Message
pub trait FieldGroup {
    fn tag(&self) -> Tag;
    fn write(&self) -> LocalField;
    fn read(&self, tag_value: &LocalField) -> Result<LocalField, MessageRejectErrorEnum>;
}

impl dyn FieldValue {
    pub fn default() -> Box<dyn FieldValue + Send> {
        Box::<FIXBoolean>::default()
    }
}
