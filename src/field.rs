use crate::{tag::Tag, tag_value::TagValue};
use std::error::Error;

// FieldValueWriter is an interface for writing field values
pub trait FieldValueWriter {
    // write writes out the contents of the FieldValue to a []byte
    fn write(&self) -> String;
}

// FieldValueReader is an interface for reading field values
pub trait FieldValueReader {
    // read reads the contents of the []byte into FieldValue.
    // returns an error if there are issues in the data processing
    fn read(&mut self, input: &str) -> Result<(), ()>;
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
    fn write(&self) -> Vec<TagValue>;
}

// FieldGroupReader is an interface for reading a FieldGroup
pub trait FieldGroupReader<T: Error> {
    fn tag(&self) -> Tag;
    fn read(tag_value: Vec<TagValue>) -> Result<Vec<TagValue>, T>;
}

// FieldGroup is the interface implemented by all typed Groups in a Message
pub trait FieldGroup<T: Error> {
    fn tag(&self) -> Tag;
    fn write(&self) -> Vec<TagValue>;
    fn read(tag_value: Vec<TagValue>) -> Result<Vec<TagValue>, T>;
}
