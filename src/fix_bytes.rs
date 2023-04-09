use crate::field::{FieldValue, FieldValueReader, FieldValueWriter};
use simple_error::SimpleError;

// FIXBytes is a generic FIX field value, implements FieldValue.  Enables zero copy read from a FieldMap
type FIXBytes = Vec<u8>;

impl FieldValueReader for FIXBytes {
    fn read(&mut self, input: &[u8]) -> Result<(), SimpleError> {
        *self = input.to_vec();
        Ok(())
    }
}

impl FieldValueWriter for FIXBytes {
    fn write(&self) -> Vec<u8> {
        self.clone()
    }
}

impl FieldValue for FIXBytes {}
