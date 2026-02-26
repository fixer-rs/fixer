use crate::field::{FieldValue, FieldValueReader, FieldValueWriter};
use simple_error::SimpleResult;

// FIXBytes is a generic FIX field value, implements FieldValue.  Enables zero copy read from a FieldMap
pub type FIXBytes = Vec<u8>;

impl FieldValueReader for FIXBytes {
    fn read(&mut self, input: &[u8]) -> SimpleResult<()> {
        *self = input.to_vec();
        Ok(())
    }
}

impl FieldValueWriter for FIXBytes {
    fn write_to(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self);
    }
}

impl FieldValue for FIXBytes {}
