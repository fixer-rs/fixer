use crate::field::{FieldValue, FieldValueReader, FieldValueWriter};

// FIXBytes is a generic FIX field value, implements FieldValue.  Enables zero copy read from a FieldMap
type FIXBytes = Vec<u8>;

// func (f FIXBytes) Write() []byte {
// 	return []byte(f)
// }
impl FieldValueReader for FIXBytes {
    fn read(&mut self, input: &[u8]) -> Result<(), ()> {
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
