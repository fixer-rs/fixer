use crate::field::{FieldValue, FieldValueReader, FieldValueWriter};

// FIXString is a FIX String Value, implements FieldValue
type FIXString = String;

pub trait FIXStringTrait {
    fn string(&self) -> String;
}

impl FIXStringTrait for FIXString {
    fn string(&self) -> String {
        self.to_string()
    }
}

impl FieldValueReader for FIXString {
    fn read(&mut self, input: &str) -> Result<(), ()> {
        self.clear();
        self.push_str(input);
        Ok(())
    }
}

impl FieldValueWriter for FIXString {
    fn write(&self) -> String {
        self.to_string()
    }
}

impl FieldValue for FIXString {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fix_string_write() {
        struct TestStruct {
            field: FIXString,
            val: String,
        }
        let tests = vec![TestStruct {
            field: FIXString::from("CWB"),
            val: String::from("CWB"),
        }];
        for test in tests.iter() {
            let b = test.field.write();
            assert_eq!(b, test.val, "got {}; want {}", b, test.val);
        }
    }

    #[test]
    fn test_fix_string_read() {
        struct TestStruct<'a> {
            bytes: &'a str,
            value: String,
            expected_error: bool,
        }
        let tests = vec![TestStruct {
            bytes: "blah",
            value: String::from("blah"),
            expected_error: false,
        }];
        for test in tests.iter() {
            let mut field = FIXString::new();
            let err = field.read(test.bytes);
            if test.expected_error {
                assert_eq!(Err(()), err, "Expected error for {:?}", test.bytes);
            } else {
                assert_eq!(Ok(()), err, "UnExpected '{:?}'", err);
            }

            assert_eq!(field, test.value, "got {} want {}", field, test.value);
        }
    }
}
