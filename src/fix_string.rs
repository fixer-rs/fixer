//FIXString is a FIX String Value, implements FieldValue
type FIXString = String;

pub trait FixStringTrait {
    fn read(&mut self, bytes: &[u8]) -> Result<(), ()>;
    fn write(&self) -> Vec<u8>;
}

impl FixStringTrait for FIXString {
    fn read(&mut self, bytes: &[u8]) -> Result<(), ()> {
        let fix_string = std::str::from_utf8(bytes).map_err(|_| ())?;
        self.clear();
        self.push_str(fix_string);
        Ok(())
    }

    fn write(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::{FIXString, FixStringTrait};

    #[test]
    fn test_fixstring_write() {
        struct TestStruct {
            field: FIXString,
            val: Vec<u8>,
        }
        let tests = vec![TestStruct {
            field: FIXString::from("CWB"),
            val: "CWB".as_bytes().to_vec(),
        }];
        for test in tests.iter() {
            let b = test.field.write();
            assert_eq!(b, test.val, "got {:?}; want {:?}", b, test.val);
        }
    }

    #[test]
    fn test_fixstring_read() {
        struct TestStruct {
            bytes: Vec<u8>,
            value: String,
            expected_error: bool,
        }
        let tests = vec![TestStruct {
            bytes: "blah".as_bytes().to_vec(),
            value: String::from("blah"),
            expected_error: false,
        }];
        for test in tests.iter() {
            let mut field = FIXString::new();
            let err = field.read(&test.bytes);
            if test.expected_error {
                assert_eq!(Err(()), err, "Expected error for {:?}", test.bytes);
            } else {
                assert_eq!(Ok(()), err, "UnExpected '{:?}'", err);
            }

            assert_eq!(field, test.value, "got {} want {}", field, test.value);
        }
    }
}
