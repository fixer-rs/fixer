use crate::tag::Tag;

// TagValue is a low-level FIX field abstraction.
// Only `bytes` (the full `tag=value\x01` wire format) is stored; `value` is
// derived on demand via `sep_index` (the position of `=` in `bytes`).
#[derive(Default, Clone, Debug, PartialEq)]
pub struct TagValue {
    pub tag: Tag,
    pub bytes: Vec<u8>,
    // Position of '=' in bytes. Value slice is bytes[sep_index+1..bytes.len()-1].
    sep_index: usize,
}

impl TagValue {
    pub fn new(tag: Tag, value: &[u8]) -> Self {
        let mut tv = Self::default();
        tv.init(tag, value);
        tv
    }

    #[inline]
    pub fn value(&self) -> &[u8] {
        if self.bytes.is_empty() {
            return &[];
        }
        &self.bytes[self.sep_index + 1..self.bytes.len() - 1]
    }

    pub fn init_with_writer<W: crate::field::FieldValueWriter>(&mut self, tag: Tag, writer: &W) {
        self.bytes.clear();
        let _ = itoap::write(&mut self.bytes, tag);
        self.bytes.push(b'=');
        self.sep_index = self.bytes.len() - 1;
        writer.write_to(&mut self.bytes);
        self.bytes.push(1); // SOH delimiter
        self.tag = tag;
    }

    pub fn init(&mut self, tag: Tag, value: &[u8]) {
        self.bytes.clear();
        let _ = itoap::write(&mut self.bytes, tag);
        self.bytes.push(b'=');
        self.sep_index = self.bytes.len() - 1;
        self.bytes.extend_from_slice(value);
        self.bytes.push(1); // SOH delimiter

        self.tag = tag;
    }

    pub fn parse(&mut self, raw_field_bytes: &[u8]) -> Result<(), String> {
        let raw_str = std::str::from_utf8(raw_field_bytes).unwrap_or("<invalid utf8>");
        let sep_index = raw_field_bytes
            .iter()
            .position(|x| *x == b'=')
            .ok_or_else(|| {
                format!("TagValue::parse: No '=' in '{raw_str}'")
            })?;

        if sep_index == 0 {
            return Err(format!("TagValue::parse: No tag in '{raw_str}'"));
        }

        let parsed_tag_bytes = raw_field_bytes.get(0..sep_index).unwrap();
        let parsed_tag_str = std::str::from_utf8(parsed_tag_bytes).unwrap_or("<invalid utf8>");
        let parsed_tag = atoi_simd::parse::<isize, false, false>(parsed_tag_bytes).map_err(|_| {
            format!("tagValue.Parse: '{parsed_tag_str}'")
        })?;

        self.tag = parsed_tag;
        self.sep_index = sep_index;
        self.bytes = raw_field_bytes.to_vec();

        Ok(())
    }

    pub fn total(&self) -> isize {
        let mut total: isize = 0;
        for b in &self.bytes {
            total += *b as isize;
        }
        total
    }

    #[allow(clippy::cast_possible_wrap)]
    pub fn length(&self) -> isize {
        self.bytes.len() as isize
    }
}

impl std::fmt::Display for TagValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match std::str::from_utf8(&self.bytes) {
            Ok(s) => f.write_str(s),
            Err(_) => f.write_str("<invalid utf8>"),
        }
    }
}

#[cfg(test)]
#[allow(clippy::cast_possible_wrap)]
mod tests {
    use super::*;

    #[test]
    fn test_tag_value_init() {
        let mut tv = TagValue::default();
        tv.init(8, "blahblah".as_bytes());
        let expected_data = "8=blahblah\x01".as_bytes();

        assert_eq!(
            &tv.bytes, expected_data,
            "Expected {:?}, got {:?}",
            expected_data, tv.bytes,
        );

        let expected_value = "blahblah".as_bytes();
        assert_eq!(
            tv.value(), expected_value,
            "Expected {:?}, got {:?}",
            expected_value, tv.value(),
        );
    }

    #[test]
    fn test_tag_value_parse() {
        let string_field = "8=FIX.4.0\x01";
        let mut tv = TagValue::default();
        let result = tv.parse(string_field.as_bytes());
        assert!(result.is_ok());
        assert_eq!(8, tv.tag);
        assert_eq!(tv.bytes, string_field.as_bytes());
        assert_eq!(tv.value(), "FIX.4.0".as_bytes());
    }

    #[test]
    fn test_tag_value_parse_fail() {
        let mut string_field = "not_tag_equal_value";
        let mut tv = TagValue::default();
        let result = tv.parse(string_field.as_bytes());
        assert!(result.is_err());

        string_field = "tag_not_an_int=uhoh";
        let result = tv.parse(string_field.as_bytes());
        assert!(result.is_err());

        string_field = "=notag";
        let result = tv.parse(string_field.as_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn test_tag_value_string() {
        let string_field = "8=FIX.4.0\x01";
        let mut tv = TagValue::default();
        let result = tv.parse(string_field.as_bytes());
        assert!(result.is_ok());

        assert_eq!(String::from("8=FIX.4.0\x01"), tv.to_string());
    }

    #[test]
    fn test_tag_value_length() {
        let string_field = "8=FIX.4.0\x01";
        let mut tv = TagValue::default();
        let result = tv.parse(string_field.as_bytes());
        assert!(result.is_ok());
        assert_eq!(string_field.len() as isize, tv.length());
    }

    #[test]
    fn test_tag_value_total() {
        let string_field = "1=hello\x01";
        let mut tv = TagValue::default();
        let result = tv.parse(string_field.as_bytes());
        assert!(result.is_ok());
        assert_eq!(
            643,
            tv.total(),
            "Total is the summation of the ascii byte values of the field string"
        );
    }
}
