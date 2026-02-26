use crate::{
    errors::{
        MessageRejectErrorEnum, MessageRejectErrorResult, conditionally_required_field_missing,
        incorrect_data_format_for_value,
    },
    field::{
        Field, FieldGroupReader, FieldGroupWriter, FieldValueReader, FieldValueWriter, FieldWriter,
    },
    fix_boolean::FIXBoolean,
    fix_int::{FIXInt, FIXIntTrait},
    fix_string::FIXString,
    fix_utc_timestamp::FIXUTCTimestamp,
    tag::{TAG_BEGIN_STRING, TAG_BODY_LENGTH, TAG_CHECK_SUM, TAG_MSG_TYPE, Tag},
    tag_value::TagValue,
};
use jiff::Timestamp;
use rustc_hash::FxHashMap;
use std::{cmp::Ordering, fmt, sync::Arc, vec};

#[derive(Debug, Default, Clone)]
pub struct LocalField {
    pub data: Vec<TagValue>,
}

impl LocalField {
    pub fn new(data: Vec<TagValue>) -> Self {
        LocalField { data }
    }

    pub fn field_tag(&self) -> Tag {
        self.data[0].tag
    }

    pub fn init_field(&mut self, tag: Tag, value: &[u8]) {
        self.data[0].init(tag, value);
    }

    pub fn write_field(&self, buffer: &mut Vec<u8>) {
        for tv in &self.data {
            buffer.extend_from_slice(&tv.bytes);
        }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

// TagOrder true if tag i should occur before tag j
pub type TagOrder = fn(i: &Tag, j: &Tag) -> Ordering;

#[derive(Clone)]
pub enum TagOrderType {
    Normal,
    Header,
    Trailer,
    RepeatingGroup(Arc<FxHashMap<Tag, usize>>),
    Custom(TagOrder),
}

#[derive(Clone)]
pub struct TagSort {
    pub tags: Vec<Tag>,
    compare_type: TagOrderType,
}

impl fmt::Debug for TagSort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TagSort")
            .field("tags", &self.tags)
            .finish_non_exhaustive()
    }
}

impl TagSort {
    pub fn len(&self) -> usize {
        self.tags.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tags.len() == 0
    }

    #[allow(clippy::cast_sign_loss)]
    pub fn swap(&mut self, i: isize, j: isize) {
        self.tags.swap(i as usize, j as usize);
    }
}

#[derive(Debug, Clone)]
pub struct FieldMapContent {
    pub tag_lookup: FxHashMap<Tag, LocalField>,
    pub tag_sort: TagSort,
    // All parsed tag-values in order, including duplicates from repeating groups.
    // Populated during message parsing; used by get_group to read group members.
    pub parsed_fields: Option<Vec<TagValue>>,
}

#[derive(Debug, Clone)]
// FieldMap is a collection of fix fields that make up a fix message.
pub struct FieldMap {
    pub content: FieldMapContent,
}

impl Default for FieldMap {
    fn default() -> Self {
        FieldMap {
            content: FieldMapContent {
                tag_lookup: FxHashMap::default(),
                tag_sort: TagSort {
                    tags: vec![],
                    compare_type: TagOrderType::Normal,
                },
                parsed_fields: None,
            },
        }
    }
}

impl FieldMap {
    #[must_use]
    pub fn init(mut self) -> Self {
        self.init_with_ordering(TagOrderType::Normal);
        self
    }

    pub fn init_with_ordering(&mut self, ordering: TagOrderType) {
        self.content.tag_sort.compare_type = ordering;
    }

    // tags returns all of the Field Tags in this FieldMap
    pub fn tags(&self) -> Vec<Tag> {
        self.content.tag_sort.tags.clone()
    }

    // get parses out a field in this FieldMap. Returned reject may indicate the field is not present, or the field value is invalid.
    pub fn get<P: Field + FieldValueReader>(&self, parser: &mut P) -> MessageRejectErrorResult {
        self.get_field(parser.tag(), parser)
    }

    // has returns true if the Tag is present in this FieldMap
    pub fn has(&self, tag: Tag) -> bool {
        self.content.tag_lookup.contains_key(&tag)
    }

    // get_field parses of a field with Tag tag. Returned reject may indicate the field is not present, or the field value is invalid.
    pub fn get_field<P: FieldValueReader>(
        &self,
        tag: Tag,
        parser: &mut P,
    ) -> MessageRejectErrorResult {
        let f = self
            .content
            .tag_lookup
            .get(&tag)
            .ok_or_else(|| conditionally_required_field_missing(tag))?;

        parser
            .read(f.data[0].value())
            .map_err(|_| incorrect_data_format_for_value(tag))?;

        Ok(())
    }

    // get_bytes is a zero-copy get_field wrapper for []bytes fields
    pub fn get_bytes(&self, tag: Tag) -> Result<&[u8], MessageRejectErrorEnum> {
        let f = self
            .content
            .tag_lookup
            .get(&tag)
            .ok_or_else(|| conditionally_required_field_missing(tag))?;
        Ok(f.data[0].value())
    }

    // with_bytes borrows the raw bytes for the given tag and passes them to a
    // closure, avoiding the Vec allocation that get_bytes would require.
    pub fn with_bytes<T, F>(&self, tag: Tag, f: F) -> Result<T, MessageRejectErrorEnum>
    where
        F: FnOnce(&[u8]) -> Result<T, MessageRejectErrorEnum>,
    {
        let field = self
            .content
            .tag_lookup
            .get(&tag)
            .ok_or_else(|| conditionally_required_field_missing(tag))?;
        f(field.data[0].value())
    }

    // get_bool is a get_field wrapper for bool fields
    pub fn get_bool(&self, tag: Tag) -> Result<bool, MessageRejectErrorEnum> {
        let mut val = FIXBoolean::default();
        self.get_field(tag, &mut val)?;
        Ok(val)
    }

    // get_int is a get_field wrapper for int fields
    pub fn get_int(&self, tag: Tag) -> Result<isize, MessageRejectErrorEnum> {
        self.with_bytes(tag, |bytes| {
            let mut val = FIXInt::default();
            val.read(bytes)
                .map_err(|_| incorrect_data_format_for_value(tag))?;
            Ok(val.int())
        })
    }

    // get_time is a get_field wrapper for utc timestamp fields
    pub fn get_time(&self, tag: Tag) -> Result<Timestamp, MessageRejectErrorEnum> {
        self.with_bytes(tag, |bytes| {
            let mut val = FIXUTCTimestamp::default();
            val.read(bytes)
                .map_err(|_| incorrect_data_format_for_value(tag))?;
            Ok(val.time)
        })
    }

    // get_string is a get_field wrapper for string fields
    pub fn get_string(&self, tag: Tag) -> Result<String, MessageRejectErrorEnum> {
        let mut val = FIXString::default();
        self.get_field(tag, &mut val)?;
        Ok(val)
    }

    // get_group is a Get fntion specific to Group Fields.
    pub fn get_group<P: FieldGroupReader>(&self, parser: P) -> Result<P, MessageRejectErrorEnum> {
        let mut parser = parser;

        let tag = &parser.tag();

        // When parsed_fields is available (from message parsing), use it to build
        // the full sequence of tag-values from the group count field onward.
        // This is needed because repeating group fields have duplicate tags that
        // can't be stored individually in the HashMap.
        let tv = if let Some(ref pf) = self.content.parsed_fields {
            let start = pf.iter().position(|tv| tv.tag == *tag);
            match start {
                Some(idx) => LocalField::new(pf[idx..].to_vec()),
                None => return Err(conditionally_required_field_missing(*tag)),
            }
        } else {
            // For programmatically constructed groups (via set_group), the
            // tag_lookup entry already contains all group tag-values.
            let f = self
                .content
                .tag_lookup
                .get(tag)
                .ok_or_else(|| conditionally_required_field_missing(*tag))?;
            f.clone()
        };

        parser.read(tv).map_err(|err| {
            if let MessageRejectErrorEnum::MessageRejectError(_) = err {
                return err;
            }
            incorrect_data_format_for_value(*tag)
        })?;

        Ok(parser)
    }

    // set_field sets the field with Tag tag
    #[allow(clippy::needless_pass_by_value)]
    pub fn set_field<F: FieldValueWriter>(&mut self, tag: Tag, field: F) -> &FieldMap {
        let f = self.get_or_create(tag);
        f.data[0].init_with_writer(tag, &field);
        self
    }

    // set_bytes sets bytes
    pub fn set_bytes(&mut self, tag: Tag, value: &[u8]) -> &FieldMap {
        let f = self.get_or_create(tag);
        f.init_field(tag, value);
        self
    }

    // set_bool is a set_field wrapper for bool fields
    pub fn set_bool(&mut self, tag: Tag, value: bool) -> &FieldMap {
        self.set_field(tag, value)
    }

    // set_int is a set_field wrapper for int fields
    pub fn set_int(&mut self, tag: Tag, value: isize) -> &FieldMap {
        let f = self.get_or_create(tag);
        f.data[0].init_with_writer(tag, &(value as FIXInt));
        self
    }

    // set_string is a set_field wrapper for string fields
    pub fn set_string(&mut self, tag: Tag, value: &str) -> &FieldMap {
        self.set_bytes(tag, value.as_bytes())
    }

    // remove removes a tag from field map.
    pub fn remove(&mut self, tag: Tag) {
        self.content.tag_lookup.remove(&tag);
    }

    // clear purges all fields from field map
    pub fn clear(&mut self) {
        self.content.tag_sort.tags.clear();
        self.content.tag_lookup.clear();
    }

    // copy_into overwrites the given FieldMap with this one
    pub fn copy_into(&self, to: &mut FieldMap) {
        to.content.tag_lookup.clone_from(&self.content.tag_lookup);
        to.content.tag_sort.tags.clone_from(&self.content.tag_sort.tags);
        to.content.tag_sort.compare_type = self.content.tag_sort.compare_type.clone();
    }

    pub fn add(&mut self, f: LocalField) {
        let t = f.field_tag();

        if !self.content.tag_lookup.contains_key(&t) {
            self.content.tag_sort.tags.push(t);
        }

        self.content.tag_lookup.insert(t, f);
    }

    fn get_or_create(&mut self, tag: Tag) -> &mut LocalField {
        if let std::collections::hash_map::Entry::Vacant(e) = self.content.tag_lookup.entry(tag) {
            let f = LocalField::new(vec![TagValue::default()]);
            e.insert(f);
            self.content.tag_sort.tags.push(tag);
        }
        self.content.tag_lookup.get_mut(&tag).unwrap()
    }

    // set is a setter for fields
    #[allow(clippy::needless_pass_by_value)]
    pub fn set<F: FieldWriter>(&mut self, field: F) -> &FieldMap {
        let tag = field.tag();
        let f = self.get_or_create(tag);
        f.data[0].init_with_writer(tag, &field);
        self
    }

    // set_group is a setter specific to group fields
    #[allow(clippy::needless_pass_by_value)]
    pub fn set_group<F: FieldGroupWriter>(&mut self, field: F) -> &FieldMap {
        if !self.content.tag_lookup.contains_key(&field.tag()) {
            self.content.tag_sort.tags.push(field.tag());
        }
        self.content.tag_lookup.insert(field.tag(), field.write());
        self
    }

    // sort_tags_in_place sorts the tags inside the given content without
    // cloning. Extracted so that both sorted_tags() and write() can share
    // the logic.
    fn sort_tags_in_place(content: &mut FieldMapContent) {
        match &content.tag_sort.compare_type {
            // ascending tags
            TagOrderType::Normal => content
                .tag_sort
                .tags
                .sort_by(|i: &Tag, j: &Tag| -> Ordering { i.cmp(j) }),
            // In the message header, the first 3 tags in the message header must be 8,9,35
            TagOrderType::Header => {
                content
                    .tag_sort
                    .tags
                    .sort_by(|i: &Tag, j: &Tag| -> Ordering {
                        #[allow(clippy::trivially_copy_pass_by_ref)]
                        fn ordering(t: &Tag) -> isize {
                            match *t {
                                TAG_BEGIN_STRING => 1,
                                TAG_BODY_LENGTH => 2,
                                TAG_MSG_TYPE => 3,
                                _ => 4,
                            }
                        }

                        #[allow(clippy::similar_names)]
                        let order_i = ordering(i);
                        let order_j = ordering(j);

                        match order_i.cmp(&order_j) {
                            Ordering::Less => Ordering::Less,
                            Ordering::Equal => i.cmp(j),
                            Ordering::Greater => Ordering::Greater,
                        }
                    });
            }
            // In the trailer, CheckSum (tag 10) must be last.
            // Other trailer fields are ordered descending so that
            // SignatureLength (93) comes before Signature (89).
            TagOrderType::Trailer => {
                content
                    .tag_sort
                    .tags
                    .sort_by(|i: &Tag, j: &Tag| -> Ordering {
                        if *i == TAG_CHECK_SUM {
                            return Ordering::Greater;
                        }
                        if *j == TAG_CHECK_SUM {
                            return Ordering::Less;
                        }
                        j.cmp(i)
                    });
            }
            TagOrderType::RepeatingGroup(tag_map) => {
                let tag_map = tag_map.clone();
                content
                    .tag_sort
                    .tags
                    .sort_by(|i: &Tag, j: &Tag| -> Ordering {
                        let order_i = tag_map.get(i).copied().unwrap_or(usize::MAX);
                        let order_j = tag_map.get(j).copied().unwrap_or(usize::MAX);
                        order_i.cmp(&order_j)
                    });
            }
            TagOrderType::Custom(tag_order) => content.tag_sort.tags.sort_by(tag_order),
        }
    }

    pub fn sorted_tags(&mut self) -> Vec<Tag> {
        Self::sort_tags_in_place(&mut self.content);
        self.content.tag_sort.tags.clone()
    }

    pub fn write(&mut self, buffer: &mut Vec<u8>) {
        Self::sort_tags_in_place(&mut self.content);
        for i in 0..self.content.tag_sort.tags.len() {
            let tag = self.content.tag_sort.tags[i];
            if let Some(field) = self.content.tag_lookup.get(&tag) {
                field.write_field(buffer);
            }
        }
    }

    pub fn total(&self) -> isize {
        let mut total = 0;
        for fields in self.content.tag_lookup.values() {
            for tv in &fields.data {
                if tv.tag != TAG_CHECK_SUM {
                    total += tv.total();
                }
            }
        }
        total
    }

    pub fn length(&self) -> isize {
        let mut length = 0;
        for fields in self.content.tag_lookup.values() {
            for tv in &fields.data {
                if tv.tag != TAG_BEGIN_STRING
                    && tv.tag != TAG_BODY_LENGTH
                    && tv.tag != TAG_CHECK_SUM
                {
                    length += tv.length();
                }
            }
        }
        length
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_map_clear() {
        let mut f_map = FieldMap::default();

        f_map.set_field(1, String::from("hello"));
        f_map.set_field(2, String::from("world"));

        f_map.clear();

        assert!(
            !f_map.has(1) && !f_map.has(2),
            "All fields should be cleared"
        );
    }

    #[test]
    fn test_field_map_set_and_get() {
        struct TestCase<'a> {
            tag: Tag,
            expect_err: bool,
            expect_value: &'a str,
        }

        let mut f_map = FieldMap::default();

        f_map.set_field(1, String::from("hello"));
        f_map.set_field(2, String::from("world"));

        let tests = [
            TestCase {
                tag: 1,
                expect_err: false,
                expect_value: "hello",
            },
            TestCase {
                tag: 2,
                expect_err: false,
                expect_value: "world",
            },
            TestCase {
                tag: 44,
                expect_err: true,
                expect_value: "",
            },
        ];

        for test in &tests {
            let mut test_field = FIXString::default();
            let err = f_map.get_field(test.tag, &mut test_field);

            if test.expect_err {
                assert!(err.is_err(), "Expected Error");
                continue;
            }

            assert!(err.is_ok(), "Unexpected error");
            assert_eq!(test.expect_value, test_field);
        }
    }

    #[test]
    fn test_field_map_length() {
        let mut f_map = FieldMap::default();

        f_map.set_field(1, String::from("hello"));
        f_map.set_field(2, String::from("world"));

        f_map.set_field(8, String::from("FIX.4.4"));
        f_map.set_field(9, 100);
        f_map.set_field(10, String::from("100"));
        assert_eq!(
            16,
            f_map.length(),
            "Length should include all fields but BEGIN_STRING, BODY_LENGTH, and CHECK_SUM"
        );
    }

    #[test]
    fn test_field_map_total() {
        let mut f_map = FieldMap::default().init();

        f_map.set_field(1, String::from("hello"));
        f_map.set_field(2, String::from("world"));
        f_map.set_field(8, String::from("FIX.4.4"));
        f_map.set_field(9 as Tag, 100);
        f_map.set_field(10, String::from("100"));

        assert_eq!(
            2116,
            f_map.total(),
            "Total should includes all fields but CHECK_SUM"
        );
    }

    #[test]
    fn test_field_map_typed_set_and_get() {
        let mut f_map = FieldMap::default().init();

        f_map.set_string(1, "hello");
        f_map.set_int(2, 256);

        let s = f_map.get_string(1);
        assert!(s.is_ok());
        assert_eq!("hello", s.unwrap());

        let i = f_map.get_int(2);
        assert!(i.is_ok());
        assert_eq!(256, i.unwrap());

        let err = f_map.get_int(1);
        assert!(err.is_err(), "Type mismatch should occur error");

        let s = f_map.get_string(2);
        assert!(s.is_ok());
        assert_eq!("256", s.unwrap());

        let b = f_map.get_bytes(1);
        assert!(b.is_ok());
        assert_eq!("hello".as_bytes(), b.unwrap());
    }

    #[test]
    fn test_field_map_bool_typed_set_and_get() {
        let mut f_map = FieldMap::default().init();

        f_map.set_bool(1, true);
        let v = f_map.get_bool(1);
        assert!(v.is_ok());
        assert!(v.unwrap());

        let s = f_map.get_string(1);
        assert!(s.is_ok());
        assert_eq!("Y", s.unwrap());

        f_map.set_bool(2, false);
        let v = f_map.get_bool(2);
        assert!(v.is_ok());
        assert!(!v.unwrap());

        let s = f_map.get_string(2);
        assert!(s.is_ok());
        assert_eq!("N", s.unwrap());
    }

    #[test]
    fn test_field_map_copy_into() {
        let mut f_map_a = FieldMap::default();
        f_map_a.init_with_ordering(TagOrderType::Header);

        f_map_a.set_string(9, "length");
        f_map_a.set_string(8, "begin");
        f_map_a.set_string(35, "msgtype");
        f_map_a.set_string(1, "a");
        assert_eq!(vec![8, 9, 35, 1], f_map_a.sorted_tags());

        let mut f_map_b = FieldMap::default().init();

        f_map_b.set_string(1, "A");
        f_map_b.set_string(3, "C");
        f_map_b.set_string(4, "D");
        assert_eq!(f_map_b.sorted_tags(), vec![1, 3, 4]);

        f_map_a.copy_into(&mut f_map_b);
        assert_eq!(vec![8, 9, 35, 1], f_map_b.sorted_tags());

        // new fields
        let s = f_map_b.get_string(35);
        assert!(s.is_ok());
        assert_eq!("msgtype", s.unwrap());

        // existing fields overwritten
        let s = f_map_b.get_string(1);
        assert!(s.is_ok());
        assert_eq!("a", s.unwrap());

        // old fields cleared
        let err = f_map_b.get_string(3);
        assert!(err.is_err());

        // check that ordering is overwritten
        f_map_b.set_string(2, "B");
        assert_eq!(vec![8, 9, 35, 1, 2], f_map_b.sorted_tags());

        // updating the existing map doesn't affect the new
        let mut f_map_a = FieldMap::default().init();
        f_map_a.set_string(1, "AA");
        let s = f_map_b.get_string(1);
        assert!(s.is_ok());
        assert_eq!("a", s.unwrap());
        f_map_a.clear();
        let s = f_map_b.get_string(1);
        assert!(s.is_ok());
        assert_eq!("a", s.unwrap());
    }

    #[test]
    fn test_field_map_remove() {
        let mut f_map = FieldMap::default().init();

        f_map.set_field(1, FIXString::from("hello"));
        f_map.set_field(2, FIXString::from("world"));

        f_map.remove(1);
        assert!(!f_map.has(1));
        assert!(f_map.has(2));
    }
}
