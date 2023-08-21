use crate::{
    errors::{
        conditionally_required_field_missing, incorrect_data_format_for_value,
        MessageRejectErrorEnum, MessageRejectErrorResult,
    },
    field::{
        Field, FieldGroupReader, FieldGroupWriter, FieldValueReader, FieldValueWriter, FieldWriter,
    },
    fix_boolean::FIXBoolean,
    fix_int::{FIXInt, FIXIntTrait},
    fix_string::FIXString,
    fix_utc_timestamp::FIXUTCTimestamp,
    tag::{Tag, TAG_BEGIN_STRING, TAG_BODY_LENGTH, TAG_CHECK_SUM, TAG_MSG_TYPE},
    tag_value::TagValue,
};
use chrono::{DateTime, Utc};
use parking_lot::{Mutex, RwLock};
use std::{cmp::Ordering, collections::HashMap, fmt, sync::Arc, vec};

#[derive(Debug, Default, Clone)]
pub struct LocalField {
    pub data: Arc<Mutex<Vec<TagValue>>>,
    pub s_pos: usize,
    pub e_pos: usize,
}

impl LocalField {
    pub fn new(tag_value: Arc<Mutex<Vec<TagValue>>>) -> Self {
        let e_pos = tag_value.lock().len();
        LocalField {
            data: tag_value,
            s_pos: 0,
            e_pos,
        }
    }

    pub fn new_with_start_end(
        tag_value: Arc<Mutex<Vec<TagValue>>>,
        s_pos: usize,
        e_pos: usize,
    ) -> Self {
        LocalField {
            data: tag_value,
            s_pos,
            e_pos,
        }
    }

    pub fn field_tag(&self) -> Tag {
        let lock = self.data.lock();
        lock.get(self.s_pos).unwrap().tag
    }

    pub fn init_field(&self, tag: Tag, value: &[u8]) {
        let mut lock = self.data.lock();
        lock.get_mut(self.s_pos).unwrap().init(tag, value);
    }

    pub fn write_field(&self, buffer: &mut Vec<u8>) {
        for tv in self.data.lock().get(self.s_pos..self.e_pos).unwrap().iter() {
            buffer.extend_from_slice(&tv.bytes);
        }
    }

    pub fn len(&self) -> usize {
        self.e_pos - self.s_pos
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn cap(&self) -> usize {
        self.data.lock().len()
    }
}

// TagOrder true if tag i should occur before tag j
pub type TagOrder = fn(i: &Tag, j: &Tag) -> Ordering;

#[derive(Clone)]
pub enum TagOrderType {
    Normal,
    Header,
    Trailer,
    Custom(TagOrder),
}

#[derive(Clone)]
struct TagSort {
    tags: Vec<Tag>,
    compare_type: TagOrderType,
}

impl fmt::Debug for TagSort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TagSort").field("tags", &self.tags).finish()
    }
}

impl TagSort {
    pub fn len(&self) -> isize {
        self.tags.len() as isize
    }
    pub fn swap(&mut self, i: isize, j: isize) {
        self.tags.swap(i as usize, j as usize);
    }
}

#[derive(Debug, Clone)]
pub struct FieldMapContent {
    tag_lookup: HashMap<Tag, Arc<LocalField>>,
    tag_sort: TagSort,
}

#[derive(Debug, Clone)]
// FieldMap is a collection of fix fields that make up a fix message.
pub struct FieldMap {
    rw_lock: Arc<RwLock<FieldMapContent>>,
}

impl Default for FieldMap {
    fn default() -> Self {
        FieldMap {
            rw_lock: RwLock::new(FieldMapContent {
                tag_lookup: HashMap::new(),
                tag_sort: TagSort {
                    tags: Vec::new(),
                    compare_type: TagOrderType::Normal,
                },
            })
            .into(),
        }
    }
}

impl FieldMap {
    pub fn init(self) -> Self {
        self.init_with_ordering(TagOrderType::Normal)
    }

    pub fn init_with_ordering(self, ordering: TagOrderType) -> Self {
        self.rw_lock.write().tag_sort.compare_type = ordering;
        self
    }

    // tags returns all of the Field Tags in this FieldMap
    pub fn tags(&self) -> Vec<Tag> {
        let rlock = self.rw_lock.read();
        rlock.tag_sort.tags.to_vec()
    }

    // get parses out a field in this FieldMap. Returned reject may indicate the field is not present, or the field value is invalid.
    pub fn get<P: Field + FieldValueReader>(&self, parser: &mut P) -> MessageRejectErrorResult {
        self.get_field(parser.tag(), parser)
    }

    // has returns true if the Tag is present in this FieldMap
    pub fn has(&self, tag: Tag) -> bool {
        let rlock = self.rw_lock.read();
        rlock.tag_lookup.contains_key(&tag)
    }

    // get_field parses of a field with Tag tag. Returned reject may indicate the field is not present, or the field value is invalid.
    pub fn get_field<P: FieldValueReader>(
        &self,
        tag: Tag,
        parser: &mut P,
    ) -> MessageRejectErrorResult {
        let rlock = self.rw_lock.read();
        let f = rlock
            .tag_lookup
            .get(&tag)
            .ok_or_else(|| conditionally_required_field_missing(tag))?;

        parser
            .read(&f.data.lock().get(f.s_pos).unwrap().value)
            .map_err(|_| incorrect_data_format_for_value(tag))?;

        Ok(())
    }

    // get_bytes is a zero-copy get_field wrapper for []bytes fields
    pub fn get_bytes(&self, tag: Tag) -> Result<Vec<u8>, MessageRejectErrorEnum> {
        let rlock = self.rw_lock.read();
        let f = rlock
            .tag_lookup
            .get(&tag)
            .ok_or_else(|| conditionally_required_field_missing(tag))?;
        let result = f.data.lock().get(f.s_pos).unwrap().value.clone();
        Ok(result)
    }

    // get_bool is a get_field wrapper for bool fields
    pub fn get_bool(&self, tag: Tag) -> Result<bool, MessageRejectErrorEnum> {
        let mut val = FIXBoolean::default();
        self.get_field(tag, &mut val)?;
        Ok(val)
    }

    // get_int is a get_field wrapper for int fields
    pub fn get_int(&self, tag: Tag) -> Result<isize, MessageRejectErrorEnum> {
        let mut val = FIXInt::default();
        let bytes = self.get_bytes(tag)?;

        val.read(&bytes)
            .map_err(|_| incorrect_data_format_for_value(tag))?;

        Ok(val.int())
    }

    // get_time is a get_field wrapper for utc timestamp fields
    pub fn get_time(&self, tag: Tag) -> Result<DateTime<Utc>, MessageRejectErrorEnum> {
        let mut val = FIXUTCTimestamp::default();
        let bytes = self.get_bytes(tag)?;

        val.read(&bytes)
            .map_err(|_| incorrect_data_format_for_value(tag))?;

        Ok(val.time)
    }

    // get_string is a get_field wrapper for string fields
    pub fn get_string(&self, tag: Tag) -> Result<String, MessageRejectErrorEnum> {
        let mut val = FIXString::default();
        self.get_field(tag, &mut val)?;
        Ok(val)
    }

    // get_group is a Get fntion specific to Group Fields.
    pub fn get_group<P: FieldGroupReader>(&self, parser: P) -> MessageRejectErrorResult {
        let rlock = self.rw_lock.read();

        let tag = &parser.tag();
        let f = rlock
            .tag_lookup
            .get(tag)
            .ok_or_else(|| conditionally_required_field_missing(*tag))?;

        parser.read(f).map_err(|err| {
            if let MessageRejectErrorEnum::MessageRejectError(_) = err {
                return err;
            }
            incorrect_data_format_for_value(*tag)
        })?;

        Ok(())
    }

    // set_field sets the field with Tag tag
    pub fn set_field<F: FieldValueWriter>(&self, tag: Tag, field: F) -> &FieldMap {
        self.set_bytes(tag, &field.write())
    }

    // set_bytes sets bytes
    pub fn set_bytes(&self, tag: Tag, value: &[u8]) -> &FieldMap {
        let f = self.get_or_create(tag);
        f.init_field(tag, value);
        self
    }

    // set_bool is a set_field wrapper for bool fields
    pub fn set_bool(&self, tag: Tag, value: bool) -> &FieldMap {
        self.set_field(tag, value)
    }

    // set_int is a set_field wrapper for int fields
    pub fn set_int(&self, tag: Tag, value: isize) -> &FieldMap {
        self.set_bytes(tag, &(value as FIXInt).write())
    }

    // set_string is a set_field wrapper for string fields
    pub fn set_string(&self, tag: Tag, value: &str) -> &FieldMap {
        self.set_bytes(tag, value.as_bytes())
    }

    // clear purges all fields from field map
    pub fn clear(&self) {
        let mut wlock = self.rw_lock.write();
        wlock.tag_sort.tags.clear();
        wlock.tag_lookup.clear();
    }

    // copy_into overwrites the given FieldMap with this one
    pub fn copy_into(&self, to: &mut FieldMap) {
        let m_rlock = self.rw_lock.read();
        let mut to_wlock = to.rw_lock.write();

        to_wlock.tag_lookup = HashMap::new();

        for (k, v) in m_rlock.tag_lookup.iter() {
            let inner_lock = v.data.lock();
            let cloned_field = inner_lock.to_vec();
            let cloned_field_wrapper = Arc::new(Mutex::new(cloned_field));

            to_wlock.tag_lookup.insert(
                *k,
                Arc::new(LocalField::new_with_start_end(
                    cloned_field_wrapper,
                    v.s_pos,
                    v.s_pos + 1,
                )),
            );
        }

        to_wlock.tag_sort.tags = m_rlock.tag_sort.tags.clone();
        to_wlock.tag_sort.compare_type = m_rlock.tag_sort.compare_type.clone();
    }

    pub fn add(&mut self, f: LocalField) {
        let t = f.field_tag();
        let f_arc = Arc::new(f);

        let mut wlock = self.rw_lock.write();
        if !wlock.tag_lookup.contains_key(&t) {
            wlock.tag_sort.tags.push(t);
        }

        wlock.tag_lookup.insert(t, f_arc);
    }

    fn get_or_create(&self, tag: Tag) -> Arc<LocalField> {
        let mut wlock = self.rw_lock.write();
        if wlock.tag_lookup.contains_key(&tag) {
            let f = wlock.tag_lookup.get_mut(&tag).unwrap();
            return Arc::new(LocalField::new_with_start_end(
                f.data.clone(),
                f.s_pos,
                f.s_pos + 1,
            ));
        }

        let f = Arc::new(LocalField::new(Arc::new(Mutex::new(vec![
            TagValue::default(),
        ]))));
        wlock.tag_lookup.insert(tag, f.clone());
        wlock.tag_sort.tags.push(tag);
        f
    }

    // set is a setter for fields
    pub fn set<F: FieldWriter>(&self, field: F) -> &FieldMap {
        let tag = &field.tag();

        let f = self.get_or_create(*tag);

        f.init_field(*tag, &field.write());
        self
    }

    // set_group is a setter specific to group fields
    pub fn set_group<F: FieldGroupWriter>(&mut self, field: F) -> &FieldMap {
        let mut wlock = self.rw_lock.write();

        if !wlock.tag_lookup.contains_key(&field.tag()) {
            wlock.tag_sort.tags.push(field.tag());
        }
        wlock
            .tag_lookup
            .insert(field.tag(), Arc::new(field.write()));
        self
    }

    fn sorted_tags(&self) -> Vec<Tag> {
        let mut wlock = self.rw_lock.write();
        match wlock.tag_sort.compare_type {
            // ascending tags
            TagOrderType::Normal => wlock
                .tag_sort
                .tags
                .sort_by(|i: &Tag, j: &Tag| -> Ordering { i.cmp(j) }),
            // In the message header, the first 3 tags in the message header must be 8,9,35
            TagOrderType::Header => wlock.tag_sort.tags.sort_by(|i: &Tag, j: &Tag| -> Ordering {
                fn ordering(t: &Tag) -> isize {
                    match *t {
                        TAG_BEGIN_STRING => 1,
                        TAG_BODY_LENGTH => 2,
                        TAG_MSG_TYPE => 3,
                        _ => 4,
                    }
                }

                let orderi = ordering(i);
                let orderj = ordering(j);

                match orderi.cmp(&orderj) {
                    Ordering::Less => Ordering::Less,
                    Ordering::Equal => i.cmp(j),
                    Ordering::Greater => Ordering::Greater,
                }
            }),
            // In the trailer, CheckSum (tag 10) must be last
            TagOrderType::Trailer => wlock.tag_sort.tags.sort_by(|i: &Tag, j: &Tag| -> Ordering {
                if *i == TAG_CHECK_SUM {
                    return Ordering::Greater;
                }
                if *j == TAG_CHECK_SUM {
                    return Ordering::Less;
                }
                i.cmp(j)
            }),
            TagOrderType::Custom(tag_order) => wlock.tag_sort.tags.sort_by(tag_order),
        }
        wlock.tag_sort.tags.clone()
    }

    pub fn write(&self, buffer: &mut Vec<u8>) {
        for tag in self.sorted_tags().iter() {
            let mut wlock = self.rw_lock.write();
            if wlock.tag_lookup.contains_key(tag) {
                let field = wlock.tag_lookup.get_mut(tag).unwrap();
                field.write_field(buffer);
            }
        }
    }

    pub fn total(&self) -> isize {
        let rlock = self.rw_lock.read();
        let mut total = 0;

        for fields in rlock.tag_lookup.values() {
            fields
                .data
                .lock()
                .get(fields.s_pos..fields.e_pos)
                .unwrap()
                .iter()
                .filter(|tv| tv.tag != TAG_CHECK_SUM)
                .for_each(|tv| total += tv.total());
        }
        total
    }

    pub fn length(&self) -> isize {
        let rlock = self.rw_lock.read();
        let mut length = 0;

        for fields in rlock.tag_lookup.values() {
            fields
                .data
                .lock()
                .get(fields.s_pos..fields.e_pos)
                .unwrap()
                .iter()
                .filter(|tv| {
                    tv.tag != TAG_BEGIN_STRING
                        && tv.tag != TAG_BODY_LENGTH
                        && tv.tag != TAG_CHECK_SUM
                })
                .for_each(|tv| length += tv.length());
        }

        length
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_map_clear() {
        let f_map = FieldMap::default();

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
        let f_map = FieldMap::default();

        f_map.set_field(1, String::from("hello"));
        f_map.set_field(2, String::from("world"));

        struct TestCase<'a> {
            tag: Tag,
            expect_err: bool,
            expect_value: &'a str,
        }

        let tests = vec![
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

        for test in tests.iter() {
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
        let f_map = FieldMap::default();

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
        let f_map = FieldMap::default().init();

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
        let f_map = FieldMap::default().init();

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
        let f_map = FieldMap::default().init();

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
        let f_map_a = FieldMap::default().init_with_ordering(TagOrderType::Header);

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
        let f_map_a = FieldMap::default().init();
        f_map_a.set_string(1, "AA");
        let s = f_map_b.get_string(1);
        assert!(s.is_ok());
        assert_eq!("a", s.unwrap());
        f_map_a.clear();
        let s = f_map_b.get_string(1);
        assert!(s.is_ok());
        assert_eq!("a", s.unwrap());
    }
}
