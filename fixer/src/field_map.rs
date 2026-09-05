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
use smallvec::{SmallVec, smallvec};
use std::{cmp::Ordering, fmt, sync::Arc};

#[derive(Debug, Default, Clone)]
pub struct LocalField {
    pub data: SmallVec<[TagValue; 1]>,
}

impl LocalField {
    pub fn new(data: SmallVec<[TagValue; 1]>) -> Self {
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
    // Shared via Arc to avoid cloning during parsing.
    pub parsed_fields: Option<Arc<[TagValue]>>,
    // Per-section indices into parsed_fields, populated during parsing.
    // When present, read methods do a linear scan over these indices instead
    // of using tag_lookup, deferring HashMap<Tag, LocalField> construction
    // until the first mutation or write.
    pub field_indices: Option<Vec<u32>>,
}

/// An ordered collection of FIX tag-value fields.
///
/// Every FIX [`Message`](crate::message::Message) contains three `FieldMap`s
/// exposed as [`Header`](crate::message::Header),
/// [`Body`](crate::message::Body), and
/// [`Trailer`](crate::message::Trailer). Each section uses a different
/// [`TagOrderType`] to control serialization order (header puts 8/9/35 first,
/// trailer puts `CheckSum` last, body sorts ascending).
///
/// # Reading Fields
///
/// Use the typed getters for the common FIX types:
///
/// ```
/// use fixer::field_map::FieldMap;
///
/// let mut fm = FieldMap::default().init();
/// fm.set_string(11, "order-1");
/// fm.set_int(38, 100);
/// fm.set_bool(110, true);
///
/// assert_eq!(fm.get_string(11).unwrap(), "order-1");
/// assert_eq!(fm.get_int(38).unwrap(), 100);
/// assert!(fm.get_bool(110).unwrap());
/// ```
///
/// For zero-copy access use [`get_bytes`](FieldMap::get_bytes) or
/// [`with_bytes`](FieldMap::with_bytes).
///
/// # Writing Fields
///
/// Setters return `&FieldMap` so calls can be chained when used through the
/// underlying `field_map` field:
///
/// ```
/// use fixer::field_map::FieldMap;
///
/// let mut fm = FieldMap::default().init();
/// fm.set_string(11, "order-1");
/// fm.set_int(38, 100);
/// assert!(fm.has(11));
/// assert!(fm.has(38));
/// ```
#[derive(Debug, Clone)]
pub struct FieldMap {
    pub content: FieldMapContent,
}

impl Default for FieldMap {
    fn default() -> Self {
        Self::with_capacity(0)
    }
}

impl FieldMap {
    /// Creates a `FieldMap` with pre-allocated capacity for the given number of
    /// fields, avoiding reallocations during parsing.
    pub fn with_capacity(cap: usize) -> Self {
        FieldMap {
            content: FieldMapContent {
                tag_lookup: FxHashMap::with_capacity_and_hasher(cap, Default::default()),
                tag_sort: TagSort {
                    tags: Vec::with_capacity(cap),
                    compare_type: TagOrderType::Normal,
                },
                parsed_fields: None,
                field_indices: None,
            },
        }
    }

    #[must_use]
    pub fn init(mut self) -> Self {
        self.init_with_ordering(TagOrderType::Normal);
        self
    }

    pub fn init_with_ordering(&mut self, ordering: TagOrderType) {
        self.content.tag_sort.compare_type = ordering;
    }

    /// Drains `field_indices` into `tag_lookup` + `tag_sort`, transitioning from
    /// the index-based representation (set during parsing) to the owned
    /// representation needed for mutation.
    fn ensure_mutable(&mut self) {
        if let Some(indices) = self.content.field_indices.take() {
            let pf = self.content.parsed_fields.as_ref().unwrap();
            for i in indices {
                let tv = &pf[i as usize];
                let tag = tv.tag;
                self.content.tag_sort.tags.push(tag);
                self.content
                    .tag_lookup
                    .insert(tag, LocalField::new(smallvec![tv.clone()]));
            }
        }
    }

    /// Returns the value bytes for `tag`, checking the index-based path first.
    #[inline]
    fn lookup_value(&self, tag: Tag) -> Result<&[u8], MessageRejectErrorEnum> {
        if let Some(ref indices) = self.content.field_indices {
            let pf = self.content.parsed_fields.as_ref().unwrap();
            for &i in indices {
                if pf[i as usize].tag == tag {
                    return Ok(pf[i as usize].value());
                }
            }
            return Err(conditionally_required_field_missing(tag));
        }
        let f = self
            .content
            .tag_lookup
            .get(&tag)
            .ok_or_else(|| conditionally_required_field_missing(tag))?;
        Ok(f.data[0].value())
    }

    /// Reads a field using its [`Field`] implementation (the tag is derived
    /// from `parser.tag()`). Returns an error if the field is absent or the
    /// value cannot be parsed.
    pub fn get<P: Field + FieldValueReader>(&self, parser: &mut P) -> MessageRejectErrorResult {
        self.get_field(parser.tag(), parser)
    }

    /// Returns `true` if a field with the given tag exists.
    pub fn has(&self, tag: Tag) -> bool {
        if let Some(ref indices) = self.content.field_indices {
            let pf = self.content.parsed_fields.as_ref().unwrap();
            return indices.iter().any(|&i| pf[i as usize].tag == tag);
        }
        self.content.tag_lookup.contains_key(&tag)
    }

    /// Reads the value of the field identified by `tag` into `parser`.
    /// Returns an error if the field is absent or the value cannot be parsed.
    pub fn get_field<P: FieldValueReader>(
        &self,
        tag: Tag,
        parser: &mut P,
    ) -> MessageRejectErrorResult {
        let value = self.lookup_value(tag)?;
        parser
            .read(value)
            .map_err(|_| incorrect_data_format_for_value(tag))?;
        Ok(())
    }

    /// Returns the raw bytes of a field without copying. Returns an error if
    /// the tag is absent.
    pub fn get_bytes(&self, tag: Tag) -> Result<&[u8], MessageRejectErrorEnum> {
        self.lookup_value(tag)
    }

    /// Borrows the raw bytes for `tag` and passes them to a closure, avoiding
    /// allocation.
    pub fn with_bytes<T, F>(&self, tag: Tag, f: F) -> Result<T, MessageRejectErrorEnum>
    where
        F: FnOnce(&[u8]) -> Result<T, MessageRejectErrorEnum>,
    {
        let value = self.lookup_value(tag)?;
        f(value)
    }

    /// Returns the field value as a `bool` (`Y` = true, `N` = false).
    pub fn get_bool(&self, tag: Tag) -> Result<bool, MessageRejectErrorEnum> {
        let mut val = FIXBoolean::default();
        self.get_field(tag, &mut val)?;
        Ok(val)
    }

    /// Returns the field value parsed as an integer.
    pub fn get_int(&self, tag: Tag) -> Result<isize, MessageRejectErrorEnum> {
        self.with_bytes(tag, |bytes| {
            let mut val = FIXInt::default();
            val.read(bytes)
                .map_err(|_| incorrect_data_format_for_value(tag))?;
            Ok(val.int())
        })
    }

    /// Returns the field value parsed as a UTC timestamp.
    pub fn get_time(&self, tag: Tag) -> Result<Timestamp, MessageRejectErrorEnum> {
        self.with_bytes(tag, |bytes| {
            let mut val = FIXUTCTimestamp::default();
            val.read(bytes)
                .map_err(|_| incorrect_data_format_for_value(tag))?;
            Ok(val.time)
        })
    }

    /// Returns the field value as a `String`.
    pub fn get_string(&self, tag: Tag) -> Result<String, MessageRejectErrorEnum> {
        let mut val = FIXString::default();
        self.get_field(tag, &mut val)?;
        Ok(val)
    }

    /// Reads a repeating group. The `parser` determines the group's count tag
    /// and member field layout.
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
                Some(idx) => LocalField::new(pf[idx..].iter().cloned().collect()),
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

    /// Sets a field by tag and a [`FieldValueWriter`].
    #[allow(clippy::needless_pass_by_value)]
    pub fn set_field<F: FieldValueWriter>(&mut self, tag: Tag, field: F) -> &FieldMap {
        let f = self.get_or_create(tag);
        f.data[0].init_with_writer(tag, &field);
        self
    }

    /// Sets a field's raw bytes directly.
    pub fn set_bytes(&mut self, tag: Tag, value: &[u8]) -> &FieldMap {
        let f = self.get_or_create(tag);
        f.init_field(tag, value);
        self
    }

    /// Sets a boolean field (`true` = `Y`, `false` = `N`).
    pub fn set_bool(&mut self, tag: Tag, value: bool) -> &FieldMap {
        self.set_field(tag, value)
    }

    /// Sets an integer field.
    pub fn set_int(&mut self, tag: Tag, value: isize) -> &FieldMap {
        let f = self.get_or_create(tag);
        f.data[0].init_with_writer(tag, &(value as FIXInt));
        self
    }

    /// Sets a string field.
    pub fn set_string(&mut self, tag: Tag, value: &str) -> &FieldMap {
        self.set_bytes(tag, value.as_bytes())
    }

    /// Removes a field by tag. Does nothing if the tag is not present.
    pub fn remove(&mut self, tag: Tag) {
        self.ensure_mutable();
        self.content.tag_lookup.remove(&tag);
    }

    /// Removes all fields, retaining allocated capacity for reuse.
    pub fn clear(&mut self) {
        self.content.tag_sort.tags.clear();
        self.content.tag_lookup.clear();
        self.content.parsed_fields = None;
        self.content.field_indices = None;
    }

    /// Deep-copies this `FieldMap` into `to`, replacing its contents.
    pub fn copy_into(&self, to: &mut FieldMap) {
        if let Some(ref indices) = self.content.field_indices {
            to.content.field_indices = Some(indices.clone());
            to.content.parsed_fields.clone_from(&self.content.parsed_fields);
            to.content.tag_lookup.clear();
            to.content.tag_sort.tags.clear();
        } else {
            to.content.field_indices = None;
            to.content.tag_lookup.clone_from(&self.content.tag_lookup);
            to.content.tag_sort.tags.clone_from(&self.content.tag_sort.tags);
        }
        to.content.tag_sort.compare_type = self.content.tag_sort.compare_type.clone();
    }

    pub fn add(&mut self, f: LocalField) {
        self.ensure_mutable();
        let t = f.field_tag();

        match self.content.tag_lookup.entry(t) {
            std::collections::hash_map::Entry::Vacant(e) => {
                self.content.tag_sort.tags.push(t);
                e.insert(f);
            }
            std::collections::hash_map::Entry::Occupied(mut e) => {
                e.insert(f);
            }
        }
    }

    fn get_or_create(&mut self, tag: Tag) -> &mut LocalField {
        self.ensure_mutable();
        if let std::collections::hash_map::Entry::Vacant(e) = self.content.tag_lookup.entry(tag) {
            let f = LocalField::new(smallvec![TagValue::default()]);
            e.insert(f);
            self.content.tag_sort.tags.push(tag);
        }
        self.content.tag_lookup.get_mut(&tag).unwrap()
    }

    /// Sets a field using a [`FieldWriter`] (the tag is derived from the field).
    #[allow(clippy::needless_pass_by_value)]
    pub fn set<F: FieldWriter>(&mut self, field: F) -> &FieldMap {
        let tag = field.tag();
        let f = self.get_or_create(tag);
        f.data[0].init_with_writer(tag, &field);
        self
    }

    /// Sets a repeating group field.
    #[allow(clippy::needless_pass_by_value)]
    pub fn set_group<F: FieldGroupWriter>(&mut self, field: F) -> &FieldMap {
        self.ensure_mutable();
        let tag = field.tag();
        let value = field.write();
        match self.content.tag_lookup.entry(tag) {
            std::collections::hash_map::Entry::Vacant(e) => {
                self.content.tag_sort.tags.push(tag);
                e.insert(value);
            }
            std::collections::hash_map::Entry::Occupied(mut e) => {
                e.insert(value);
            }
        }
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
        self.ensure_mutable();
        Self::sort_tags_in_place(&mut self.content);
        self.content.tag_sort.tags.clone()
    }

    /// Returns this map's fields in wire order, including repeating-group
    /// members as a flat sequence.
    ///
    /// Works the same whether the message was parsed off the wire or built in
    /// memory, which is the point: [`parsed_fields`](FieldMapContent::parsed_fields)
    /// is a parse cache and is dropped on the first mutation, so code that
    /// reads it directly sees nothing for a message the caller constructed.
    /// Use this to walk an arbitrary `Message` generically — to serialize it
    /// to another encoding, log it, or audit it — without caring how it was
    /// produced.
    ///
    /// Takes `&mut self` because ordering is applied lazily: a built map is
    /// sorted on demand. Nothing observable changes.
    ///
    /// ```
    /// use fixer::field_map::FieldMap;
    ///
    /// let mut fm = FieldMap::default().init();
    /// fm.set_string(11, "order-1");
    /// fm.set_int(38, 100);
    ///
    /// let fields: Vec<_> = fm
    ///     .ordered_fields()
    ///     .into_iter()
    ///     .map(|(tag, value)| (tag, String::from_utf8_lossy(value).into_owned()))
    ///     .collect();
    /// assert_eq!(
    ///     vec![(11, "order-1".to_string()), (38, "100".to_string())],
    ///     fields
    /// );
    /// ```
    pub fn ordered_fields(&mut self) -> Vec<(Tag, &[u8])> {
        // Parsed messages keep the wire sequence, which already has group
        // members inline and in order.
        if let Some(indices) = self.content.field_indices.as_ref() {
            let Some(parsed) = self.content.parsed_fields.as_ref() else {
                return Vec::new();
            };
            return indices
                .iter()
                .map(|&i| {
                    let tv = &parsed[i as usize];
                    (tv.tag, tv.value())
                })
                .collect();
        }

        // Built maps sort on demand. A group is stored as one LocalField under
        // its counter tag holding the counter and every member, so flattening
        // each entry restores the same sequence.
        let tags = self.sorted_tags();
        let mut out = Vec::with_capacity(tags.len());
        for tag in tags {
            if let Some(lf) = self.content.tag_lookup.get(&tag) {
                out.extend(lf.data.iter().map(|tv| (tv.tag, tv.value())));
            }
        }
        out
    }

    pub fn write(&mut self, buffer: &mut Vec<u8>) {
        self.ensure_mutable();
        Self::sort_tags_in_place(&mut self.content);
        for i in 0..self.content.tag_sort.tags.len() {
            let tag = self.content.tag_sort.tags[i];
            if let Some(field) = self.content.tag_lookup.get(&tag) {
                field.write_field(buffer);
            }
        }
    }

    pub fn total(&self) -> isize {
        if let Some(ref indices) = self.content.field_indices {
            let pf = self.content.parsed_fields.as_ref().unwrap();
            let mut total = 0;
            for &i in indices {
                let tv = &pf[i as usize];
                if tv.tag != TAG_CHECK_SUM {
                    total += tv.total();
                }
            }
            return total;
        }
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
        if let Some(ref indices) = self.content.field_indices {
            let pf = self.content.parsed_fields.as_ref().unwrap();
            let mut length = 0;
            for &i in indices {
                let tv = &pf[i as usize];
                if tv.tag != TAG_BEGIN_STRING
                    && tv.tag != TAG_BODY_LENGTH
                    && tv.tag != TAG_CHECK_SUM
                {
                    length += tv.length();
                }
            }
            return length;
        }
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

    /// The case from issue #95: a message built in memory has no
    /// `parsed_fields`, so anything reading that directly saw nothing. This
    /// must work regardless of how the map was produced.
    #[test]
    fn test_ordered_fields_on_built_map() {
        let mut fm = FieldMap::default().init();
        fm.set_string(11, "order-1");
        fm.set_string(55, "AAPL");
        fm.set_int(38, 100);

        assert!(
            fm.content.parsed_fields.is_none(),
            "a built map has no parse cache"
        );

        let got: Vec<(Tag, String)> = fm
            .ordered_fields()
            .into_iter()
            .map(|(t, v)| (t, String::from_utf8_lossy(v).into_owned()))
            .collect();
        assert_eq!(
            vec![
                (11, "order-1".to_string()),
                (38, "100".to_string()),
                (55, "AAPL".to_string()),
            ],
            got
        );
    }

    /// A group is stored as one entry under its counter tag; the flattened
    /// view has to expand it back to counter followed by members.
    #[test]
    fn test_ordered_fields_expands_groups() {
        use crate::repeating_group::{RepeatingGroup, group_element};

        let mut fm = FieldMap::default().init();
        fm.set_string(11, "order-1");

        let mut parties = RepeatingGroup::new(453, vec![group_element(448), group_element(452)]);
        for (id, role) in [("BROKER-A", "1"), ("BROKER-B", "2")] {
            let e = parties.add();
            e.field_map.set_string(448, id);
            e.field_map.set_string(452, role);
        }
        fm.set_group(parties);

        let got: Vec<(Tag, String)> = fm
            .ordered_fields()
            .into_iter()
            .map(|(t, v)| (t, String::from_utf8_lossy(v).into_owned()))
            .collect();

        assert_eq!(
            vec![
                (11, "order-1".to_string()),
                (453, "2".to_string()),
                (448, "BROKER-A".to_string()),
                (452, "1".to_string()),
                (448, "BROKER-B".to_string()),
                (452, "2".to_string()),
            ],
            got
        );
    }

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
