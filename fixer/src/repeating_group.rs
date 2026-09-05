use crate::{
    errors::{MessageRejectErrorEnum, repeating_group_fields_out_of_order},
    field::{FieldGroupReader, FieldGroupWriter, FieldTag},
    field_map::{FieldMap, LocalField, TagOrderType},
    tag::Tag,
    tag_value::TagValue,
};
use delegate::delegate;
use dyn_clone::{DynClone, clone_trait_object};
use rustc_hash::FxHashMap;
use smallvec::smallvec;
use std::sync::Arc;

// GroupItem interface is used to construct repeating group templates.
// Tag returns the tag identifying this GroupItem.

// Read Parameter to Read is tagValues.  For most fields, only the first tagValue will be required.
// The length of the slice extends from the tagValue mapped to the field to be read through the
// following fields. This can be useful for GroupItems made up of repeating groups.

// The Read fntion returns the remaining tagValues not processed by the GroupItem. If there was a
// problem reading the field, an error may be returned.

pub trait GroupItem: DynClone + FieldTag + FieldGroupReader {
    /// Whether [`read`](FieldGroupReader::read) can consume more than the
    /// single tag-value this item matched on.
    ///
    /// A plain field consumes exactly its own tag-value, so the caller can
    /// snapshot it before reading. A nested `RepeatingGroup` consumes its whole
    /// subtree, and the caller has to hold on to the input to recover the
    /// consumed span afterwards — which costs a copy, so it is worth knowing in
    /// advance which items need it.
    ///
    /// Defaults to `true`, the conservative answer: an item that consumes more
    /// than it admits to would have the rest of its content dropped.
    fn spans_multiple_fields(&self) -> bool {
        true
    }
}

clone_trait_object!(GroupItem);

#[derive(Clone)]
struct ProtoGroupElement {
    tag: Tag,
}

impl FieldTag for ProtoGroupElement {
    fn tag(&self) -> Tag {
        self.tag
    }
}

impl FieldGroupReader for ProtoGroupElement {
    fn read(&mut self, tv: LocalField) -> Result<LocalField, MessageRejectErrorEnum> {
        if !tv.is_empty() && tv.data[0].tag == self.tag {
            return Ok(LocalField::new(tv.data[1..].iter().cloned().collect()));
        }
        Ok(tv)
    }
}

impl GroupItem for ProtoGroupElement {
    fn spans_multiple_fields(&self) -> bool {
        false
    }
}

// GroupElement returns a GroupItem made up of a single field.
pub fn group_element(tag: Tag) -> Box<dyn GroupItem> {
    Box::new(ProtoGroupElement { tag })
}

// GroupTemplate specifies the group item order for a RepeatingGroup.
pub type GroupTemplate = Vec<Box<dyn GroupItem>>;

// Group is a group of fields occurring in a repeating group.
#[derive(Clone, Default, Debug)]
pub struct Group {
    pub field_map: FieldMap,
}

impl Group {
    delegate! {
        to self.field_map {
            pub fn sorted_tags(&mut self) -> Vec<Tag>;
        }
    }
}

// RepeatingGroup is a FIX Repeating Group type.
#[derive(Clone, Default)]
pub struct RepeatingGroup {
    tag: Tag,
    template: GroupTemplate,
    pub groups: Vec<Group>,
    // Pre-computed lookup: tag → index in template. Built once in `new()`.
    template_lookup: FxHashMap<Tag, usize>,
    // Pre-computed tag ordering for group FieldMaps. Built once in `new()`.
    tag_order: Arc<FxHashMap<Tag, usize>>,
}

impl RepeatingGroup {
    // new returns an initilized RepeatingGroup instance.
    pub fn new(tag: Tag, template: GroupTemplate) -> Self {
        let template_lookup: FxHashMap<Tag, usize> = template
            .iter()
            .enumerate()
            .map(|(i, item)| (item.tag(), i))
            .collect();
        let tag_order = Arc::new(template_lookup.clone());
        RepeatingGroup {
            tag,
            template,
            groups: vec![],
            template_lookup,
            tag_order,
        }
    }

    // len returns the number of Groups in this RepeatingGroup.
    pub fn len(&self) -> usize {
        self.groups.len()
    }

    // is_empty returns true if this RepeatingGroup has no groups.
    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    // get returns the ith group in this RepeatingGroup.
    pub fn get(&self, i: usize) -> &Group {
        &self.groups[i]
    }

    // add appends a new group to the RepeatingGroup and returns the new Group.
    //
    // The new Group is given this group's template ordering, the same one
    // `read` installs. Without it the entry would serialize in ascending tag
    // order, which puts the delimiter second whenever it is not the lowest tag
    // in the entry (e.g. NoPartyIDs, delimited by PartyID 448 but also
    // carrying PartyIDSource 447) and yields a message peers cannot parse.
    pub fn add(&mut self) -> &mut Group {
        let mut group = Group {
            field_map: FieldMap::default(),
        };
        group
            .field_map
            .init_with_ordering(TagOrderType::RepeatingGroup(self.tag_order.clone()));
        self.groups.push(group);
        self.groups.last_mut().unwrap()
    }

    fn find_item_in_group_template(&self, t: Tag) -> Option<Box<dyn GroupItem>> {
        let &idx = self.template_lookup.get(&t)?;
        Some(self.template[idx].clone())
    }

    fn delimiter(&self) -> Tag {
        self.template.first().unwrap().tag()
    }

    fn is_delimiter(&self, t: Tag) -> bool {
        self.delimiter() == t
    }
}

impl FieldTag for RepeatingGroup {
    fn tag(&self) -> Tag {
        self.tag
    }
}

impl FieldGroupReader for RepeatingGroup {
    fn read(&mut self, tv: LocalField) -> Result<LocalField, MessageRejectErrorEnum> {
        if tv.is_empty() {
            return Ok(LocalField::new(smallvec![]));
        }

        let Ok(expected_group_size) = atoi_simd::parse::<usize, false, false>(tv.data[0].value()) else {
            return Ok(tv);
        };

        if expected_group_size == 0 {
            return Ok(LocalField::new(tv.data[1..].iter().cloned().collect()));
        }

        let mut tv = LocalField::new(tv.data[1..].iter().cloned().collect());
        let tag_ordering = self.tag_order.clone();

        while !tv.is_empty() {
            let tag = tv.data[0].tag;
            let Some(mut gi) = self.find_item_in_group_template(tag) else {
                break;
            };

            // Everything the item consumes has to end up on the entry. For a
            // plain field that is just the tag-value it matched, so snapshot it
            // and hand the input straight over. A nested group consumes its
            // whole subtree, so keep a copy to slice the consumed span out of
            // afterwards — storing only the first tag-value there would keep
            // the nested NumInGroup counter and drop its entries.
            let first = tv.data[0].clone();
            let before = gi.spans_multiple_fields().then(|| tv.clone());

            let before_len = tv.data.len();
            tv = gi.read(tv)?;
            let consumed = before_len.saturating_sub(tv.data.len());
            if consumed == 0 {
                // The item matched on tag but consumed nothing; stop rather
                // than revisiting the same position forever.
                break;
            }

            let span = match before {
                Some(before) => {
                    LocalField::new(before.data[..consumed].iter().cloned().collect())
                }
                None => LocalField::new(smallvec![first]),
            };

            if self.is_delimiter(gi.tag()) {
                let mut group = Group {
                    field_map: FieldMap::default(),
                };
                group.field_map.init_with_ordering(TagOrderType::RepeatingGroup(tag_ordering.clone()));
                self.groups.push(group);
            }

            let Some(last_group) = self.groups.last_mut() else {
                // A member field arrived before the group's delimiter, so there
                // is no entry to attach it to. Reject rather than panic: this
                // is peer-supplied data.
                return Err(repeating_group_fields_out_of_order(
                    self.tag,
                    format!(
                        "group {}: field {} appeared before the delimiter {}",
                        self.tag,
                        tag,
                        self.delimiter()
                    ),
                ));
            };

            last_group.field_map.content.tag_lookup.insert(tag, span);
            last_group.field_map.content.tag_sort.tags.push(gi.tag());
        }

        if self.groups.len() != expected_group_size {
            return Err(repeating_group_fields_out_of_order(
                self.tag,
                format!(
                    "group {}: template is wrong or delimiter {} not found: expected {} groups, but found {}",
                    self.tag,
                    self.delimiter(),
                    expected_group_size,
                    self.groups.len()
                ),
            ));
        }

        Ok(tv)
    }
}

impl FieldGroupWriter for RepeatingGroup {
    // write returns tagValues for all Items in the repeating group ordered by
    // Group sequence and Group template order.
    fn write(&self) -> LocalField {
        let mut len_buf = Vec::new();
        let _ = itoap::write(&mut len_buf, self.groups.len());

        let mut tv = TagValue::default();
        tv.init(self.tag, &len_buf);
        let mut tvs = smallvec![tv];

        for group in &self.groups {
            let mut group_clone = group.clone();
            let tags = group_clone.sorted_tags();
            for tag in tags {
                if let Some(fields) = group.field_map.content.tag_lookup.get(&tag) {
                    tvs.extend(fields.data.iter().cloned());
                }
            }
        }

        LocalField::new(tvs)
    }
}

impl GroupItem for RepeatingGroup {}

#[cfg(test)]
#[allow(clippy::items_after_statements)]
mod tests {
    use crate::{
        field::{FieldGroupReader, FieldGroupWriter},
        field_map::LocalField,
        fix_string::FIXString,
        message::Message,
        repeating_group::{GroupTemplate, RepeatingGroup, group_element},
        tag::Tag,
        tag_value::TagValue,
    };
    use smallvec::smallvec;

    #[test]
    fn test_repeating_group_add() {
        let mut f = RepeatingGroup::new(0, vec![group_element(1)]);

        struct TestCase {
            expected_len: usize,
        }

        let test_cases = [TestCase { expected_len: 1 }, TestCase { expected_len: 2 }];

        for tc in &test_cases {
            f.add();

            assert_eq!(
                f.len(),
                tc.expected_len,
                "Expected {} groups, got {}",
                tc.expected_len,
                f.len()
            );

            f.groups.last_mut().unwrap().field_map.set_field(1, FIXString::from("hello"));

            let get_result = f.groups.get(tc.expected_len - 1);
            assert!(get_result.is_some());

            let g = get_result.unwrap();
            assert!(
                g.field_map.has(1),
                "expected tag in group {}",
                tc.expected_len
            );

            let mut v = FIXString::new();
            let get_result = g.field_map.get_field(1, &mut v);
            assert!(get_result.is_ok());

            assert_eq!(v, "hello", "expected hello in group {}", tc.expected_len);
        }
    }

    #[test]
    fn test_repeating_group_write() {
        let mut f1 = RepeatingGroup::new(10, vec![group_element(1), group_element(2)]);

        f1.add();
        f1.groups.last_mut().unwrap().field_map.set_field(1, FIXString::from("hello"));

        let mut f2 = RepeatingGroup::new(11, vec![group_element(1), group_element(2)]);

        f2.add();
        f2.groups.last_mut().unwrap().field_map.set_field(1, FIXString::from("hello"));
        f2.groups.last_mut().unwrap().field_map.set_field(2, FIXString::from("world"));

        let mut f3 = RepeatingGroup::new(12, vec![group_element(1), group_element(2)]);

        f3.add();
        f3.groups.last_mut().unwrap().field_map.set_field(1, FIXString::from("hello"));
        f3.add();
        f3.groups.last_mut().unwrap().field_map.set_field(1, FIXString::from("world"));

        let mut f4 = RepeatingGroup::new(13, vec![group_element(1), group_element(2)]);

        f4.add();
        f4.groups.last_mut().unwrap().field_map.set_field(1, FIXString::from("hello"));
        f4.groups.last_mut().unwrap().field_map.set_field(2, FIXString::from("world"));
        f4.add();
        f4.groups.last_mut().unwrap().field_map.set_field(1, FIXString::from("goodbye"));

        struct TestCase<'a> {
            f: RepeatingGroup,
            expected: &'a [u8],
        }

        let test_cases = [
            TestCase {
                f: f1,
                expected: "10=11=hello".as_bytes(),
            },
            TestCase {
                f: f2,
                expected: "11=11=hello2=world".as_bytes(),
            },
            TestCase {
                f: f3,
                expected: "12=21=hello1=world".as_bytes(),
            },
            TestCase {
                f: f4,
                expected: "13=21=hello2=world1=goodbye".as_bytes(),
            },
        ];

        for tc in &test_cases {
            let mut tvbytes = vec![];
            let tvs = tc.f.write();
            for tv in &tvs.data {
                tvbytes.extend_from_slice(&tv.bytes);
            }
            assert_eq!(
                tc.expected,
                &tvbytes,
                "expected {} got {}",
                std::str::from_utf8(tc.expected).unwrap(),
                std::str::from_utf8(&tvbytes).unwrap()
            );
        }
    }

    #[test]
    fn test_repeating_group_read_error() {
        let single_field_template = vec![group_element(1)];

        struct TestCase {
            tv: LocalField,
            expected_group_num: usize,
        }

        let test_cases = [
            TestCase {
                tv: LocalField::new(smallvec![
                    TagValue::new(0, b"1"),
                    TagValue::new(2, b"not in template"),
                    TagValue::new(1, b"hello"),
                ]),
                expected_group_num: 0,
            },
            TestCase {
                tv: LocalField::new(smallvec![
                    TagValue::new(0, b"2"),
                    TagValue::new(1, b"hello"),
                    TagValue::new(2, b"not in template"),
                    TagValue::new(1, b"hello"),
                ]),
                expected_group_num: 1,
            },
        ];

        for tc in &test_cases {
            let mut f = RepeatingGroup::new(0, single_field_template.clone());
            let read_result = f.read(tc.tv.clone());
            assert!(
                read_result.is_err() && f.groups.len() == tc.expected_group_num,
                "Should have raised an error because expected group number is wrong: {} instead of {}",
                f.groups.len(),
                tc.expected_group_num
            );
        }
    }

    #[test]
    fn test_repeating_group_read() {
        let single_field_template = vec![group_element(1)];
        let multi_field_template = vec![group_element(1), group_element(2), group_element(3)];

        #[derive(Default)]
        struct TestCase {
            group_template: Option<GroupTemplate>,
            tv: LocalField,
            expected_group_tvs: Vec<LocalField>,
        }

        let mut test_cases = [
            TestCase {
                group_template: Some(single_field_template.clone()),
                tv: LocalField::new(smallvec![TagValue::new(0, b"0")]),
                ..Default::default()
            },
            TestCase {
                group_template: Some(single_field_template.clone()),
                tv: LocalField::new(smallvec![
                    TagValue::new(0, b"1"),
                    TagValue::new(1, b"hello"),
                ]),
                expected_group_tvs: vec![LocalField::new(smallvec![TagValue::new(1, b"hello")])],
            },
            TestCase {
                group_template: Some(single_field_template.clone()),
                tv: LocalField::new(smallvec![
                    TagValue::new(0, b"1"),
                    TagValue::new(1, b"hello"),
                    TagValue::new(2, b"not in group"),
                ]),
                expected_group_tvs: vec![LocalField::new(smallvec![TagValue::new(1, b"hello")])],
            },
            TestCase {
                group_template: Some(single_field_template.clone()),
                tv: LocalField::new(smallvec![
                    TagValue::new(0, b"2"),
                    TagValue::new(1, b"hello"),
                    TagValue::new(1, b"world"),
                ]),
                expected_group_tvs: vec![
                    LocalField::new(smallvec![TagValue::new(1, b"hello")]),
                    LocalField::new(smallvec![TagValue::new(1, b"world")]),
                ],
            },
            TestCase {
                group_template: Some(multi_field_template.clone()),
                tv: LocalField::new(smallvec![
                    TagValue::new(0, b"2"),
                    TagValue::new(1, b"hello"),
                    TagValue::new(1, b"goodbye"),
                    TagValue::new(2, b"cruel"),
                    TagValue::new(3, b"world"),
                ]),
                expected_group_tvs: vec![
                    LocalField::new(smallvec![TagValue::new(1, b"hello")]),
                    LocalField::new(smallvec![
                        TagValue::new(1, b"goodbye"),
                        TagValue::new(2, b"cruel"),
                        TagValue::new(3, b"world"),
                    ]),
                ],
            },
            TestCase {
                group_template: Some(multi_field_template.clone()),
                tv: LocalField::new(smallvec![
                    TagValue::new(0, b"3"),
                    TagValue::new(1, b"hello"),
                    TagValue::new(1, b"goodbye"),
                    TagValue::new(2, b"cruel"),
                    TagValue::new(3, b"world"),
                    TagValue::new(1, b"another"),
                ]),
                expected_group_tvs: vec![
                    LocalField::new(smallvec![TagValue::new(1, b"hello")]),
                    LocalField::new(smallvec![
                        TagValue::new(1, b"goodbye"),
                        TagValue::new(2, b"cruel"),
                        TagValue::new(3, b"world"),
                    ]),
                    LocalField::new(smallvec![TagValue::new(1, b"another")]),
                ],
            },
        ];

        for tc in &mut test_cases {
            let mut f = RepeatingGroup::new(0, tc.group_template.take().unwrap());

            let read_result = f.read(tc.tv.clone());
            assert!(read_result.is_ok());

            assert_eq!(
                f.groups.len(),
                tc.expected_group_tvs.len(),
                "expected {} groups, got {}",
                tc.expected_group_tvs.len(),
                f.groups.len()
            );

            for (g, group) in f.groups.iter().enumerate() {
                for expected in &tc.expected_group_tvs[g].data {
                    let mut actual = FIXString::new();
                    let get_field_result = group.field_map.get_field(expected.tag, &mut actual);
                    assert!(get_field_result.is_ok());
                    assert!(!group.field_map.content.tag_sort.tags.is_empty());
                    assert_eq!(group.field_map.content.tag_sort.tags.len(), group.field_map.content.tag_lookup.len());
                    assert_eq!(
                        std::str::from_utf8(expected.value()).unwrap(),
                        actual,
                        "{}, {}: expected {}, got {}",
                        g,
                        expected.tag,
                        std::str::from_utf8(expected.value()).unwrap(),
                        actual
                    );
                }
            }
        }
    }

    // Entries created with `add` must serialize in template order, not
    // ascending tag order: the delimiter has to come first even when it is not
    // the lowest tag in the entry.
    #[test]
    fn test_repeating_group_add_uses_template_order() {
        let mut f = RepeatingGroup::new(453, vec![group_element(448), group_element(447)]);

        let group = f.add();
        // Set the lower tag first, so ascending order would be observable.
        group.field_map.set_field(447, FIXString::from("D"));
        group.field_map.set_field(448, FIXString::from("BROKER-A"));

        let tvs = f.write();
        let tags: Vec<Tag> = tvs.data.iter().map(|tv| tv.tag).collect();
        assert_eq!(vec![453, 448, 447], tags);
    }

    // A nested group's contents must survive into the parent entry's FieldMap,
    // not just the nested group's own count field.
    #[test]
    fn test_repeating_group_read_recursive_preserves_nested_content() {
        let nested_template = vec![group_element(400)];
        let parent_template: GroupTemplate = vec![
            group_element(200),
            Box::new(RepeatingGroup::new(300, nested_template.clone())),
        ];

        let mut f = RepeatingGroup::new(100, parent_template);
        f.read(LocalField::new(smallvec![
            TagValue::new(0, b"1"),
            TagValue::new(200, b"hello"),
            TagValue::new(300, b"2"),
            TagValue::new(400, b"foo"),
            TagValue::new(400, b"bar"),
        ]))
        .unwrap();

        assert_eq!(1, f.len());

        let entry = f.get(0);
        let nested = entry
            .field_map
            .get_group(RepeatingGroup::new(300, nested_template))
            .expect("nested group should be readable from the parent entry");

        assert_eq!(2, nested.len(), "nested group entries were dropped");
        assert_eq!(
            b"foo",
            nested.get(0).field_map.get_bytes(400).unwrap()
        );
        assert_eq!(
            b"bar",
            nested.get(1).field_map.get_bytes(400).unwrap()
        );
    }

    // Peer-supplied data whose first group member is not the delimiter used to
    // panic on `groups.last_mut().unwrap()`.
    #[test]
    fn test_repeating_group_read_member_before_delimiter() {
        let mut f = RepeatingGroup::new(100, vec![group_element(200), group_element(201)]);

        let err = f
            .read(LocalField::new(smallvec![
                TagValue::new(0, b"1"),
                TagValue::new(201, b"oops"),
                TagValue::new(200, b"hello"),
            ]))
            .expect_err("a member before the delimiter should be rejected");

        assert!(
            err.to_string().contains("before the delimiter"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_repeating_group_read_recursive() {
        let single_field_template = vec![group_element(4)];
        let parent_template = vec![
            group_element(2),
            Box::new(RepeatingGroup::new(3, single_field_template)),
            group_element(5),
        ];

        let mut f = RepeatingGroup::new(1, parent_template);
        let read_result = f.read(LocalField::new(smallvec![
            TagValue::new(0, b"2"),
            TagValue::new(2, b"hello"),
            TagValue::new(3, b"1"),
            TagValue::new(4, b"foo"),
            TagValue::new(2, b"world"),
            TagValue::new(3, b"2"),
            TagValue::new(4, b"foo"),
            TagValue::new(4, b"bar"),
            TagValue::new(5, b"fubar"),
        ]));
        assert!(read_result.is_ok());
        assert_eq!(2, f.len());
    }

    #[test]
    fn test_repeating_group_read_complete() {
        let raw_msg = "8=FIXT.1.19=26835=W34=711849=TEST52=20151027-18:41:52.69856=TST22=9948=TSTX15262=7268=4269=4270=0.07499272=20151027273=18:41:52.698269=7270=0.07501272=20151027273=18:41:52.698269=8270=0.07494272=20151027273=18:41:52.698269=B271=60272=20151027273=18:41:52.69810=163".as_bytes();

        let mut msg = Message::new();
        let parse_result = msg.parse_message(raw_msg);
        assert!(
            parse_result.is_ok(),
            "Unexpected error, {}",
            parse_result.unwrap_err(),
        );

        let template = vec![
            group_element(269),
            group_element(270),
            group_element(271),
            group_element(272),
            group_element(273),
        ];

        let f = RepeatingGroup::new(268, template);

        let get_group_result = msg.body.get_group(f);
        assert!(
            get_group_result.is_ok(),
            "Unexpected error",
        );

        let get_group = get_group_result.unwrap();

        assert_eq!(
            get_group.len(),
            4,
            "expected {} groups, got {}",
            4,
            get_group.len()
        );

        let expected_group_tags = [
            vec![269 as Tag, 270 as Tag, 272 as Tag, 273 as Tag],
            vec![269 as Tag, 270 as Tag, 272 as Tag, 273 as Tag],
            vec![269 as Tag, 270 as Tag, 272 as Tag, 273 as Tag],
            vec![269 as Tag, 271 as Tag, 272 as Tag, 273 as Tag],
        ];

        let expected_group_values = [
            vec![
                FIXString::from("4"),
                FIXString::from("0.07499"),
                FIXString::from("20151027"),
                FIXString::from("18:41:52.698"),
            ],
            vec![
                FIXString::from("7"),
                FIXString::from("0.07501"),
                FIXString::from("20151027"),
                FIXString::from("18:41:52.698"),
            ],
            vec![
                FIXString::from("8"),
                FIXString::from("0.07494"),
                FIXString::from("20151027"),
                FIXString::from("18:41:52.698"),
            ],
            vec![
                FIXString::from("B"),
                FIXString::from("60"),
                FIXString::from("20151027"),
                FIXString::from("18:41:52.698"),
            ],
        ];

        for (i, group) in get_group.groups.iter().enumerate() {
            for (j, tag) in expected_group_tags[i].iter().enumerate() {
                assert!(
                    group.field_map.has(*tag),
                    "expected {} in group {}",
                    expected_group_tags[i][j],
                    i
                );

                let mut actual = FIXString::new();
                let get_result = group.field_map.get_field(*tag, &mut actual);
                assert!(
                    get_result.is_ok(),
                    "error getting field {tag} from group {i}"
                );
                assert_eq!(
                    expected_group_values[i][j], actual,
                    "Expected {} got {}",
                    expected_group_tags[i][j], actual
                );
            }
        }
    }
}
