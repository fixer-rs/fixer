use crate::{
    errors::{repeating_group_fields_out_of_order, MessageRejectErrorEnum},
    field::{FieldGroupReader, FieldGroupWriter, FieldTag},
    field_map::{FieldMap, LocalField, TagOrderType},
    tag::Tag,
    tag_value::TagValue,
};
use delegate::delegate;
use dyn_clone::{clone_trait_object, DynClone};
use parking_lot::Mutex;
use std::{collections::HashMap, sync::Arc};

// GroupItem interface is used to construct repeating group templates.
// Tag returns the tag identifying this GroupItem.

// Read Parameter to Read is tagValues.  For most fields, only the first tagValue will be required.
// The length of the slice extends from the tagValue mapped to the field to be read through the
// following fields. This can be useful for GroupItems made up of repeating groups.

// The Read fntion returns the remaining tagValues not processed by the GroupItem. If there was a
// problem reading the field, an error may be returned.

pub trait GroupItem: DynClone + FieldTag + FieldGroupReader {}

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
        if !tv.is_empty() {
            let lock = tv.data.lock();
            if lock.get(tv.s_pos).unwrap().tag == self.tag {
                return Ok(LocalField::new_with_start_end(
                    tv.data.clone(),
                    tv.s_pos + 1,
                    tv.e_pos,
                ));
            }
        }
        Ok(tv)
    }
}

impl GroupItem for ProtoGroupElement {}

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
            pub fn init_with_ordering(self, ordering_type: TagOrderType) -> FieldMap;
            pub fn sorted_tags(&self) -> Vec<Tag>;
        }
    }
}

// RepeatingGroup is a FIX Repeating Group type.
#[derive(Clone, Default)]
pub struct RepeatingGroup {
    tag: Tag,
    template: GroupTemplate,
    pub groups: Vec<Arc<Group>>,
}

impl RepeatingGroup {
    // new returns an initilized RepeatingGroup instance.
    pub fn new(tag: Tag, template: GroupTemplate) -> Self {
        RepeatingGroup {
            tag,
            template,
            groups: vec![],
        }
    }

    // len returns the number of Groups in this RepeatingGroup.
    fn len(&self) -> usize {
        self.groups.len()
    }

    // get returns the ith group in this RepeatingGroup.
    fn get(&self, i: usize) -> Arc<Group> {
        self.groups[i].clone()
    }

    // add appends a new group to the RepeatingGroup and returns the new Group.
    fn add(&mut self) -> Arc<Group> {
        let g = Arc::new(Group {
            field_map: FieldMap::default(),
        });
        self.groups.push(g.clone());
        g
    }

    fn find_item_in_group_template(&self, t: Tag) -> Option<Box<dyn GroupItem>> {
        for template_field in self.template.iter() {
            if t == template_field.tag() {
                return Some(template_field.clone());
            }
        }
        None
    }

    fn group_tag_order(&self) -> Arc<HashMap<Tag, usize>> {
        Arc::new(
            self.template
                .iter()
                .enumerate()
                .map(|template_field| (template_field.1.tag(), template_field.0))
                .collect(),
        )
    }

    fn delimiter(&self) -> Tag {
        self.template.get(0).unwrap().tag()
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
        let mut tv = tv;
        if tv.is_empty() {
            return Ok(LocalField::new(Arc::new(Mutex::new(vec![]))));
        }

        let lock = tv.data.lock();
        let value = &lock.get(tv.s_pos).unwrap().value;

        let expected_group_size_result = atoi_simd::parse::<usize>(value);

        if expected_group_size_result.is_err() {
            drop(lock);
            // TODO: check error
            return Ok(tv);
        }

        let expected_group_size = expected_group_size_result.unwrap();

        if expected_group_size == 0 {
            return Ok(LocalField::new_with_start_end(
                tv.data.clone(),
                tv.s_pos + 1,
                tv.e_pos,
            ));
        }

        let until = lock.len();
        let data = tv.data.clone();
        drop(lock);

        tv = LocalField::new_with_start_end(data, tv.s_pos + 1, until);

        let tag_ordering = self.group_tag_order();

        let mut group = Arc::new(Group {
            field_map: FieldMap::default()
                .init_with_ordering(TagOrderType::RepeatingGroup(tag_ordering.clone())),
        });

        while !tv.is_empty() {
            let lock = tv.data.lock();
            let mut tag = lock.get(tv.s_pos).unwrap().tag;
            let gi_result = self.find_item_in_group_template(tag);
            if gi_result.is_none() {
                break;
            }
            let mut gi = gi_result.unwrap();
            drop(lock);

            let tv_range = tv.clone();
            let lock = tv_range.data.lock();
            tag = lock.get(tv_range.s_pos).unwrap().tag;
            drop(lock);

            tv = gi.read(tv)?;
            if self.is_delimiter(gi.tag()) {
                group = Arc::new(Group {
                    field_map: FieldMap::default()
                        .init_with_ordering(TagOrderType::RepeatingGroup(tag_ordering.clone())),
                });
                self.groups.push(group.clone());
            }

            let mut lock = group.field_map.rw_lock.write();
            lock.tag_lookup.insert(tag, tv_range);
            lock.tag_sort.tags.push(gi.tag());
        }

        if self.groups.len() != expected_group_size {
            return Err(repeating_group_fields_out_of_order(self.tag, format!("group {}: template is wrong or delimiter {} not found: expected {} groups, but found {}", self.tag, self.delimiter(), expected_group_size, self.groups.len())));
        }

        Ok(tv)
    }
}

impl FieldGroupWriter for RepeatingGroup {
    // write returns tagValues for all Items in the repeating group ordered by
    // Group sequence and Group template order.
    fn write(&self) -> LocalField {
        let mut new_buffer = itoa::Buffer::new();
        let bytes_str = new_buffer.format(self.groups.len());

        let mut tv = TagValue::default();
        tv.init(self.tag, bytes_str.as_bytes());
        let mut tvs = vec![tv];

        for group in self.groups.iter() {
            let tags = group.sorted_tags();
            for tag in tags {
                let lock = group.field_map.rw_lock.read();
                if let Some(fields) = lock.tag_lookup.get(&tag) {
                    let lock = fields.data.lock();
                    let fields_slice = lock.get(fields.s_pos..fields.e_pos).unwrap();
                    tvs.extend_from_slice(fields_slice);
                }
            }
        }

        LocalField::new(Arc::new(Mutex::new(tvs)))
    }
}

impl GroupItem for RepeatingGroup {}

#[cfg(test)]
mod tests {
    use crate::{
        field::{FieldGroupReader, FieldGroupWriter},
        field_map::LocalField,
        fix_string::FIXString,
        message::Message,
        repeating_group::{group_element, GroupTemplate, RepeatingGroup},
        tag::Tag,
        tag_value::TagValue,
    };
    use parking_lot::Mutex;
    use std::sync::Arc;

    #[test]
    fn test_repeating_group_add() {
        let mut f = RepeatingGroup {
            template: vec![group_element(1)],
            ..Default::default()
        };

        struct TestCase {
            expected_len: usize,
        }

        let test_cases = vec![TestCase { expected_len: 1 }, TestCase { expected_len: 2 }];

        for tc in test_cases.iter() {
            let g = f.add();

            assert_eq!(
                f.len(),
                tc.expected_len,
                "Expected {} groups, got {}",
                tc.expected_len,
                f.len()
            );

            g.field_map.set_field(1, FIXString::from("hello"));

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
        let mut f1 = RepeatingGroup {
            tag: 10,
            template: vec![group_element(1), group_element(2)],
            ..Default::default()
        };

        let g1 = f1.add();
        g1.field_map.set_field(1, FIXString::from("hello"));

        let mut f2 = RepeatingGroup {
            tag: 11,
            template: vec![group_element(1), group_element(2)],
            ..Default::default()
        };

        let g2 = f2.add();
        g2.field_map.set_field(1, FIXString::from("hello"));
        g2.field_map.set_field(2, FIXString::from("world"));

        let mut f3 = RepeatingGroup {
            tag: 12,
            template: vec![group_element(1), group_element(2)],
            ..Default::default()
        };

        let g31 = f3.add();
        g31.field_map.set_field(1, FIXString::from("hello"));
        let g32 = f3.add();
        g32.field_map.set_field(1, FIXString::from("world"));

        let mut f4 = RepeatingGroup {
            tag: 13,
            template: vec![group_element(1), group_element(2)],
            ..Default::default()
        };

        let g41 = f4.add();
        g41.field_map.set_field(1, FIXString::from("hello"));
        g41.field_map.set_field(2, FIXString::from("world"));
        let g42 = f4.add();
        g42.field_map.set_field(1, FIXString::from("goodbye"));

        struct TestCase<'a> {
            f: RepeatingGroup,
            expected: &'a [u8],
        }

        let test_cases = vec![
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

        for tc in test_cases.iter() {
            let mut tvbytes = vec![];
            let tvs = tc.f.write();
            let lock = tvs.data.lock();
            for tv in lock.get(tvs.s_pos..tvs.e_pos).unwrap().iter() {
                tvbytes.extend_from_slice(&tv.bytes);
            }
            assert_eq!(
                tc.expected,
                &tvbytes,
                "expected {} got {}",
                String::from_utf8_lossy(tc.expected),
                String::from_utf8_lossy(&tvbytes)
            )
        }
    }

    #[test]
    fn test_repeating_group_read_error() {
        let single_field_template = vec![group_element(1)];

        struct TestCase {
            tv: LocalField,
            expected_group_num: usize,
        }

        let test_cases = vec![
            TestCase {
                tv: LocalField::new(Arc::new(Mutex::new(vec![
                    TagValue {
                        tag: 0,
                        value: "1".as_bytes().to_vec(),
                        bytes: vec![],
                    },
                    TagValue {
                        tag: 2,
                        value: "not in template".as_bytes().to_vec(),
                        bytes: vec![],
                    },
                    TagValue {
                        tag: 1,
                        value: "hello".as_bytes().to_vec(),
                        bytes: vec![],
                    },
                ]))),
                expected_group_num: 0,
            },
            TestCase {
                tv: LocalField::new(Arc::new(Mutex::new(vec![
                    TagValue {
                        tag: 0,
                        value: "2".as_bytes().to_vec(),
                        bytes: vec![],
                    },
                    TagValue {
                        tag: 1,
                        value: "hello".as_bytes().to_vec(),
                        bytes: vec![],
                    },
                    TagValue {
                        tag: 2,
                        value: "not in template".as_bytes().to_vec(),
                        bytes: vec![],
                    },
                    TagValue {
                        tag: 1,
                        value: "hello".as_bytes().to_vec(),
                        bytes: vec![],
                    },
                ]))),
                expected_group_num: 1,
            },
        ];

        for tc in test_cases.iter() {
            let mut f = RepeatingGroup {
                template: single_field_template.clone(),
                ..Default::default()
            };
            let read_result = f.read(tc.tv.clone());
            assert!(read_result.is_err() && f.groups.len() == tc.expected_group_num, "Should have raised an error because expected group number is wrong: {} instead of {}", f.groups.len(), tc.expected_group_num);
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

        let mut test_cases = vec![
            TestCase {
                group_template: Some(single_field_template.clone()),
                tv: LocalField::new(Arc::new(Mutex::new(vec![TagValue {
                    tag: 0,
                    value: "0".as_bytes().to_vec(),
                    ..Default::default()
                }]))),
                ..Default::default()
            },
            TestCase {
                group_template: Some(single_field_template.clone()),
                tv: LocalField::new(Arc::new(Mutex::new(vec![
                    TagValue {
                        tag: 0,
                        value: "1".as_bytes().to_vec(),
                        ..Default::default()
                    },
                    TagValue {
                        tag: 1,
                        value: "hello".as_bytes().to_vec(),
                        ..Default::default()
                    },
                ]))),
                expected_group_tvs: vec![LocalField::new(Arc::new(Mutex::new(vec![TagValue {
                    tag: 1,
                    value: "hello".as_bytes().to_vec(),
                    ..Default::default()
                }])))],
            },
            TestCase {
                group_template: Some(single_field_template.clone()),
                tv: LocalField::new(Arc::new(Mutex::new(vec![
                    TagValue {
                        tag: 0,
                        value: "1".as_bytes().to_vec(),
                        ..Default::default()
                    },
                    TagValue {
                        tag: 1,
                        value: "hello".as_bytes().to_vec(),
                        ..Default::default()
                    },
                    TagValue {
                        tag: 2,
                        value: "not in group".as_bytes().to_vec(),
                        ..Default::default()
                    },
                ]))),
                expected_group_tvs: vec![LocalField::new(Arc::new(Mutex::new(vec![TagValue {
                    tag: 1,
                    value: "hello".as_bytes().to_vec(),
                    ..Default::default()
                }])))],
            },
            TestCase {
                group_template: Some(single_field_template.clone()),
                tv: LocalField::new(Arc::new(Mutex::new(vec![
                    TagValue {
                        tag: 0,
                        value: "2".as_bytes().to_vec(),
                        ..Default::default()
                    },
                    TagValue {
                        tag: 1,
                        value: "hello".as_bytes().to_vec(),
                        ..Default::default()
                    },
                    TagValue {
                        tag: 1,
                        value: "world".as_bytes().to_vec(),
                        ..Default::default()
                    },
                ]))),
                expected_group_tvs: vec![
                    LocalField::new(Arc::new(Mutex::new(vec![TagValue {
                        tag: 1,
                        value: "hello".as_bytes().to_vec(),
                        ..Default::default()
                    }]))),
                    LocalField::new(Arc::new(Mutex::new(vec![TagValue {
                        tag: 1,
                        value: "world".as_bytes().to_vec(),
                        ..Default::default()
                    }]))),
                ],
            },
            TestCase {
                group_template: Some(multi_field_template.clone()),
                tv: LocalField::new(Arc::new(Mutex::new(vec![
                    TagValue {
                        tag: 0,
                        value: "2".as_bytes().to_vec(),
                        ..Default::default()
                    },
                    TagValue {
                        tag: 1,
                        value: "hello".as_bytes().to_vec(),
                        ..Default::default()
                    },
                    TagValue {
                        tag: 1,
                        value: "goodbye".as_bytes().to_vec(),
                        ..Default::default()
                    },
                    TagValue {
                        tag: 2,
                        value: "cruel".as_bytes().to_vec(),
                        ..Default::default()
                    },
                    TagValue {
                        tag: 3,
                        value: "world".as_bytes().to_vec(),
                        ..Default::default()
                    },
                ]))),
                expected_group_tvs: vec![
                    LocalField::new(Arc::new(Mutex::new(vec![TagValue {
                        tag: 1,
                        value: "hello".as_bytes().to_vec(),
                        ..Default::default()
                    }]))),
                    LocalField::new(Arc::new(Mutex::new(vec![
                        TagValue {
                            tag: 1,
                            value: "goodbye".as_bytes().to_vec(),
                            ..Default::default()
                        },
                        TagValue {
                            tag: 2,
                            value: "cruel".as_bytes().to_vec(),
                            ..Default::default()
                        },
                        TagValue {
                            tag: 3,
                            value: "world".as_bytes().to_vec(),
                            ..Default::default()
                        },
                    ]))),
                ],
            },
            TestCase {
                group_template: Some(multi_field_template.clone()),
                tv: LocalField::new(Arc::new(Mutex::new(vec![
                    TagValue {
                        tag: 0,
                        value: "3".as_bytes().to_vec(),
                        ..Default::default()
                    },
                    TagValue {
                        tag: 1,
                        value: "hello".as_bytes().to_vec(),
                        ..Default::default()
                    },
                    TagValue {
                        tag: 1,
                        value: "goodbye".as_bytes().to_vec(),
                        ..Default::default()
                    },
                    TagValue {
                        tag: 2,
                        value: "cruel".as_bytes().to_vec(),
                        ..Default::default()
                    },
                    TagValue {
                        tag: 3,
                        value: "world".as_bytes().to_vec(),
                        ..Default::default()
                    },
                    TagValue {
                        tag: 1,
                        value: "another".as_bytes().to_vec(),
                        ..Default::default()
                    },
                ]))),
                expected_group_tvs: vec![
                    LocalField::new(Arc::new(Mutex::new(vec![TagValue {
                        tag: 1,
                        value: "hello".as_bytes().to_vec(),
                        ..Default::default()
                    }]))),
                    LocalField::new(Arc::new(Mutex::new(vec![
                        TagValue {
                            tag: 1,
                            value: "goodbye".as_bytes().to_vec(),
                            ..Default::default()
                        },
                        TagValue {
                            tag: 2,
                            value: "cruel".as_bytes().to_vec(),
                            ..Default::default()
                        },
                        TagValue {
                            tag: 3,
                            value: "world".as_bytes().to_vec(),
                            ..Default::default()
                        },
                    ]))),
                    LocalField::new(Arc::new(Mutex::new(vec![TagValue {
                        tag: 1,
                        value: "another".as_bytes().to_vec(),
                        ..Default::default()
                    }]))),
                ],
            },
        ];

        for tc in test_cases.iter_mut() {
            let mut f = RepeatingGroup {
                tag: 0,
                template: tc.group_template.take().unwrap(),
                ..Default::default()
            };

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
                let lock = tc.expected_group_tvs[g].data.lock();

                for expected in lock.iter() {
                    let mut actual = FIXString::new();
                    let get_field_result = group.field_map.get_field(expected.tag, &mut actual);
                    assert!(get_field_result.is_ok());
                    let read = group.field_map.rw_lock.read();
                    assert!(!read.tag_sort.tags.is_empty());
                    assert_eq!(read.tag_sort.tags.len(), read.tag_lookup.len());
                    assert_eq!(
                        String::from_utf8_lossy(&expected.value),
                        actual,
                        "{}, {}: expected {}, got {}",
                        g,
                        expected.tag,
                        String::from_utf8_lossy(&expected.value),
                        actual
                    );
                }
            }
        }
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
        let read_result = f.read(LocalField::new(Arc::new(Mutex::new(vec![
            TagValue {
                tag: 0,
                value: "2".as_bytes().to_vec(),
                ..Default::default()
            },
            TagValue {
                tag: 2,
                value: "hello".as_bytes().to_vec(),
                ..Default::default()
            },
            TagValue {
                tag: 3,
                value: "1".as_bytes().to_vec(),
                ..Default::default()
            },
            TagValue {
                tag: 4,
                value: "foo".as_bytes().to_vec(),
                ..Default::default()
            },
            TagValue {
                tag: 2,
                value: "world".as_bytes().to_vec(),
                ..Default::default()
            },
            TagValue {
                tag: 3,
                value: "2".as_bytes().to_vec(),
                ..Default::default()
            },
            TagValue {
                tag: 4,
                value: "foo".as_bytes().to_vec(),
                ..Default::default()
            },
            TagValue {
                tag: 4,
                value: "bar".as_bytes().to_vec(),
                ..Default::default()
            },
            TagValue {
                tag: 5,
                value: "fubar".as_bytes().to_vec(),
                ..Default::default()
            },
        ]))));
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

        let f = RepeatingGroup {
            tag: 268,
            template,
            ..Default::default()
        };

        let get_group_result = msg.body.get_group(f);
        assert!(
            get_group_result.is_ok(),
            "Unexpected error", //{:?}",
                                // get_group_result.unwrap_err(),
        );

        let get_group = get_group_result.unwrap();

        assert_eq!(
            get_group.len(),
            4,
            "expected {} groups, got {}",
            4,
            get_group.len()
        );

        let expected_group_tags = vec![
            vec![269 as Tag, 270 as Tag, 272 as Tag, 273 as Tag],
            vec![269 as Tag, 270 as Tag, 272 as Tag, 273 as Tag],
            vec![269 as Tag, 270 as Tag, 272 as Tag, 273 as Tag],
            vec![269 as Tag, 271 as Tag, 272 as Tag, 273 as Tag],
        ];

        let expected_group_values = vec![
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
                    "error getting field {} from group {}",
                    tag,
                    i
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
