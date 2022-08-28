use anyhow::Error;
use delegate::delegate;
use quick_xml::de::from_reader;
use std::{
    collections::{HashMap, HashSet},
    fmt,
    io::BufRead,
};
use tokio::fs::File;
use tokio::io::AsyncReadExt;

pub mod build;
pub mod xml;

// DataDictionary models FIX messages, components, and fields.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct DataDictionary {
    pub fix_type: String,
    pub major: isize,
    pub minor: isize,
    pub service_pack: isize,
    pub field_type_by_tag: HashMap<isize, FieldType>,
    pub field_type_by_name: HashMap<String, FieldType>,
    pub messages: HashMap<String, MessageDef>,
    pub component_types: HashMap<String, ComponentType>,
    pub header: MessageDef,
    pub trailer: MessageDef,
}

// MessagePart can represent a Field, Repeating Group, or Component
#[derive(Clone, Eq)]
pub enum MessagePart {
    FieldDef(FieldDef),
    FieldType(FieldType),
    ComponentType(ComponentType),
    Component(Component),
}

impl Default for MessagePart {
    fn default() -> Self {
        MessagePart::FieldDef(FieldDef::default())
    }
}

impl MessagePart {
    pub fn name(&self) -> &str {
        match self {
            Self::FieldDef(fd) => fd.name(),
            Self::FieldType(ft) => ft.name(),
            Self::ComponentType(ct) => ct.name(),
            Self::Component(c) => c.name(),
        }
    }

    pub fn required(&self) -> bool {
        match self {
            Self::FieldDef(fd) => fd.required(),
            Self::FieldType(ft) => ft.required(),
            Self::ComponentType(ct) => ct.required(),
            Self::Component(c) => c.required(),
        }
    }

    pub fn fields(&self) -> Option<&Vec<FieldDef>> {
        match self {
            Self::FieldDef(_) => None,
            Self::FieldType(_) => None,
            Self::ComponentType(ct) => Some(ct.fields()),
            Self::Component(c) => Some(c.fields()),
        }
    }

    // required_fields returns those fields that are required for this component
    pub fn required_fields(&self) -> Option<&Vec<FieldDef>> {
        match self {
            Self::FieldDef(fd) => Some(fd.required_fields()),
            Self::FieldType(_) => None,
            Self::ComponentType(ct) => Some(ct.required_fields()),
            Self::Component(c) => Some(c.required_fields()),
        }
    }
}

impl fmt::Debug for MessagePart {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "name: {}, required: {}", self.name(), self.required())
    }
}

impl PartialEq for MessagePart {
    fn eq(&self, other: &Self) -> bool {
        self.name() == other.name() && self.required() == other.required()
    }
}

#[derive(Default, Debug, Clone, PartialEq, Eq)]
// ComponentType is a grouping of fields.
pub struct ComponentType {
    name: String,
    parts: Vec<MessagePart>,
    fields: Vec<FieldDef>,
    required_fields: Vec<FieldDef>,
    required_parts: Vec<MessagePart>,
}

impl ComponentType {
    // new returns an initialized ComponentType
    pub fn new(name: String, parts: Vec<MessagePart>) -> Self {
        let mut comp = ComponentType {
            name,
            parts,
            ..Default::default()
        };

        for part in comp.parts.iter() {
            if part.required() {
                comp.required_parts.push(part.clone());
            }

            match part {
                MessagePart::FieldDef(fd) => {
                    comp.fields.push(fd.clone());
                    if part.required() {
                        comp.required_fields.push(fd.clone());
                    }
                }
                MessagePart::FieldType(_) => {}
                MessagePart::ComponentType(ct) => {
                    comp.fields.extend_from_slice(ct.fields());
                    if ct.required() {
                        comp.required_fields.extend_from_slice(ct.required_fields());
                    }
                }
                MessagePart::Component(c) => {
                    comp.fields.extend_from_slice(c.fields());
                    if c.required() {
                        comp.required_fields.extend_from_slice(c.required_fields());
                    }
                }
            }
        }
        comp
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn required(&self) -> bool {
        false
    }

    // required_parts returns those parts that are required for this component
    pub fn required_parts(&self) -> &Vec<MessagePart> {
        &self.required_parts
    }

    // parts returns all parts in declaration order contained in this component
    pub fn parts(&self) -> &Vec<MessagePart> {
        &self.parts
    }

    // fields returns all fields contained in this component.
    // Includes fields encapsulated in components of this component
    pub fn fields(&self) -> &Vec<FieldDef> {
        &self.fields
    }

    // required_fields returns those fields that are required for this component
    pub fn required_fields(&self) -> &Vec<FieldDef> {
        &self.required_fields
    }
}

// TagSet is set for tags.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct TagSet(HashSet<isize>);

// add adds a tag to the tagset.
impl TagSet {
    pub fn add(&mut self, tag: isize) {
        self.0.insert(tag);
    }
}

// Component is a Component as it appears in a given MessageDef
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct Component {
    pub component_type: ComponentType,
    pub required: bool,
}

impl Component {
    // new returns an initialized Component instance
    pub fn new(component_type: ComponentType, required: bool) -> Self {
        Component {
            component_type,
            required,
        }
    }

    pub fn required(&self) -> bool {
        self.required
    }

    delegate! {
        to self.component_type {
            pub fn name(&self) -> &str;
            pub fn fields(&self) -> &Vec<FieldDef>;
            pub fn required_fields(&self) -> &Vec<FieldDef>;
        }
    }
}

// FieldDef models a field belonging to a message.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct FieldDef {
    field_type: FieldType,
    required: bool,
    pub parts: Vec<MessagePart>,
    pub fields: Vec<FieldDef>,
    required_parts: Vec<MessagePart>,
    required_fields: Vec<FieldDef>,
}

impl FieldDef {
    // new returns an initialized FieldDef
    pub fn new(field_type: FieldType, required: bool) -> Self {
        FieldDef {
            field_type,
            required,
            ..Default::default()
        }
    }

    // new_group returns an initialized FieldDef for a repeating group
    pub fn new_group(field_type: FieldType, required: bool, parts: Vec<MessagePart>) -> FieldDef {
        let mut field = FieldDef {
            field_type,
            required,
            parts,
            ..Default::default()
        };

        for part in field.parts.iter() {
            if part.required() {
                field.required_parts.push(part.clone());
            }

            match part {
                MessagePart::FieldDef(fd) => {
                    field.fields.push(fd.clone());
                    if part.required() {
                        field.required_fields.push(fd.clone());
                    }
                }
                MessagePart::Component(c) => {
                    field.fields.extend_from_slice(c.fields());
                    if c.required() {
                        field.required_fields.extend_from_slice(c.required_fields());
                    }
                }
                _ => {} // TODO: other type should return error
            }
        }
        field
    }

    delegate! {
        to self.field_type {
            pub fn name(&self) -> &str;
            pub fn tag(&self) -> isize;
        }
    }

    // required returns true if this FieldDef is required for the containing MessageDef
    pub fn required(&self) -> bool {
        self.required
    }

    // is_group is true if the field is a repeating group.
    pub fn is_group(&self) -> bool {
        !self.fields.is_empty()
    }

    // required_parts returns those parts that are required for this FieldDef.
    // is_group must return true
    pub fn required_parts(&self) -> &Vec<MessagePart> {
        &self.required_parts
    }

    // required_fields returns those fields that are required for this FieldDef.
    // is_group must return true
    pub fn required_fields(&self) -> &Vec<FieldDef> {
        &self.required_fields
    }

    pub fn child_tags(&self) -> Vec<isize> {
        let mut tags = Vec::new();

        for field in self.fields.iter() {
            tags.push(field.tag());
            tags.extend(field.child_tags());
        }

        tags
    }
}

// FieldType holds information relating to a field.  Includes Tag, type, and enums, if defined.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct FieldType {
    name: String,
    tag: isize,
    pub r#type: String,
    pub enums: HashMap<String, Enum>,
}

impl FieldType {
    // new returns an initialized FieldType
    pub fn new(name: String, tag: isize, fix_type: String) -> Self {
        FieldType {
            name,
            tag,
            r#type: fix_type,
            enums: HashMap::new(),
        }
    }

    // name returns the name of this component type
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn required(&self) -> bool {
        false // will be overriden
    }

    pub fn tag(&self) -> isize {
        self.tag
    }
}

// Enum is a container for value and description.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct Enum {
    pub value: String,
    pub description: String,
}

// MessageDef can apply to header, trailer, or body of a FIX Message.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct MessageDef {
    pub name: String,
    pub msg_type: String,
    pub fields: HashMap<isize, FieldDef>,
    // Parts are the MessageParts of contained in this MessageDef in declaration order
    pub parts: Vec<MessagePart>,
    pub required_parts: Vec<MessagePart>,
    pub required_tags: TagSet,
    pub tags: TagSet,
}

impl MessageDef {
    // new returns an initialized MessageDef
    pub fn new(name: String, msg_type: String, parts: Vec<MessagePart>) -> Self {
        let mut msg = MessageDef {
            name,
            msg_type,
            fields: hashmap! {},
            required_tags: TagSet(hashset! {}),
            tags: TagSet(hashset! {}),
            parts,
            required_parts: Vec::new(),
        };

        let mut process_field = |field: &FieldDef, allow_required: bool| {
            let tag = field.tag();
            msg.fields.insert(tag, field.clone());
            msg.tags.add(tag);
            for t in field.child_tags() {
                msg.tags.add(t);
            }

            if allow_required && field.required() {
                msg.required_tags.add(tag);
            }
        };

        for part in msg.parts.iter() {
            if part.required() {
                msg.required_parts.push(part.clone());
            }

            match part {
                MessagePart::FieldDef(fd) => {
                    process_field(fd, true);
                }

                MessagePart::ComponentType(ct) => {
                    for f in ct.fields() {
                        process_field(f, ct.required());
                    }
                }
                MessagePart::Component(c) => {
                    for f in c.fields() {
                        process_field(f, c.required());
                    }
                }
                _ => {} // TODO: other type should return error
            }
        }
        msg
    }

    // required_parts returns those parts that are required for this Message
    pub fn required_parts(&self) -> &Vec<MessagePart> {
        &self.required_parts
    }
}

// parse loads and build a datadictionary instance from an xml file.
async fn parse(path: &'_ str) -> Result<DataDictionary, Error> {
    let mut file = File::open(path).await?;

    let mut contents = vec![];
    file.read_to_end(&mut contents).await.map_err(|err| {
        let err_string = format!("problem opening file: {}", path);
        Error::new(err).context(err_string)
    })?;

    parse_src(&*contents)
}

// parse_src loads and build a datadictionary instance from an xml source.
pub fn parse_src<R: BufRead>(xml_src: R) -> Result<DataDictionary, Error> {
    let xml_doc: xml::XMLDoc =
        from_reader(xml_src).map_err(|err| Error::new(err).context("problem parsing XML file"))?;

    let mut builder = build::Builder::default();
    let dict = builder.build(&xml_doc)?;

    Ok(dict)
}

#[cfg(test)]
mod component_type_tests {
    use super::*;

    #[test]
    fn test_new_component_type() {
        let ft1 = FieldType::new(String::from("aname1"), 11, String::from("INT"));
        let ft2 = FieldType::new(String::from("aname2"), 12, String::from("INT"));

        let optional_field1 = FieldDef::new(ft1.clone(), false);
        let required_field1 = FieldDef::new(ft1.clone(), true);
        let optional_field2 = FieldDef::new(ft2.clone(), false);
        let required_field2 = FieldDef::new(ft2.clone(), true);

        let required_comp1 = Component::new(
            ComponentType::new(
                String::from("comp1"),
                vec![MessagePart::FieldDef(required_field1.clone())],
            ),
            true,
        );

        let optional_comp1 = Component::new(
            ComponentType::new(
                String::from("comp1"),
                vec![MessagePart::FieldDef(required_field1.clone())],
            ),
            false,
        );

        struct TestCase {
            test_name: String,
            parts: Vec<MessagePart>,
            expected_fields: Vec<FieldDef>,
            expected_required_parts: Vec<MessagePart>,
            expected_required_fields: Vec<FieldDef>,
        }

        let tests = vec![
            TestCase {
                test_name: String::from("test1"),
                parts: vec![MessagePart::FieldDef(optional_field1.clone())],
                expected_fields: vec![optional_field1.clone()],
                expected_required_parts: Vec::new(),
                expected_required_fields: Vec::new(),
            },
            TestCase {
                test_name: String::from("test2"),
                parts: vec![MessagePart::FieldDef(required_field1.clone())],
                expected_fields: vec![required_field1.clone()],
                expected_required_fields: vec![required_field1.clone()],
                expected_required_parts: vec![MessagePart::FieldDef(required_field1.clone())],
            },
            TestCase {
                test_name: String::from("test3"),
                parts: vec![
                    MessagePart::FieldDef(required_field1.clone()),
                    MessagePart::FieldDef(optional_field2.clone()),
                ],
                expected_fields: vec![required_field1.clone(), optional_field2.clone()],
                expected_required_fields: vec![required_field1.clone()],
                expected_required_parts: vec![MessagePart::FieldDef(required_field1.clone())],
            },
            TestCase {
                test_name: String::from("test4"),
                parts: vec![
                    MessagePart::FieldDef(required_field2.clone()),
                    MessagePart::Component(optional_comp1.clone()),
                ],
                expected_fields: vec![required_field2.clone(), required_field1.clone()],
                expected_required_fields: vec![required_field2.clone()],
                expected_required_parts: vec![MessagePart::FieldDef(required_field2.clone())],
            },
            TestCase {
                test_name: String::from("test5"),
                parts: vec![
                    MessagePart::FieldDef(required_field2.clone()),
                    MessagePart::Component(required_comp1.clone()),
                ],
                expected_fields: vec![required_field2.clone(), required_field1.clone()],
                expected_required_fields: vec![required_field2.clone(), required_field1.clone()],
                expected_required_parts: vec![
                    MessagePart::FieldDef(required_field2.clone()),
                    MessagePart::Component(required_comp1.clone()),
                ],
            },
        ];

        for test in tests.iter() {
            let ct = ComponentType::new(String::from("cname"), test.parts.clone());

            assert_eq!(String::from("cname"), ct.name(), "{}", test.test_name);
            assert_eq!(&test.expected_fields, ct.fields(), "{}", test.test_name);
            assert_eq!(&test.parts, ct.parts(), "{}", test.test_name);
            assert_eq!(
                &test.expected_required_fields,
                ct.required_fields(),
                "{}",
                test.test_name,
            );
            assert_eq!(
                &test.expected_required_parts,
                ct.required_parts(),
                "{}",
                test.test_name,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_once::AsyncOnce;

    #[tokio::test]
    async fn test_parse_bad_path() {
        let result = parse("../spec/bogus.xml").await;
        assert!(result.is_err(), "Expected err");
    }

    #[tokio::test]
    async fn test_parse_recursive_components() {
        let result = parse("./spec/FIX44.xml").await;
        assert!(!result.is_err(), "Unexpected err: {:?}", result);
        assert!(result.is_ok(), "Dictionary is nil");
    }

    // global variable
    lazy_static! {
        static ref DICT: AsyncOnce<DataDictionary> = AsyncOnce::new(async {
            let dd = parse("./spec/FIX43.xml").await.unwrap();
            dd
        });
    }

    #[tokio::test]
    async fn test_components() {
        let d = DICT.get().await.clone();
        assert!(
            d.component_types.contains_key("SpreadOrBenchmarkCurveData"),
            "Component not found"
        );
    }

    #[tokio::test]
    async fn test_fields_by_tag() {
        let d = DICT.get().await.clone();

        struct TestCase {
            tag: isize,
            name: &'static str,
            r#type: &'static str,
            enums_are_nil: bool,
        }

        let tests = vec![
            TestCase {
                tag: 655,
                name: "ContraLegRefID",
                r#type: "STRING",
                enums_are_nil: true,
            },
            TestCase {
                tag: 658,
                name: "QuoteRequestRejectReason",
                r#type: "INT",
                enums_are_nil: false,
            },
        ];

        for test in tests.iter() {
            assert!(
                d.field_type_by_tag.contains_key(&test.tag),
                "{} not found",
                test.tag
            );

            let f = d.field_type_by_tag.get(&test.tag).unwrap();

            assert_eq!(
                f.name(),
                test.name,
                "Expected {} got {}",
                test.name,
                f.name()
            );

            assert_eq!(
                f.r#type, test.r#type,
                "Expected {} got {}",
                test.r#type, f.r#type
            );
            assert!(
                !(!f.enums.is_empty() && test.enums_are_nil),
                "Expected no enums"
            );

            assert!(
                !(f.enums.is_empty() && !test.enums_are_nil),
                "Expected enums"
            );
        }
    }

    #[tokio::test]
    async fn test_enum_fields_by_tag() {
        let d = DICT.get().await.clone();

        let f = d.field_type_by_tag.get(&658).unwrap();

        struct TestCase {
            value: &'static str,
            description: &'static str,
        }

        let tests = vec![
            TestCase {
                value: "1",
                description: "UNKNOWN_SYMBOL",
            },
            TestCase {
                value: "2",
                description: "EXCHANGE",
            },
            TestCase {
                value: "3",
                description: "QUOTE_REQUEST_EXCEEDS_LIMIT",
            },
            TestCase {
                value: "4",
                description: "TOO_LATE_TO_ENTER",
            },
            TestCase {
                value: "5",
                description: "INVALID_PRICE",
            },
            TestCase {
                value: "6",
                description: "NOT_AUTHORIZED_TO_REQUEST_QUOTE",
            },
        ];

        assert_eq!(
            f.enums.len(),
            tests.len(),
            "Expected {} enums got {}",
            tests.len(),
            f.enums.len()
        );

        for test in tests.iter() {
            assert!(
                f.enums.contains_key(test.value),
                "Expected Enum {}",
                test.value
            );

            let r#enum = f.enums.get(test.value).unwrap();
            assert_eq!(
                r#enum.value, test.value,
                "Expected value {} got {}",
                test.value, r#enum.value
            );

            assert_eq!(
                r#enum.description, test.description,
                "Expected value {} got {}",
                test.description, r#enum.description
            );
        }
    }

    #[tokio::test]
    async fn test_data_dictionary_messages() {
        let d = DICT.get().await.clone();
        assert!(d.messages.contains_key("D"), "Did not find message");
    }

    #[tokio::test]
    async fn test_data_dictionary_header() {
        // no need to test header existence as it's not Option
    }

    #[tokio::test]
    async fn test_data_dictionary_trailer() {
        // no need to test trailer existence as it's not Option
    }

    #[tokio::test]
    async fn test_message_required_tags() {
        let d = DICT.get().await.clone();

        let nos = d.messages.get("D").unwrap();

        struct TestCase {
            message_def: MessageDef,
            tag: isize,
            required: bool,
        }

        let tests = vec![
            TestCase {
                message_def: nos.clone(),
                tag: 11,
                required: true,
            },
            TestCase {
                message_def: nos.clone(),
                tag: 526,
                required: false,
            },
            TestCase {
                message_def: d.header.clone(),
                tag: 8,
                required: true,
            },
            TestCase {
                message_def: d.header.clone(),
                tag: 115,
                required: false,
            },
            TestCase {
                message_def: d.trailer.clone(),
                tag: 10,
                required: true,
            },
            TestCase {
                message_def: d.trailer.clone(),
                tag: 89,
                required: false,
            },
        ];

        for test in tests.iter() {
            let TagSet(inner_tag) = &test.message_def.required_tags;
            let required = inner_tag.contains(&test.tag);
            assert!(
                !(required && !test.required),
                "{} should not be required",
                &test.tag
            );
            assert!(
                !(!required && test.required),
                "{} should not required",
                &test.tag
            )
        }
    }

    #[tokio::test]
    async fn test_message_tags() {
        let d = DICT.get().await.clone();

        let nos = d.messages.get("D").unwrap();

        struct TestCase {
            message_def: MessageDef,
            tag: isize,
        }

        let tests = vec![
            TestCase {
                message_def: nos.clone(),
                tag: 11,
            },
            TestCase {
                message_def: nos.clone(),
                tag: 526,
            },
            TestCase {
                message_def: d.header.clone(),
                tag: 8,
            },
            TestCase {
                message_def: d.header.clone(),
                tag: 115,
            },
            TestCase {
                message_def: d.trailer.clone(),
                tag: 10,
            },
            TestCase {
                message_def: d.trailer.clone(),
                tag: 89,
            },
        ];

        for test in tests.iter() {
            let TagSet(inner_tag) = &test.message_def.tags;
            assert!(inner_tag.contains(&test.tag), "{} is not known", &test.tag);
        }
    }
}

#[cfg(test)]
mod field_def_tests {
    use super::*;

    #[test]
    fn test_new_field_def() {
        let ft = FieldType::new(String::from("aname"), 11, String::from("INT"));

        struct TestCase {
            required: bool,
        }

        let tests = vec![TestCase { required: true }];

        for test in tests.iter() {
            let fd = FieldDef::new(ft.clone(), test.required);
            assert!(!fd.is_group(), "field def is not a group");
            assert_eq!("aname", fd.name());
            assert_eq!(test.required, fd.required());
        }
    }
}

#[cfg(test)]
mod field_type_tests {
    use super::*;

    #[test]
    fn test_new_field_type() {
        let ft = FieldType::new(String::from("myname"), 10, String::from("STRING"));
        assert_eq!(String::from("myname"), ft.name());
        assert_eq!(10, ft.tag());
        assert_eq!("STRING", ft.r#type);
    }
}

#[cfg(test)]
mod group_field_def_tests {
    use super::*;

    #[test]
    fn test_new_group_field() {
        let ft = FieldType::new(String::from("aname"), 11, String::from("INT"));
        let fg = FieldDef::new_group(ft, true, Vec::new());
        assert_eq!(String::from("aname"), fg.name());
        assert!(fg.required());
    }
}

#[cfg(test)]
mod message_def_tests {
    use super::*;

    #[test]
    fn test_new_message_def() {
        let ft1 = FieldType::new(String::from("type1"), 11, String::from("STRING"));
        let ft2 = FieldType::new(String::from("type2"), 12, String::from("STRING"));
        let ft3 = FieldType::new(String::from("type3"), 13, String::from("INT"));

        let optionalfd1 = FieldDef::new(ft1.clone(), false);
        let requiredfd1 = FieldDef::new(ft1.clone(), true);

        let optionalfd2 = FieldDef::new(ft2.clone(), false);
        //	let requiredfd2 = FieldDef::new(ft2.clone(), true);

        let optional_group1 = FieldDef::new_group(
            ft3.clone(),
            false,
            vec![
                MessagePart::FieldDef(requiredfd1.clone()),
                MessagePart::FieldDef(optionalfd2.clone()),
            ],
        );
        let required_group1 = FieldDef::new_group(
            ft3.clone(),
            true,
            vec![
                MessagePart::FieldDef(requiredfd1.clone()),
                MessagePart::FieldDef(optionalfd2.clone()),
            ],
        );

        let ct1 = ComponentType::new(
            String::from("ct1"),
            vec![MessagePart::FieldDef(required_group1.clone())],
        );

        let optional_comp1 = Component::new(ct1.clone(), false);

        struct TestCase {
            parts: Vec<MessagePart>,
            expected_tags: TagSet,
            expected_required_tags: TagSet,
            expected_required_parts: Vec<MessagePart>,
        }

        let tests = vec![
            TestCase {
                parts: vec![],
                expected_tags: TagSet(hashset! {}),
                expected_required_tags: TagSet(hashset! {}),
                expected_required_parts: vec![],
            },
            TestCase {
                parts: vec![MessagePart::FieldDef(optionalfd1.clone())],
                expected_tags: TagSet(hashset! {11 }),
                expected_required_tags: TagSet(hashset! {}),
                expected_required_parts: vec![],
            },
            TestCase {
                parts: vec![
                    MessagePart::FieldDef(requiredfd1.clone()),
                    MessagePart::FieldDef(optionalfd2.clone()),
                ],
                expected_tags: TagSet(hashset! {11, 12 }),
                expected_required_tags: TagSet(hashset! {11 }),
                expected_required_parts: vec![MessagePart::FieldDef(requiredfd1.clone())],
            },
            TestCase {
                parts: vec![MessagePart::FieldDef(optional_group1.clone())],
                expected_tags: TagSet(hashset! {11, 12, 13 }),
                expected_required_tags: TagSet(hashset! {}),
                expected_required_parts: vec![],
            },
            TestCase {
                parts: vec![MessagePart::FieldDef(required_group1.clone())],
                expected_tags: TagSet(hashset! {11, 12, 13 }),
                expected_required_tags: TagSet(hashset! {13 }),
                expected_required_parts: vec![MessagePart::FieldDef(required_group1.clone())],
            },
            TestCase {
                parts: vec![MessagePart::Component(optional_comp1.clone())],
                expected_tags: TagSet(hashset! {11, 12, 13 }),
                expected_required_tags: TagSet(hashset! {}),
                expected_required_parts: vec![],
            },
        ];

        for test in tests.iter() {
            let md = MessageDef::new(
                String::from("some message"),
                String::from("X"),
                test.parts.clone(),
            );

            assert_eq!(String::from("some message"), md.name);
            assert_eq!(String::from("X"), md.msg_type);
            assert_eq!(test.expected_tags, md.tags);
            assert_eq!(test.expected_required_tags, md.required_tags);
            assert_eq!(test.parts, md.parts);
            assert_eq!(&test.expected_required_parts, md.required_parts());
        }
    }
}
