use delegate::delegate;
use dyn_clone::{clone_box, clone_trait_object, DynClone};
use intertrait::cast::*;
use intertrait::*;
use std::{
    any::{Any, TypeId},
    collections::HashMap,
    io,
};

#[derive(Default)]
pub struct LocalAny {}

// DataDictionary models FIX messages, components, and fields.
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
pub trait MessagePart: DynClone {
    fn name(&self) -> &str;
    fn required(&self) -> bool;
    fn as_any(&self) -> &dyn Any;
}

clone_trait_object!(MessagePart);

// MessagePartWithFields is a MessagePart with multiple Fields
pub trait MessagePartWithFields: MessagePart {
    fn fields(&self) -> Vec<&FieldDef>;
    fn required_fields(&self) -> Vec<&FieldDef>;
}

#[derive(Clone, Default)]
// ComponentType is a grouping of fields.
pub struct ComponentType {
    name: String,
    parts: Vec<Box<dyn MessagePart>>,
    fields: Vec<FieldDef>,
    required_fields: Vec<FieldDef>,
    required_parts: Vec<Box<dyn MessagePart>>,
}

impl ComponentType {
    // new_component_type returns an initialized component type
    pub fn new_component_type(name: String, parts: Vec<Box<dyn MessagePart>>) -> ComponentType {
        let mut comp = ComponentType {
            name,
            parts,
            ..Default::default()
        };

        for part in comp.parts.iter() {
            let part_ref = &**part;
            if part_ref.required() {
                comp.required_parts.push(clone_box(part_ref));
            }

            if part_ref.type_id() == TypeId::of::<dyn MessagePartWithFields>() {
                let part_with_fields = part.cast::<dyn MessagePartWithFields>().unwrap();

                comp.fields.extend(
                    part_with_fields
                        .fields()
                        .into_iter()
                        .cloned()
                        .collect::<Vec<FieldDef>>(),
                );

                if part_with_fields.required() {
                    comp.required_fields.extend(
                        part_with_fields
                            .required_fields()
                            .into_iter()
                            .cloned()
                            .collect::<Vec<FieldDef>>(),
                    );
                }
                continue;
            }

            if part_ref.type_id() == TypeId::of::<FieldDef>() {
                let part_with_fields = part.as_any().downcast_ref::<FieldDef>().unwrap();

                comp.fields.push(part_with_fields.clone());
                if part_with_fields.required() {
                    comp.required_fields.push(part_with_fields.clone());
                }

                continue;
            }
        }
        comp
    }

    // required_parts returns those parts that are required for this component
    pub fn required_parts(&self) -> Vec<Box<dyn MessagePart>> {
        self.required_parts
            .iter()
            .map(|part| clone_box(&**part))
            .collect()
    }

    // parts returns all parts in declaration order contained in this component
    pub fn parts(&self) -> Vec<Box<dyn MessagePart>> {
        self.parts.iter().map(|part| clone_box(&**part)).collect()
    }
}

impl MessagePart for ComponentType {
    // name returns the name of this component type
    fn name(&self) -> &str {
        &self.name
    }

    fn required(&self) -> bool {
        false // will be overriden
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl MessagePartWithFields for ComponentType {
    // fields returns all fields contained in this component.
    // Includes fields encapsulated in components of this component
    fn fields(&self) -> Vec<&FieldDef> {
        self.fields.iter().collect::<Vec<&FieldDef>>()
    }

    // required_fields returns those fields that are required for this component
    fn required_fields(&self) -> Vec<&FieldDef> {
        self.required_fields.iter().collect::<Vec<&FieldDef>>()
    }
}

// TagSet is set for tags.
pub struct TagSet(HashMap<isize, LocalAny>);

// add adds a tag to the tagset.
impl TagSet {
    pub fn add(&mut self, tag: isize) {
        self.0.insert(tag, LocalAny::default());
    }
}

// Component is a Component as it appears in a given MessageDef
#[cast_to(MessagePart, MessagePartWithFields)]
#[derive(Default, Clone)]
pub struct Component {
    pub component_type: ComponentType,
    required: bool,
}

// new_component returns an initialized Component instance
pub fn new_component(component_type: ComponentType, required: bool) -> Component {
    Component {
        component_type,
        required,
    }
}

impl MessagePart for Component {
    delegate! {
        to self.component_type {
            fn name(&self) -> &str;
        }
    }

    fn required(&self) -> bool {
        self.required
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl MessagePartWithFields for Component {
    delegate! {
        to self.component_type {
            fn fields(&self) -> Vec<&FieldDef>;
            fn required_fields(&self) -> Vec<&FieldDef>;
        }
    }
}

// Field models a field or repeating group in a message
pub trait Field {
    fn tag(&self) -> isize;
}

// FieldDef models a field belonging to a message.
#[derive(Default, Clone)]
pub struct FieldDef {
    field_type: FieldType,
    required: bool,
    pub parts: Vec<Box<dyn MessagePart>>,
    pub fields: Vec<FieldDef>,
    required_parts: Vec<Box<dyn MessagePart>>,
    required_fields: Vec<FieldDef>,
}

// new_field_def returns an initialized FieldDef
pub fn new_field_def(field_type: FieldType, required: bool) -> FieldDef {
    FieldDef {
        field_type,
        required,
        ..Default::default()
    }
}

// new_group_field_def returns an initialized FieldDef for a repeating group
pub fn new_group_field_def(
    field_type: FieldType,
    required: bool,
    parts: Vec<Box<dyn MessagePart>>,
) -> Result<FieldDef, ()> {
    let mut field = FieldDef {
        field_type,
        required,
        parts,
        ..Default::default()
    };

    for part in field.parts.iter() {
        let part_ref = &**part;
        if part_ref.required() {
            field.required_parts.push(clone_box(part_ref));
        }

        if part_ref.type_id() == TypeId::of::<Component>() {
            let comp = part.as_any().downcast_ref::<Component>().unwrap();

            field.fields.extend(
                comp.fields()
                    .into_iter()
                    .cloned()
                    .collect::<Vec<FieldDef>>(),
            );
            if comp.required {
                field.required_fields.extend(
                    comp.required_fields()
                        .into_iter()
                        .cloned()
                        .collect::<Vec<FieldDef>>(),
                );
            }
            continue;
        }

        if part_ref.type_id() == TypeId::of::<FieldDef>() {
            let part_with_fields: &FieldDef = part.as_any().downcast_ref::<FieldDef>().unwrap();

            field.fields.push(part_with_fields.clone());
            if part_with_fields.required() {
                field.required_fields.push(part_with_fields.clone());
            }

            continue;
        }

        // TODO: other type should return error
    }
    Ok(field)
}

impl FieldDef {
    // is_group is true if the field is a repeating group.
    pub fn is_group(&self) -> bool {
        self.fields.is_empty()
    }

    // required_parts returns those parts that are required for this FieldDef.
    // is_group must return true
    pub fn required_parts(&self) -> &Vec<Box<dyn MessagePart>> {
        &self.required_parts
    }

    // required_fields returns those fields that are required for this FieldDef.
    // is_group must return true
    pub fn required_fields(&self) -> &Vec<FieldDef> {
        &self.required_fields
    }

    fn child_tags(&self) -> Vec<isize> {
        let mut tags = Vec::new();

        for field in self.fields.iter() {
            tags.push(field.tag());
            tags.extend(field.child_tags());
        }

        tags
    }
}

impl MessagePart for FieldDef {
    delegate! {
        to self.field_type {
            fn name(&self) -> &str;
        }
    }

    // required returns true if this FieldDef is required for the containing MessageDef
    fn required(&self) -> bool {
        self.required
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl Field for FieldDef {
    delegate! {
        to self.field_type {
            fn tag(&self) -> isize;
        }
    }
}

// FieldType holds information relating to a field.  Includes Tag, type, and enums, if defined.
#[derive(Default, Clone)]
pub struct FieldType {
    name: String,
    tag: isize,
    pub r#type: String,
    pub enums: HashMap<String, Enum>,
}

// //NewFieldType returns a pointer to an initialized FieldType
pub fn new_field_type(name: String, tag: isize, fix_type: String) -> FieldType {
    FieldType {
        name,
        tag,
        r#type: fix_type,
        enums: HashMap::new(),
    }
}

impl Field for FieldType {
    fn tag(&self) -> isize {
        self.tag
    }
}

impl MessagePart for FieldType {
    // name returns the name of this component type
    fn name(&self) -> &str {
        &self.name
    }

    fn required(&self) -> bool {
        false // will be overriden
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// Enum is a container for value and description.
#[derive(Default, Clone)]
pub struct Enum {
    pub value: String,
    pub description: String,
}

// MessageDef can apply to header, trailer, or body of a FIX Message.
pub struct MessageDef {
    pub name: String,
    pub msg_type: String,
    pub fields: HashMap<isize, FieldDef>,
    // Parts are the MessageParts of contained in this MessageDef in declaration order
    pub parts: Vec<Box<dyn MessagePart>>,
    pub required_parts: Vec<Box<dyn MessagePart>>,
    pub required_tags: TagSet,
    pub tags: TagSet,
}

impl MessageDef {
    // required_parts returns those parts that are required for this Message
    pub fn required_parts(&self) -> &Vec<Box<dyn MessagePart>> {
        &self.required_parts
    }

    // new_message_def returns an initialized MessageDef
    pub fn new_message_def(
        name: String,
        msg_type: String,
        parts: Vec<Box<dyn MessagePart>>,
    ) -> Result<MessageDef, ()> {
        let mut msg = MessageDef {
            name,
            msg_type,
            fields: HashMap::new(),
            required_tags: TagSet(HashMap::new()),
            tags: TagSet(HashMap::new()),
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
            let part_ref = &**part;
            if part_ref.required() {
                msg.required_parts.push(clone_box(part_ref));
            }

            if part_ref.type_id() == TypeId::of::<dyn MessagePartWithFields>() {
                let part_with_fields = part.cast::<dyn MessagePartWithFields>().unwrap();

                for f in part_with_fields.fields() {
                    // field if required in component is required in message only if
                    // component is required
                    process_field(f, part_with_fields.required());
                }
                continue;
            }

            if part_ref.type_id() == TypeId::of::<FieldDef>() {
                let part_with_fields = part.cast::<FieldDef>().unwrap();
                process_field(part_with_fields, true);
                continue;
            }

            // TODO: other type should return error
        }
        Ok(msg)
    }
}

// parse loads and build a datadictionary instance from an xml file.
// func Parse(path string) (*DataDictionary, error) {
// 	var xmlFile *os.File
// 	var err error
// 	xmlFile, err = os.Open(path)
// 	if err != nil {
// 		return nil, errors.Wrapf(err, "problem opening file: %v", path)
// 	}
// 	defer xmlFile.Close()

// 	return ParseSrc(xmlFile)
// }

// parse_src loads and build a datadictionary instance from an xml source.
pub fn parse_src(xml_src: Box<dyn io::Read>) -> Result<DataDictionary, ()> {
    // 	doc := new(XMLDoc)
    // 	decoder := xml.NewDecoder(xmlSrc)
    // 	if err := decoder.Decode(doc); err != nil {
    // 		return nil, errors.Wrapf(err, "problem parsing XML file")
    // 	}

    // 	b := new(builder)
    // 	dict, err := b.build(doc)
    // 	if err != nil {
    // 		return nil, err
    // 	}

    // 	return dict, nil
    Err(())
}
