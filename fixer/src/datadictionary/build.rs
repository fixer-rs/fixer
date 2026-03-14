use super::{
    Component, ComponentType, DataDictionary, Enum, FieldDef, FieldType, MessageDef, MessagePart,
    xml::{XMLComponent, XMLComponentEnum, XMLDoc, XMLField},
};
use rustc_hash::FxHashMap;
use simple_error::{SimpleError, SimpleResult};

#[derive(Default)]
pub struct Builder {
    doc: XMLDoc,
    dict: DataDictionary,
    component_by_name: FxHashMap<String, XMLComponent>,
}

impl Builder {
    pub fn build<'a>(&'a mut self, doc: &'a XMLDoc) -> SimpleResult<DataDictionary> {
        if doc.r#type != "FIX" && doc.r#type != "FIXT" {
            return Err(simple_error!("type attribute must be FIX or FIXT"));
        }

        self.doc = doc.clone();
        self.dict = DataDictionary {
            fix_type: doc.r#type.clone(),
            service_pack: doc.service_pack,
            ..Default::default()
        };

        let major = match doc.major.parse::<isize>() {
            Ok(i) => Ok(i),
            Err(_e) => Err(simple_error!("major attribute not valid on <fix>")),
        }?;

        let minor = match doc.minor.parse::<isize>() {
            Ok(i) => Ok(i),
            Err(_e) => Err(simple_error!("minor attribute not valid on <fix>")),
        }?;

        self.dict.major = major;
        self.dict.minor = minor;

        self.component_by_name = hashmap! {};
        if let Some(components) = &doc.components {
            let inner_components = components.clone();
            if let Some(comps) = &inner_components.components {
                for c in comps {
                    self.component_by_name
                        .insert(c.name.as_ref().unwrap().clone(), c.clone());
                }
            }
        }

        self.build_field_types();

        self.build_components()?;

        self.build_message_defs()?;

        if let Some(doc_header) = &self.doc.header.clone() {
            let header = self.build_message_def(doc_header)?;
            self.dict.header = header;
        }

        if let Some(doc_trailer) = &self.doc.trailer.clone() {
            let trailer = self.build_message_def(doc_trailer)?;
            self.dict.trailer = trailer;
        }

        Ok(std::mem::take(&mut self.dict))
    }

    #[allow(clippy::needless_pass_by_value)]
    fn find_or_build_component_type(
        &mut self,
        xml_member: XMLComponentEnum,
    ) -> SimpleResult<ComponentType> {
        if self.dict.component_types.contains_key(xml_member.name()) {
            return Ok(self
                .dict
                .component_types
                .get(xml_member.name())
                .unwrap()
                .clone());
        }

        if !self.component_by_name.contains_key(xml_member.name()) {
            return Err(new_unknown_component(xml_member.name()));
        }

        let xml_comp = self.component_by_name.get(xml_member.name()).unwrap();
        let comp = self.build_component_type(xml_comp.clone())?;
        self.dict
            .component_types
            .insert(xml_member.name().to_string(), comp.clone());

        Ok(comp)
    }

    #[allow(clippy::needless_pass_by_value)]
    fn build_component_type(&mut self, xml_component: XMLComponent) -> SimpleResult<ComponentType> {
        let mut parts: Vec<MessagePart> = vec![];

        if let Some(members) = &xml_component.members {
            for member in members {
                if member.is_component() {
                    let component_type = self.find_or_build_component_type(member.clone())?;
                    let child_component = Component::new(component_type, member.is_required());
                    parts.push(MessagePart::Component(child_component));
                } else {
                    let field = self.build_field_def(member)?;
                    parts.push(MessagePart::FieldDef(field));
                }
            }
        }

        Ok(ComponentType::new(
            xml_component.name.as_ref().unwrap().clone(),
            parts,
        ))
    }

    fn build_components(&mut self) -> SimpleResult<()> {
        self.dict.component_types = hashmap! {};
        if let Some(components) = &self.doc.components.clone() {
            let inner_components = components.clone();
            if let Some(comps) = &inner_components.components {
                for c in comps {
                    if !self
                        .dict
                        .component_types
                        .contains_key(c.name.as_ref().unwrap())
                    {
                        let built_component = self.build_component_type(c.clone())?;
                        self.dict
                            .component_types
                            .insert(c.name.as_ref().unwrap().clone(), built_component);
                    }
                }
            }
        }

        Ok(())
    }

    fn build_message_defs(&mut self) -> SimpleResult<()> {
        self.dict.messages = hashmap! {};

        if let Some(messages) = &self.doc.messages.clone() {
            let inner_messages = messages.clone();
            if let Some(msgs) = &inner_messages.messages {
                for m in msgs {
                    let message_def = self.build_message_def(m)?;
                    let name = message_def.msg_type.clone();
                    self.dict.messages.insert(name, message_def);
                }
            }
        }

        Ok(())
    }

    fn build_message_def(&mut self, xml_message: &XMLComponent) -> SimpleResult<MessageDef> {
        let mut parts: Vec<MessagePart> = vec![];

        if let Some(members) = &xml_message.members {
            for member in members {
                if member.is_component() {
                    if !self.dict.component_types.contains_key(member.name()) {
                        return Err(new_unknown_component(member.name()));
                    }

                    let component_type = self.dict.component_types.get(member.name()).unwrap();

                    parts.push(MessagePart::Component(Component::new(
                        component_type.clone(),
                        member.is_required(),
                    )));
                } else {
                    let field = self.build_field_def(member)?;
                    parts.push(MessagePart::FieldDef(field));
                }
            }
        }

        let name = xml_message.name.clone().unwrap_or_default();
        let msg_type = xml_message.msg_type.clone().unwrap_or_default();

        Ok(MessageDef::new(name, msg_type, parts))
    }

    fn build_group_field_def(
        &mut self,
        xml_field: &XMLComponentEnum,
        group_field_type: FieldType,
    ) -> SimpleResult<FieldDef> {
        let mut parts: Vec<MessagePart> = vec![];

        let required = xml_field.is_required();

        let inner = match xml_field {
            XMLComponentEnum::Component(c)
            | XMLComponentEnum::Field(c)
            | XMLComponentEnum::Group(c) => &c.fields,
            _ => &None,
        };

        if let Some(members) = inner {
            for member in members {
                if member.is_component() {
                    let comp_type = self.find_or_build_component_type(member.clone())?;
                    let comp = Component::new(comp_type, member.is_required());
                    parts.push(MessagePart::Component(comp));
                } else {
                    let f = self.build_field_def(member)?;
                    parts.push(MessagePart::FieldDef(f));
                }
            }
        }

        Ok(FieldDef::new_group(group_field_type, required, parts))
    }

    fn build_field_def(&mut self, xml_field: &XMLComponentEnum) -> SimpleResult<FieldDef> {
        if !self.dict.field_type_by_name.contains_key(xml_field.name()) {
            return Err(new_unknown_field(xml_field.name()));
        }

        let field_type = self.dict.field_type_by_name.get(xml_field.name()).unwrap();

        if xml_field.is_group() {
            return self.build_group_field_def(xml_field, field_type.clone());
        }

        Ok(FieldDef::new(field_type.clone(), xml_field.is_required()))
    }

    fn build_field_types(&mut self) {
        self.dict.field_type_by_tag = hashmap! {};
        self.dict.field_type_by_name = hashmap! {};
        if let Some(inner_fields) = &self.doc.fields {
            if let Some(fields) = &inner_fields.fields {
                for f in fields {
                    let field = build_field_type(f);
                    self.dict
                        .field_type_by_tag
                        .insert(field.tag(), field.clone());
                    self.dict
                        .field_type_by_name
                        .insert(field.name().to_string(), field.clone());
                }
            }
        }
    }
}

fn build_field_type(xml_field: &XMLField) -> FieldType {
    let mut field = FieldType::new(
        xml_field.name.as_ref().unwrap().clone(),
        *xml_field.number.as_ref().unwrap(),
        xml_field.r#type.as_ref().unwrap().clone(),
    );

    if let Some(values) = &xml_field.values {
        if !values.is_empty() {
            field.enums = hashmap! {};
            for e in values {
                field.enums.insert(
                    e.r#enum.clone(),
                    Enum {
                        value: e.r#enum.clone(),
                        description: e.description.clone(),
                    },
                );
            }
        }
    }

    field
}

fn new_unknown_component(name: &str) -> SimpleError {
    simple_error!("unknown component {}", name)
}

fn new_unknown_field(name: &str) -> SimpleError {
    simple_error!("unknown field {}", name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::datadictionary::xml::XMLComponentMember;

    struct BuildSuite {
        doc: XMLDoc,
        builder: Builder,
    }

    impl BuildSuite {
        fn setup_test() -> Self {
            BuildSuite {
                doc: XMLDoc {
                    r#type: "FIX".to_string(),
                    major: "4".to_string(),
                    minor: "5".to_string(),
                    ..Default::default()
                },
                builder: Builder::default(),
            }
        }
    }

    #[test]
    fn test_valid_types() {
        let mut suite = BuildSuite::setup_test();
        let tests = vec!["FIX", "FIXT"];

        for test in tests {
            suite.doc.r#type = test.to_string();
            let result = suite.builder.build(&suite.doc);
            assert!(result.is_ok());
            assert_eq!(test, &result.unwrap().fix_type);
        }
    }

    #[test]
    fn test_invalid_types() {
        let mut suite = BuildSuite::setup_test();
        let tests = vec!["", "invalid"];

        for test in tests {
            suite.doc.r#type = test.to_string();
            let doc = suite.doc.clone();
            let result = suite.builder.build(&doc);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_valid_major() {
        let mut suite = BuildSuite::setup_test();
        let tests = vec![4, 5];

        for test in tests {
            suite.doc.major.clear();
            itoap::write_to_string(&mut suite.doc.major, test);
            let result = suite.builder.build(&suite.doc);
            assert!(result.is_ok());
            assert_eq!(test, result.unwrap().major);
        }
    }

    #[test]
    fn test_invalid_major() {
        let mut suite = BuildSuite::setup_test();
        let tests = vec!["", "notanumber"];

        for test in tests {
            suite.doc.major = test.to_string();
            let result = suite.builder.build(&suite.doc);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_valid_minor() {
        let mut suite = BuildSuite::setup_test();
        let tests = vec![4, 5];

        for test in tests {
            suite.doc.minor.clear();
            itoap::write_to_string(&mut suite.doc.minor, test);
            let result = suite.builder.build(&suite.doc);
            assert!(result.is_ok());
            assert_eq!(test, result.unwrap().minor);
        }
    }

    #[test]
    fn test_invalid_minor() {
        let mut suite = BuildSuite::setup_test();
        let tests = vec!["", "notanumber"];

        for test in tests {
            suite.doc.minor = test.to_string();
            let result = suite.builder.build(&suite.doc);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_build_field_def() {
        let tests = vec!["field", "group"];

        for test in tests {
            let xml_field = if test == "field" {
                let comp = XMLComponentMember {
                    name: "myfield".to_string(),
                    ..Default::default()
                };
                XMLComponentEnum::Field(comp)
            } else {
                let comp = XMLComponentMember {
                    name: "myfield".to_string(),
                    ..Default::default()
                };
                XMLComponentEnum::Group(comp)
            };

            let field_type_by_name: FxHashMap<String, FieldType> = hashmap! {
                "myfield".to_string() => FieldType::new("some field".to_string(), 11, "INT".to_string()),
            };

            let dict = DataDictionary {
                field_type_by_name,
                ..Default::default()
            };

            let mut b = Builder {
                dict,
                ..Default::default()
            };

            let result = b.build_field_def(&xml_field);
            assert!(result.is_ok());
            assert_eq!(11, result.as_ref().unwrap().tag());
            assert!(result.as_ref().unwrap().child_tags().is_empty());
        }
    }
}
