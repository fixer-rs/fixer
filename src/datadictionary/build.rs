use super::{
    xml::{XMLComponent, XMLComponentEnum, XMLDoc, XMLField},
    Component, ComponentType, DataDictionary, Enum, FieldDef, FieldType, MessageDef, MessagePart,
};
use anyhow::Error;
use std::collections::HashMap;

#[derive(Default)]
pub struct Builder {
    doc: XMLDoc,
    dict: DataDictionary,
    component_by_name: HashMap<String, XMLComponent>,
}

impl Builder {
    pub fn build<'a>(&'a mut self, doc: &'a XMLDoc) -> Result<DataDictionary, Error> {
        if doc.r#type != "FIX" && doc.r#type != "FIXT" {
            return Err(anyhow!("type attribute must be FIX or FIXT"));
        }

        self.doc = doc.clone();
        self.dict = DataDictionary {
            fix_type: doc.r#type.clone(),
            service_pack: doc.service_pack,
            ..Default::default()
        };

        let major = match doc.major.parse::<isize>() {
            Ok(i) => Ok(i),
            Err(_e) => Err(anyhow!("major attribute not valid on <fix>")),
        }?;

        let minor = match doc.minor.parse::<isize>() {
            Ok(i) => Ok(i),
            Err(_e) => Err(anyhow!("minor attribute not valid on <fix>")),
        }?;

        self.dict.major = major;
        self.dict.minor = minor;

        self.component_by_name = hashmap! {};
        if doc.components.is_some() {
            let inner_components = doc.components.as_ref().unwrap().clone();
            if inner_components.components.is_some() {
                for c in inner_components.components.as_ref().unwrap().iter() {
                    self.component_by_name
                        .insert(c.name.as_ref().unwrap().to_string(), c.clone());
                }
            }
        }

        self.build_field_types();

        self.build_components()?;

        self.build_message_defs()?;

        if self.doc.header.is_some() {
            let header = self.build_message_def(self.doc.header.as_ref().unwrap().clone())?;
            self.dict.header = header;
        }

        if self.doc.trailer.is_some() {
            let trailer = self.build_message_def(self.doc.trailer.as_ref().unwrap().clone())?;
            self.dict.trailer = trailer;
        }

        Ok(self.dict.clone())
    }

    fn find_or_build_component_type(
        &mut self,
        xml_member: XMLComponentEnum,
    ) -> Result<ComponentType, Error> {
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

    fn build_component_type(
        &mut self,
        xml_component: XMLComponent,
    ) -> Result<ComponentType, Error> {
        let mut parts: Vec<MessagePart> = vec![];

        if xml_component.members.is_some() {
            for member in xml_component.members.as_ref().unwrap().iter() {
                if member.is_component() {
                    let component_type = self.find_or_build_component_type(member.clone())?;
                    let child_component = Component::new(component_type, member.is_required());
                    parts.push(MessagePart::Component(child_component));
                } else {
                    let field = self.build_field_def(member.clone())?;
                    parts.push(MessagePart::FieldDef(field))
                }
            }
        }

        Ok(ComponentType::new(
            xml_component.name.as_ref().unwrap().to_string(),
            parts,
        ))
    }

    fn build_components(&mut self) -> Result<(), Error> {
        self.dict.component_types = hashmap! {};
        if self.doc.components.is_some() {
            let inner_components = self.doc.components.as_ref().unwrap().clone();
            if inner_components.components.is_some() {
                for c in inner_components.components.as_ref().unwrap().iter() {
                    if !self
                        .dict
                        .component_types
                        .contains_key(c.name.as_ref().unwrap())
                    {
                        let built_component = self.build_component_type(c.clone())?;
                        self.dict
                            .component_types
                            .insert(c.name.as_ref().unwrap().to_string(), built_component);
                    }
                }
            }
        }

        Ok(())
    }

    fn build_message_defs(&mut self) -> Result<(), Error> {
        self.dict.messages = hashmap! {};

        if self.doc.messages.is_some() {
            let inner_messages = self.doc.messages.as_ref().unwrap().clone();
            if inner_messages.messages.is_some() {
                for m in inner_messages.messages.as_ref().unwrap().iter() {
                    let message_def = self.build_message_def(m.clone())?;
                    let name = message_def.msg_type.to_string();
                    self.dict.messages.insert(name, message_def);
                }
            }
        }

        Ok(())
    }

    fn build_message_def(&mut self, xml_message: XMLComponent) -> Result<MessageDef, Error> {
        let mut parts: Vec<MessagePart> = vec![];

        if xml_message.members.is_some() {
            for member in xml_message.members.as_ref().unwrap().iter() {
                if member.is_component() {
                    if !self.dict.component_types.contains_key(member.name()) {
                        return Err(new_unknown_component(member.name()));
                    }

                    parts.push(MessagePart::Component(Component::new(
                        ComponentType::default(),
                        member.is_required(),
                    )));
                } else {
                    let field = self.build_field_def(member.clone())?;
                    parts.push(MessagePart::FieldDef(field));
                }
            }
        }

        Ok(MessageDef::new(
            xml_message.name.unwrap_or_default(),
            xml_message.msg_type.unwrap_or_default(),
            parts,
        ))
    }

    fn build_group_field_def(
        &mut self,
        xml_field: XMLComponentEnum,
        group_field_type: FieldType,
    ) -> Result<FieldDef, Error> {
        let mut parts: Vec<MessagePart> = vec![];

        let required = xml_field.is_required();

        match xml_field {
            XMLComponentEnum::Component(c) => {
                if c.fields.is_some() {
                    for member in c.fields.as_ref().unwrap().iter() {
                        let comp_type = self.find_or_build_component_type(member.clone())?;
                        let comp = Component::new(comp_type, member.is_required());
                        parts.push(MessagePart::Component(comp));
                    }
                }
            }
            XMLComponentEnum::Field(f) => {
                if f.fields.is_some() {
                    for member in f.fields.as_ref().unwrap().iter() {
                        let f = self.build_field_def(member.clone())?;
                        parts.push(MessagePart::FieldDef(f));
                    }
                }
            }
            _ => {}
        }

        Ok(FieldDef::new_group(group_field_type, required, parts))
    }

    fn build_field_def(&mut self, xml_field: XMLComponentEnum) -> Result<FieldDef, Error> {
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
        if self.doc.fields.is_some() {
            let inner_fields = self.doc.fields.as_ref().unwrap();
            if inner_fields.fields.is_some() {
                for f in inner_fields.fields.as_ref().unwrap().iter() {
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

    if xml_field.values.is_some() && !xml_field.values.as_ref().unwrap().is_empty() {
        field.enums = hashmap! {};
        for e in xml_field.values.as_ref().unwrap().iter() {
            field.enums.insert(
                e.r#enum.to_string(),
                Enum {
                    value: e.r#enum.to_string(),
                    description: e.description.to_string(),
                },
            );
        }
    }

    field
}

fn new_unknown_component(name: &str) -> Error {
    anyhow!("unknown component {}", name)
}

fn new_unknown_field(name: &str) -> Error {
    anyhow!("unknown field {}", name)
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
            suite.doc.major = itoa::Buffer::new().format(test).to_string();
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
            suite.doc.minor = itoa::Buffer::new().format(test).to_string();
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

            let field_type_by_name: HashMap<String, FieldType> = hashmap! {
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

            let result = b.build_field_def(xml_field);
            assert!(result.is_ok());
            assert_eq!(11, result.as_ref().unwrap().tag());
            assert!(result.as_ref().unwrap().child_tags().is_empty());
        }
    }
}
