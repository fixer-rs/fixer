use serde::{Deserialize, Serialize};

// XMLDoc is the unmarshalled root of a FIX Dictionary.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone, Default)]
pub struct XMLDoc {
    pub r#type: String,
    pub major: String,
    pub minor: String,
    #[serde(rename = "servicepack")]
    pub service_pack: isize,
    pub header: Option<XMLComponent>,
    pub trailer: Option<XMLComponent>,
    pub messages: Option<XMLMessages>,
    pub components: Option<XMLComponents>,
    pub fields: Option<XMLFields>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone, Default)]
pub struct XMLMessages {
    #[serde(rename = "message")]
    pub messages: Option<Vec<XMLComponent>>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone, Default)]
pub struct XMLComponents {
    #[serde(rename = "component")]
    pub components: Option<Vec<XMLComponent>>,
}

// XMLComponent can represent header, trailer, messages/message, or components/component xml elements.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone, Default)]
pub struct XMLComponent {
    pub name: Option<String>,
    #[serde(rename = "msgcat")]
    pub msg_cat: Option<String>,
    #[serde(rename = "msgtype")]
    pub msg_type: Option<String>,
    #[serde(rename = "$value")]
    pub members: Option<Vec<XMLComponentEnum>>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub enum XMLComponentEnum {
    #[serde(rename = "field")]
    Field(XMLComponentMember),
    #[serde(rename = "component")]
    Component(XMLComponentMember),
    #[serde(rename = "group")]
    Group(XMLComponentMember),
    #[serde(rename = "message")]
    Message(XMLComponentMember),
}

impl Default for XMLComponentEnum {
    fn default() -> Self {
        let member = XMLComponentMember::default();
        XMLComponentEnum::Field(member)
    }
}

impl XMLComponentEnum {
    pub fn field_name(&self) -> &'static str {
        match self {
            XMLComponentEnum::Component(_) => "component",
            XMLComponentEnum::Group(_) => "group",
            XMLComponentEnum::Field(_) => "field",
            XMLComponentEnum::Message(_) => "message",
        }
    }

    pub fn name(&'_ self) -> &'_ str {
        match self {
            XMLComponentEnum::Component(member)
            | XMLComponentEnum::Group(member)
            | XMLComponentEnum::Field(member)
            | XMLComponentEnum::Message(member) => &member.name,
        }
    }

    pub fn is_component(&self) -> bool {
        if let XMLComponentEnum::Component(_) = self {
            return true;
        }
        false
    }

    pub fn is_group(&self) -> bool {
        if let XMLComponentEnum::Group(_) = self {
            return true;
        }
        false
    }

    pub fn is_required(&self) -> bool {
        match self {
            XMLComponentEnum::Component(inner)
            | XMLComponentEnum::Field(inner)
            | XMLComponentEnum::Group(inner)
            | XMLComponentEnum::Message(inner) => {
                if inner.required.is_some() {
                    inner.required.as_ref().unwrap() == "Y"
                } else {
                    false
                }
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone, Default)]
pub struct XMLFields {
    #[serde(rename = "field")]
    pub fields: Option<Vec<XMLField>>,
}

// XMLField represents the fields/field xml element.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone, Default)]
pub struct XMLField {
    pub number: Option<isize>,
    pub name: Option<String>,
    pub r#type: Option<String>,
    #[serde(rename = "value")]
    pub values: Option<Vec<XMLValue>>,
}

// XMLValue represents the fields/field/value xml element.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone, Default)]
pub struct XMLValue {
    pub r#enum: String,
    pub description: String,
}

// XMLComponentMember represents child elements of header, trailer, messages/message, and components/component elements
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone, Default)]
pub struct XMLComponentMember {
    pub name: String,
    pub required: Option<String>,
    #[serde(rename = "$value")]
    pub fields: Option<Vec<XMLComponentEnum>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use once_cell::sync::Lazy;
    use quick_xml::de::{from_str, DeError};
    use std::any::{Any, TypeId};

    static CACHED_XML_DOC: Lazy<XMLDoc> = Lazy::new(|| {
        let xml = r#"<fix major='4' type='FIX' servicepack='0' minor='3'>
    <header>
        <field name='BeginString' required='Y' />
        <group name='NoHops' required='N'>
            <field name='HopCompID' required='N' />
            <field name='HopSendingTime' required='N' />
            <field name='HopRefID' required='N' />
        </group>
    </header>
    <messages>
        <message name='Heartbeat' msgcat='admin' msgtype='0'>
        <field name='TestReqID' required='N' />
        </message>
        <message name='IOI' msgcat='app' msgtype='6'>
        <field name='IOIid' required='Y' />
        <field name='IOITransType' required='Y' />
        <field name='IOIRefID' required='N' />
        <component name='Instrument' required='Y' />
        <group name='NoRoutingIDs' required='N'>
            <field name='RoutingType' required='N' />
            <field name='RoutingID' required='N' />
        </group>

        </message>
        <message name='NewOrderSingle' msgcat='app' msgtype='D'>
        <field name='ClOrdID' required='Y' />
        <field name='SecondaryClOrdID' required='N' />
        <field name='ClOrdLinkID' required='N' />
        <component name='Parties' required='N' />
        <field name='TradeOriginationDate' required='N' />
        <field name='Account' required='N' />
        <field name='AccountType' required='N' />
        <field name='DayBookingInst' required='N' />
        <field name='BookingUnit' required='N' />
        <field name='PreallocMethod' required='N' />
        <group name='NoAllocs' required='N'>
            <field name='AllocAccount' required='N' />
            <field name='IndividualAllocID' required='N' />
            <component name='NestedParties' required='N' />
            <field name='AllocQty' required='N' />
        </group>
        <field name='SettlmntTyp' required='N' />
        <field name='FutSettDate' required='N' />
        <field name='CashMargin' required='N' />
        <field name='ClearingFeeIndicator' required='N' />
        <field name='HandlInst' required='Y' />
        <field name='ExecInst' required='N' />
        <field name='MinQty' required='N' />
        <field name='MaxFloor' required='N' />
        <field name='ExDestination' required='N' />
        <group name='NoTradingSessions' required='N'>
            <field name='TradingSessionID' required='N' />
            <field name='TradingSessionSubID' required='N' />
        </group>
        </message>

    </messages>

    <trailer>
        <field name='SignatureLength' required='N' />
        <field name='Signature' required='N' />
        <field name='CheckSum' required='Y' />
    </trailer>
    </fix>
    "#;
        let xml_doc: Result<XMLDoc, DeError> = from_str(xml);
        xml_doc.unwrap()
    });

    #[test]
    fn test_boiler_plate() {
        let doc = CACHED_XML_DOC.clone();

        struct TestCase {
            value: Box<dyn Any>,
            expected_value: Box<dyn Any>,
        }

        let tests = vec![
            TestCase {
                value: Box::new(doc.r#type),
                expected_value: Box::new(String::from("FIX")),
            },
            TestCase {
                value: Box::new(doc.major),
                expected_value: Box::new(String::from("4")),
            },
            TestCase {
                value: Box::new(doc.minor),
                expected_value: Box::new(String::from("3")),
            },
            TestCase {
                value: Box::new(doc.service_pack),
                expected_value: Box::new(0 as isize),
            },
        ];

        for test in tests.iter() {
            if (&*test.value).type_id() == TypeId::of::<String>() {
                let value = (&*test.value).downcast_ref::<String>();
                assert!(value.is_some());
                let expected_value = (&*test.expected_value).downcast_ref::<String>();
                assert!(expected_value.is_some());
                assert_eq!(
                    value.unwrap(),
                    expected_value.unwrap(),
                    "Expected {} got {}",
                    value.unwrap(),
                    expected_value.unwrap(),
                );
            }
            if (&*test.value).type_id() == TypeId::of::<isize>() {
                let value = (&*test.value).downcast_ref::<isize>();
                assert!(value.is_some());
                let expected_value = (&*test.expected_value).downcast_ref::<isize>();
                assert!(expected_value.is_some());
                assert_eq!(
                    value.unwrap(),
                    expected_value.unwrap(),
                    "Expected {} got {}",
                    value.unwrap(),
                    expected_value.unwrap(),
                );
            }
        }
    }

    #[test]
    fn test_component_members() {
        let doc = CACHED_XML_DOC.clone();
        assert!(doc.header.is_some(), "Header is nil");

        struct TestCase<'a> {
            value: XMLComponentEnum,
            xml_name_local: &'a str,
            name: &'a str,
            required: bool,
        }
        let tests = vec![
            TestCase {
                value: {
                    let doc_clone = CACHED_XML_DOC.clone();
                    let header = doc_clone.header.as_ref().unwrap();
                    let value = header.members.as_ref().unwrap()[0].clone();
                    value
                },
                xml_name_local: "field",
                name: "BeginString",
                required: true,
            },
            TestCase {
                value: {
                    let doc_clone = CACHED_XML_DOC.clone();
                    let header = doc_clone.header.as_ref().unwrap();
                    let value = header.members.as_ref().unwrap()[1].clone();
                    value
                },
                xml_name_local: "group",
                name: "NoHops",
                required: false,
            },
            TestCase {
                value: {
                    let doc_clone = CACHED_XML_DOC.clone();
                    let header = doc_clone.header.as_ref().unwrap();
                    let value = header.members.as_ref().unwrap()[1].clone();
                    let default = XMLComponentMember::default();
                    let member = match value {
                        XMLComponentEnum::Group(ref inner) => inner,
                        _ => &default,
                    };
                    member.fields.as_ref().unwrap()[0].clone()
                },
                xml_name_local: "field",
                name: "HopCompID",
                required: false,
            },
            TestCase {
                value: {
                    let doc_clone = CACHED_XML_DOC.clone();
                    let trailer = doc_clone.trailer.as_ref().unwrap();
                    let value = trailer.members.as_ref().unwrap()[0].clone();
                    value
                },
                xml_name_local: "field",
                name: "SignatureLength",
                required: false,
            },
            TestCase {
                value: {
                    let doc_clone = CACHED_XML_DOC.clone();
                    let messages = &doc_clone.messages.as_ref().unwrap();
                    let message = &messages.messages.as_ref().unwrap()[0];
                    let inner_message = &message.members.as_ref().unwrap()[0];
                    inner_message.clone()
                },
                xml_name_local: "field",
                name: "TestReqID",
                required: false,
            },
            TestCase {
                value: {
                    let doc_clone = CACHED_XML_DOC.clone();
                    let messages = &doc_clone.messages.as_ref().unwrap();
                    let message = &messages.messages.as_ref().unwrap()[1];
                    let inner_message = &message.members.as_ref().unwrap()[3];
                    inner_message.clone()
                },
                xml_name_local: "component",
                name: "Instrument",
                required: true,
            },
            TestCase {
                value: {
                    let doc_clone = CACHED_XML_DOC.clone();
                    let messages = &doc_clone.messages.as_ref().unwrap();
                    let message = &messages.messages.as_ref().unwrap()[1];
                    let inner_message = &message.members.as_ref().unwrap()[4];
                    inner_message.clone()
                },
                xml_name_local: "group",
                name: "NoRoutingIDs",
                required: false,
            },
            TestCase {
                value: {
                    let doc_clone = CACHED_XML_DOC.clone();
                    let messages = &doc_clone.messages.as_ref().unwrap();
                    let message = &messages.messages.as_ref().unwrap()[1];
                    let inner_message = &message.members.as_ref().unwrap()[4];
                    let default = XMLComponentMember::default();
                    let member = match inner_message {
                        XMLComponentEnum::Group(ref inner) => inner,
                        _ => &default,
                    };
                    member.fields.as_ref().unwrap()[0].clone()
                },
                xml_name_local: "field",
                name: "RoutingType",
                required: false,
            },
            TestCase {
                value: {
                    let doc_clone = CACHED_XML_DOC.clone();
                    let messages = &doc_clone.messages.as_ref().unwrap();
                    let message = &messages.messages.as_ref().unwrap()[1];
                    let inner_message = &message.members.as_ref().unwrap()[4];
                    let default = XMLComponentMember::default();
                    let member = match inner_message {
                        XMLComponentEnum::Group(ref inner) => inner,
                        _ => &default,
                    };
                    member.fields.as_ref().unwrap()[1].clone()
                },
                xml_name_local: "field",
                name: "RoutingID",
                required: false,
            },
        ];
        for test in tests.iter() {
            match &test.value {
                XMLComponentEnum::Component(inner)
                | XMLComponentEnum::Field(inner)
                | XMLComponentEnum::Group(inner)
                | XMLComponentEnum::Message(inner) => {
                    assert_eq!(test.value.field_name(), test.xml_name_local);
                    assert_eq!(
                        &inner.name, &test.name,
                        "{}: Expected Name {} got {}",
                        &test.name, &test.name, &inner.name
                    );
                    assert_eq!(test.value.is_required(), test.required);
                }
            }
        }
    }

    #[test]
    fn test_messages() {
        let doc = CACHED_XML_DOC.clone();
        struct TestCase<'a> {
            value: XMLComponent,
            name: &'a str,
            msg_cat: &'a str,
            msg_type: &'a str,
        }

        let tests = vec![TestCase {
            value: {
                let doc_clone = &doc.clone();
                let messages = &doc_clone.messages.as_ref().unwrap();
                let message = &messages.messages.as_ref().unwrap()[0];
                message.clone()
            },
            name: "Heartbeat",
            msg_cat: "admin",
            msg_type: "0",
        }];

        for test in tests.iter() {
            assert!(test.value.name.is_some());
            assert_eq!(test.value.name.as_ref().unwrap(), test.name);
            assert!(test.value.msg_cat.is_some());
            assert_eq!(test.value.msg_cat.as_ref().unwrap(), test.msg_cat);
            assert!(test.value.msg_type.is_some());
            assert_eq!(test.value.msg_type.as_ref().unwrap(), test.msg_type);
        }
    }
}
