use serde::{Deserialize, Serialize};

// XMLDoc is the unmarshalled root of a FIX Dictionary.
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct XMLDoc {
    pub r#type: String,
    pub major: String,
    pub minor: String,
    #[serde(rename = "servicepack")]
    pub service_pack: isize,
    pub header: Option<XMLComponent>,
    pub trailer: Option<XMLComponent>,
    pub messages: Option<Vec<XMLComponent>>,
    pub components: Option<Vec<XMLComponent>>,
    pub fields: Option<Vec<XMLField>>,
}

// XMLComponent can represent header, trailer, messages/message, or components/component xml elements.
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Default)]
pub struct XMLComponent {
    pub name: Option<String>,
    #[serde(rename = "msgcat")]
    pub msg_cat: Option<String>,
    #[serde(rename = "msgtype")]
    pub msg_type: Option<String>,
    #[serde(rename = "$value")]
    pub fields: Option<Vec<XMLComponentMemberEnum>>,
}

// XMLField represents the fields/field xml element.
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct XMLField {
    pub number: Option<isize>,
    pub name: Option<String>,
    pub r#type: Option<String>,
    pub value: Option<Vec<XMLValue>>,
}

// XMLValue represents the fields/field/value xml element.
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct XMLValue {
    pub r#enum: String,
    pub description: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub enum XMLComponentMemberEnum {
    #[serde(rename = "field")]
    Field(XMLComponentMember),
    #[serde(rename = "component")]
    Component(XMLComponentMember),
    #[serde(rename = "group")]
    Group(XMLComponentMember),
    #[serde(rename = "message")]
    Message(XMLComponent),
}

impl Default for XMLComponentMemberEnum {
    fn default() -> Self {
        let member = XMLComponentMember::default();
        XMLComponentMemberEnum::Field(member)
    }
}

// XMLComponentMember represents child elements of header, trailer, messages/message, and components/component elements
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Default)]
pub struct XMLComponentMember {
    pub name: String,
    pub required: String,
    #[serde(rename = "$value")]
    pub fields: Option<Vec<XMLComponentMemberEnum>>,
}

impl XMLComponentMemberEnum {
    pub fn field_name(&self) -> &'static str {
        match self {
            XMLComponentMemberEnum::Component(_) => "component",
            XMLComponentMemberEnum::Group(_) => "group",
            XMLComponentMemberEnum::Field(_) => "field",
            _ => "message",
        }
    }

    pub fn is_component(&self) -> bool {
        if let XMLComponentMemberEnum::Component(_) = self {
            return true;
        }
        false
    }

    pub fn is_group(&self) -> bool {
        if let XMLComponentMemberEnum::Group(_) = self {
            return true;
        }
        false
    }

    pub fn is_required(&self) -> bool {
        match self {
            XMLComponentMemberEnum::Message(_) => false,
            XMLComponentMemberEnum::Component(inner)
            | XMLComponentMemberEnum::Field(inner)
            | XMLComponentMemberEnum::Group(inner) => inner.required == "Y",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lazy_static::lazy_static;
    use quick_xml::de::{from_str, DeError};
    use std::any::{Any, TypeId};

    lazy_static! {
        static ref CACHED_XML_DOC: XMLDoc = {
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

            // XMLDoc { type: "FIX", major: "4", minor: "3", service_pack: 0, header: Some(XMLComponent { name: None, msg_cat: None, msg_type: None, field: Some([Field(XMLComponentMember { name: "BeginString", required: "Y", fields: None }), Group(XMLComponentMember { name: "NoHops", required: "N", fields: None })]) }), trailer: Some(XMLComponent { name: None, msg_cat: None, msg_type: None, field: Some([Field(XMLComponentMember { name: "SignatureLength", required: "N", fields: None }), Field(XMLComponentMember { name: "Signature", required: "N", fields: None }), Field(XMLComponentMember { name: "CheckSum", required: "Y", fields: None })]) }), messages: Some([XMLComponent { name: None, msg_cat: None, msg_type: None, field: Some([Message(XMLComponent { name: Some("Heartbeat"), msg_cat: Some("admin"), msg_type: Some("0"), field: Some([Field(XMLComponentMember { name: "TestReqID", required: "N", fields: None })]) }), Message(XMLComponent { name: Some("IOI"), msg_cat: Some("app"), msg_type: Some("6"), field: Some([Field(XMLComponentMember { name: "IOIid", required: "Y", fields: None }), Field(XMLComponentMember { name: "IOITransType", required: "Y", fields: None }), Field(XMLComponentMember { name: "IOIRefID", required: "N", fields: None }), Component(XMLComponent { name: Some("Instrument"), msg_cat: None, msg_type: None, field: None }), Group(XMLComponentMember { name: "NoRoutingIDs", required: "N", fields: None })]) }), Message(XMLComponent { name: Some("NewOrderSingle"), msg_cat: Some("app"), msg_type: Some("D"), field: Some([Field(XMLComponentMember { name: "ClOrdID", required: "Y", fields: None }), Field(XMLComponentMember { name: "SecondaryClOrdID", required: "N", fields: None }), Field(XMLComponentMember { name: "ClOrdLinkID", required: "N", fields: None }), Component(XMLComponent { name: Some("Parties"), msg_cat: None, msg_type: None, field: None }), Field(XMLComponentMember { name: "TradeOriginationDate", required: "N", fields: None }), Field(XMLComponentMember { name: "Account", required: "N", fields: None }), Field(XMLComponentMember { name: "AccountType", required: "N", fields: None }), Field(XMLComponentMember { name: "DayBookingInst", required: "N", fields: None }), Field(XMLComponentMember { name: "BookingUnit", required: "N", fields: None }), Field(XMLComponentMember { name: "PreallocMethod", required: "N", fields: None }), Group(XMLComponentMember { name: "NoAllocs", required: "N", fields: None }), Field(XMLComponentMember { name: "SettlmntTyp", required: "N", fields: None }), Field(XMLComponentMember { name: "FutSettDate", required: "N", fields: None }), Field(XMLComponentMember { name: "CashMargin", required: "N", fields: None }), Field(XMLComponentMember { name: "ClearingFeeIndicator", required: "N", fields: None }), Field(XMLComponentMember { name: "HandlInst", required: "Y", fields: None }), Field(XMLComponentMember { name: "ExecInst", required: "N", fields: None }), Field(XMLComponentMember { name: "MinQty", required: "N", fields: None }), Field(XMLComponentMember { name: "MaxFloor", required: "N", fields: None }), Field(XMLComponentMember { name: "ExDestination", required: "N", fields: None }), Group(XMLComponentMember { name: "NoTradingSessions", required: "N", fields: None })]) })]) }]), components: None, fields: None }
        };
    }

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

        struct TestCase {
            value: XMLComponentMemberEnum,
            xml_name_local: &'static str,
            name: &'static str,
            required: bool,
        }
        let tests = vec![
            TestCase {
                value: {
                    let doc_clone = &doc.clone();
                    let header = doc_clone.header.as_ref().unwrap();
                    let value = header.fields.as_ref().unwrap()[0].clone();
                    value
                },
                xml_name_local: "field",
                name: "BeginString",
                required: true,
            },
            TestCase {
                value: {
                    let doc_clone = &doc.clone();
                    let header = doc_clone.header.as_ref().unwrap();
                    let value = header.fields.as_ref().unwrap()[1].clone();
                    value
                },
                xml_name_local: "group",
                name: "NoHops",
                required: false,
            },
            TestCase {
                value: {
                    let doc_clone = &doc.clone();
                    let header = doc_clone.header.as_ref().unwrap();
                    let value = header.fields.as_ref().unwrap()[1].clone();
                    let default = XMLComponentMember::default();
                    let member = match value {
                        XMLComponentMemberEnum::Group(ref inner) => inner,
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
                    let doc_clone = &doc.clone();
                    let trailer = doc_clone.trailer.as_ref().unwrap();
                    let value = trailer.fields.as_ref().unwrap()[0].clone();
                    value
                },
                xml_name_local: "field",
                name: "SignatureLength",
                required: false,
            },
            TestCase {
                value: {
                    let doc_clone = &doc.clone();
                    let message = &doc_clone.messages.as_ref().unwrap()[0];
                    let value = message.fields.as_ref().unwrap()[0].clone();
                    let default = XMLComponent::default();
                    let member = match value {
                        XMLComponentMemberEnum::Message(ref inner) => inner,
                        _ => &default,
                    };
                    member.fields.as_ref().unwrap()[0].clone()
                },
                xml_name_local: "field",
                name: "TestReqID",
                required: false,
            },
            TestCase {
                value: {
                    let doc_clone = &doc.clone();
                    let message = &doc_clone.messages.as_ref().unwrap()[0];
                    let value = message.fields.as_ref().unwrap()[1].clone();
                    let default = XMLComponent::default();
                    let member = match value {
                        XMLComponentMemberEnum::Message(ref inner) => inner,
                        _ => &default,
                    };
                    member.fields.as_ref().unwrap()[3].clone()
                },
                xml_name_local: "component",
                name: "Instrument",
                required: true,
            },
            TestCase {
                value: {
                    let doc_clone = &doc.clone();
                    let message = &doc_clone.messages.as_ref().unwrap()[0];
                    let value = message.fields.as_ref().unwrap()[1].clone();
                    let default = XMLComponent::default();
                    let member = match value {
                        XMLComponentMemberEnum::Message(ref inner) => inner,
                        _ => &default,
                    };
                    member.fields.as_ref().unwrap()[4].clone()
                },
                xml_name_local: "group",
                name: "NoRoutingIDs",
                required: false,
            },
            TestCase {
                value: {
                    let doc_clone = &doc.clone();
                    let message = &doc_clone.messages.as_ref().unwrap()[0];
                    let value = message.fields.as_ref().unwrap()[1].clone();
                    let default = XMLComponent::default();
                    let member = match value {
                        XMLComponentMemberEnum::Message(ref inner) => inner,
                        _ => &default,
                    };
                    let value2 = member.fields.as_ref().unwrap()[4].clone();
                    let default2 = XMLComponentMember::default();
                    let member2 = match value2 {
                        XMLComponentMemberEnum::Group(ref inner) => inner,
                        _ => &default2,
                    };
                    member2.fields.as_ref().unwrap()[0].clone()
                },
                xml_name_local: "field",
                name: "RoutingType",
                required: false,
            },
            TestCase {
                value: {
                    let doc_clone = &doc.clone();
                    let message = &doc_clone.messages.as_ref().unwrap()[0];
                    let value = message.fields.as_ref().unwrap()[1].clone();
                    let default = XMLComponent::default();
                    let member = match value {
                        XMLComponentMemberEnum::Message(ref inner) => inner,
                        _ => &default,
                    };
                    let value2 = member.fields.as_ref().unwrap()[4].clone();
                    let default2 = XMLComponentMember::default();
                    let member2 = match value2 {
                        XMLComponentMemberEnum::Group(ref inner) => inner,
                        _ => &default2,
                    };
                    member2.fields.as_ref().unwrap()[1].clone()
                },
                xml_name_local: "field",
                name: "RoutingID",
                required: false,
            },
        ];
        for test in tests.iter() {
            match &test.value {
                XMLComponentMemberEnum::Message(_) => {
                    assert!(false, "not correct type")
                }
                XMLComponentMemberEnum::Component(inner)
                | XMLComponentMemberEnum::Field(inner)
                | XMLComponentMemberEnum::Group(inner) => {
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
        struct TestCase {
            value: XMLComponent,
            name: &'static str,
            msg_cat: &'static str,
            msg_type: &'static str,
        }

        let tests = vec![TestCase {
            value: {
                let doc_clone = &doc.clone();
                let message = &doc_clone.messages.as_ref().unwrap()[0];
                let value = message.fields.as_ref().unwrap()[0].clone();
                let default = XMLComponent::default();
                let member = match value {
                    XMLComponentMemberEnum::Message(inner) => inner,
                    _ => default,
                };
                member
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
