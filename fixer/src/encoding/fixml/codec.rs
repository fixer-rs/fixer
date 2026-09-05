use crate::datadictionary::DataDictionary;
use crate::encoding::Codec;
use crate::encoding::fixml::abbr::FixmlAbbreviations;
use crate::field_map::FieldMap;
use crate::message::{Message, ParseError};
use crate::repeating_group::{GroupTemplate, RepeatingGroup, group_element};
use crate::tag::{TAG_BEGIN_STRING, TAG_BODY_LENGTH, TAG_CHECK_SUM, TAG_MSG_TYPE, Tag};
use fastxml::event::{StreamingParser, XmlEvent, XmlEventHandler};
use std::collections::HashSet;
use std::sync::Arc;

/// FIXML codec — spec-compliant XML encoding for FIX messages.
///
/// Uses `fastxml` for XML parsing and manual string building for serialization.
/// Requires a [`DataDictionary`] and [`FixmlAbbreviations`] (loaded from the
/// FIX repository) for field/component name translation and message structure.
///
/// Spec-compliant features:
/// - `<FIXML>` root with version attribute
/// - Message element using abbreviated name (e.g., `<Order>`)
/// - Fields as XML attributes with abbreviated names
/// - Components as nested child elements (e.g., `<Instrmt Sym="AAPL"/>`)
/// - Repeating groups as repeated elements (counter tag omitted)
/// - `<Hdr>` sub-element for header fields
/// - `BodyLength`, `CheckSum`, `BeginString`, `MsgType` omitted
pub struct FixmlCodec {
    _dd: Arc<DataDictionary>,
    abbr: Arc<FixmlAbbreviations>,
}

// Tags omitted from FIXML (wire-format artifacts or implied by XML structure).
const SKIP_TAGS: &[Tag] = &[TAG_BODY_LENGTH, TAG_CHECK_SUM, TAG_BEGIN_STRING, TAG_MSG_TYPE];

impl FixmlCodec {
    pub fn new(dd: Arc<DataDictionary>, abbr: Arc<FixmlAbbreviations>) -> Self {
        Self { _dd: dd, abbr }
    }
}

impl Codec for FixmlCodec {
    fn decode(
        &self,
        data: &bytes::Bytes,
        _transport_dd: &Option<Arc<DataDictionary>>,
        _app_dd: &Option<Arc<DataDictionary>>,
    ) -> Result<Message, ParseError> {
        let handler = FixmlHandler::new();
        let mut parser = StreamingParser::new(std::io::BufReader::new(data.as_ref()));
        parser.add_handler(Box::new(handler));
        parser.parse().map_err(|e| ParseError {
            orig_error: format!("FIXML parse error: {e}"),
        })?;

        let mut root = None;
        for h in parser.into_handlers() {
            if let Ok(h) = h.as_any().downcast::<FixmlHandler>() {
                root = Some(h.into_root()?);
            }
        }
        let root = root.ok_or_else(|| ParseError {
            orig_error: "FIXML handler lost during parsing".to_string(),
        })?;

        // <FIXML> wraps a single message element; some producers omit it.
        let msg_node = if root.name == "FIXML" {
            root.children.first().ok_or_else(|| ParseError {
                orig_error: "No FIXML message element found".to_string(),
            })?
        } else {
            &root
        };

        let msg_type = self
            .abbr
            .abbr_to_msg_type
            .get(&msg_node.name)
            .ok_or_else(|| ParseError {
                orig_error: format!("Unknown FIXML message element: <{}>", msg_node.name),
            })?;

        let mut msg = Message::new();
        msg.header
            .field_map
            .set_bytes(TAG_MSG_TYPE, msg_type.as_bytes());

        let contents = self.abbr.msg_contents(msg_type);
        let fields: Vec<Tag> = contents
            .map(|c| {
                c.iter()
                    .filter(|e| e.is_field && e.indent == 0)
                    .filter_map(|e| e.tag_text.parse::<Tag>().ok())
                    .collect()
            })
            .unwrap_or_default();
        let components: Vec<String> = contents
            .map(|c| {
                c.iter()
                    .filter(|e| !e.is_field && e.indent == 0)
                    .map(|e| e.tag_text.clone())
                    .collect()
            })
            .unwrap_or_default();

        for (name, value) in &msg_node.attrs {
            if let Some(tag) = resolve_attr(&self.abbr, &fields, name) {
                msg.body.field_map.set_bytes(tag, value.as_bytes());
            }
        }

        let mut body_children: Vec<Node> = Vec::new();
        for child in &msg_node.children {
            match child.name.as_str() {
                "Hdr" => {
                    let (f, c) = section_context(&self.abbr, "StandardHeader");
                    decode_into(
                        &self.abbr,
                        &child.attrs,
                        &child.children,
                        &f,
                        &c,
                        &mut msg.header.field_map,
                    );
                }
                "Trlr" => {
                    let (f, c) = section_context(&self.abbr, "StandardTrailer");
                    decode_into(
                        &self.abbr,
                        &child.attrs,
                        &child.children,
                        &f,
                        &c,
                        &mut msg.trailer.field_map,
                    );
                }
                // Collected rather than handled one at a time: sibling elements
                // of the same repeating component are a single group.
                _ => body_children.push(child.clone()),
            }
        }

        decode_into(
            &self.abbr,
            &[],
            &body_children,
            &fields,
            &components,
            &mut msg.body.field_map,
        );

        Ok(msg)
    }

    fn encode(&self, msg: &mut Message) -> Vec<u8> {
        let msg_type = msg.header.get_string(TAG_MSG_TYPE).unwrap_or_default();
        let msg_elem = self
            .abbr
            .msg_type_to_abbr
            .get(&msg_type)
            .cloned()
            .unwrap_or(msg_type.clone());

        let mut xml = String::with_capacity(512);

        // <FIXML> root with version attribute.
        xml.push_str("<FIXML");
        if !self.abbr.fix_version.is_empty() {
            xml.push_str(" v=\"");
            xml.push_str(&self.abbr.fix_version);
            xml.push('"');
        }
        xml.push('>');

        // Collect all body fields into a lookup for efficient access.
        let body = collect_fields(&mut msg.body.field_map);

        // Which repeating components this message can contain, keyed by the
        // NumInGroup tag that introduces each one on the wire.
        let mut counters = rustc_hash::FxHashMap::default();
        if let Some(contents) = self.abbr.msg_contents(&msg_type) {
            collect_repeating(&self.abbr, contents, 0, &mut counters, &mut HashSet::new());
        }

        // Open message element.
        xml.push('<');
        xml.push_str(&msg_elem);

        // Encode body using message structure from MsgContents.
        if let Some(contents) = self.abbr.msg_contents(&msg_type) {
            // Fields outside any repeating group. A group's members are only
            // reachable through the group, so they must not leak into the
            // message element or a sibling block.
            let scalars = scope_scalars(&body, &self.abbr, &counters);

            // First pass: write direct fields as attributes on message element.
            for entry in contents {
                if !entry.is_field || entry.indent > 0 {
                    continue;
                }
                if let Ok(tag) = entry.tag_text.parse::<Tag>() {
                    if SKIP_TAGS.contains(&tag) {
                        continue;
                    }
                    if let Some(value) = scalars.get(&tag) {
                        write_attr(&mut xml, &self.abbr, tag, value);
                    }
                }
            }

            xml.push('>');

            // Second pass: write components as child elements.
            for entry in contents {
                if entry.is_field
                    || entry.indent > 0
                    || entry.tag_text == "StandardHeader"
                    || entry.tag_text == "StandardTrailer"
                {
                    continue;
                }

                encode_component(&entry.tag_text, &mut xml, &self.abbr, &body, &counters);
            }
        } else {
            // No MsgContents available — flat encode all body fields.
            for (tag, value) in &body {
                if SKIP_TAGS.contains(tag) {
                    continue;
                }
                write_attr(&mut xml, &self.abbr, *tag, value);
            }
            xml.push('>');
        }

        // Header and trailer are ordinary components (StandardHeader -> <Hdr>,
        // StandardTrailer -> <Trlr>), so they go through the same path as the
        // body. That matters because the header carries a repeating group of
        // its own: Hop, for third-party routing.
        for (component, field_map) in [
            ("StandardHeader", &mut msg.header.field_map),
            ("StandardTrailer", &mut msg.trailer.field_map),
        ] {
            let fields = collect_fields(field_map);
            if fields.is_empty() {
                continue;
            }
            let mut section_counters = rustc_hash::FxHashMap::default();
            if let Some(contents) = self.abbr.component_contents(component) {
                collect_repeating(
                    &self.abbr,
                    contents,
                    self.abbr.member_indent(component),
                    &mut section_counters,
                    &mut HashSet::new(),
                );
            }
            encode_component(component, &mut xml, &self.abbr, &fields, &section_counters);
        }

        // Close message and root.
        xml.push_str("</");
        xml.push_str(&msg_elem);
        xml.push('>');
        xml.push_str("</FIXML>");

        xml.into_bytes()
    }
}

// ---------------------------------------------------------------------------
// Streaming SAX handler
// ---------------------------------------------------------------------------

/// A parsed XML element. FIXML documents are small, so decoding builds the
/// tree first and then walks it with the schema in hand — resolving an
/// attribute needs to know which component encloses it, which a streaming
/// pass does not know until it has the element name.
#[derive(Default, Clone)]
struct Node {
    name: String,
    attrs: Vec<(String, String)>,
    children: Vec<Node>,
}

struct FixmlHandler {
    stack: Vec<Node>,
    root: Option<Node>,
    error: Option<String>,
}

impl FixmlHandler {
    fn new() -> Self {
        Self {
            stack: Vec::new(),
            root: None,
            error: None,
        }
    }

    fn into_root(self) -> Result<Node, ParseError> {
        if let Some(err) = self.error {
            return Err(ParseError { orig_error: err });
        }
        self.root.ok_or_else(|| ParseError {
            orig_error: "No FIXML message element found".to_string(),
        })
    }
}

impl XmlEventHandler for FixmlHandler {
    fn handle(&mut self, event: &XmlEvent) -> fastxml::Result<()> {
        match event {
            XmlEvent::StartElement {
                name, attributes, ..
            } => {
                self.stack.push(Node {
                    name: name.as_ref().to_string(),
                    attrs: attributes
                        .iter()
                        .map(|(k, v)| (k.as_str().to_string(), v.as_str().to_string()))
                        .collect(),
                    children: Vec::new(),
                });
            }
            XmlEvent::EndElement { .. } => {
                if let Some(node) = self.stack.pop() {
                    match self.stack.last_mut() {
                        Some(parent) => parent.children.push(node),
                        None => self.root = Some(node),
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn as_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }
}

/// The fields and components a section allows, for name resolution.
fn section_context(abbr: &FixmlAbbreviations, component: &str) -> (Vec<Tag>, Vec<String>) {
    (
        abbr.member_fields(component),
        abbr.member_components(component),
    )
}

/// Resolve an XML attribute name to a tag within `candidates`.
///
/// FIXML abbreviations are only unique inside the component that defines
/// them — FIX.4.4 alone gives six different tags the name `Qty` — so the
/// enclosing component's fields are tried before the global map.
fn resolve_attr(
    abbr: &FixmlAbbreviations,
    candidates: &[Tag],
    name: &str,
) -> Option<Tag> {
    for &tag in candidates {
        if abbr.tag_to_abbr.get(&tag).is_some_and(|a| a == name) {
            return Some(tag);
        }
    }
    if let Some(&tag) = abbr.abbr_to_tag.get(name) {
        return Some(tag);
    }
    name.parse::<Tag>().ok()
}

/// Resolve a child element name to one of the components valid at this level.
///
/// Element names repeat across the schema too (`Pty` is both `Parties` and
/// `NestedParties`), so only the components reachable here are considered.
fn resolve_component(
    abbr: &FixmlAbbreviations,
    candidates: &[String],
    elem: &str,
) -> Option<String> {
    candidates
        .iter()
        .find(|name| {
            abbr.component_to_abbr
                .get(*name)
                .is_some_and(|a| a == elem)
        })
        .cloned()
        .or_else(|| abbr.abbr_to_component.get(elem).cloned())
}

/// The `GroupTemplate` for a repeating component, in repository order.
///
/// A plain block inside a group contributes its fields inline; a nested
/// repeating component becomes a nested `RepeatingGroup`.
fn group_template(abbr: &FixmlAbbreviations, component: &str) -> GroupTemplate {
    fn push_component(
        abbr: &FixmlAbbreviations,
        component: &str,
        indent: usize,
        out: &mut GroupTemplate,
        seen: &mut HashSet<String>,
    ) {
        if !seen.insert(component.to_string()) {
            return;
        }
        let Some(entries) = abbr.component_contents(component) else {
            return;
        };
        for entry in entries {
            if entry.indent != indent {
                continue;
            }
            if entry.is_field {
                if let Ok(tag) = entry.tag_text.parse::<Tag>() {
                    out.push(group_element(tag));
                }
            } else if abbr.is_repeating(&entry.tag_text) {
                if let Some(counter) = abbr.group_counter_tag(&entry.tag_text) {
                    out.push(Box::new(RepeatingGroup::new(
                        counter,
                        group_template(abbr, &entry.tag_text),
                    )));
                }
            } else {
                push_component(abbr, &entry.tag_text, abbr.member_indent(&entry.tag_text), out, seen);
            }
        }
    }

    let mut out = GroupTemplate::new();
    push_component(
        abbr,
        component,
        abbr.member_indent(component),
        &mut out,
        &mut HashSet::new(),
    );
    out
}

/// Write `node`'s attributes and children into `target`.
///
/// `fields` and `components` are what the schema allows at this level, used to
/// disambiguate abbreviated names.
fn decode_into(
    abbr: &FixmlAbbreviations,
    attrs: &[(String, String)],
    children: &[Node],
    fields: &[Tag],
    components: &[String],
    target: &mut FieldMap,
) {
    for (name, value) in attrs {
        if let Some(tag) = resolve_attr(abbr, fields, name) {
            target.set_bytes(tag, value.as_bytes());
        }
    }

    // Repeated elements of the same component form one group, so collect them
    // before building anything.
    let mut order: Vec<String> = Vec::new();
    let mut grouped: rustc_hash::FxHashMap<String, Vec<&Node>> = rustc_hash::FxHashMap::default();
    for child in children {
        let Some(component) = resolve_component(abbr, components, &child.name) else {
            continue;
        };
        if !grouped.contains_key(&component) {
            order.push(component.clone());
        }
        grouped.entry(component).or_default().push(child);
    }

    for component in order {
        let nodes = &grouped[&component];
        let sub_fields = abbr.member_fields(&component);
        let sub_components = abbr.member_components(&component);

        if abbr.is_repeating(&component) {
            let Some(counter) = abbr.group_counter_tag(&component) else {
                continue;
            };
            let mut rg = RepeatingGroup::new(counter, group_template(abbr, &component));
            for child in nodes {
                // Populate the Group `add` hands back rather than swapping in a
                // fresh FieldMap: `add` installs the group's template ordering,
                // which keeps the delimiter first when the entry is written.
                let entry = rg.add();
                decode_into(
                    abbr,
                    &child.attrs,
                    &child.children,
                    &sub_fields,
                    &sub_components,
                    &mut entry.field_map,
                );
            }
            target.set_group(rg);
        } else {
            // A block is flattened into its parent, matching the tag-value form.
            for child in nodes {
                decode_into(
                    abbr,
                    &child.attrs,
                    &child.children,
                    &sub_fields,
                    &sub_components,
                    target,
                );
            }
        }
    }
}

/// Records every repeating component reachable from `contents`, keyed by the
/// `NumInGroup` tag that introduces it.
fn collect_repeating(
    abbr: &FixmlAbbreviations,
    contents: &[crate::encoding::fixml::abbr::ContentEntry],
    indent: usize,
    out: &mut rustc_hash::FxHashMap<Tag, String>,
    seen: &mut HashSet<String>,
) {
    for entry in contents {
        if entry.is_field || entry.indent != indent {
            continue;
        }
        let name = &entry.tag_text;
        if !seen.insert(name.clone()) {
            continue;
        }
        if abbr.is_repeating(name)
            && let Some(counter) = abbr.group_counter_tag(name)
        {
            out.insert(counter, name.clone());
        }
        if let Some(sub) = abbr.component_contents(name) {
            collect_repeating(abbr, sub, abbr.member_indent(name), out, seen);
        }
    }
}

/// Extent of the repeating group introduced at `scope[start]`.
///
/// The counter is followed by the group's entries, which run until a tag that
/// does not belong to the group.
fn group_extent(
    scope: &[(Tag, Vec<u8>)],
    start: usize,
    abbr: &FixmlAbbreviations,
    component: &str,
) -> usize {
    let Some(all) = abbr.component_all_tags.get(component) else {
        return start + 1;
    };
    let mut end = start + 1;
    while end < scope.len() && all.contains(&scope[end].0) {
        end += 1;
    }
    end
}

/// The fields of `scope` that sit outside any repeating group, keyed by tag.
///
/// Group members repeat, so a plain map would keep only the last one and let
/// it masquerade as a scalar field of the enclosing message or block.
fn scope_scalars<'a>(
    scope: &'a [(Tag, Vec<u8>)],
    abbr: &FixmlAbbreviations,
    counters: &rustc_hash::FxHashMap<Tag, String>,
) -> rustc_hash::FxHashMap<Tag, &'a [u8]> {
    let mut out = rustc_hash::FxHashMap::default();
    let mut i = 0;
    while i < scope.len() {
        let tag = scope[i].0;
        if let Some(component) = counters.get(&tag) {
            i = group_extent(scope, i, abbr, component);
        } else {
            out.entry(tag).or_insert_with(|| scope[i].1.as_slice());
            i += 1;
        }
    }
    out
}

/// Splits a group's fields into one slice per entry.
///
/// `span` starts at the `NumInGroup` counter. Entries begin at each occurrence
/// of the group's delimiter, which the FIX spec fixes as its first member.
fn split_group_entries(
    span: &[(Tag, Vec<u8>)],
    delimiter: Option<Tag>,
) -> Vec<&[(Tag, Vec<u8>)]> {
    let members = &span[1..];
    let Some(delimiter) = delimiter else {
        return if members.is_empty() {
            Vec::new()
        } else {
            vec![members]
        };
    };

    let starts: Vec<usize> = members
        .iter()
        .enumerate()
        .filter(|(_, (tag, _))| *tag == delimiter)
        .map(|(i, _)| i)
        .collect();

    starts
        .iter()
        .enumerate()
        .map(|(n, &begin)| {
            let end = starts.get(n + 1).copied().unwrap_or(members.len());
            &members[begin..end]
        })
        .collect()
}

/// Encode one component of `scope` as a child element.
///
/// A repeating component becomes one element per entry with no counter
/// attribute — FIXML derives the count from the number of elements.
fn encode_component(
    component_name: &str,
    xml: &mut String,
    abbr: &FixmlAbbreviations,
    scope: &[(Tag, Vec<u8>)],
    counters: &rustc_hash::FxHashMap<Tag, String>,
) {
    let elem_name = abbr
        .component_to_abbr
        .get(component_name)
        .cloned()
        .unwrap_or_else(|| component_name.to_string());

    if abbr.is_repeating(component_name) {
        let Some(counter) = abbr.group_counter_tag(component_name) else {
            return;
        };
        let Some(start) = scope.iter().position(|(tag, _)| *tag == counter) else {
            return;
        };
        let end = group_extent(scope, start, abbr, component_name);
        let delimiter = abbr.member_fields(component_name).first().copied();

        for entry in split_group_entries(&scope[start..end], delimiter) {
            write_element(&elem_name, xml, abbr, component_name, entry, counters);
        }
        return;
    }

    write_element(&elem_name, xml, abbr, component_name, scope, counters);
}

/// Write a single element for `component_name`, drawing its fields from
/// `scope` and recursing into its sub-components.
fn write_element(
    elem_name: &str,
    xml: &mut String,
    abbr: &FixmlAbbreviations,
    component_name: &str,
    scope: &[(Tag, Vec<u8>)],
    counters: &rustc_hash::FxHashMap<Tag, String>,
) {
    let scalars = scope_scalars(scope, abbr, counters);

    // Repository order, so attribute order is stable.
    let attrs: Vec<(Tag, &[u8])> = abbr
        .member_fields(component_name)
        .into_iter()
        .filter(|tag| !SKIP_TAGS.contains(tag))
        .filter_map(|tag| scalars.get(&tag).map(|v| (tag, *v)))
        .collect();

    // Only recurse into sub-components that have data in this scope.
    let sub_components: Vec<String> = abbr
        .member_components(component_name)
        .into_iter()
        .filter(|sub| component_has_data(abbr, sub, scope, &scalars))
        .collect();

    if attrs.is_empty() && sub_components.is_empty() {
        return;
    }

    xml.push('<');
    xml.push_str(elem_name);
    for (tag, value) in &attrs {
        write_attr(xml, abbr, *tag, value);
    }

    if sub_components.is_empty() {
        xml.push_str("/>");
    } else {
        xml.push('>');
        for sub in &sub_components {
            encode_component(sub, xml, abbr, scope, counters);
        }
        xml.push_str("</");
        xml.push_str(elem_name);
        xml.push('>');
    }
}

/// Whether any tag belonging to `component` is present in `scope`.
///
/// `scalars` is the caller's already-computed view of the fields in `scope`
/// that sit outside any group; recomputing it per candidate component made
/// encoding quadratic in the number of components a message declares.
fn component_has_data(
    abbr: &FixmlAbbreviations,
    component: &str,
    scope: &[(Tag, Vec<u8>)],
    scalars: &rustc_hash::FxHashMap<Tag, &[u8]>,
) -> bool {
    let Some(all) = abbr.component_all_tags.get(component) else {
        return false;
    };
    if abbr.is_repeating(component) {
        // A group is present only if its counter is, so an empty group is not
        // mistaken for one carrying data.
        return abbr
            .group_counter_tag(component)
            .is_some_and(|counter| scope.iter().any(|(tag, _)| *tag == counter));
    }
    all.iter().any(|tag| scalars.contains_key(tag))
}

/// Write a single XML attribute: ` AbbrName="value"`.
fn write_attr(xml: &mut String, abbr: &FixmlAbbreviations, tag: Tag, value: &[u8]) {
    let attr_name = abbr
        .tag_to_abbr
        .get(&tag)
        .cloned()
        .unwrap_or_else(|| tag.to_string());
    let val_str = String::from_utf8_lossy(value);
    xml.push(' ');
    xml.push_str(&attr_name);
    xml.push_str("=\"");
    xml_escape_into(xml, &val_str);
    xml.push('"');
}

/// Collect all (tag, value bytes) pairs from a `FieldMap`, preserving order.
fn collect_fields(fm: &mut FieldMap) -> Vec<(Tag, Vec<u8>)> {
    if let Some(ref indices) = fm.content.field_indices {
        let pf = fm.content.parsed_fields.as_ref().unwrap();
        return indices
            .iter()
            .map(|&i| {
                let tv = &pf[i as usize];
                (tv.tag, tv.value().to_vec())
            })
            .collect();
    }

    let tags = fm.sorted_tags();
    let mut result = Vec::new();
    for tag in tags {
        if let Some(lf) = fm.content.tag_lookup.get(&tag) {
            for tv in &lf.data {
                result.push((tv.tag, tv.value().to_vec()));
            }
        }
    }
    result
}

/// Escape special XML characters in attribute values.
fn xml_escape_into(buf: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '&' => buf.push_str("&amp;"),
            '<' => buf.push_str("&lt;"),
            '>' => buf.push_str("&gt;"),
            '"' => buf.push_str("&quot;"),
            '\'' => buf.push_str("&apos;"),
            _ => buf.push(c),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::datadictionary::FieldType;
    use crate::fix_string::FIXString;
    use crate::tag::*;

    /// Real FIX.4.4 structure, rather than a hand-built approximation of it.
    fn test_abbr() -> Arc<FixmlAbbreviations> {
        Arc::new(FixmlAbbreviations::bundled("FIX.4.4").expect("bundled FIX.4.4"))
    }

    fn test_dd() -> Arc<DataDictionary> {
        let mut dd = DataDictionary::default();
        let fields: &[(Tag, &str, &str)] = &[
            (TAG_BEGIN_STRING, "BeginString", "STRING"),
            (TAG_BODY_LENGTH, "BodyLength", "LENGTH"),
            (TAG_MSG_TYPE, "MsgType", "STRING"),
            (TAG_SENDER_COMP_ID, "SenderCompID", "STRING"),
            (TAG_TARGET_COMP_ID, "TargetCompID", "STRING"),
            (TAG_MSG_SEQ_NUM, "MsgSeqNum", "SEQNUM"),
            (TAG_SENDING_TIME, "SendingTime", "UTCTIMESTAMP"),
            (TAG_CHECK_SUM, "CheckSum", "STRING"),
            (11, "ClOrdID", "STRING"),
            (21, "HandlInst", "CHAR"),
            (22, "SecurityIDSource", "STRING"),
            (38, "OrderQty", "QTY"),
            (40, "OrdType", "CHAR"),
            (44, "Price", "PRICE"),
            (48, "SecurityID", "STRING"),
            (54, "Side", "CHAR"),
            (55, "Symbol", "STRING"),
            (60, "TransactTime", "UTCTIMESTAMP"),
        ];
        for &(tag, name, typ) in fields {
            let ft = FieldType::new(name.to_string(), tag, typ.to_string());
            dd.field_type_by_tag.insert(tag, ft.clone());
            dd.field_type_by_name.insert(name.to_string(), ft);
        }
        Arc::new(dd)
    }

    #[test]
    fn test_fixml_encode_with_components() {
        let dd = test_dd();
        let abbr = test_abbr();
        let codec = FixmlCodec::new(dd, abbr);

        let mut msg = Message::new();
        msg.header
            .set_field(TAG_BEGIN_STRING, FIXString::from("FIX.4.4"));
        msg.header.set_field(TAG_MSG_TYPE, FIXString::from("D"));
        msg.header
            .set_field(TAG_SENDER_COMP_ID, FIXString::from("BUY"));
        msg.header
            .set_field(TAG_TARGET_COMP_ID, FIXString::from("SELL"));
        msg.header.set_int(TAG_MSG_SEQ_NUM, 4);
        // Direct fields on message element
        msg.body.set_string(11, "ORDER-001");
        msg.body.set_string(54, "1");
        msg.body.set_string(40, "2");
        msg.body.set_string(44, "150.25");
        // Instrument component fields
        msg.body.set_string(55, "AAPL");
        msg.body.set_string(48, "037833100");
        msg.body.set_string(22, "1");
        // OrderQtyData component fields
        msg.body.set_int(38, 100);

        let encoded = codec.encode(&mut msg);
        let xml = String::from_utf8(encoded).unwrap();

        // Root element with version
        assert!(xml.starts_with("<FIXML v=\"FIX.4.4\">"), "Got: {xml}");
        // Message element
        assert!(xml.contains("<Order"), "Should have <Order> element: {xml}");
        // Direct fields as attributes on Order
        assert!(xml.contains("ClOrdID=\"ORDER-001\""), "Direct field: {xml}");
        assert!(xml.contains("Side=\"1\""), "Direct field: {xml}");
        assert!(xml.contains("Px=\"150.25\""), "Direct field: {xml}");
        // Instrument as nested element
        assert!(xml.contains("<Instrmt"), "Component element: {xml}");
        assert!(xml.contains("Sym=\"AAPL\""), "Component attr: {xml}");
        assert!(xml.contains("ID=\"037833100\""), "Component attr: {xml}");
        // OrderQtyData as nested element
        assert!(xml.contains("<OrdQty"), "Component element: {xml}");
        // Header
        assert!(xml.contains("<Hdr"), "Header element: {xml}");
        assert!(xml.contains("SID=\"BUY\""), "Header attr: {xml}");
        // Omitted tags
        assert!(!xml.contains("BgnStr="), "BeginString omitted: {xml}");
        assert!(!xml.contains("MsgTyp="), "MsgType omitted: {xml}");
    }

    #[test]
    fn test_fixml_decode_with_components() {
        let dd = test_dd();
        let abbr = test_abbr();
        let codec = FixmlCodec::new(dd, abbr);

        let xml = r#"<FIXML v="FIX.4.4"><Order ClOrdID="ORDER-001" Side="1" OrdTyp="2" Px="150.25"><Instrmt Sym="AAPL" ID="037833100" Src="1"/><OrdQty Qty="100"/><Hdr SID="BUY" TID="SELL" SeqNum="4"/></Order></FIXML>"#;
        let data = bytes::Bytes::from(xml);

        let msg = codec.decode(&data, &None, &None).unwrap();

        assert!(msg.is_msg_type_of("D"));
        assert_eq!(msg.header.get_string(TAG_SENDER_COMP_ID).unwrap(), "BUY");
        assert_eq!(msg.header.get_string(TAG_TARGET_COMP_ID).unwrap(), "SELL");
        assert_eq!(msg.header.get_int(TAG_MSG_SEQ_NUM).unwrap(), 4);
        // Direct body fields
        assert_eq!(msg.body.get_string(11).unwrap(), "ORDER-001");
        assert_eq!(msg.body.get_string(54).unwrap(), "1");
        assert_eq!(msg.body.get_string(40).unwrap(), "2");
        assert_eq!(msg.body.get_string(44).unwrap(), "150.25");
        // Component fields (flattened into body)
        assert_eq!(msg.body.get_string(55).unwrap(), "AAPL");
        assert_eq!(msg.body.get_string(48).unwrap(), "037833100");
        assert_eq!(msg.body.get_string(22).unwrap(), "1");
        assert_eq!(msg.body.get_int(38).unwrap(), 100);
    }

    /// A repeating group becomes one element per entry, with the NumInGroup
    /// counter left implicit. This used to emit the counter as an attribute on
    /// a single element and drop every entry.
    #[test]
    fn test_fixml_encode_repeating_group() {
        let codec = FixmlCodec::new(test_dd(), test_abbr());

        let mut msg = Message::new();
        msg.header.set_field(TAG_MSG_TYPE, FIXString::from("D"));
        msg.body.set_field(11, FIXString::from("ORDER-1"));

        let mut parties = RepeatingGroup::new(
            453,
            vec![group_element(448), group_element(447), group_element(452)],
        );
        {
            let e = parties.add();
            e.field_map.set_field(448, FIXString::from("BROKER-A"));
            e.field_map.set_field(447, FIXString::from("D"));
            e.field_map.set_field(452, FIXString::from("1"));
        }
        {
            let e = parties.add();
            e.field_map.set_field(448, FIXString::from("BROKER-B"));
            e.field_map.set_field(452, FIXString::from("2"));
        }
        msg.body.set_group(parties);

        let xml = String::from_utf8(codec.encode(&mut msg)).unwrap();

        assert_eq!(2, xml.matches("<Pty ").count(), "expected two entries: {xml}");
        assert!(xml.contains(r#"<Pty ID="BROKER-A" Src="D" R="1"/>"#), "{xml}");
        assert!(xml.contains(r#"<Pty ID="BROKER-B" R="2"/>"#), "{xml}");
        assert!(
            !xml.contains("NoPtyIDs"),
            "the counter is implied by the element count: {xml}"
        );
    }

    #[test]
    fn test_fixml_decode_repeating_group() {
        let codec = FixmlCodec::new(test_dd(), test_abbr());

        let xml = r#"<FIXML v="FIX.4.4"><Order ClOrdID="ORDER-1"><Pty ID="BROKER-A" Src="D" R="1"/><Pty ID="BROKER-B" R="2"/></Order></FIXML>"#;
        let msg = codec
            .decode(&bytes::Bytes::from(xml), &None, &None)
            .unwrap();

        let parties = msg
            .body
            .get_group(RepeatingGroup::new(
                453,
                vec![group_element(448), group_element(447), group_element(452)],
            ))
            .expect("Parties should decode");

        assert_eq!(2, parties.len());
        assert_eq!(b"BROKER-A", parties.get(0).field_map.get_bytes(448).unwrap());
        assert_eq!(b"D", parties.get(0).field_map.get_bytes(447).unwrap());
        assert_eq!(b"BROKER-B", parties.get(1).field_map.get_bytes(448).unwrap());
        assert_eq!(b"2", parties.get(1).field_map.get_bytes(452).unwrap());
    }

    #[test]
    fn test_fixml_repeating_group_round_trip() {
        let codec = FixmlCodec::new(test_dd(), test_abbr());

        let mut msg = Message::new();
        msg.header.set_field(TAG_MSG_TYPE, FIXString::from("D"));
        msg.body.set_field(11, FIXString::from("ORDER-1"));
        msg.body.set_field(55, FIXString::from("AAPL"));

        let template = || vec![group_element(448), group_element(447), group_element(452)];
        let mut parties = RepeatingGroup::new(453, template());
        for (id, role) in [("BROKER-A", "1"), ("BROKER-B", "2"), ("BROKER-C", "3")] {
            let e = parties.add();
            e.field_map.set_field(448, FIXString::from(id));
            e.field_map.set_field(452, FIXString::from(role));
        }
        msg.body.set_group(parties);

        let xml = codec.encode(&mut msg);
        let decoded = codec
            .decode(&bytes::Bytes::from(xml), &None, &None)
            .unwrap();

        assert_eq!(b"AAPL", decoded.body.get_bytes(55).unwrap());
        let parties = decoded
            .body
            .get_group(RepeatingGroup::new(453, template()))
            .expect("Parties should survive the round trip");
        assert_eq!(3, parties.len());
        for (i, (id, role)) in [("BROKER-A", "1"), ("BROKER-B", "2"), ("BROKER-C", "3")]
            .into_iter()
            .enumerate()
        {
            assert_eq!(id.as_bytes(), parties.get(i).field_map.get_bytes(448).unwrap());
            assert_eq!(role.as_bytes(), parties.get(i).field_map.get_bytes(452).unwrap());
        }
    }

    /// `PtysSubGrp` (NoPartySubIDs) nests inside `Parties`, so the entries have
    /// to nest as elements rather than flatten into the parent.
    #[test]
    fn test_fixml_nested_repeating_group() {
        let codec = FixmlCodec::new(test_dd(), test_abbr());

        let xml = r#"<FIXML v="FIX.4.4"><Order ClOrdID="ORDER-1"><Pty ID="BROKER-A" R="1"><Sub ID="SUB-1" Typ="1"/><Sub ID="SUB-2" Typ="2"/></Pty></Order></FIXML>"#;
        let msg = codec
            .decode(&bytes::Bytes::from(xml), &None, &None)
            .unwrap();

        let sub_template = || vec![group_element(523), group_element(803)];
        let parties = msg
            .body
            .get_group(RepeatingGroup::new(
                453,
                vec![
                    group_element(448),
                    group_element(447),
                    group_element(452),
                    Box::new(RepeatingGroup::new(802, sub_template())),
                ],
            ))
            .expect("Parties should decode");

        assert_eq!(1, parties.len());
        let entry = parties.get(0);
        assert_eq!(b"BROKER-A", entry.field_map.get_bytes(448).unwrap());

        let subs = entry
            .field_map
            .get_group(RepeatingGroup::new(802, sub_template()))
            .expect("nested PtysSubGrp should decode");
        assert_eq!(2, subs.len());
        assert_eq!(b"SUB-1", subs.get(0).field_map.get_bytes(523).unwrap());
        assert_eq!(b"SUB-2", subs.get(1).field_map.get_bytes(523).unwrap());
    }

    /// FIXML abbreviations are only unique within their component: six FIX.4.4
    /// fields are abbreviated `Qty`. Resolving against a global map picked
    /// whichever was inserted last.
    #[test]
    fn test_fixml_ambiguous_abbreviation_resolves_in_context() {
        let codec = FixmlCodec::new(test_dd(), test_abbr());

        let xml = r#"<FIXML v="FIX.4.4"><Order ClOrdID="ORDER-1"><OrdQty Qty="100"/></Order></FIXML>"#;
        let msg = codec
            .decode(&bytes::Bytes::from(xml), &None, &None)
            .unwrap();

        assert_eq!(
            b"100",
            msg.body.get_bytes(38).unwrap(),
            "Qty inside <OrdQty> is OrderQty (38)"
        );
        for other in [27, 53, 80, 687, 879] {
            assert!(
                msg.body.get_bytes(other).is_err(),
                "Qty must not also land on tag {other}"
            );
        }
    }

    /// `Snt` is FIX.4.4's abbreviation for both SendingTime (52) and tag 629,
    /// so header attributes need the same context-aware resolution as the body.
    #[test]
    fn test_fixml_decode_header_resolves_in_context() {
        let codec = FixmlCodec::new(test_dd(), test_abbr());

        let xml = r#"<FIXML v="FIX.4.4"><Order ClOrdID="ORDER-1"><Hdr SID="BUY" TID="SELL" SeqNum="4" Snt="20230912-10:30:00"/></Order></FIXML>"#;
        let msg = codec
            .decode(&bytes::Bytes::from(xml), &None, &None)
            .unwrap();

        assert_eq!(b"BUY", msg.header.get_bytes(TAG_SENDER_COMP_ID).unwrap());
        assert_eq!(b"4", msg.header.get_bytes(TAG_MSG_SEQ_NUM).unwrap());
        assert_eq!(
            b"20230912-10:30:00",
            msg.header.get_bytes(TAG_SENDING_TIME).unwrap(),
            "Snt in a header is SendingTime (52), not tag 629"
        );
        assert!(msg.header.get_bytes(629).is_err(), "must not land on 629");
    }

    /// The header carries a repeating group of its own (Hop, for third-party
    /// routing). `<Hdr>` used to be written as flat attributes and decoded
    /// with its children ignored, so hops were dropped in both directions.
    ///
    /// `Hop` is also typed `ImplicitBlock` in the repository despite
    /// repeating, which is why `is_repeating` goes by structure.
    #[test]
    fn test_fixml_header_repeating_group_round_trip() {
        let codec = FixmlCodec::new(test_dd(), test_abbr());

        let mut msg = Message::new();
        msg.header.set_field(TAG_MSG_TYPE, FIXString::from("D"));
        msg.header
            .set_field(TAG_SENDER_COMP_ID, FIXString::from("BUY"));
        msg.body.set_field(11, FIXString::from("ORDER-1"));

        let template = || vec![group_element(628), group_element(629), group_element(630)];
        let mut hops = RepeatingGroup::new(627, template());
        for (id, reference) in [("HOP-1", "REF-1"), ("HOP-2", "REF-2")] {
            let hop = hops.add();
            hop.field_map.set_field(628, FIXString::from(id));
            hop.field_map.set_field(630, FIXString::from(reference));
        }
        msg.header.set_group(hops);

        let xml = String::from_utf8(codec.encode(&mut msg)).unwrap();
        assert_eq!(2, xml.matches("<Hop ").count(), "expected two hops: {xml}");
        assert!(xml.contains("HOP-1") && xml.contains("HOP-2"), "{xml}");
        assert!(
            !xml.contains("NoHops"),
            "the counter is implied by the element count: {xml}"
        );

        let decoded = codec
            .decode(&bytes::Bytes::from(xml.clone()), &None, &None)
            .unwrap();
        assert_eq!(
            b"BUY",
            decoded.header.get_bytes(TAG_SENDER_COMP_ID).unwrap()
        );

        let hops = decoded
            .header
            .get_group(RepeatingGroup::new(627, template()))
            .expect("header group should survive the round trip");
        assert_eq!(2, hops.len());
        assert_eq!(b"HOP-1", hops.get(0).field_map.get_bytes(628).unwrap());
        assert_eq!(b"REF-2", hops.get(1).field_map.get_bytes(630).unwrap());
    }

    #[test]
    fn test_fixml_round_trip() {
        let dd = test_dd();
        let abbr = test_abbr();
        let codec = FixmlCodec::new(dd, abbr);

        let mut msg = Message::new();
        msg.header
            .set_field(TAG_BEGIN_STRING, FIXString::from("FIX.4.4"));
        msg.header.set_field(TAG_MSG_TYPE, FIXString::from("D"));
        msg.header
            .set_field(TAG_SENDER_COMP_ID, FIXString::from("BUY"));
        msg.header.set_int(TAG_MSG_SEQ_NUM, 4);
        msg.body.set_string(11, "ORDER-001");
        msg.body.set_string(55, "AAPL");
        msg.body.set_string(54, "1");
        msg.body.set_string(40, "2");
        msg.body.set_int(38, 100);

        let encoded = codec.encode(&mut msg);
        let data = bytes::Bytes::from(encoded);
        let decoded = codec.decode(&data, &None, &None).unwrap();

        assert!(decoded.is_msg_type_of("D"));
        assert_eq!(decoded.header.get_string(TAG_SENDER_COMP_ID).unwrap(), "BUY");
        assert_eq!(decoded.header.get_int(TAG_MSG_SEQ_NUM).unwrap(), 4);
        assert_eq!(decoded.body.get_string(11).unwrap(), "ORDER-001");
        assert_eq!(decoded.body.get_string(55).unwrap(), "AAPL");
        assert_eq!(decoded.body.get_string(54).unwrap(), "1");
        assert_eq!(decoded.body.get_int(38).unwrap(), 100);
    }

    #[test]
    fn test_fixml_decode_invalid() {
        let dd = test_dd();
        let abbr = test_abbr();
        let codec = FixmlCodec::new(dd, abbr);

        assert!(codec
            .decode(&bytes::Bytes::from("not xml"), &None, &None)
            .is_err());
        assert!(codec
            .decode(&bytes::Bytes::from("<NotFIXML/>"), &None, &None)
            .is_err());
        assert!(codec
            .decode(
                &bytes::Bytes::from("<FIXML><UnknownMsg/></FIXML>"),
                &None,
                &None
            )
            .is_err());
    }

    #[test]
    fn test_fixml_xml_escape() {
        let dd = test_dd();
        let abbr = test_abbr();
        let codec = FixmlCodec::new(dd, abbr);

        let mut msg = Message::new();
        msg.header.set_field(TAG_MSG_TYPE, FIXString::from("D"));
        msg.body.set_string(11, "A&B<C>D\"E");

        let encoded = codec.encode(&mut msg);
        let xml = String::from_utf8(encoded).unwrap();
        assert!(
            xml.contains("ClOrdID=\"A&amp;B&lt;C&gt;D&quot;E\""),
            "Escape: {xml}"
        );
    }
}
