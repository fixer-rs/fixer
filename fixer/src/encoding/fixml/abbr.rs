use crate::tag::Tag;
use rustc_hash::FxHashMap;
use std::collections::HashSet;

/// Bidirectional abbreviation maps and message structure for FIXML encoding.
///
/// Maps between FIX tag numbers / field names and their FIXML abbreviated
/// names, plus message→component→field structure from `MsgContents.xml`.
#[derive(Debug, Clone, Default)]
pub struct FixmlAbbreviations {
    /// Tag number → abbreviated XML attribute name (e.g., 55 → "Sym")
    pub tag_to_abbr: FxHashMap<Tag, String>,
    /// Abbreviated XML attribute name → tag number (e.g., "Sym" → 55)
    pub abbr_to_tag: FxHashMap<String, Tag>,
    /// `MsgType` code → abbreviated XML element name (e.g., "D" → "Order")
    pub msg_type_to_abbr: FxHashMap<String, String>,
    /// Abbreviated XML element name → `MsgType` code (e.g., "Order" → "D")
    pub abbr_to_msg_type: FxHashMap<String, String>,
    /// Component name → abbreviated XML element name (e.g., "Instrument" → "Instrmt")
    pub component_to_abbr: FxHashMap<String, String>,
    /// Abbreviated XML element name → component name (e.g., "Instrmt" → "Instrument")
    pub abbr_to_component: FxHashMap<String, String>,
    /// `MsgType` code → `NotReqXML` flag (true = session message, skip in FIXML)
    pub msg_not_req_xml: FxHashMap<String, bool>,
    /// FIX version string (e.g., "FIX.4.4")
    pub fix_version: String,

    // --- Message structure (from MsgContents.xml) ---

    /// `ComponentID` → ordered list of content entries for that message/component.
    pub contents: FxHashMap<String, Vec<ContentEntry>>,
    /// `MsgType` → `ComponentID` (from `Messages.xml`)
    pub msg_type_to_component_id: FxHashMap<String, String>,
    /// Component name → `ComponentID` (from `Components.xml`)
    pub component_name_to_id: FxHashMap<String, String>,
    /// Component name → `ComponentType` (e.g., "Block", "`BlockRepeating`")
    pub component_type: FxHashMap<String, String>,
    /// Tags that belong to a component (component name → set of tags).
    /// Built by resolving `MsgContents` entries for each component.
    pub component_tags: FxHashMap<String, HashSet<Tag>>,
}

/// A single entry from `MsgContents.xml`.
#[derive(Debug, Clone)]
pub struct ContentEntry {
    /// Either a tag number (field) or a component name.
    pub tag_text: String,
    /// True if `tag_text` is numeric (a field tag), false if it's a component name.
    pub is_field: bool,
    /// Nesting level (0 = top-level, 1+ = inside repeating group).
    pub indent: usize,
    /// Ordering position.
    pub position: usize,
    /// Required flag.
    pub required: bool,
}

impl FixmlAbbreviations {
    /// Build from FIX repository XML files.
    pub fn from_fix_repository(base_path: &str) -> Result<Self, String> {
        let mut abbr = Self::default();

        load_field_abbreviations(&format!("{base_path}/Fields.xml"), &mut abbr)?;
        load_message_abbreviations(&format!("{base_path}/Messages.xml"), &mut abbr)?;
        load_component_abbreviations(&format!("{base_path}/Components.xml"), &mut abbr)?;
        load_msg_contents(&format!("{base_path}/MsgContents.xml"), &mut abbr)?;
        build_component_tags(&mut abbr);

        Ok(abbr)
    }

    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_field(&mut self, tag: Tag, abbr_name: &str) {
        self.tag_to_abbr.insert(tag, abbr_name.to_string());
        self.abbr_to_tag
            .entry(abbr_name.to_string())
            .or_insert(tag);
    }

    pub fn add_message(&mut self, msg_type: &str, abbr_name: &str) {
        self.msg_type_to_abbr
            .insert(msg_type.to_string(), abbr_name.to_string());
        self.abbr_to_msg_type
            .insert(abbr_name.to_string(), msg_type.to_string());
    }

    pub fn add_component(&mut self, component_name: &str, abbr_name: &str) {
        self.component_to_abbr
            .insert(component_name.to_string(), abbr_name.to_string());
        self.abbr_to_component
            .insert(abbr_name.to_string(), component_name.to_string());
    }

    /// Get the ordered component entries for a given `MsgType`.
    pub fn msg_contents(&self, msg_type: &str) -> Option<&Vec<ContentEntry>> {
        let cid = self.msg_type_to_component_id.get(msg_type)?;
        self.contents.get(cid)
    }

    /// Get the ordered entries for a component by name.
    pub fn component_contents(&self, component_name: &str) -> Option<&Vec<ContentEntry>> {
        let cid = self.component_name_to_id.get(component_name)?;
        self.contents.get(cid)
    }

    /// Check if a component is a repeating group (`BlockRepeating`).
    pub fn is_repeating(&self, component_name: &str) -> bool {
        self.component_type
            .get(component_name)
            .is_some_and(|t| t == "BlockRepeating" || t == "ImplicitBlockRepeating")
    }
}

// ---------------------------------------------------------------------------
// Repository XML loaders
// ---------------------------------------------------------------------------

fn parse_xml(path: &str) -> Result<fastxml::XmlDocument, String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("Failed to read {path}: {e}"))?;
    fastxml::parse(content.as_bytes()).map_err(|e| format!("Failed to parse {path}: {e}"))
}

fn child_text(node: &fastxml::XmlNode, name: &str) -> Option<String> {
    node.get_child_elements()
        .into_iter()
        .find(|c| c.get_name() == name)
        .and_then(|c| c.get_content())
}

fn load_field_abbreviations(path: &str, abbr: &mut FixmlAbbreviations) -> Result<(), String> {
    let doc = parse_xml(path)?;
    let root = doc
        .get_root_element()
        .map_err(|e| format!("No root in {path}: {e}"))?;

    for node in root.get_child_elements() {
        if node.get_name() != "Field" {
            continue;
        }
        if let (Some(tag), Some(a)) = (
            child_text(&node, "Tag").and_then(|s| s.parse::<Tag>().ok()),
            child_text(&node, "AbbrName"),
        ) {
            abbr.add_field(tag, &a);
        }
    }
    Ok(())
}

fn load_message_abbreviations(path: &str, abbr: &mut FixmlAbbreviations) -> Result<(), String> {
    let doc = parse_xml(path)?;
    let root = doc
        .get_root_element()
        .map_err(|e| format!("No root in {path}: {e}"))?;

    // Capture FIX version from the root element attributes.
    if let Some(v) = root.get_attribute("version") {
        abbr.fix_version = v;
    }

    for node in root.get_child_elements() {
        if node.get_name() != "Message" {
            continue;
        }
        let msg_type = child_text(&node, "MsgType");
        let abbr_name = child_text(&node, "AbbrName");
        let component_id = child_text(&node, "ComponentID");
        let not_req_xml = child_text(&node, "NotReqXML");

        if let (Some(mt), Some(a)) = (&msg_type, &abbr_name) {
            abbr.add_message(mt, a);
        }
        if let (Some(mt), Some(cid)) = (&msg_type, &component_id) {
            abbr.msg_type_to_component_id
                .insert(mt.clone(), cid.clone());
        }
        if let Some(mt) = &msg_type {
            let is_not_req = not_req_xml.as_deref() == Some("1");
            abbr.msg_not_req_xml.insert(mt.clone(), is_not_req);
        }
    }
    Ok(())
}

fn load_component_abbreviations(path: &str, abbr: &mut FixmlAbbreviations) -> Result<(), String> {
    let doc = parse_xml(path)?;
    let root = doc
        .get_root_element()
        .map_err(|e| format!("No root in {path}: {e}"))?;

    for node in root.get_child_elements() {
        if node.get_name() != "Component" {
            continue;
        }
        let name = child_text(&node, "Name");
        let abbr_name = child_text(&node, "AbbrName");
        let component_id = child_text(&node, "ComponentID");
        let comp_type = child_text(&node, "ComponentType");

        if let (Some(n), Some(a)) = (&name, &abbr_name) {
            abbr.add_component(n, a);
        }
        if let (Some(n), Some(cid)) = (&name, &component_id) {
            abbr.component_name_to_id.insert(n.clone(), cid.clone());
        }
        if let (Some(n), Some(ct)) = (&name, &comp_type) {
            abbr.component_type.insert(n.clone(), ct.clone());
        }
    }
    Ok(())
}

fn load_msg_contents(path: &str, abbr: &mut FixmlAbbreviations) -> Result<(), String> {
    let doc = parse_xml(path)?;
    let root = doc
        .get_root_element()
        .map_err(|e| format!("No root in {path}: {e}"))?;

    for node in root.get_child_elements() {
        if node.get_name() != "MsgContent" {
            continue;
        }
        let Some(cid) = child_text(&node, "ComponentID") else {
            continue;
        };
        let Some(tag_text) = child_text(&node, "TagText") else {
            continue;
        };
        let indent: usize = child_text(&node, "Indent")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let position: usize = child_text(&node, "Position")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let required = child_text(&node, "Reqd").as_deref() == Some("1");
        let is_field = tag_text.chars().next().is_some_and(|c| c.is_ascii_digit());

        abbr.contents.entry(cid).or_default().push(ContentEntry {
            tag_text,
            is_field,
            indent,
            position,
            required,
        });
    }

    // Sort each component's entries by position.
    for entries in abbr.contents.values_mut() {
        entries.sort_by_key(|e| e.position);
    }

    Ok(())
}

/// Build the `component_tags` map: for each component, collect the set of
/// field tags that belong directly to it (Indent=0 fields).
fn build_component_tags(abbr: &mut FixmlAbbreviations) {
    // Clone component_name_to_id to avoid borrow issues.
    let comp_ids: Vec<(String, String)> = abbr
        .component_name_to_id
        .iter()
        .map(|(n, cid)| (n.clone(), cid.clone()))
        .collect();

    for (comp_name, cid) in &comp_ids {
        let mut tags = HashSet::new();
        if let Some(entries) = abbr.contents.get(cid) {
            for entry in entries {
                if entry.is_field
                    && entry.indent == 0
                    && let Ok(tag) = entry.tag_text.parse::<Tag>()
                {
                    tags.insert(tag);
                }
            }
        }
        abbr.component_tags.insert(comp_name.clone(), tags);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manual_abbreviations() {
        let mut abbr = FixmlAbbreviations::new();
        abbr.add_field(55, "Sym");
        abbr.add_field(44, "Px");
        abbr.add_message("D", "Order");
        abbr.add_component("Instrument", "Instrmt");

        assert_eq!(abbr.tag_to_abbr.get(&55).unwrap(), "Sym");
        assert_eq!(abbr.abbr_to_tag.get("Px").unwrap(), &44);
        assert_eq!(abbr.msg_type_to_abbr.get("D").unwrap(), "Order");
        assert_eq!(abbr.abbr_to_msg_type.get("Order").unwrap(), "D");
        assert_eq!(abbr.component_to_abbr.get("Instrument").unwrap(), "Instrmt");
        assert_eq!(abbr.abbr_to_component.get("Instrmt").unwrap(), "Instrument");
    }

    #[test]
    fn test_load_from_fix_repository() {
        let base = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../karunatmp/fix_repository_2010_edition_20200402/FIX.4.4/Base"
        );
        if !std::path::Path::new(&format!("{base}/Fields.xml")).exists() {
            return;
        }

        let abbr = FixmlAbbreviations::from_fix_repository(base).unwrap();

        // Field abbreviations
        assert_eq!(abbr.tag_to_abbr.get(&55).unwrap(), "Sym");
        assert_eq!(abbr.tag_to_abbr.get(&44).unwrap(), "Px");
        assert_eq!(abbr.tag_to_abbr.get(&1).unwrap(), "Acct");
        assert_eq!(abbr.abbr_to_tag.get("Sym").unwrap(), &55);

        // Message abbreviations
        assert_eq!(abbr.msg_type_to_abbr.get("D").unwrap(), "Order");
        assert_eq!(abbr.msg_type_to_abbr.get("8").unwrap(), "ExecRpt");

        // Component abbreviations
        assert_eq!(
            abbr.component_to_abbr.get("Instrument").unwrap(),
            "Instrmt"
        );
        assert_eq!(abbr.component_to_abbr.get("Parties").unwrap(), "Pty");

        // MsgContents structure
        let contents = abbr.msg_contents("D").unwrap();
        assert!(!contents.is_empty());
        // First entry should be StandardHeader
        assert_eq!(contents[0].tag_text, "StandardHeader");
        assert!(!contents[0].is_field);

        // Instrument component should have tag 55
        let instrmt_tags = abbr.component_tags.get("Instrument").unwrap();
        assert!(instrmt_tags.contains(&55));
        assert!(instrmt_tags.contains(&48)); // SecurityID

        // Parties should be repeating
        assert!(abbr.is_repeating("Parties"));
        assert!(!abbr.is_repeating("Instrument"));

        // NotReqXML
        assert!(abbr.msg_not_req_xml.get("0") == Some(&true)); // Heartbeat
        assert!(abbr.msg_not_req_xml.get("D") == Some(&false)); // NewOrderSingle

        // Version
        assert_eq!(abbr.fix_version, "FIX.4.4");
    }
}
