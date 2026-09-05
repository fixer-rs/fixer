use crate::tag::Tag;
use rustc_hash::FxHashMap;
use std::collections::HashSet;
use std::fmt::Write as _;

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
    /// Every tag reachable from a component, including through its
    /// sub-components. Used to find where a repeating group's run of fields
    /// ends when walking a flattened message.
    pub component_all_tags: FxHashMap<String, HashSet<Tag>>,
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

    /// Loads the abbreviations bundled with the crate for a FIX version.
    ///
    /// Supported versions are `FIX.4.4`, `FIX.5.0`, `FIX.5.0SP1`,
    /// `FIX.5.0SP2` and `FIXT.1.1` — the FIX repository defines the
    /// `AbbrName` values FIXML is built on only from FIX.4.4 onward.
    ///
    /// The FIX repository these are derived from is not redistributable in
    /// full and is ~7 MB of XML per edition, so the fields FIXML actually
    /// needs are extracted into a compact table under `spec/fixml/` and
    /// embedded here. Use [`from_fix_repository`](Self::from_fix_repository)
    /// to load a repository edition this crate does not bundle.
    pub fn bundled(version: &str) -> Result<Self, String> {
        let raw = match version {
            "FIX.4.4" => include_str!("../../../../spec/fixml/FIX.4.4.tsv"),
            "FIX.5.0" => include_str!("../../../../spec/fixml/FIX.5.0.tsv"),
            "FIX.5.0SP1" => include_str!("../../../../spec/fixml/FIX.5.0SP1.tsv"),
            "FIX.5.0SP2" => include_str!("../../../../spec/fixml/FIX.5.0SP2.tsv"),
            "FIXT.1.1" => include_str!("../../../../spec/fixml/FIXT.1.1.tsv"),
            "FIX.4.0" | "FIX.4.1" | "FIX.4.2" | "FIX.4.3" => {
                return Err(format!(
                    "{version} has no FIXML abbreviations: the FIX repository \
                     only defines AbbrName from FIX.4.4 onward"
                ));
            }
            other => return Err(format!("no bundled FIXML abbreviations for {other}")),
        };
        Self::from_compact(raw)
    }

    /// Serializes the primary data to the compact table format read by
    /// [`from_compact`](Self::from_compact).
    ///
    /// Only the data loaded from the repository is written; the reverse
    /// lookups and `component_tags` are rebuilt on load.
    pub fn to_compact(&self) -> String {
        let mut out = String::new();
        out.push_str("V\t");
        out.push_str(&self.fix_version);
        out.push('\n');

        let mut fields: Vec<(&Tag, &String)> = self.tag_to_abbr.iter().collect();
        fields.sort_by_key(|(t, _)| **t);
        for (tag, abbr) in fields {
            let _ = writeln!(out, "F\t{tag}\t{abbr}");
        }

        let mut msg_types: Vec<&String> = self
            .msg_not_req_xml
            .keys()
            .chain(self.msg_type_to_abbr.keys())
            .chain(self.msg_type_to_component_id.keys())
            .collect();
        msg_types.sort();
        msg_types.dedup();
        for mt in msg_types {
            let abbr = self.msg_type_to_abbr.get(mt).cloned().unwrap_or_default();
            let cid = self
                .msg_type_to_component_id
                .get(mt)
                .cloned()
                .unwrap_or_default();
            let nr = u8::from(*self.msg_not_req_xml.get(mt).unwrap_or(&false));
            let _ = writeln!(out, "M\t{mt}\t{abbr}\t{cid}\t{nr}");
        }

        let mut comps: Vec<&String> = self
            .component_name_to_id
            .keys()
            .chain(self.component_to_abbr.keys())
            .chain(self.component_type.keys())
            .collect();
        comps.sort();
        comps.dedup();
        for name in comps {
            let abbr = self.component_to_abbr.get(name).cloned().unwrap_or_default();
            let cid = self
                .component_name_to_id
                .get(name)
                .cloned()
                .unwrap_or_default();
            let ct = self.component_type.get(name).cloned().unwrap_or_default();
            let _ = writeln!(out, "C\t{name}\t{abbr}\t{cid}\t{ct}");
        }

        let mut cids: Vec<&String> = self.contents.keys().collect();
        cids.sort();
        for cid in cids {
            for e in &self.contents[cid] {
                let reqd = u8::from(e.required);
                let _ = writeln!(
                    out,
                    "X\t{cid}\t{}\t{}\t{}\t{reqd}",
                    e.tag_text, e.indent, e.position
                );
            }
        }

        out
    }

    /// Parses the compact table format written by
    /// [`to_compact`](Self::to_compact).
    pub fn from_compact(raw: &str) -> Result<Self, String> {
        let mut abbr = Self::default();

        for (n, line) in raw.lines().enumerate() {
            if line.is_empty() {
                continue;
            }
            let f: Vec<&str> = line.split('\t').collect();
            let bad = || format!("malformed FIXML abbreviation table at line {}", n + 1);
            match f[0] {
                "V" if f.len() == 2 => abbr.fix_version = f[1].to_string(),
                "F" if f.len() == 3 => {
                    let tag: Tag = f[1].parse().map_err(|_| bad())?;
                    abbr.add_field(tag, f[2]);
                }
                "M" if f.len() == 5 => {
                    if !f[2].is_empty() {
                        abbr.add_message(f[1], f[2]);
                    }
                    if !f[3].is_empty() {
                        abbr.msg_type_to_component_id
                            .insert(f[1].to_string(), f[3].to_string());
                    }
                    abbr.msg_not_req_xml.insert(f[1].to_string(), f[4] == "1");
                }
                "C" if f.len() == 5 => {
                    if !f[2].is_empty() {
                        abbr.add_component(f[1], f[2]);
                    }
                    if !f[3].is_empty() {
                        abbr.component_name_to_id
                            .insert(f[1].to_string(), f[3].to_string());
                    }
                    if !f[4].is_empty() {
                        abbr.component_type
                            .insert(f[1].to_string(), f[4].to_string());
                    }
                }
                "X" if f.len() == 6 => {
                    let entry = ContentEntry {
                        tag_text: f[2].to_string(),
                        is_field: f[2].parse::<Tag>().is_ok(),
                        indent: f[3].parse().map_err(|_| bad())?,
                        position: f[4].parse().map_err(|_| bad())?,
                        required: f[5] == "1",
                    };
                    abbr.contents.entry(f[1].to_string()).or_default().push(entry);
                }
                _ => return Err(bad()),
            }
        }

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
    /// The nesting level a component's own members sit at.
    ///
    /// A repeating group puts its `NumInGroup` counter at level 0 and its
    /// members at level 1; a plain block has its fields at level 0.
    pub fn member_indent(&self, component_name: &str) -> usize {
        usize::from(self.is_repeating(component_name))
    }

    /// The `NumInGroup` tag of a repeating component, i.e. its single
    /// level-0 field entry.
    pub fn group_counter_tag(&self, component_name: &str) -> Option<Tag> {
        if !self.is_repeating(component_name) {
            return None;
        }
        self.component_contents(component_name)?
            .iter()
            .find(|e| e.is_field && e.indent == 0)
            .and_then(|e| e.tag_text.parse::<Tag>().ok())
    }

    /// The component's own field tags, in repository order.
    ///
    /// Order matters: the first is a repeating group's delimiter, and it also
    /// keeps generated XML attribute order stable.
    pub fn member_fields(&self, component_name: &str) -> Vec<Tag> {
        let indent = self.member_indent(component_name);
        self.component_contents(component_name)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|e| e.is_field && e.indent == indent)
                    .filter_map(|e| e.tag_text.parse::<Tag>().ok())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The component's own sub-components, in repository order.
    pub fn member_components(&self, component_name: &str) -> Vec<String> {
        let indent = self.member_indent(component_name);
        self.component_contents(component_name)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|e| !e.is_field && e.indent == indent)
                    .map(|e| e.tag_text.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

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
/// Every tag reachable from `component`, following sub-components.
fn collect_all_tags(
    abbr: &FixmlAbbreviations,
    component: &str,
    seen: &mut HashSet<String>,
    out: &mut HashSet<Tag>,
) {
    if !seen.insert(component.to_string()) {
        return;
    }
    if let Some(entries) = abbr.component_contents(component) {
        for entry in entries {
            if entry.is_field {
                if let Ok(tag) = entry.tag_text.parse::<Tag>() {
                    out.insert(tag);
                }
            } else {
                collect_all_tags(abbr, &entry.tag_text, seen, out);
            }
        }
    }
}

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

    for (comp_name, _) in &comp_ids {
        let mut all = HashSet::new();
        collect_all_tags(abbr, comp_name, &mut HashSet::new(), &mut all);
        abbr.component_all_tags.insert(comp_name.clone(), all);
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

    /// The bundled tables are the only abbreviation source most users have, so
    /// this must exercise them directly rather than skipping when the FIX
    /// repository is absent.
    #[test]
    fn test_bundled_fix44() {
        let abbr = FixmlAbbreviations::bundled("FIX.4.4").unwrap();

        assert_eq!(abbr.tag_to_abbr.get(&55).unwrap(), "Sym");
        assert_eq!(abbr.tag_to_abbr.get(&44).unwrap(), "Px");
        assert_eq!(abbr.tag_to_abbr.get(&1).unwrap(), "Acct");
        assert_eq!(abbr.abbr_to_tag.get("Sym").unwrap(), &55);

        assert_eq!(abbr.msg_type_to_abbr.get("D").unwrap(), "Order");
        assert_eq!(abbr.msg_type_to_abbr.get("8").unwrap(), "ExecRpt");

        assert_eq!(abbr.component_to_abbr.get("Instrument").unwrap(), "Instrmt");
        assert_eq!(abbr.component_to_abbr.get("Parties").unwrap(), "Pty");

        let contents = abbr.msg_contents("D").unwrap();
        assert!(!contents.is_empty());
        assert_eq!(contents[0].tag_text, "StandardHeader");
        assert!(!contents[0].is_field);

        let instrmt_tags = abbr.component_tags.get("Instrument").unwrap();
        assert!(instrmt_tags.contains(&55));
        assert!(instrmt_tags.contains(&48));

        assert!(abbr.is_repeating("Parties"));
        assert!(!abbr.is_repeating("Instrument"));

        assert_eq!(abbr.msg_not_req_xml.get("0"), Some(&true)); // Heartbeat
        assert_eq!(abbr.msg_not_req_xml.get("D"), Some(&false)); // NewOrderSingle

        assert_eq!(abbr.fix_version, "FIX.4.4");
    }

    #[test]
    fn test_bundled_all_versions() {
        for version in [
            "FIX.4.4",
            "FIX.5.0",
            "FIX.5.0SP1",
            "FIX.5.0SP2",
            "FIXT.1.1",
        ] {
            let abbr = FixmlAbbreviations::bundled(version)
                .unwrap_or_else(|e| panic!("{version}: {e}"));
            assert_eq!(abbr.fix_version, version);
            assert!(!abbr.tag_to_abbr.is_empty(), "{version} has no fields");
            assert!(!abbr.contents.is_empty(), "{version} has no contents");
        }
    }

    #[test]
    fn test_bundled_rejects_versions_without_abbreviations() {
        // The repository defines AbbrName only from FIX.4.4 onward; bundling a
        // table for these would silently fall back to numeric attribute names.
        for version in ["FIX.4.0", "FIX.4.1", "FIX.4.2", "FIX.4.3"] {
            let err = FixmlAbbreviations::bundled(version).unwrap_err();
            assert!(err.contains("FIX.4.4"), "unexpected error: {err}");
        }
        assert!(FixmlAbbreviations::bundled("FIX.9.9").is_err());
    }

    #[test]
    fn test_compact_round_trip() {
        let abbr = FixmlAbbreviations::bundled("FIX.4.4").unwrap();
        let once = abbr.to_compact();
        let reparsed = FixmlAbbreviations::from_compact(&once).unwrap();
        assert_eq!(once, reparsed.to_compact());
    }

    /// Keeps the vendored tables honest: when the repository is available they
    /// must reproduce exactly what is checked in. Regenerate with
    /// `make fixml-abbr FIX_REPOSITORY=...`.
    #[test]
    fn test_bundled_matches_fix_repository() {
        let repo = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../karunatmp/fix_repository_2010_edition_20200402"
        );
        for version in [
            "FIX.4.4",
            "FIX.5.0",
            "FIX.5.0SP1",
            "FIX.5.0SP2",
            "FIXT.1.1",
        ] {
            let base = format!("{repo}/{version}/Base");
            if !std::path::Path::new(&format!("{base}/Fields.xml")).exists() {
                continue;
            }
            let from_repo = FixmlAbbreviations::from_fix_repository(&base).unwrap();
            let bundled = FixmlAbbreviations::bundled(version).unwrap();
            assert_eq!(
                from_repo.to_compact(),
                bundled.to_compact(),
                "{version}: spec/fixml is stale, regenerate it"
            );
        }
    }
}
