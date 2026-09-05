use std::fs;
use std::path::Path;

use fixer::datadictionary::{DataDictionary, FieldDef};
use heck::{ToSnakeCase, ToShoutySnakeCase};
use rustc_hash::FxHashSet;
use serde::Serialize;
use tera::{Context, Tera};

use crate::globals::GlobalFieldTypes;
use crate::helpers::{
    begin_string, fixer_type, package_name, required_fields, router_begin_string,
    transport_package_name, FixerType,
};

/// Ensure an identifier doesn't start with a digit (invalid in Rust).
fn sanitize_ident(name: &str) -> String {
    if name.starts_with(|c: char| c.is_ascii_digit()) {
        format!("_{name}")
    } else {
        name.to_string()
    }
}

#[derive(Serialize)]
struct TagField {
    const_name: String,
    tag: isize,
}

#[derive(Serialize)]
struct EnumValue {
    const_name: String,
    value: String,
}

#[derive(Serialize)]
struct EnumField {
    name: String,
    mod_name: String,
    enums: Vec<EnumValue>,
}

#[derive(Serialize)]
struct FieldInfo {
    name: String,
    const_name: String,
    tag: isize,
    fix_type: String,
    fixer_type: String,
}

/// Generate `tag.rs` — all tag constants sorted by name.
pub fn generate_tags(tera: &Tera, global_types: &GlobalFieldTypes, output_dir: &Path) {
    let mut fields: Vec<TagField> = global_types
        .types
        .iter()
        .map(|ft| TagField {
            const_name: ft.name.to_shouty_snake_case(),
            tag: ft.tag,
        })
        .collect();
    fields.sort_by(|a, b| a.const_name.cmp(&b.const_name));

    let mut context = Context::new();
    context.insert("fields", &fields);

    let rendered = tera
        .render("tag.rs.tera", &context)
        .expect("Failed to render tag.rs");

    let out_path = output_dir.join("tag.rs");
    fs::write(&out_path, rendered).unwrap_or_else(|e| panic!("Failed to write {}: {e}", out_path.display()));
}

/// Generate `enums.rs` — enum sub-modules with `&str` constants.
///
/// Only generates enums for fields that have enum values and are not booleans.
pub fn generate_enums(
    tera: &Tera,
    global_types: &GlobalFieldTypes,
    use_float: bool,
    output_dir: &Path,
) {
    let mut fields: Vec<EnumField> = global_types
        .types
        .iter()
        .filter(|ft| {
            if ft.enums.is_empty() {
                return false;
            }
            // Exclude booleans — they have Y/N enums but we don't generate them.
            match fixer_type(&ft.fix_type, use_float) {
                Ok(t) => t != FixerType::FIXBoolean,
                Err(_) => false,
            }
        })
        .map(|ft| {
            let mut enums: Vec<EnumValue> = ft
                .enums
                .values()
                .map(|e| EnumValue {
                    const_name: sanitize_ident(&e.description.to_shouty_snake_case()),
                    value: e.value.clone(),
                })
                .collect();
            enums.sort_by(|a, b| a.const_name.cmp(&b.const_name));

            EnumField {
                name: ft.name.clone(),
                mod_name: ft.name.to_snake_case(),
                enums,
            }
        })
        .collect();
    fields.sort_by(|a, b| a.mod_name.cmp(&b.mod_name));

    let mut context = Context::new();
    context.insert("fields", &fields);

    let rendered = tera
        .render("enums.rs.tera", &context)
        .expect("Failed to render enums.rs");

    let out_path = output_dir.join("enums.rs");
    fs::write(&out_path, rendered)
        .unwrap_or_else(|e| panic!("Failed to write {}: {e}", out_path.display()));
}

/// Generate `field.rs` — typed field wrapper structs for all global fields.
pub fn generate_fields(
    tera: &Tera,
    global_types: &GlobalFieldTypes,
    use_float: bool,
    output_dir: &Path,
) {
    let mut has_decimal = false;
    let mut has_timestamp = false;

    let mut fields: Vec<FieldInfo> = global_types
        .types
        .iter()
        .filter_map(|ft| {
            let ft_enum = fixer_type(&ft.fix_type, use_float).ok()?;
            if ft_enum == FixerType::FIXDecimal {
                has_decimal = true;
            }
            if ft_enum == FixerType::FIXUTCTimestamp {
                has_timestamp = true;
            }
            Some(FieldInfo {
                name: ft.name.clone(),
                const_name: ft.name.to_shouty_snake_case(),
                tag: ft.tag,
                fix_type: ft.fix_type.clone(),
                fixer_type: ft_enum.as_str().to_string(),
            })
        })
        .collect();
    fields.sort_by(|a, b| a.name.cmp(&b.name));

    let mut context = Context::new();
    context.insert("fields", &fields);
    context.insert("needs_decimal", &has_decimal);
    context.insert("needs_timestamp", &has_timestamp);

    let rendered = tera
        .render("field.rs.tera", &context)
        .expect("Failed to render field.rs");

    let out_path = output_dir.join("field.rs");
    fs::write(&out_path, rendered)
        .unwrap_or_else(|e| panic!("Failed to write {}: {e}", out_path.display()));
}

/// Field info for message/header/trailer templates.
#[derive(Serialize)]
struct MessageFieldInfo {
    name: String,
    snake_name: String,
    const_name: String,
    tag: isize,
    fixer_type: String,
    is_group: bool,
    /// For group fields, the generated element type name (e.g. `NoOrders`).
    /// Empty for ordinary fields.
    group_type: String,
}

/// A repeating group to generate types for.
///
/// One is emitted per group occurrence, including nested groups, so the member
/// set always matches the position the group appears in.
#[derive(Serialize)]
struct GroupInfo {
    name: String,
    /// Element type name, unique within the generated module.
    type_name: String,
    const_name: String,
    tag: isize,
    /// Members in FIX declaration order. The first is the group delimiter, so
    /// this order is load-bearing and must not be sorted.
    fields: Vec<MessageFieldInfo>,
}

/// Info about a message for the mod.rs template.
#[derive(Serialize)]
struct MessageModInfo {
    mod_name: String,
}

fn build_field_info(fd: &FieldDef, global_types: &GlobalFieldTypes, use_float: bool) -> Option<MessageFieldInfo> {
    let gft = global_types.by_name.get(fd.name())?;
    let ft = fixer_type(&gft.fix_type, use_float).ok()?;
    Some(MessageFieldInfo {
        name: fd.name().to_string(),
        snake_name: fd.name().to_snake_case(),
        const_name: fd.name().to_shouty_snake_case(),
        tag: fd.tag(),
        fixer_type: ft.as_str().to_string(),
        is_group: fd.is_group(),
        group_type: String::new(),
    })
}

/// Walks `fds`, collecting a `GroupInfo` for every repeating group reachable
/// from them, and returns the field infos with `group_type` filled in.
///
/// Nested group type names are qualified by their enclosing group
/// (`NoOrders` -> `NoOrdersNoAllocs`) so every type is unique within the
/// module; `used` guards against a collision between two distinct paths.
fn collect_fields_and_groups<'a, I>(
    fds: I,
    prefix: &str,
    global_types: &GlobalFieldTypes,
    use_float: bool,
    groups: &mut Vec<GroupInfo>,
    used: &mut FxHashSet<String>,
) -> Vec<MessageFieldInfo>
where
    I: IntoIterator<Item = &'a FieldDef>,
{
    let mut infos = Vec::new();

    for fd in fds {
        let Some(mut info) = build_field_info(fd, global_types, use_float) else {
            continue;
        };

        if fd.is_group() {
            let mut type_name = format!("{prefix}{}", fd.name());
            let mut n = 2;
            while !used.insert(type_name.clone()) {
                type_name = format!("{prefix}{}{n}", fd.name());
                n += 1;
            }

            // Declaration order matters: the first member is the delimiter.
            let members = collect_fields_and_groups(
                &fd.fields,
                &type_name,
                global_types,
                use_float,
                groups,
                used,
            );

            groups.push(GroupInfo {
                name: fd.name().to_string(),
                const_name: fd.name().to_shouty_snake_case(),
                tag: fd.tag(),
                fields: members,
                type_name: type_name.clone(),
            });

            info.group_type = type_name;
        }

        infos.push(info);
    }

    infos
}

/// True if any field in `fields` or in `groups`' members needs the given type.
fn any_fixer_type(fields: &[MessageFieldInfo], groups: &[GroupInfo], want: &str) -> bool {
    fields.iter().any(|f| f.fixer_type == want)
        || groups
            .iter()
            .any(|g| g.fields.iter().any(|f| f.fixer_type == want))
}

/// Generate `header.rs` for a FIX version package.
pub fn generate_header(
    tera: &Tera,
    spec: &DataDictionary,
    global_types: &GlobalFieldTypes,
    use_float: bool,
    output_dir: &Path,
) {
    let mut groups = Vec::new();
    let mut used = FxHashSet::default();
    let mut by_name: Vec<&FieldDef> = spec.header.fields.values().collect();
    by_name.sort_by_key(|fd| fd.name());
    let mut sorted = collect_fields_and_groups(
        by_name,
        "",
        global_types,
        use_float,
        &mut groups,
        &mut used,
    );
    sorted.sort_by(|a, b| a.name.cmp(&b.name));

    let mut context = Context::new();
    context.insert("package", &package_name(spec));
    context.insert("begin_string", &begin_string(spec));
    context.insert("fields", &sorted);
    context.insert("groups", &groups);
    context.insert(
        "needs_decimal",
        &any_fixer_type(&sorted, &groups, "FIXDecimal"),
    );
    context.insert(
        "needs_timestamp",
        &any_fixer_type(&sorted, &groups, "FIXUTCTimestamp"),
    );

    let rendered = tera
        .render("header.rs.tera", &context)
        .expect("Failed to render header.rs");

    let out_path = output_dir.join("header.rs");
    fs::write(&out_path, rendered)
        .unwrap_or_else(|e| panic!("Failed to write {}: {e}", out_path.display()));
}

/// Generate `trailer.rs` for a FIX version package.
pub fn generate_trailer(
    tera: &Tera,
    spec: &DataDictionary,
    global_types: &GlobalFieldTypes,
    use_float: bool,
    output_dir: &Path,
) {
    let fields: Vec<MessageFieldInfo> = spec
        .trailer
        .fields
        .values()
        .filter_map(|fd| build_field_info(fd, global_types, use_float))
        .collect();

    let mut sorted = fields;
    sorted.sort_by(|a, b| a.name.cmp(&b.name));

    let mut context = Context::new();
    context.insert("package", &package_name(spec));
    context.insert("fields", &sorted);

    let rendered = tera
        .render("trailer.rs.tera", &context)
        .expect("Failed to render trailer.rs");

    let out_path = output_dir.join("trailer.rs");
    fs::write(&out_path, rendered)
        .unwrap_or_else(|e| panic!("Failed to write {}: {e}", out_path.display()));
}

/// Generate a single message file (e.g. `new_order_single.rs`).
pub fn generate_message(
    tera: &Tera,
    spec: &DataDictionary,
    msg_type: &str,
    global_types: &GlobalFieldTypes,
    use_float: bool,
    output_dir: &Path,
) {
    let msg_def = spec
        .messages
        .get(msg_type)
        .unwrap_or_else(|| panic!("Message type '{msg_type}' not found in spec"));

    let mut groups = Vec::new();
    let mut used = FxHashSet::default();
    // Sort by name first so the generated accessors, and the group type names
    // derived from them, are stable across runs (msg_def.fields is a hash map).
    let mut by_name: Vec<&FieldDef> = msg_def.fields.values().collect();
    by_name.sort_by_key(|fd| fd.name());
    let mut sorted = collect_fields_and_groups(
        by_name,
        "",
        global_types,
        use_float,
        &mut groups,
        &mut used,
    );
    sorted.sort_by(|a, b| a.name.cmp(&b.name));

    let req = required_fields(msg_def);
    let required: Vec<MessageFieldInfo> = req
        .iter()
        .filter_map(|fd| build_field_info(fd, global_types, use_float))
        .collect();

    let has_decimal = any_fixer_type(&sorted, &groups, "FIXDecimal");
    let has_timestamp = any_fixer_type(&sorted, &groups, "FIXUTCTimestamp");

    let mut context = Context::new();
    context.insert("name", &msg_def.name);
    context.insert("fix_package", &package_name(spec));
    context.insert("msg_type", msg_type);
    context.insert("router_begin_string", &router_begin_string(spec));
    context.insert("fields", &sorted);
    context.insert("groups", &groups);
    context.insert("required_fields", &required);
    context.insert("needs_decimal", &has_decimal);
    context.insert("needs_timestamp", &has_timestamp);

    let rendered = tera
        .render("message.rs.tera", &context)
        .expect("Failed to render message.rs");

    let file_name = format!("{}.rs", msg_def.name.to_snake_case());
    let out_path = output_dir.join(&file_name);
    fs::write(&out_path, rendered)
        .unwrap_or_else(|e| panic!("Failed to write {}: {e}", out_path.display()));
}

/// Generate all files for a single FIX version package.
///
/// Creates a directory (e.g. `fix44/`) containing `mod.rs`, `header.rs`,
/// `trailer.rs`, and one file per message.
pub fn generate_package(
    tera: &Tera,
    spec: &DataDictionary,
    global_types: &GlobalFieldTypes,
    use_float: bool,
    output_dir: &Path,
) {
    let pkg = package_name(spec);
    let pkg_dir = output_dir.join(&pkg);
    fs::create_dir_all(&pkg_dir)
        .unwrap_or_else(|e| panic!("Failed to create {}: {e}", pkg_dir.display()));

    // Determine if this package owns its header/trailer.
    // FIX 5.0+ uses fixt11's header/trailer, so only generate if
    // this package IS the transport package.
    let transport_pkg = transport_package_name(spec);
    let has_header = transport_pkg == pkg;

    if has_header {
        generate_header(tera, spec, global_types, use_float, &pkg_dir);
        generate_trailer(tera, spec, global_types, use_float, &pkg_dir);
    }

    // Generate each message.
    let mut messages: Vec<MessageModInfo> = Vec::new();
    for msg_type in spec.messages.keys() {
        let msg_def = &spec.messages[msg_type];
        let mod_name = msg_def.name.to_snake_case();
        generate_message(tera, spec, msg_type, global_types, use_float, &pkg_dir);
        messages.push(MessageModInfo { mod_name });
    }
    messages.sort_by(|a, b| a.mod_name.cmp(&b.mod_name));

    // Generate mod.rs.
    let mut context = Context::new();
    context.insert("has_header", &has_header);
    context.insert("messages", &messages);

    let rendered = tera
        .render("mod.rs.tera", &context)
        .expect("Failed to render mod.rs");

    let out_path = pkg_dir.join("mod.rs");
    fs::write(&out_path, rendered)
        .unwrap_or_else(|e| panic!("Failed to write {}: {e}", out_path.display()));
}

/// Generate root `lib.rs` listing all version packages.
pub fn generate_lib_rs(tera: &Tera, packages: &[String], output_dir: &Path) {
    let mut sorted = packages.to_vec();
    sorted.sort();

    let mut context = Context::new();
    context.insert("packages", &sorted);

    let rendered = tera
        .render("lib.rs.tera", &context)
        .expect("Failed to render lib.rs");

    let out_path = output_dir.join("lib.rs");
    fs::write(&out_path, rendered)
        .unwrap_or_else(|e| panic!("Failed to write {}: {e}", out_path.display()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::globals::build_global_field_types;
    use fixer::datadictionary::DataDictionary;
    use tokio::runtime::Runtime;

    fn parse_spec(path: &str) -> DataDictionary {
        Runtime::new()
            .unwrap()
            .block_on(DataDictionary::parse(path))
            .unwrap()
    }

    fn test_tera() -> Tera {
        crate::build_tera()
    }

    #[test]
    fn test_generate_tags() {
        let fix44 = parse_spec("../spec/FIX44.xml");
        let globals = build_global_field_types(&[fix44]);
        let tera = test_tera();

        let tmp = tempfile::tempdir().unwrap();
        generate_tags(&tera, &globals, tmp.path());

        let content = fs::read_to_string(tmp.path().join("tag.rs")).unwrap();

        // Should have the header.
        assert!(content.contains("// Code generated by fixer-gen. DO NOT EDIT."));
        assert!(content.contains("use fixer::tag::Tag;"));

        // Should contain known tags in SCREAMING_SNAKE_CASE.
        assert!(content.contains("pub const ACCOUNT: Tag = 1;"));
        assert!(content.contains("pub const MSG_TYPE: Tag = 35;"));
        assert!(content.contains("pub const SENDER_COMP_ID: Tag = 49;"));
        assert!(content.contains("pub const TARGET_COMP_ID: Tag = 56;"));
        assert!(content.contains("pub const BEGIN_STRING: Tag = 8;"));

        // Should NOT contain lowercase or PascalCase.
        assert!(!content.contains("pub const Account:"));
        assert!(!content.contains("pub const MsgType:"));

        // All lines with "pub const" should have the right format.
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("pub const ") {
                assert!(
                    trimmed.ends_with(';'),
                    "Tag line should end with semicolon: {trimmed}"
                );
                assert!(
                    trimmed.contains(": Tag = "),
                    "Tag line should have ': Tag = ': {trimmed}"
                );
            }
        }
    }

    #[test]
    fn test_generate_tags_multiple_specs() {
        let fix40 = parse_spec("../spec/FIX40.xml");
        let fix44 = parse_spec("../spec/FIX44.xml");
        let fix50sp2 = parse_spec("../spec/FIX50SP2.xml");
        let globals = build_global_field_types(&[fix40, fix44, fix50sp2]);
        let tera = test_tera();

        let tmp = tempfile::tempdir().unwrap();
        generate_tags(&tera, &globals, tmp.path());

        let content = fs::read_to_string(tmp.path().join("tag.rs")).unwrap();

        // Count tag lines — should be large with multiple specs.
        let tag_count = content
            .lines()
            .filter(|l| l.trim().starts_with("pub const "))
            .count();
        assert!(
            tag_count > 100,
            "Expected >100 tags from multiple specs, got {tag_count}"
        );

        // Tags should be sorted alphabetically.
        let names: Vec<&str> = content
            .lines()
            .filter_map(|l| {
                let trimmed = l.trim();
                if trimmed.starts_with("pub const ") {
                    Some(trimmed.split(':').next().unwrap().trim_start_matches("pub const "))
                } else {
                    None
                }
            })
            .collect();
        for w in names.windows(2) {
            assert!(w[0] <= w[1], "Tags not sorted: {} > {}", w[0], w[1]);
        }
    }

    #[test]
    fn test_generate_enums() {
        let fix44 = parse_spec("../spec/FIX44.xml");
        let globals = build_global_field_types(&[fix44]);
        let tera = test_tera();

        let tmp = tempfile::tempdir().unwrap();
        generate_enums(&tera, &globals, false, tmp.path());

        let content = fs::read_to_string(tmp.path().join("enums.rs")).unwrap();

        // Should have the header.
        assert!(content.contains("// Code generated by fixer-gen. DO NOT EDIT."));

        // Should contain known enum modules.
        assert!(content.contains("pub mod adv_side {"), "Should have adv_side module");
        assert!(content.contains("pub mod ord_type {"), "Should have ord_type module");

        // Should have enum constants inside modules.
        assert!(content.contains(r#"pub const BUY: &str = "B";"#));
        assert!(content.contains(r#"pub const SELL: &str = "S";"#));

        // Should NOT contain boolean fields (PossDupFlag is BOOLEAN with Y/N enums).
        assert!(
            !content.contains("pub mod poss_dup_flag"),
            "Boolean fields should be excluded"
        );

        // Modules should be sorted.
        let mod_names: Vec<&str> = content
            .lines()
            .filter_map(|l| {
                let trimmed = l.trim();
                trimmed
                    .strip_prefix("pub mod ")
                    .and_then(|s| s.strip_suffix(" {"))
            })
            .collect();
        for w in mod_names.windows(2) {
            assert!(w[0] <= w[1], "Enum modules not sorted: {} > {}", w[0], w[1]);
        }
    }

    #[test]
    fn test_generate_fields() {
        let fix44 = parse_spec("../spec/FIX44.xml");
        let globals = build_global_field_types(&[fix44]);
        let tera = test_tera();

        let tmp = tempfile::tempdir().unwrap();
        generate_fields(&tera, &globals, false, tmp.path());

        let content = fs::read_to_string(tmp.path().join("field.rs")).unwrap();

        // Should have the header.
        assert!(content.contains("// Code generated by fixer-gen. DO NOT EDIT."));

        // Should have field wrapper structs.
        assert!(content.contains("pub struct AccountField(pub FIXString)"));
        assert!(content.contains("pub struct SideField(pub FIXString)"));
        assert!(content.contains("pub struct PriceField(pub FIXDecimal)"));

        // Should have new/value methods.
        assert!(content.contains("pub fn new(val: String) -> Self"));
        assert!(content.contains("pub fn value(&self) -> &str"));

        // Should have FieldValueReader/Writer impls.
        assert!(content.contains("impl FieldValueReader for AccountField"));
        assert!(content.contains("impl FieldValueWriter for AccountField"));
        assert!(content.contains("impl FieldValue for AccountField"));

        // Should have tag() method referencing SCREAMING_SNAKE_CASE.
        assert!(content.contains("pub fn tag() -> Tag { tag::ACCOUNT }"));

        // Should have decimal imports since FIX44 has decimal fields.
        assert!(content.contains("use rust_decimal::Decimal;"));

        // Should have timestamp imports since FIX44 has timestamp fields.
        assert!(content.contains("use jiff::Timestamp;"));

        // Fields should be sorted by name (without "Field" suffix).
        let field_names: Vec<&str> = content
            .lines()
            .filter_map(|l| {
                let trimmed = l.trim();
                trimmed
                    .strip_prefix("pub struct ")
                    .and_then(|s| s.split("Field(").next())
            })
            .collect();
        for w in field_names.windows(2) {
            assert!(w[0] <= w[1], "Fields not sorted: {} > {}", w[0], w[1]);
        }
    }

    #[test]
    fn test_generate_fields_use_float() {
        let fix44 = parse_spec("../spec/FIX44.xml");
        let globals = build_global_field_types(&[fix44]);
        let tera = test_tera();

        let tmp = tempfile::tempdir().unwrap();
        generate_fields(&tera, &globals, true, tmp.path());

        let content = fs::read_to_string(tmp.path().join("field.rs")).unwrap();

        // With use_float=true, Price should be FIXFloat, not FIXDecimal.
        assert!(content.contains("pub struct PriceField(pub FIXFloat)"));
        assert!(!content.contains("pub struct PriceField(pub FIXDecimal)"));

        // Should NOT have decimal imports.
        assert!(!content.contains("use rust_decimal::Decimal;"));
    }

    #[test]
    fn test_generate_enums_multiple_specs() {
        let fix42 = parse_spec("../spec/FIX42.xml");
        let fix44 = parse_spec("../spec/FIX44.xml");
        let globals = build_global_field_types(&[fix42, fix44]);
        let tera = test_tera();

        let tmp = tempfile::tempdir().unwrap();
        generate_enums(&tera, &globals, false, tmp.path());

        let content = fs::read_to_string(tmp.path().join("enums.rs")).unwrap();

        // OrdType should have merged enums from both specs.
        assert!(content.contains("pub mod ord_type {"));

        // Should have enum values within the ord_type module.
        let in_ord_type: String = content
            .split("pub mod ord_type {")
            .nth(1)
            .unwrap()
            .split('}')
            .next()
            .unwrap()
            .to_string();
        // MARKET and LIMIT should exist.
        assert!(in_ord_type.contains("MARKET"), "OrdType should have MARKET");
        assert!(in_ord_type.contains("LIMIT"), "OrdType should have LIMIT");
    }

    #[test]
    fn test_generate_header() {
        let fix44 = parse_spec("../spec/FIX44.xml");
        let globals = build_global_field_types(std::slice::from_ref(&fix44));
        let tera = test_tera();

        let tmp = tempfile::tempdir().unwrap();
        generate_header(&tera, &fix44, &globals, false, tmp.path());

        let content = fs::read_to_string(tmp.path().join("header.rs")).unwrap();

        assert!(content.contains("// Code generated by fixer-gen. DO NOT EDIT."));
        assert!(content.contains("pub struct Header<'a>"));
        assert!(content.contains("pub fn new(header: &mut FieldMap) -> Header<'_>"));
        // Should set BEGIN_STRING.
        assert!(content.contains("FIX.4.4"));
        // Should have setters for common header fields.
        assert!(content.contains("set_sender_comp_id"));
        assert!(content.contains("set_target_comp_id"));
        assert!(content.contains("set_msg_type"));
        // Should have has_ methods.
        assert!(content.contains("has_sender_comp_id"));
    }

    #[test]
    fn test_generate_trailer() {
        let fix44 = parse_spec("../spec/FIX44.xml");
        let globals = build_global_field_types(std::slice::from_ref(&fix44));
        let tera = test_tera();

        let tmp = tempfile::tempdir().unwrap();
        generate_trailer(&tera, &fix44, &globals, false, tmp.path());

        let content = fs::read_to_string(tmp.path().join("trailer.rs")).unwrap();

        assert!(content.contains("// Code generated by fixer-gen. DO NOT EDIT."));
        assert!(content.contains("pub struct Trailer<'a>"));
        // Trailer typically has CheckSum, Signature, SignatureLength.
        assert!(content.contains("has_check_sum") || content.contains("has_signature"));
    }

    #[test]
    fn test_generate_message() {
        let fix44 = parse_spec("../spec/FIX44.xml");
        let globals = build_global_field_types(std::slice::from_ref(&fix44));
        let tera = test_tera();

        let tmp = tempfile::tempdir().unwrap();
        // Heartbeat is MsgType "0".
        generate_message(&tera, &fix44, "0", &globals, false, tmp.path());

        let content = fs::read_to_string(tmp.path().join("heartbeat.rs")).unwrap();

        assert!(content.contains("// Code generated by fixer-gen. DO NOT EDIT."));
        assert!(content.contains("pub struct Heartbeat"));
        assert!(content.contains("pub fn from_message(msg: Message) -> Self"));
        assert!(content.contains("pub fn to_message(self) -> Message"));
        // Heartbeat has TestReqID field.
        assert!(content.contains("set_test_req_id"));
        assert!(content.contains("get_test_req_id"));
        assert!(content.contains("has_test_req_id"));
        // Route function.
        assert!(content.contains("pub fn route(router: RouteOut)"));
        assert!(content.contains("\"FIX.4.4\""));
        assert!(content.contains("\"0\""));
    }

    #[test]
    fn test_generate_message_new_order_single() {
        let fix44 = parse_spec("../spec/FIX44.xml");
        let globals = build_global_field_types(std::slice::from_ref(&fix44));
        let tera = test_tera();

        let tmp = tempfile::tempdir().unwrap();
        // NewOrderSingle is MsgType "D".
        generate_message(&tera, &fix44, "D", &globals, false, tmp.path());

        let content = fs::read_to_string(tmp.path().join("new_order_single.rs")).unwrap();

        assert!(content.contains("pub struct NewOrderSingle"));
        // Should have required fields in constructor.
        assert!(content.contains("pub fn new("));
        // Should have setters for various field types.
        assert!(content.contains("set_price"));    // Decimal
        assert!(content.contains("set_side"));     // String
        assert!(content.contains("set_cl_ord_id")); // String
        // Should have decimal imports since NewOrderSingle has Price.
        assert!(content.contains("use rust_decimal::Decimal;"));
    }

    #[test]
    fn test_generate_package() {
        let fix44 = parse_spec("../spec/FIX44.xml");
        let globals = build_global_field_types(std::slice::from_ref(&fix44));
        let tera = test_tera();

        let tmp = tempfile::tempdir().unwrap();
        generate_package(&tera, &fix44, &globals, false, tmp.path());

        let pkg_dir = tmp.path().join("fix44");
        assert!(pkg_dir.exists(), "fix44/ directory should exist");

        // Should have mod.rs.
        let mod_content = fs::read_to_string(pkg_dir.join("mod.rs")).unwrap();
        assert!(mod_content.contains("pub mod header;"));
        assert!(mod_content.contains("pub mod trailer;"));
        assert!(mod_content.contains("pub use header::Header;"));
        assert!(mod_content.contains("pub use trailer::Trailer;"));
        // Should list message modules.
        assert!(mod_content.contains("pub mod heartbeat;"));

        // Should have header.rs and trailer.rs.
        assert!(pkg_dir.join("header.rs").exists());
        assert!(pkg_dir.join("trailer.rs").exists());

        // Should have message files.
        assert!(pkg_dir.join("heartbeat.rs").exists());

        // Count generated message files (excluding mod.rs, header.rs, trailer.rs).
        let msg_count = fs::read_dir(&pkg_dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                std::path::Path::new(&name).extension().is_some_and(|ext| ext.eq_ignore_ascii_case("rs")) && name != "mod.rs" && name != "header.rs" && name != "trailer.rs"
            })
            .count();
        assert!(
            msg_count > 10,
            "FIX44 should have many messages, got {msg_count}"
        );
    }

    #[test]
    fn test_generate_package_fix50_no_header() {
        let fix50 = parse_spec("../spec/FIX50.xml");
        let globals = build_global_field_types(std::slice::from_ref(&fix50));
        let tera = test_tera();

        let tmp = tempfile::tempdir().unwrap();
        generate_package(&tera, &fix50, &globals, false, tmp.path());

        let pkg_dir = tmp.path().join("fix50");
        assert!(pkg_dir.exists());

        // FIX50 uses fixt11 header/trailer, so should NOT have its own.
        let mod_content = fs::read_to_string(pkg_dir.join("mod.rs")).unwrap();
        assert!(!mod_content.contains("pub mod header;"), "FIX50 should not have its own header");
        assert!(!mod_content.contains("pub mod trailer;"), "FIX50 should not have its own trailer");
        assert!(!pkg_dir.join("header.rs").exists());
        assert!(!pkg_dir.join("trailer.rs").exists());

        // Should still have messages (FIX50 has ExecutionReport=8, NewOrderSingle=D, etc.)
        assert!(pkg_dir.join("new_order_single.rs").exists());
    }

    #[test]
    fn test_generate_lib_rs() {
        let tera = test_tera();
        let packages = vec![
            "fix44".to_string(),
            "fix42".to_string(),
            "fixt11".to_string(),
            "fix50sp2".to_string(),
        ];

        let tmp = tempfile::tempdir().unwrap();
        generate_lib_rs(&tera, &packages, tmp.path());

        let content = fs::read_to_string(tmp.path().join("lib.rs")).unwrap();

        assert!(content.contains("// Code generated by fixer-gen. DO NOT EDIT."));
        assert!(content.contains("pub mod tag;"));
        assert!(content.contains("pub mod enums;"));
        assert!(content.contains("pub mod field;"));
        assert!(content.contains("pub mod fix42;"));
        assert!(content.contains("pub mod fix44;"));
        assert!(content.contains("pub mod fix50sp2;"));
        assert!(content.contains("pub mod fixt11;"));

        // Packages should be sorted.
        let mods: Vec<&str> = content
            .lines()
            .filter_map(|l| {
                let trimmed = l.trim();
                trimmed
                    .strip_prefix("pub mod ")
                    .and_then(|s| s.strip_suffix(';'))
            })
            .filter(|m| !["tag", "enums", "field"].contains(m))
            .collect();
        for w in mods.windows(2) {
            assert!(w[0] <= w[1], "Packages not sorted: {} > {}", w[0], w[1]);
        }
    }
}
