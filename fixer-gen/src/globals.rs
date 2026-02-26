use std::collections::HashMap;

use fixer::datadictionary::{DataDictionary, Enum, FieldType};
use rustc_hash::FxHashMap;

/// Aggregated global field type, combining information across all FIX specs.
#[derive(Debug, Clone)]
pub struct GlobalFieldType {
    pub name: String,
    pub tag: isize,
    pub fix_type: String,
    pub enums: FxHashMap<String, Enum>,
}

impl GlobalFieldType {
    fn from_field_type(ft: &FieldType) -> Self {
        Self {
            name: ft.name().to_string(),
            tag: ft.tag(),
            fix_type: ft.r#type.clone(),
            enums: ft.enums.clone(),
        }
    }
}

/// Result of aggregating field types across all specs.
pub struct GlobalFieldTypes {
    /// Sorted by name for deterministic output.
    pub types: Vec<GlobalFieldType>,
    /// Lookup by field name.
    pub by_name: HashMap<String, GlobalFieldType>,
}

/// Merge field types across all FIX specs.
///
/// Ports Go's `internal/globals.go:BuildGlobalFieldTypes`.
///
/// When the same field name appears in multiple specs:
/// - The newer spec's field type wins.
/// - Enums are merged: old enums not present in the new spec are kept,
///   unless a new enum already has the same description.
pub fn build_global_field_types(specs: &[DataDictionary]) -> GlobalFieldTypes {
    let mut lookup: HashMap<String, GlobalFieldType> = HashMap::new();

    for spec in specs {
        for ft in spec.field_type_by_tag.values() {
            let name = ft.name().to_string();

            if let Some(old) = lookup.get(&name) {
                // Merge old enums into new field's enums.
                let mut merged = GlobalFieldType::from_field_type(ft);

                for (enum_val, old_enum) in &old.enums {
                    if merged.enums.contains_key(enum_val) {
                        continue;
                    }

                    // Verify an existing enum doesn't have the same description.
                    // Keep newer enum in that case.
                    let duplicate_desc = merged
                        .enums
                        .values()
                        .any(|new_enum| new_enum.description == old_enum.description);

                    if !duplicate_desc {
                        merged.enums.insert(enum_val.clone(), old_enum.clone());
                    }
                }

                lookup.insert(name, merged);
            } else {
                lookup.insert(name.clone(), GlobalFieldType::from_field_type(ft));
            }
        }
    }

    let mut types: Vec<GlobalFieldType> = lookup.values().cloned().collect();
    types.sort_by(|a, b| a.name.cmp(&b.name));

    let by_name = lookup;

    GlobalFieldTypes { types, by_name }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::runtime::Runtime;

    fn parse_spec(path: &str) -> DataDictionary {
        Runtime::new()
            .unwrap()
            .block_on(DataDictionary::parse(path))
            .unwrap()
    }

    #[test]
    fn test_build_global_field_types_single_spec() {
        let spec = parse_spec("../spec/FIX44.xml");
        let globals = build_global_field_types(&[spec]);

        // Should have field types.
        assert!(!globals.types.is_empty());

        // Should be sorted by name.
        for w in globals.types.windows(2) {
            assert!(w[0].name <= w[1].name, "{} > {}", w[0].name, w[1].name);
        }

        // Lookup should match.
        assert_eq!(globals.types.len(), globals.by_name.len());

        // Known field: Account is tag 1.
        let account = globals.by_name.get("Account").expect("Account not found");
        assert_eq!(account.tag, 1);
        assert_eq!(account.fix_type, "STRING");
    }

    #[test]
    fn test_build_global_field_types_multiple_specs() {
        let fix40 = parse_spec("../spec/FIX40.xml");
        let fix44 = parse_spec("../spec/FIX44.xml");
        let globals = build_global_field_types(&[fix40, fix44]);

        // FIX44 has more fields than FIX40, so combined should have at least as many as FIX44.
        let fix44_only = parse_spec("../spec/FIX44.xml");
        let fix44_globals = build_global_field_types(&[fix44_only]);
        assert!(globals.types.len() >= fix44_globals.types.len());

        // Enums should be merged — OrdType exists in both with potentially different enum sets.
        let ord_type = globals.by_name.get("OrdType").expect("OrdType not found");
        assert!(!ord_type.enums.is_empty());
    }

    #[test]
    fn test_build_global_field_types_enum_merge() {
        let fix42 = parse_spec("../spec/FIX42.xml");
        let fix44 = parse_spec("../spec/FIX44.xml");

        let fix42_globals = build_global_field_types(&[fix42.clone()]);
        let fix44_globals = build_global_field_types(&[fix44.clone()]);
        let merged = build_global_field_types(&[fix42, fix44]);

        // For fields with enums that exist in both specs, the merged set should be
        // >= the larger of the two individual sets (enums from older spec are preserved).
        if let (Some(old_side), Some(new_side), Some(merged_side)) = (
            fix42_globals.by_name.get("Side"),
            fix44_globals.by_name.get("Side"),
            merged.by_name.get("Side"),
        ) {
            assert!(
                merged_side.enums.len() >= old_side.enums.len(),
                "merged enums should be >= FIX42 enums"
            );
            assert!(
                merged_side.enums.len() >= new_side.enums.len(),
                "merged enums should be >= FIX44 enums"
            );
        }
    }
}
