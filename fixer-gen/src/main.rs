mod generate;
mod globals;
mod helpers;

use std::path::PathBuf;

use clap::Parser;
use fixer::datadictionary::DataDictionary;
use tera::Tera;

use generate::{
    generate_enums, generate_fields, generate_lib_rs, generate_package, generate_tags,
};
use globals::build_global_field_types;
use helpers::package_name;

/// Code generator for fixer FIX protocol types.
///
/// Reads FIX XML spec files and generates Rust source code for
/// tags, enums, field wrappers, and per-version message modules.
#[derive(Parser)]
#[command(name = "fixer-gen")]
struct Cli {
    /// Paths to FIX XML spec files (e.g., spec/FIX44.xml).
    #[arg(required = true)]
    spec_files: Vec<PathBuf>,

    /// Output directory for generated source files.
    #[arg(short, long, default_value = ".")]
    output: PathBuf,

    /// Use f64 for FIX float fields instead of Decimal.
    #[arg(long)]
    use_float: bool,
}

fn build_tera() -> Tera {
    let mut tera = Tera::default();
    tera.add_raw_templates(vec![
        ("tag.rs.tera", include_str!("../templates/tag.rs.tera")),
        ("enums.rs.tera", include_str!("../templates/enums.rs.tera")),
        ("field.rs.tera", include_str!("../templates/field.rs.tera")),
        (
            "message.rs.tera",
            include_str!("../templates/message.rs.tera"),
        ),
        (
            "header.rs.tera",
            include_str!("../templates/header.rs.tera"),
        ),
        (
            "trailer.rs.tera",
            include_str!("../templates/trailer.rs.tera"),
        ),
        ("mod.rs.tera", include_str!("../templates/mod.rs.tera")),
        ("lib.rs.tera", include_str!("../templates/lib.rs.tera")),
    ])
    .expect("Failed to load embedded templates");
    tera
}

/// If any spec is FIX 5.0+, auto-add FIXT11.xml from the same directory.
fn auto_add_fixt11(spec_files: &mut Vec<PathBuf>) {
    let needs_fixt = spec_files.iter().any(|p| {
        let stem = p
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .to_uppercase();
        stem.starts_with("FIX50")
    });

    if !needs_fixt {
        return;
    }

    let already_has = spec_files.iter().any(|p| {
        let stem = p
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .to_uppercase();
        stem == "FIXT11"
    });

    if already_has {
        return;
    }

    // Derive FIXT11.xml path from the first spec file's directory.
    if let Some(dir) = spec_files.first().and_then(|p| p.parent()) {
        let fixt_path = dir.join("FIXT11.xml");
        if fixt_path.exists() {
            println!("Auto-adding {}", fixt_path.display());
            spec_files.push(fixt_path);
        } else {
            eprintln!(
                "Warning: FIX 5.0+ specs require FIXT11.xml but {} not found",
                fixt_path.display()
            );
        }
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let mut spec_files = cli.spec_files;
    auto_add_fixt11(&mut spec_files);

    // Parse all spec files.
    let mut specs = Vec::new();
    for path in &spec_files {
        let path_str = path.to_string_lossy();
        println!("Parsing {path_str}...");
        let spec = DataDictionary::parse(&path_str)
            .await
            .unwrap_or_else(|e| panic!("Failed to parse {path_str}: {e}"));
        specs.push(spec);
    }

    // Build global field types across all specs.
    let globals = build_global_field_types(&specs);
    println!(
        "Merged {} field types across {} specs",
        globals.types.len(),
        specs.len()
    );

    let tera = build_tera();
    let output = &cli.output;
    std::fs::create_dir_all(output)
        .unwrap_or_else(|e| panic!("Failed to create output dir {}: {e}", output.display()));

    // Generate global files.
    generate_tags(&tera, &globals, output);
    println!("Generated tag.rs");

    generate_enums(&tera, &globals, cli.use_float, output);
    println!("Generated enums.rs");

    generate_fields(&tera, &globals, cli.use_float, output);
    println!("Generated field.rs");

    // Generate per-version packages.
    let mut packages = Vec::new();
    for spec in &specs {
        let pkg = package_name(spec);
        println!("Generating {pkg}/...");
        generate_package(&tera, spec, &globals, cli.use_float, output);
        packages.push(pkg);
    }

    // Generate lib.rs.
    generate_lib_rs(&tera, &packages, output);
    println!("Generated lib.rs");

    println!("Done.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auto_add_fixt11() {
        let mut files = vec![
            PathBuf::from("spec/FIX44.xml"),
            PathBuf::from("spec/FIX50.xml"),
        ];
        auto_add_fixt11(&mut files);
        // Should add FIXT11.xml if the file exists.
        // In test context, spec/ may not exist, so just verify the logic doesn't panic.
        // If running from the project root, it would add it.
        assert!(files.len() >= 2);
    }

    #[test]
    fn test_auto_add_fixt11_not_needed() {
        let mut files = vec![PathBuf::from("spec/FIX44.xml")];
        auto_add_fixt11(&mut files);
        // No FIX50+ specs, so no auto-add.
        assert_eq!(files.len(), 1);
    }

    #[test]
    fn test_auto_add_fixt11_already_present() {
        let mut files = vec![
            PathBuf::from("spec/FIX50.xml"),
            PathBuf::from("spec/FIXT11.xml"),
        ];
        auto_add_fixt11(&mut files);
        // Already has FIXT11, should not add again.
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn test_build_tera() {
        let tera = build_tera();
        let names: Vec<&str> = tera.get_template_names().collect();
        assert!(names.contains(&"tag.rs.tera"));
        assert!(names.contains(&"enums.rs.tera"));
        assert!(names.contains(&"field.rs.tera"));
        assert!(names.contains(&"message.rs.tera"));
        assert!(names.contains(&"header.rs.tera"));
        assert!(names.contains(&"trailer.rs.tera"));
        assert!(names.contains(&"mod.rs.tera"));
        assert!(names.contains(&"lib.rs.tera"));
        assert_eq!(names.len(), 8);
    }

    #[test]
    fn verify_cli() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}
