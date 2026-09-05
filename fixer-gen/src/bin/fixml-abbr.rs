//! Extracts the FIXML abbreviation tables bundled with `fixer` from a FIX
//! repository checkout.
//!
//! The repository is ~7 MB of XML per edition and is not redistributable in
//! full, but FIXML only needs 15 attributes out of it. This writes those into
//! the compact tables under `spec/fixml/` that
//! `FixmlAbbreviations::bundled` embeds — about 500 KB for every version.
//!
//! Run via `make fixml-abbr FIX_REPOSITORY=/path/to/repository`.

use std::path::{Path, PathBuf};

use clap::Parser;
use fixer::encoding::fixml::abbr::FixmlAbbreviations;

/// Versions to extract. Each must be a directory in the repository containing
/// a `Base/` subdirectory.
///
/// FIX 4.0 through 4.3 are absent on purpose: the repository carries no
/// `AbbrName` for them, so a table would only make FIXML fall back to numeric
/// attribute names.
const VERSIONS: &[&str] = &[
    "FIX.4.4",
    "FIX.5.0",
    "FIX.5.0SP1",
    "FIX.5.0SP2",
    "FIXT.1.1",
];

#[derive(Parser)]
#[command(
    about = "Extract FIXML abbreviation tables from a FIX repository",
    long_about = None
)]
struct Args {
    /// Path to the FIX repository root (the directory holding FIX.4.4/, ...).
    repository: PathBuf,

    /// Directory to write the tables into.
    #[arg(short, long, default_value = "spec/fixml")]
    output: PathBuf,
}

fn main() {
    let args = Args::parse();

    std::fs::create_dir_all(&args.output)
        .unwrap_or_else(|e| panic!("failed to create {}: {e}", args.output.display()));

    let mut written = 0;
    for version in VERSIONS {
        let base = args.repository.join(version).join("Base");
        if !base.join("Fields.xml").exists() {
            eprintln!("skipping {version}: no Fields.xml under {}", base.display());
            continue;
        }

        let abbr = FixmlAbbreviations::from_fix_repository(&base.to_string_lossy())
            .unwrap_or_else(|e| panic!("failed to load {version}: {e}"));

        assert!(
            !abbr.tag_to_abbr.is_empty(),
            "{version} has no field abbreviations; FIXML needs AbbrName, which \
             the repository only carries from FIX.4.4 onward"
        );

        // The version attribute drives `bundled`'s lookup, so a mismatch would
        // silently hand back the wrong table.
        assert_eq!(
            &abbr.fix_version, version,
            "{version}/Base/Messages.xml declares version {:?}",
            abbr.fix_version
        );

        let out: &Path = &args.output.join(format!("{version}.tsv"));
        std::fs::write(out, abbr.to_compact())
            .unwrap_or_else(|e| panic!("failed to write {}: {e}", out.display()));

        println!("wrote {} ({} fields)", out.display(), abbr.tag_to_abbr.len());
        written += 1;
    }

    assert!(written > 0, "no versions found under {}", args.repository.display());
}
