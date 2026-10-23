# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.11.0] - 2026-10-23

### Security

- Require `rustls-webpki` >= 0.103.16 and `webpki-roots` >= 1.0.10 (the latter
  with the MongoDB features) for the eMudhra CA key compromise
  (CVE-2026-111943; RUSTSEC-2026-0381, RUSTSEC-2026-0382). Both are only
  transitive dependencies; the floors ensure an existing lockfile cannot keep a
  vulnerable version when fixer is updated.
- A peer could crash the engine with a repeating group whose first field is not
  the group's delimiter. This is now rejected as a malformed message.

### Breaking changes

- **Minimum supported Rust version is now 1.94** (was 1.88). See
  [Minimum Supported Rust Version](README.md#minimum-supported-rust-version)
  for the policy going forward.
- **`fixer-fix`: repeating groups have typed accessors.** Each group field now
  has its own generated types, e.g. `NoOrdersRepeatingGroup` and `NoOrders`,
  in place of a plain `NumInGroup` integer setter. Message constructors no
  longer take group counters as arguments: the count is derived from the
  number of entries added.
- **`SessionSettings::clone` is now a deep copy.** It used to share the
  underlying map, so changing a clone changed the original — including the
  engine's `[DEFAULT]` settings via `Settings::global_settings()`. Code that
  relied on that to configure defaults should use the new
  `Settings::overlay_global_settings`.

### Added

- `encoding` module with a `Codec` trait and JSON (`JsonCodec`) and FIXML
  (`FixmlCodec`) encodings alongside tag-value. FIXML abbreviations for
  FIX.4.4 through FIX.5.0SP2 and FIXT.1.1 are bundled
  (`FixmlAbbreviations::bundled`).
- `FieldMap::ordered_fields`, an ordered view of a map's fields that works the
  same for parsed and programmatically built messages (#95).
- `Settings::session_settings_for` and `Settings::overlay_global_settings`.
- Native Windows support (#112).

### Fixed

- Parsing a message was quadratic in its size: every field formatted an
  unused error message containing the rest of the buffer. A 50-entry market
  data snapshot now parses about 9x faster with 7x less allocation (#109).
- A repeating group nested inside another lost its entries when read off the
  wire (#94).
- Repeating group entries built in code were written in ascending tag order,
  so a group whose delimiter is not its lowest tag produced messages peers
  could not parse.
- `Settings::parse` panicked on a setting that appears before any section
  header; it now returns an error.
- Session setup looked up one session's settings by copying every session's,
  which made accepting a connection quadratic in the number of configured
  sessions (#44).

### Changed

- Dependencies updated, including OpenTelemetry 0.33, sqlx 0.9, mongodb 3.9,
  quick-xml 0.42 and tera 2.

[0.11.0]: https://github.com/fixer-rs/fixer/compare/c2c43fb...v0.11.0
