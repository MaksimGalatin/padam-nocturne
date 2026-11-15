use std::fs;
use std::path::Path;

fn extract_padam_version(init_py: &str) -> Option<String> {
    for line in init_py.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("__version__") {
            let eq = rest.trim_start().strip_prefix('=')?.trim();
            let unquoted = eq.trim_matches(|c| c == '"' || c == '\'');
            if !unquoted.is_empty() {
                return Some(unquoted.to_string());
            }
        }
    }
    None
}

fn main() {
    let init_path = Path::new("../../padam/__init__.py");
    println!("cargo:rerun-if-changed=../../padam/__init__.py");
    if let Ok(raw) = fs::read_to_string(init_path) {
        if let Some(ver) = extract_padam_version(&raw) {
            println!("cargo:rustc-env=PADAM_VERSION={ver}");
            let pkg_ver = std::env::var("CARGO_PKG_VERSION").unwrap_or_default();
            assert_eq!(
                pkg_ver, ver,
                "Cargo.toml version ({pkg_ver}) must match padam/__init__.py ({ver})"
            );
        }
    }
    tauri_build::build()
}
